use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

#[cfg(windows)]
use process_wrap::tokio::JobObject;
#[cfg(unix)]
use process_wrap::tokio::ProcessGroup;
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::domain::{Failure, FailureCode};

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub environment: BTreeMap<OsString, OsString>,
    pub current_dir: PathBuf,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
}

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub success: bool,
    pub status_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ManagedProcessSpec {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub environment: BTreeMap<OsString, OsString>,
    pub current_dir: PathBuf,
    pub stderr_limit: usize,
}

#[derive(Debug)]
pub struct ManagedProcess {
    child: Option<Box<dyn ChildWrapper>>,
    stderr_task: Option<tokio::task::JoinHandle<std::io::Result<LimitedRead>>>,
}

#[derive(Debug, Clone)]
pub struct ManagedProcessResult {
    pub success: bool,
    pub status_code: Option<i32>,
    pub forced: bool,
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
}

#[derive(Debug)]
struct LimitedRead {
    bytes: Vec<u8>,
    truncated: bool,
}

pub async fn run_command(spec: CommandSpec) -> Result<CommandResult, Failure> {
    if spec.timeout.is_zero() {
        return Err(Failure::new(
            FailureCode::BudgetExhausted,
            "provider command has no remaining wall-clock budget",
        ));
    }
    let mut command = Command::new(&spec.executable);
    command
        .args(&spec.args)
        .current_dir(&spec.current_dir)
        .env_clear()
        .envs(spec.environment.iter())
        .stdin(if spec.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut command = CommandWrap::from(command);
    command.wrap(KillOnDrop);
    #[cfg(unix)]
    command.wrap(ProcessGroup::leader());
    #[cfg(windows)]
    command.wrap(JobObject);

    let mut child = command.spawn().map_err(|error| {
        Failure::new(
            FailureCode::ProviderFailed,
            format!(
                "failed to launch {}: {error}",
                spec.executable.to_string_lossy()
            ),
        )
    })?;

    let stdout = child.stdout().take().ok_or_else(|| {
        Failure::new(
            FailureCode::InternalError,
            "provider stdout pipe was not created",
        )
    })?;
    let stderr = child.stderr().take().ok_or_else(|| {
        Failure::new(
            FailureCode::InternalError,
            "provider stderr pipe was not created",
        )
    })?;

    let stdout_limit = spec.stdout_limit;
    let stderr_limit = spec.stderr_limit;
    let stdout_task = tokio::spawn(async move { read_limited(stdout, stdout_limit).await });
    let stderr_task = tokio::spawn(async move { read_limited(stderr, stderr_limit).await });

    if let Some(input) = spec.stdin {
        let mut stdin = child.stdin().take().ok_or_else(|| {
            Failure::new(
                FailureCode::InternalError,
                "provider stdin pipe was not created",
            )
        })?;
        // A child that never reads its stdin would otherwise fill the pipe and block
        // this write past the point where the command timeout should have applied.
        let write = async {
            stdin.write_all(&input).await?;
            stdin.shutdown().await
        };
        tokio::time::timeout(spec.timeout, write)
            .await
            .map_err(|_| {
                Failure::new(
                    FailureCode::BudgetExhausted,
                    "provider did not accept its stdin within the command budget",
                )
            })?
            .map_err(|error| {
                Failure::new(
                    FailureCode::ProviderFailed,
                    format!("failed to write provider stdin: {error}"),
                )
            })?;
    }

    let wait_result = tokio::time::timeout(spec.timeout, child.wait()).await;
    let (status, timed_out) = match wait_result {
        Ok(result) => (
            Some(result.map_err(|error| {
                Failure::new(
                    FailureCode::ProviderFailed,
                    format!("provider wait failed: {error}"),
                )
            })?),
            false,
        ),
        Err(_) => {
            let _ = Box::into_pin(child.kill()).await;
            let status = child.wait().await.ok();
            (status, true)
        }
    };

    let stdout_read = join_reader(stdout_task, "stdout").await?;
    let stderr_read = join_reader(stderr_task, "stderr").await?;
    let success = !timed_out
        && status
            .as_ref()
            .is_some_and(std::process::ExitStatus::success);
    Ok(CommandResult {
        success,
        status_code: status.and_then(|value| value.code()),
        timed_out,
        stdout: stdout_read.bytes,
        stderr: stderr_read.bytes,
    })
}

impl ManagedProcess {
    pub fn spawn(spec: ManagedProcessSpec) -> Result<Self, Failure> {
        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.args)
            .current_dir(&spec.current_dir)
            .env_clear()
            .envs(spec.environment.iter())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut command = CommandWrap::from(command);
        command.wrap(KillOnDrop);
        #[cfg(unix)]
        command.wrap(ProcessGroup::leader());
        #[cfg(windows)]
        command.wrap(JobObject);
        let mut child = command.spawn().map_err(|error| {
            Failure::new(
                FailureCode::ProviderFailed,
                format!(
                    "failed to launch {}: {error}",
                    spec.executable.to_string_lossy()
                ),
            )
        })?;
        let stderr = child.stderr().take().ok_or_else(|| {
            Failure::new(
                FailureCode::InternalError,
                "managed process stderr pipe was not created",
            )
        })?;
        let stderr_limit = spec.stderr_limit;
        let stderr_task = tokio::spawn(async move { read_limited(stderr, stderr_limit).await });
        Ok(Self {
            child: Some(child),
            stderr_task: Some(stderr_task),
        })
    }

    pub fn has_exited(&mut self) -> Result<bool, Failure> {
        let Some(child) = self.child.as_mut() else {
            return Ok(true);
        };
        child
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|error| {
                Failure::new(
                    FailureCode::ProviderFailed,
                    format!("managed process status check failed: {error}"),
                )
            })
    }

    pub async fn shutdown(
        &mut self,
        graceful_timeout: Duration,
    ) -> Result<ManagedProcessResult, Failure> {
        let Some(child) = self.child.as_mut() else {
            return Err(Failure::new(
                FailureCode::InternalError,
                "managed process was already shut down",
            ));
        };
        let mut forced = graceful_timeout.is_zero();
        let status = if forced {
            Box::into_pin(child.kill()).await.map_err(|error| {
                Failure::new(
                    FailureCode::ProviderFailed,
                    format!("managed process termination failed: {error}"),
                )
            })?;
            child.try_wait().map_err(|error| {
                Failure::new(
                    FailureCode::ProviderFailed,
                    format!("managed process status collection failed: {error}"),
                )
            })?
        } else {
            match tokio::time::timeout(graceful_timeout, child.wait()).await {
                Ok(result) => Some(result.map_err(|error| {
                    Failure::new(
                        FailureCode::ProviderFailed,
                        format!("managed process wait failed: {error}"),
                    )
                })?),
                Err(_) => {
                    forced = true;
                    Box::into_pin(child.kill()).await.map_err(|error| {
                        Failure::new(
                            FailureCode::ProviderFailed,
                            format!("managed process forced termination failed: {error}"),
                        )
                    })?;
                    child.try_wait().map_err(|error| {
                        Failure::new(
                            FailureCode::ProviderFailed,
                            format!("managed process status collection failed: {error}"),
                        )
                    })?
                }
            }
        };
        self.child.take();
        let stderr = match self.stderr_task.take() {
            Some(task) => join_reader(task, "stderr").await?,
            None => LimitedRead {
                bytes: Vec::new(),
                truncated: false,
            },
        };
        Ok(ManagedProcessResult {
            success: status
                .as_ref()
                .is_some_and(std::process::ExitStatus::success),
            status_code: status.and_then(|value| value.code()),
            forced,
            stderr: stderr.bytes,
            stderr_truncated: stderr.truncated,
        })
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        if let Some(task) = &self.stderr_task {
            task.abort();
        }
    }
}

pub fn resolve_executable(
    explicit: Option<&Path>,
    candidates: &[&str],
) -> Result<PathBuf, Failure> {
    if let Some(path) = explicit {
        if is_executable_file(path) {
            return Ok(path.to_path_buf());
        }
        return Err(Failure::new(
            FailureCode::ToolUnavailable,
            format!("configured executable is not usable: {}", path.display()),
        ));
    }
    let path_value = env::var_os("PATH").unwrap_or_default();
    for directory in env::split_paths(&path_value) {
        for candidate in candidates {
            let path = directory.join(candidate);
            if is_executable_file(&path) {
                return Ok(path);
            }
            #[cfg(windows)]
            {
                let path = directory.join(format!("{candidate}.exe"));
                if is_executable_file(&path) {
                    return Ok(path);
                }
            }
        }
    }
    Err(Failure::new(
        FailureCode::ToolUnavailable,
        format!("executable not found in PATH: {}", candidates.join(", ")),
    ))
}

pub async fn probe_version(
    executable: &Path,
    current_dir: &Path,
    environment: &BTreeMap<OsString, OsString>,
    timeout: Duration,
) -> Result<String, Failure> {
    let result = run_command(CommandSpec {
        executable: executable.to_path_buf(),
        args: vec![OsString::from("--version")],
        environment: environment.clone(),
        current_dir: current_dir.to_path_buf(),
        stdin: None,
        timeout,
        stdout_limit: 8 * 1024,
        stderr_limit: 8 * 1024,
    })
    .await?;
    if result.timed_out {
        return Err(Failure::new(
            FailureCode::ToolUnavailable,
            "version probe timed out",
        ));
    }
    if !result.success {
        return Err(Failure::new(
            FailureCode::ToolUnavailable,
            format!(
                "version probe failed with status {:?}: {}",
                result.status_code,
                first_line(&result.stderr)
            ),
        ));
    }
    let line = first_line(&result.stdout);
    if line.is_empty() {
        return Err(Failure::new(
            FailureCode::ToolUnavailable,
            "version probe returned empty output",
        ));
    }
    Ok(line)
}

#[must_use]
pub fn isolated_environment(home: &Path) -> BTreeMap<OsString, OsString> {
    let mut values = BTreeMap::new();
    copy_environment(&mut values, "PATH");
    copy_environment(&mut values, "SystemRoot");
    copy_environment(&mut values, "COMSPEC");
    copy_environment(&mut values, "PATHEXT");
    copy_environment(&mut values, "WINDIR");
    copy_environment(&mut values, "LOCALAPPDATA");
    copy_environment(&mut values, "APPDATA");
    copy_environment(&mut values, "ProgramFiles");
    copy_environment(&mut values, "ProgramFiles(x86)");
    copy_environment(&mut values, "LD_LIBRARY_PATH");
    copy_environment(&mut values, "DYLD_LIBRARY_PATH");
    copy_environment(&mut values, "LANG");
    copy_environment(&mut values, "LC_ALL");
    values.insert(OsString::from("HOME"), home.as_os_str().to_os_string());
    values.insert(
        OsString::from("USERPROFILE"),
        home.as_os_str().to_os_string(),
    );
    values.insert(OsString::from("TMPDIR"), home.as_os_str().to_os_string());
    values.insert(OsString::from("TEMP"), home.as_os_str().to_os_string());
    values.insert(OsString::from("TMP"), home.as_os_str().to_os_string());
    values.insert(OsString::from("NO_COLOR"), OsString::from("1"));
    values
}

#[must_use]
pub fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn copy_environment(target: &mut BTreeMap<OsString, OsString>, name: &str) {
    if let Some(value) = env::var_os(name) {
        target.insert(OsString::from(name), value);
    }
}

async fn join_reader(
    task: tokio::task::JoinHandle<std::io::Result<LimitedRead>>,
    stream_name: &str,
) -> Result<LimitedRead, Failure> {
    task.await
        .map_err(|error| {
            Failure::new(
                FailureCode::ProviderFailed,
                format!("provider {stream_name} reader task failed: {error}"),
            )
        })?
        .map_err(|error| {
            Failure::new(
                FailureCode::ProviderFailed,
                format!("provider {stream_name} read failed: {error}"),
            )
        })
}

async fn read_limited<R>(mut reader: R, limit: usize) -> std::io::Result<LimitedRead>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut total = 0_usize;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        let remaining = limit.saturating_sub(bytes.len());
        if remaining > 0 {
            bytes.extend_from_slice(&buffer[..read.min(remaining)]);
        }
    }
    Ok(LimitedRead {
        bytes,
        truncated: total > limit,
    })
}

pub(crate) fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{CommandSpec, first_line, run_command};

    #[test]
    fn first_line_is_bounded_to_one_line() {
        assert_eq!(first_line(b"one\ntwo"), "one");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_terminates_the_process_group() {
        let result = run_command(CommandSpec {
            executable: PathBuf::from("/bin/sh"),
            args: vec![OsString::from("-c"), OsString::from("sleep 30 & wait")],
            environment: BTreeMap::new(),
            current_dir: std::env::temp_dir(),
            stdin: None,
            timeout: Duration::from_millis(50),
            stdout_limit: 1024,
            stderr_limit: 1024,
        })
        .await;
        assert!(result.is_ok());
        assert!(result.ok().is_some_and(|value| value.timed_out));
    }
}
