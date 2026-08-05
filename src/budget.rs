use std::time::{Duration, Instant};

use crate::domain::{BudgetConfig, BudgetUsage, Failure, FailureCode};

#[derive(Debug, Clone)]
pub struct BudgetTracker {
    config: BudgetConfig,
    started: Instant,
    usage: BudgetUsage,
}

impl BudgetTracker {
    pub fn new(config: BudgetConfig) -> Result<Self, Failure> {
        validate_config(&config)?;
        Ok(Self {
            config,
            started: Instant::now(),
            usage: BudgetUsage::default(),
        })
    }

    #[must_use]
    pub fn config(&self) -> &BudgetConfig {
        &self.config
    }

    #[must_use]
    pub fn usage(&self) -> BudgetUsage {
        let mut usage = self.usage.clone();
        usage.elapsed_ms = elapsed_ms(self.started);
        usage
    }

    pub fn check_wall(&self) -> Result<(), Failure> {
        if self.started.elapsed() >= Duration::from_millis(self.config.max_wall_ms) {
            return Err(exhausted("wall-clock budget exhausted"));
        }
        Ok(())
    }

    #[must_use]
    pub fn remaining_wall(&self) -> Duration {
        Duration::from_millis(self.config.max_wall_ms).saturating_sub(self.started.elapsed())
    }

    #[must_use]
    pub fn remaining_total_bytes(&self) -> usize {
        self.config
            .max_total_bytes
            .saturating_sub(self.usage.total_bytes)
    }

    #[must_use]
    pub fn remaining_network_operations(&self) -> u32 {
        self.config
            .max_network_operations
            .saturating_sub(self.usage.network_operations)
    }

    #[must_use]
    pub fn remaining_retry_delay_ms(&self) -> u64 {
        self.config
            .max_retry_delay_ms
            .saturating_sub(self.usage.retry_delay_ms)
    }

    /// Reserves provider-specific network units: request attempts for direct
    /// HTTP/media and public upstream connections for egress-backed providers.
    pub fn reserve_network(&mut self, count: u32) -> Result<(), Failure> {
        let next = self
            .usage
            .network_operations
            .checked_add(count)
            .ok_or_else(|| exhausted("network-operation counter overflow"))?;
        if next > self.config.max_network_operations {
            return Err(exhausted("network-operation budget exhausted"));
        }
        self.usage.network_operations = next;
        Ok(())
    }

    pub fn reserve_browser_launch(&mut self) -> Result<(), Failure> {
        let next = self
            .usage
            .browser_launches
            .checked_add(1)
            .ok_or_else(|| exhausted("browser-launch counter overflow"))?;
        if next > self.config.max_browser_launches {
            return Err(exhausted("browser-launch budget exhausted"));
        }
        self.usage.browser_launches = next;
        Ok(())
    }

    pub fn reserve_response_bytes(
        &mut self,
        response_bytes_before: usize,
        chunk_bytes: usize,
    ) -> Result<(), Failure> {
        let response_total = response_bytes_before
            .checked_add(chunk_bytes)
            .ok_or_else(|| exhausted("response byte counter overflow"))?;
        if response_total > self.config.max_response_bytes {
            return Err(exhausted("per-response byte budget exhausted"));
        }
        self.reserve_total_bytes(chunk_bytes)
    }

    pub fn reserve_extracted_bytes(&mut self, bytes: usize) -> Result<(), Failure> {
        if bytes > self.config.max_extracted_bytes {
            return Err(exhausted("extracted-content byte budget exhausted"));
        }
        self.reserve_total_bytes(bytes)
    }

    /// Screenshot artifacts have no ceiling of their own; they draw from the same
    /// total-byte pool as every other stage so one large capture cannot be paid for
    /// twice. Named separately to keep the call site's intent readable.
    pub fn reserve_artifact_bytes(&mut self, bytes: usize) -> Result<(), Failure> {
        self.reserve_total_bytes(bytes)
    }

    /// Bytes a browser backend moved through the egress proxy. Also drawn from the
    /// shared total-byte pool rather than a separate allowance.
    pub fn reserve_external_network_bytes(&mut self, bytes: usize) -> Result<(), Failure> {
        self.reserve_total_bytes(bytes)
    }

    pub fn reserve_redirect(&mut self) -> Result<(), Failure> {
        let next = self
            .usage
            .redirects
            .checked_add(1)
            .ok_or_else(|| exhausted("redirect counter overflow"))?;
        if next > self.config.max_redirects {
            return Err(exhausted("redirect budget exhausted"));
        }
        self.usage.redirects = next;
        Ok(())
    }

    pub fn reserve_retry(&mut self) -> Result<(), Failure> {
        let next = self
            .usage
            .retries
            .checked_add(1)
            .ok_or_else(|| exhausted("retry counter overflow"))?;
        if next > self.config.max_retries {
            return Err(exhausted("retry budget exhausted"));
        }
        self.usage.retries = next;
        Ok(())
    }

    pub fn reserve_retry_delay(&mut self, delay: Duration) -> Result<(), Failure> {
        let delay_ms = u64::try_from(delay.as_millis())
            .map_err(|_| exhausted("retry-delay conversion overflow"))?;
        let next = self
            .usage
            .retry_delay_ms
            .checked_add(delay_ms)
            .ok_or_else(|| exhausted("retry-delay counter overflow"))?;
        if next > self.config.max_retry_delay_ms {
            return Err(exhausted("retry-delay budget exhausted"));
        }
        self.usage.retry_delay_ms = next;
        Ok(())
    }

    fn reserve_total_bytes(&mut self, bytes: usize) -> Result<(), Failure> {
        let next = self
            .usage
            .total_bytes
            .checked_add(bytes)
            .ok_or_else(|| exhausted("total byte counter overflow"))?;
        if next > self.config.max_total_bytes {
            return Err(exhausted("total byte budget exhausted"));
        }
        self.usage.total_bytes = next;
        Ok(())
    }
}

pub fn validate_config(config: &BudgetConfig) -> Result<(), Failure> {
    if config.max_wall_ms == 0
        || config.max_network_operations == 0
        || config.max_response_bytes == 0
        || config.max_extracted_bytes == 0
        || config.max_total_bytes == 0
        || config.connect_timeout_ms == 0
        || config.read_timeout_ms == 0
    {
        return Err(Failure::new(
            FailureCode::InvalidRequest,
            "all mandatory budgets and timeouts must be non-zero",
        ));
    }
    if config.max_response_bytes > config.max_total_bytes
        || config.max_extracted_bytes > config.max_total_bytes
    {
        return Err(Failure::new(
            FailureCode::InvalidRequest,
            "per-stage byte budgets cannot exceed max_total_bytes",
        ));
    }
    if config.connect_timeout_ms > config.max_wall_ms || config.read_timeout_ms > config.max_wall_ms
    {
        return Err(Failure::new(
            FailureCode::InvalidRequest,
            "connect/read timeout cannot exceed max_wall_ms",
        ));
    }
    Ok(())
}

fn exhausted(message: &str) -> Failure {
    Failure::new(FailureCode::BudgetExhausted, message)
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{BudgetTracker, validate_config};
    use crate::domain::BudgetConfig;

    #[test]
    fn rejects_zero_limits() {
        let config = BudgetConfig {
            max_wall_ms: 0,
            ..BudgetConfig::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn operation_budget_is_hard() {
        let config = BudgetConfig {
            max_network_operations: 1,
            ..BudgetConfig::default()
        };
        let budget = BudgetTracker::new(config);
        assert!(budget.is_ok());
        let Some(mut budget) = budget.ok() else {
            return;
        };
        assert!(budget.reserve_network(1).is_ok());
        assert!(budget.reserve_network(1).is_err());
    }
}
