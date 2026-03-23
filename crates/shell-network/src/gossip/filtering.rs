use crate::fetch::FetchDecision;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct AnnouncementFilter {
    pub max_transaction_bytes: Option<u64>,
    pub max_sidecar_bytes: Option<u64>,
    pub allow_unsolicited_sidecars: bool,
}

impl AnnouncementFilter {
    pub fn transaction_fetch_decision(&self, announced_size: u64) -> FetchDecision {
        match self.max_transaction_bytes {
            Some(limit) if announced_size > limit => FetchDecision::Skip,
            _ => FetchDecision::Fetch,
        }
    }

    pub fn sidecar_fetch_decision(
        &self,
        announced_size: u64,
        was_requested: bool,
    ) -> FetchDecision {
        match self.max_sidecar_bytes {
            Some(limit) if announced_size > limit => FetchDecision::Skip,
            _ if !self.allow_unsolicited_sidecars && !was_requested => FetchDecision::Defer,
            _ => FetchDecision::Fetch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsolicited_sidecars_are_deferred_until_requested() {
        let filter = AnnouncementFilter {
            max_transaction_bytes: None,
            max_sidecar_bytes: Some(1_024),
            allow_unsolicited_sidecars: false,
        };

        assert_eq!(
            filter.sidecar_fetch_decision(512, false),
            FetchDecision::Defer
        );
    }
}
