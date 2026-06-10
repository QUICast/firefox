use crate::config::{
    SourceFilter, SubscriptionAddressFamily, SubscriptionConfig, validate_multicast_selection,
};
use crate::error::McrxError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Configuration for raw multicast IP datagram receive.
///
/// Unlike [`SubscriptionConfig`], this configuration is not tied to a UDP
/// destination port. It represents multicast membership and interface
/// selection only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSubscriptionConfig {
    /// The destination multicast group to join.
    pub group: IpAddr,
    /// The source filtering mode for the subscription.
    pub source: SourceFilter,
    /// The local interface address to join on, if explicitly specified.
    pub interface: Option<IpAddr>,
    /// The local IPv6 interface index to join on, if explicitly specified.
    pub interface_index: Option<u32>,
}

impl RawSubscriptionConfig {
    /// Validates the configuration and returns an error if it is not usable.
    pub fn validate(&self) -> Result<(), McrxError> {
        validate_multicast_selection(
            self.group,
            &self.source,
            self.interface,
            self.interface_index,
        )
    }

    /// Returns the configured address family.
    pub fn family(&self) -> SubscriptionAddressFamily {
        match self.group {
            IpAddr::V4(_) => SubscriptionAddressFamily::Ipv4,
            IpAddr::V6(_) => SubscriptionAddressFamily::Ipv6,
        }
    }

    /// Returns `true` when this is an IPv4 subscription.
    pub fn is_ipv4(&self) -> bool {
        matches!(self.family(), SubscriptionAddressFamily::Ipv4)
    }

    /// Returns `true` when this is an IPv6 subscription.
    pub fn is_ipv6(&self) -> bool {
        matches!(self.family(), SubscriptionAddressFamily::Ipv6)
    }

    /// Returns the configured source address, if any.
    pub fn source_addr(&self) -> Option<IpAddr> {
        match self.source {
            SourceFilter::Any => None,
            SourceFilter::Source(source) => Some(source),
        }
    }

    /// Creates an ASM (`(*, G)`) raw subscription configuration.
    pub fn asm(group: Ipv4Addr) -> Self {
        Self::asm_ip(group.into())
    }

    /// Creates an IPv6 ASM (`(*, G)`) raw subscription configuration.
    pub fn asm_v6(group: Ipv6Addr) -> Self {
        Self::asm_ip(group.into())
    }

    /// Creates an ASM (`(*, G)`) raw subscription configuration from any IP family.
    pub fn asm_ip(group: IpAddr) -> Self {
        Self {
            group,
            source: SourceFilter::Any,
            interface: None,
            interface_index: None,
        }
    }

    /// Creates an SSM (`(S, G)`) raw subscription configuration.
    pub fn ssm(group: Ipv4Addr, source: Ipv4Addr) -> Self {
        Self::ssm_ip(group.into(), source.into())
    }

    /// Creates an IPv6 SSM (`(S, G)`) raw subscription configuration.
    pub fn ssm_v6(group: Ipv6Addr, source: Ipv6Addr) -> Self {
        Self::ssm_ip(group.into(), source.into())
    }

    /// Creates an SSM (`(S, G)`) raw subscription configuration from any IP family.
    pub fn ssm_ip(group: IpAddr, source: IpAddr) -> Self {
        Self {
            group,
            source: SourceFilter::Source(source),
            interface: None,
            interface_index: None,
        }
    }

    pub(crate) fn membership_compat_config(&self) -> SubscriptionConfig {
        SubscriptionConfig {
            group: self.group,
            source: self.source.clone(),
            dst_port: 1,
            interface: self.interface,
            interface_index: self.interface_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ipv4_raw_config_passes_validation() {
        let cfg = RawSubscriptionConfig::asm(Ipv4Addr::new(239, 1, 2, 3));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn valid_ipv4_ssm_raw_config_passes_validation() {
        let cfg =
            RawSubscriptionConfig::ssm(Ipv4Addr::new(232, 1, 2, 3), Ipv4Addr::new(10, 0, 0, 1));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn ipv4_raw_ssm_requires_232_range() {
        let cfg =
            RawSubscriptionConfig::ssm(Ipv4Addr::new(239, 1, 1, 1), Ipv4Addr::new(10, 0, 0, 1));

        let result = cfg.validate();
        assert!(matches!(result, Err(McrxError::InvalidIpv4SsmGroup)));
    }

    #[test]
    fn valid_ipv6_ssm_raw_config_passes_validation() {
        let cfg = RawSubscriptionConfig::ssm_v6(
            "ff3e::8000:1234".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn ipv6_raw_ssm_requires_ff3x_group_range() {
        let cfg = RawSubscriptionConfig::ssm_v6(
            "ff12::1234".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        );

        let result = cfg.validate();
        assert!(matches!(result, Err(McrxError::InvalidIpv6SsmGroup)));
    }

    #[test]
    fn ipv4_raw_config_rejects_interface_index() {
        let mut cfg = RawSubscriptionConfig::asm(Ipv4Addr::new(239, 1, 2, 3));
        cfg.interface_index = Some(7);

        let result = cfg.validate();
        assert!(matches!(result, Err(McrxError::InterfaceIndexRequiresIpv6)));
    }
}
