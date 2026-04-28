use crate::config::FilterConfig;

#[derive(Debug, Clone)]
pub enum PackageResolution {
    Known(Vec<String>),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterReason {
    Disabled,
    Allowed,
    RejectedAndroidPackage,
    RejectedByDenylist,
    RejectedNotInScope,
    RejectedUnknownPackage,
}

#[derive(Debug, Clone)]
pub struct FilterDecision {
    pub allowed: bool,
    pub reason: FilterReason,
    pub packages: Vec<String>,
}

pub fn evaluate(
    scoop: &[String],
    config: &FilterConfig,
    resolution: PackageResolution,
) -> FilterDecision {
    if !config.enabled {
        return FilterDecision {
            allowed: true,
            reason: FilterReason::Disabled,
            packages: match resolution {
                PackageResolution::Known(packages) => packages,
                PackageResolution::Unknown => Vec::new(),
            },
        };
    }

    let packages = match resolution {
        PackageResolution::Known(packages) => packages,
        PackageResolution::Unknown => {
            if config.allow_unknown_package {
                return FilterDecision {
                    allowed: true,
                    reason: FilterReason::Allowed,
                    packages: Vec::new(),
                };
            }
            return FilterDecision {
                allowed: false,
                reason: FilterReason::RejectedUnknownPackage,
                packages: Vec::new(),
            };
        }
    };

    if scoop.is_empty()
        || !packages
            .iter()
            .any(|pkg| scoop.iter().any(|entry| entry == pkg))
    {
        return FilterDecision {
            allowed: false,
            reason: FilterReason::RejectedNotInScope,
            packages,
        };
    }

    if config.block_android_package
        && packages
            .iter()
            .any(|pkg| pkg == "android" || pkg.starts_with("android."))
    {
        return FilterDecision {
            allowed: false,
            reason: FilterReason::RejectedAndroidPackage,
            packages,
        };
    }

    if packages
        .iter()
        .any(|pkg| config.deny_packages.iter().any(|deny| deny == pkg))
    {
        return FilterDecision {
            allowed: false,
            reason: FilterReason::RejectedByDenylist,
            packages,
        };
    }

    FilterDecision {
        allowed: true,
        reason: FilterReason::Allowed,
        packages,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> FilterConfig {
        FilterConfig::default()
    }

    fn base_scope() -> Vec<String> {
        vec!["com.allowed".to_string()]
    }

    #[test]
    fn disabled_filter_allows_unknown_package() {
        let mut config = base_config();
        config.enabled = false;

        let decision = evaluate(&base_scope(), &config, PackageResolution::Unknown);
        assert!(decision.allowed);
        assert_eq!(decision.reason, FilterReason::Disabled);
    }

    #[test]
    fn android_package_is_blocked_before_allowlist_checks() {
        let config = base_config();
        let scope = vec!["android".to_string()];

        let decision = evaluate(
            &scope,
            &config,
            PackageResolution::Known(vec!["android".to_string()]),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);
    }

    #[test]
    fn denylist_takes_priority_over_allowlist() {
        let mut config = base_config();
        config.block_android_package = false;
        config.deny_packages = vec!["com.example.app".to_string()];
        let scope = vec!["com.example.app".to_string()];

        let decision = evaluate(
            &scope,
            &config,
            PackageResolution::Known(vec!["com.example.app".to_string()]),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, FilterReason::RejectedByDenylist);
    }

    #[test]
    fn scope_rejects_non_matching_known_package() {
        let mut config = base_config();
        config.block_android_package = false;

        let decision = evaluate(
            &base_scope(),
            &config,
            PackageResolution::Known(vec!["com.other".to_string()]),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, FilterReason::RejectedNotInScope);
    }

    #[test]
    fn unknown_package_can_be_allowed_explicitly() {
        let mut config = base_config();
        config.allow_unknown_package = true;

        let decision = evaluate(&base_scope(), &config, PackageResolution::Unknown);
        assert!(decision.allowed);
        assert_eq!(decision.reason, FilterReason::Allowed);
    }

    #[test]
    fn empty_scope_rejects_all_known_packages() {
        let mut config = base_config();
        config.block_android_package = false;

        let decision = evaluate(
            &[],
            &config,
            PackageResolution::Known(vec!["com.anything".to_string()]),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, FilterReason::RejectedNotInScope);
    }

    #[test]
    fn disabled_filter_still_requires_scope_membership() {
        let mut config = base_config();
        config.enabled = false;
        config.block_android_package = false;

        let decision = evaluate(
            &base_scope(),
            &config,
            PackageResolution::Known(vec!["com.other".to_string()]),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, FilterReason::RejectedNotInScope);
    }
}
