use crate::config::FilterConfig;
use kmr_common::consts::{AID_APP_START, AID_USER_OFFSET};

#[derive(Debug, Clone)]
pub enum PackageResolution {
    Known(Vec<String>),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    Disabled,
    Allowed,
    RejectedAndroidPackage,
    RejectedByDenylist,
    RejectedNotInScope,
    RejectedUnknownPackage,
}

impl FilterDecision {
    pub fn allowed(self) -> bool {
        matches!(self, Self::Allowed | Self::Disabled)
    }
}

pub fn evaluate(
    scoop: &[String],
    config: &FilterConfig,
    uid: u32,
    resolution: &PackageResolution,
) -> FilterDecision {
    if !config.enabled {
        return FilterDecision::Disabled;
    }

    if config.block_android_package && uid % AID_USER_OFFSET < AID_APP_START {
        return FilterDecision::RejectedAndroidPackage;
    }

    let packages = match resolution {
        PackageResolution::Known(packages) => packages,
        PackageResolution::Unknown => {
            return if config.allow_unknown_package {
                FilterDecision::Allowed
            } else {
                FilterDecision::RejectedUnknownPackage
            };
        }
    };

    if config.block_android_package
        && packages.iter().any(|pkg| pkg == "android" || pkg.starts_with("android."))
    {
        FilterDecision::RejectedAndroidPackage
    } else if packages.iter().any(|pkg| config.deny_packages.contains(pkg)) {
        FilterDecision::RejectedByDenylist
    } else if !packages.iter().any(|pkg| scoop.contains(pkg)) {
        FilterDecision::RejectedNotInScope
    } else {
        FilterDecision::Allowed
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
    fn disabled_filter_reports_disabled_and_allows() {
        let mut config = base_config();
        config.enabled = false;

        let decision = evaluate(&base_scope(), &config, 10_000, &PackageResolution::Unknown);
        assert!(decision.allowed());
        assert_eq!(decision, FilterDecision::Disabled);
    }

    #[test]
    fn android_package_is_rejected_when_blocking_is_enabled() {
        let config = base_config();
        let scope = vec!["android".to_string()];

        let decision = evaluate(
            &scope,
            &config,
            10_000,
            &PackageResolution::Known(vec!["android".to_string()]),
        );
        assert!(!decision.allowed());
        assert_eq!(decision, FilterDecision::RejectedAndroidPackage);
    }

    #[test]
    fn denylist_rejection_takes_precedence_over_scope() {
        let mut config = base_config();
        config.block_android_package = false;
        config.deny_packages = vec!["com.example.app".to_string()];
        let scope = vec!["com.example.app".to_string()];

        let decision = evaluate(
            &scope,
            &config,
            10_000,
            &PackageResolution::Known(vec!["com.example.app".to_string()]),
        );
        assert!(!decision.allowed());
        assert_eq!(decision, FilterDecision::RejectedByDenylist);
    }

    #[test]
    fn known_package_outside_scope_is_rejected() {
        let mut config = base_config();
        config.block_android_package = false;

        let decision = evaluate(
            &base_scope(),
            &config,
            10_000,
            &PackageResolution::Known(vec!["com.other".to_string()]),
        );
        assert!(!decision.allowed());
        assert_eq!(decision, FilterDecision::RejectedNotInScope);

        config.allow_unknown_package = true;
        assert!(evaluate(&base_scope(), &config, 10_000, &PackageResolution::Unknown).allowed());
        let empty = evaluate(&base_scope(), &config, 10_000, &PackageResolution::Known(Vec::new()));
        assert!(!empty.allowed());
        assert_eq!(empty, FilterDecision::RejectedNotInScope);
    }

    #[test]
    fn unknown_package_policy_only_allows_app_uids() {
        let mut config = base_config();
        config.allow_unknown_package = true;

        for uid in [10_000, 110_000] {
            let decision = evaluate(&base_scope(), &config, uid, &PackageResolution::Unknown);
            assert!(decision.allowed());
            assert_eq!(decision, FilterDecision::Allowed);
        }
        for uid in [9_999, 109_999] {
            let decision = evaluate(&base_scope(), &config, uid, &PackageResolution::Unknown);
            assert!(!decision.allowed());
            assert_eq!(decision, FilterDecision::RejectedAndroidPackage);
        }
    }

    #[test]
    fn root_follows_android_package_policy() {
        let mut config = base_config();
        config.allow_unknown_package = true;

        let decision = evaluate(&base_scope(), &config, 0, &PackageResolution::Unknown);
        assert!(!decision.allowed());
        assert_eq!(decision, FilterDecision::RejectedAndroidPackage);

        config.block_android_package = false;
        let decision = evaluate(&base_scope(), &config, 0, &PackageResolution::Unknown);
        assert!(decision.allowed());
        assert_eq!(decision, FilterDecision::Allowed);
    }

    #[test]
    fn android_prefixed_package_in_scope_is_allowed() {
        let config = base_config();
        let scope = vec!["com.android.vending".to_string()];
        let decision = evaluate(&scope, &config, 10_000, &PackageResolution::Known(scope.clone()));
        assert!(decision.allowed());
        assert_eq!(decision, FilterDecision::Allowed);
    }

    #[test]
    fn empty_scope_keeps_android_and_denylist_precedence() {
        let mut config = base_config();
        config.block_android_package = false;
        let decision = evaluate(
            &[],
            &config,
            10_000,
            &PackageResolution::Known(vec!["com.anything".to_string()]),
        );
        assert!(!decision.allowed());
        assert_eq!(decision, FilterDecision::RejectedNotInScope);

        let config = base_config();
        let decision =
            evaluate(&[], &config, 10_000, &PackageResolution::Known(vec!["android".to_string()]));
        assert_eq!(decision, FilterDecision::RejectedAndroidPackage);

        let mut config = base_config();
        config.block_android_package = false;
        config.deny_packages = vec!["com.blocked".to_string()];
        let decision = evaluate(
            &[],
            &config,
            10_000,
            &PackageResolution::Known(vec!["com.blocked".to_string()]),
        );
        assert_eq!(decision, FilterDecision::RejectedByDenylist);
    }
}
