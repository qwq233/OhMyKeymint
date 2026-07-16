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
            let allowed = config.allow_unknown_package;
            return FilterDecision {
                allowed,
                reason: if allowed {
                    FilterReason::Allowed
                } else {
                    FilterReason::RejectedUnknownPackage
                },
                packages: Vec::new(),
            };
        }
    };

    let reason = if !packages.iter().any(|pkg| scoop.contains(pkg)) {
        FilterReason::RejectedNotInScope
    } else if config.block_android_package
        && packages
            .iter()
            .any(|pkg| pkg == "android" || pkg.starts_with("android."))
    {
        FilterReason::RejectedAndroidPackage
    } else if packages
        .iter()
        .any(|pkg| config.deny_packages.contains(pkg))
    {
        FilterReason::RejectedByDenylist
    } else {
        FilterReason::Allowed
    };

    FilterDecision {
        allowed: reason == FilterReason::Allowed,
        reason,
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
    fn filter_decision_matrix() {
        let mut config = base_config();
        config.enabled = false;

        let decision = evaluate(&base_scope(), &config, PackageResolution::Unknown);
        assert!(decision.allowed);
        assert_eq!(decision.reason, FilterReason::Disabled);

        let config = base_config();
        let scope = vec!["android".to_string()];

        let decision = evaluate(
            &scope,
            &config,
            PackageResolution::Known(vec!["android".to_string()]),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);

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

        let mut config = base_config();
        config.block_android_package = false;

        let decision = evaluate(
            &base_scope(),
            &config,
            PackageResolution::Known(vec!["com.other".to_string()]),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, FilterReason::RejectedNotInScope);

        let mut config = base_config();
        config.allow_unknown_package = true;

        let decision = evaluate(&base_scope(), &config, PackageResolution::Unknown);
        assert!(decision.allowed);
        assert_eq!(decision.reason, FilterReason::Allowed);

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
}
