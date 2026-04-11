use crate::core::types::{Package, PackageSource};

/// Builds a Package URL (PURL) for a package
/// See: https://github.com/package-url/purl-spec
pub fn build_purl(pkg: &Package) -> Option<String> {
    match &pkg.source {
        PackageSource::Npm => Some(format!("pkg:npm/{}@{}", pkg.name, pkg.version)),
        PackageSource::PyPI => Some(format!("pkg:pypi/{}@{}", pkg.name.to_lowercase(), pkg.version)),
        PackageSource::CargoToml => Some(format!("pkg:cargo/{}@{}", pkg.name, pkg.version)),
        PackageSource::Go => Some(format!("pkg:golang/{}@{}", pkg.name, pkg.version)),
        PackageSource::GIT => Some(format!("pkg:git/{}@{}", pkg.name, pkg.version)),
        PackageSource::RubyGems => Some(format!("pkg:gem/{}@{}", pkg.name, pkg.version)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_npm_purl() {
        let pkg = Package {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: PackageSource::Npm,
            path: None,
            purl: None,
        };
        assert_eq!(
            build_purl(&pkg),
            Some("pkg:npm/lodash@4.17.21".to_string())
        );
    }

    #[test]
    fn test_pypi_purl() {
        let pkg = Package {
            name: "Django".to_string(),
            version: "3.2.0".to_string(),
            source: PackageSource::PyPI,
            path: None,
            purl: None,
        };
        assert_eq!(
            build_purl(&pkg),
            Some("pkg:pypi/django@3.2.0".to_string())
        );
    }

    #[test]
    fn test_cargo_purl() {
        let pkg = Package {
            name: "serde".to_string(),
            version: "1.0.0".to_string(),
            source: PackageSource::CargoToml,
            path: None,
            purl: None,
        };
        assert_eq!(
            build_purl(&pkg),
            Some("pkg:cargo/serde@1.0.0".to_string())
        );
    }

    #[test]
    fn test_go_purl() {
        let pkg = Package {
            name: "github.com/user/package".to_string(),
            version: "v1.0.0".to_string(),
            source: PackageSource::Go,
            path: None,
            purl: None,
        };
        assert_eq!(
            build_purl(&pkg),
            Some("pkg:golang/github.com/user/package@v1.0.0".to_string())
        );
    }

    #[test]
    fn test_homebrew_purl() {
        let pkg = Package {
            name: "python".to_string(),
            version: "3.9.0".to_string(),
            source: PackageSource::GIT,
            path: Some(PathBuf::from("/usr/local/Cellar/python/3.9.0")),
            purl: None,
        };
        assert_eq!(
            build_purl(&pkg),
            Some("pkg:generic/homebrew/python@3.9.0".to_string())
        );
    }

    #[test]
    fn test_rubygems_purl() {
        let pkg = Package {
            name: "rails".to_string(),
            version: "6.0.0".to_string(),
            source: PackageSource::RubyGems,
            path: None,
            purl: None,
        };
        assert_eq!(
            build_purl(&pkg),
            Some("pkg:gem/rails@6.0.0".to_string())
        );
    }
}
