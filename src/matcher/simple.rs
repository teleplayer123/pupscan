use crate::core::traits::Matcher;
use crate::core::types::*;
use semver::{Version, VersionReq};

pub struct SimpleMatcher;

impl Matcher for SimpleMatcher {
    fn match_packages(
        &self,
        packages: &[Package],
        vulns: &[Vulnerability],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for pkg in packages {
            let cleaned_version = normalize_version(&pkg.version);

            let parsed_version = match Version::parse(&cleaned_version) {
                Ok(v) => v,
                Err(_) => continue,
            };

            for vuln in vulns {
                if pkg.name != vuln.package {
                    continue;
                }

                for range in &vuln.version_ranges {
                    if let Ok(req) = VersionReq::parse(range) {
                        if req.matches(&parsed_version) {
                            findings.push(Finding {
                                package: pkg.clone(),
                                vulnerability: vuln.clone(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        findings
    }
}

fn normalize_version(v: &str) -> String {
    v.trim()
        .trim_start_matches('^')
        .trim_start_matches('~')
        .trim_start_matches(">=")
        .trim_start_matches('=')
        .to_string()
}