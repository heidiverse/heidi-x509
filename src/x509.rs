use whitespace_sifter::WhitespaceSifter;
use x509_parser::{
    der_parser::oid,
    parse_x509_certificate,
    prelude::{
        ParsedExtension, TbsCertificateStructureValidator, Validator, VecLogger,
        X509ExtensionsValidator,
    },
    time::ASN1Time,
    x509::X509Name,
};

pub fn select_root<T: AsRef<[u8]>>(cert: T, root_store: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    for c in root_store {
        let Ok((_, root)) = parse_x509_certificate(c.as_slice()) else {
            continue;
        };
        if are_x509_name_equal(&cert.issuer, &root.subject) {
            return Some(c);
        }
    }
    None
}

pub fn verify_chain_at(
    certs: Vec<Vec<u8>>,
    time: ASN1Time,
    #[cfg(feature = "crl")] check_crl: bool,
) -> bool {
    // a valid chain requires at least two certificates (leaf + issuer)
    if certs.len() < 2 {
        tracing::error!("chain must contain at least two certificates");
        return false;
    }
    // first certificate is the leaf certificate
    let mut certs = certs;
    // the last (or rather first) certificate is not an intermediate and is not counted towards the path len
    let total_path_len = certs.len() - 1;
    let mut prev_cert = certs.pop();
    let mut current_position = 1;
    while let Some(issuer_cert) = prev_cert {
        prev_cert = certs.pop();
        if let Some(subject_cert) = prev_cert.as_ref() {
            let (_, issuer_cert) =
                x509_parser::parse_x509_certificate(issuer_cert.as_slice()).unwrap();
            let mut logger = VecLogger::default();
            let structure_validity =
                TbsCertificateStructureValidator.validate(&issuer_cert, &mut logger);
            let x509_extensions_validity =
                X509ExtensionsValidator.validate(&issuer_cert.extensions(), &mut logger);
            if !(structure_validity && x509_extensions_validity) {
                tracing::error!("subject cert has invalid structure");
                return false;
            }
            let (_, subject_cert) =
                x509_parser::parse_x509_certificate(subject_cert.as_slice()).unwrap();
            let structure_validity =
                TbsCertificateStructureValidator.validate(&subject_cert, &mut logger);
            let x509_extensions_validity =
                X509ExtensionsValidator.validate(&subject_cert.extensions(), &mut logger);
            if !(structure_validity && x509_extensions_validity) {
                tracing::error!("issuer cert has invalid structure");
                return false;
            }
            if !is_key_usage_correct(&issuer_cert) {
                tracing::error!("issuer cert has incorrect key usage");
                return false;
            }
            match is_basic_constraint_fulfilled(&issuer_cert, current_position, total_path_len) {
                Ok(false) | Err(_) => {
                    tracing::error!("basic constraint not fullfileld");
                    return false;
                }
                _ => {}
            }

            let is_valid = subject_cert
                .verify_signature(Some(issuer_cert.public_key()))
                .is_ok();
            if !is_valid {
                tracing::error!("signature invalid");
                return false;
            }
            if !are_x509_name_equal(&subject_cert.issuer, &issuer_cert.subject) {
                tracing::error!("issuer name and subject name missmatch");
                return false;
            }

            let issuer_validity = issuer_cert.validity();
            if !issuer_validity.is_valid_at(time) {
                tracing::error!("subject certificate is not valid");
                return false;
            }
            let subject_validity = subject_cert.validity();
            if !subject_validity.is_valid_at(time) {
                tracing::error!("issuer certificate is not valid");
                return false;
            }
            #[cfg(feature = "crl")]
            if check_crl {
                match check_revocation(&subject_cert) {
                    // certificate is revoked (on the CRL)
                    Ok(true) => return false,
                    // something went wrong
                    Err(_) => return false,
                    // network error or not on the list
                    _ => {}
                }
                #[cfg(feature = "crl")]
                match check_revocation(&issuer_cert) {
                    // certificate is revoked (on the CRL)
                    Ok(true) => return false,
                    // something went wrong
                    Err(_) => return false,
                    // network error or not on the list
                    _ => {}
                }
            }
            current_position += 1;
        }
    }
    true
}

pub fn verify_chain(certs: Vec<Vec<u8>>) -> bool {
    verify_chain_at(
        certs,
        ASN1Time::now(),
        #[cfg(feature = "crl")]
        true,
    )
}
// key usage should be parsable and if present be certSign
fn is_key_usage_correct(cert: &x509_parser::prelude::X509Certificate) -> bool {
    let Ok(key_usage) = cert.key_usage() else {
        // log_error!("X509", "Failed to parse keyusage");
        return false;
    };
    let Some(key_usage) = key_usage else {
        // no key usage, everything fine
        return true;
    };
    key_usage.value.key_cert_sign()
}

/// Make sure signing certificates have cA true
fn is_basic_constraint_fulfilled(
    cert: &x509_parser::prelude::X509Certificate,
    current_path_len: usize,
    total_path_len: usize,
) -> Result<bool, ()> {
    let Ok(basic_constraints) = cert.get_extension_unique(&oid!(2.5.29.19)) else {
        return Err(());
    };
    // It was parsed successfully but no CRL found
    let Some(basic_constraints) = basic_constraints else {
        return Ok(false);
    };
    let ParsedExtension::BasicConstraints(basic_constraints) = basic_constraints.parsed_extension()
    else {
        return Err(());
    };
    // all intermediate have to have ca = true
    if !basic_constraints.ca {
        return Ok(false);
    }
    let remaining_path_len = total_path_len.saturating_sub(current_path_len);
    if let Some(path_constraint) = basic_constraints.path_len_constraint {
        if remaining_path_len > path_constraint as usize {
            return Ok(false);
        }
    }
    Ok(true)
}

/// compare x509 name removing trailing/leading bits and lowercasing
fn are_x509_name_equal(left: &X509Name, right: &X509Name) -> bool {
    left.iter().count() == right.iter().count()
        && left.iter().zip(right.iter()).all(|(l, r)| {
            l.iter().count() == r.iter().count()
                && l.iter()
                    .zip(r.iter())
                    .all(|(lc, rc)| match (lc.as_str(), rc.as_str()) {
                        (Ok(ls), Ok(rs)) => ls.sift().to_lowercase() == rs.sift().to_lowercase(),
                        _ => lc.as_slice() == rc.as_slice(),
                    })
        })
}

#[cfg(feature = "crl")]
/// Simplified function for checking and fetching a CRL over URL
///
/// Note: *Network errors are ignored!*
fn check_revocation(cert: &x509_parser::prelude::X509Certificate) -> Result<bool, ()> {
    // log_debug!("X509", "checking revocation");
    // We have a parse error, return err

    use x509_parser::{
        der_parser::oid,
        prelude::{DistributionPointName, GeneralName},
    };
    let Ok(maybe_dist_points) = cert.get_extension_unique(&oid!(2.5.29.31)) else {
        return Err(());
    };
    // It was parsed successfully but no CRL found
    let Some(crl_distribution_points) = maybe_dist_points else {
        return Ok(false);
    };
    // Something is terribly wrong, as we should have matched to the OID before
    let ParsedExtension::CRLDistributionPoints(dist_points) =
        crl_distribution_points.parsed_extension()
    else {
        return Err(());
    };
    // We only look at the first point
    let Some(point) = dist_points.points.first() else {
        return Err(());
    };
    // The URL CRL must be in the distribution_point field
    let Some(pt) = point.distribution_point.as_ref() else {
        return Err(());
    };
    // If it is not a full name we don't know what to do
    let DistributionPointName::FullName(full_name) = pt else {
        return Err(());
    };
    // again look at the first name only
    let Some(full_name) = full_name.first() else {
        return Err(());
    };
    // we don't know how to handle CLRs that do not point towards an URL
    let GeneralName::URI(uri) = full_name else {
        return Err(());
    };
    // fetch the revocation list
    let Ok(mut response) = ureq::get(*uri).call() else {
        // failed network requests are ignored
        return Ok(false);
    };
    let b = response.body_mut();
    let Ok(list) = b.read_to_vec() else {
        // if the stream is somewhat broken, ignore!
        return Ok(false);
    };
    // we fetched something, but it fails to parse, error out
    let Ok((_, crl)) = x509_parser::parse_x509_crl(&list) else {
        return Err(());
    };
    let result = crl
        .iter_revoked_certificates()
        .find(|a| *a.serial() == cert.serial);
    // log_debug!(
    //     "X509",
    //     &format!("successfully loaded CRL, revoked: {}", result.is_some())
    // );
    Ok(result.is_some())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        io::{Cursor, Read},
    };

    use flate2::read::GzDecoder;

    use x509_parser::der_parser::asn1_rs::{Any, Tag};
    use x509_parser::x509::{AttributeTypeAndValue, RelativeDistinguishedName, X509Name};

    use super::{are_x509_name_equal, verify_chain};

    #[test]
    /// Tests from https://csrc.nist.gov/Projects/pki-testing/x-509-path-validation-test-suite Version 1.07
    /// Tests regarding the CRL are currently ignored, as the certificates do not contain distribution points.
    ///
    fn test_x509_path_validation() {
        let truth_table: HashMap<&str, bool> = [
            ("test1", true),
            ("test2", false),
            ("test3", false),
            ("test4", true),
            ("test5", false),
            ("test6", false),
            ("test7", true),
            ("test8", false),
            ("test9", false),
            ("test10", false),
            ("test11", false),
            ("test12", true),
            ("test13", false),
            ("test14", false),
            ("test15", true),
            ("test16", true),
            ("test17", true),
            ("test18", true),
            ("test22", false),
            ("test23", false),
            ("test24", true),
            ("test25", false),
            ("test26", true),
            ("test27", true),
            ("test28", false),
            ("test29", false),
            ("test33", true),
            ("test54", false),
            ("test55", false),
            ("test56", true),
            ("test57", true),
            ("test58", false),
            ("test59", false),
            ("test60", false),
            ("test61", false),
            ("test62", true),
            ("test63", true),
        ]
        .into_iter()
        .collect();
        let test_suite_bytes = include_bytes!("../x509tests.tgz");
        let test_suite_bytes = GzDecoder::new(Cursor::new(test_suite_bytes));
        let mut test_suite_archive = tar::Archive::new(test_suite_bytes);
        let mut test_map = BTreeMap::<String, Vec<(String, Vec<u8>)>>::new();
        let mut test_vec = Vec::new();
        for entry in test_suite_archive.entries().unwrap() {
            let Ok(mut entry) = entry else {
                continue;
            };
            let path = entry.path().unwrap();
            if path.extension().is_some() {
                let testfile = path.strip_prefix("X509tests").unwrap();
                let test_name = testfile.parent().unwrap().to_str().unwrap().to_string();
                let file_name = testfile.file_name().unwrap().to_str().unwrap().to_string();
                if !test_vec.contains(&test_name) {
                    test_vec.push(test_name.clone());
                }
                let directory = test_map.entry(test_name).or_default();
                let mut file_bytes = Vec::with_capacity(entry.size() as usize);
                entry.read_to_end(&mut file_bytes).unwrap();
                directory.push((file_name, file_bytes));
            }
        }
        let mut correct = 0;
        let mut total = 0;
        for test in test_vec {
            let test_files = &test_map[&test];
            let mut certs = test_files
                .iter()
                .filter(|a| a.0.ends_with(".crt"))
                .map(|a| a.1.clone())
                .collect::<Vec<_>>();
            certs.reverse();
            let result = verify_chain(certs);
            let matches = if let Some(expected) = truth_table.get(&test.as_str()) {
                total += 1;
                if expected == &result {
                    correct += 1;
                    "✅"
                } else {
                    "❌"
                }
            } else {
                "-"
            };
            println!(
                "{}: {} [{}] -> {matches}",
                test,
                result,
                truth_table
                    .get(&test.as_str())
                    .map(|a| a.to_string())
                    .unwrap_or("N/A".to_string())
            );
        }
        println!("{correct}/{total}");
    }

    fn make_rdn<'a>(oid_parts: &[u64], value: &'a [u8]) -> RelativeDistinguishedName<'a> {
        let oid = x509_parser::der_parser::asn1_rs::Oid::from(oid_parts)
            .unwrap()
            .to_owned();
        let any = Any::from_tag_and_data(Tag::PrintableString, value);
        RelativeDistinguishedName::new(vec![AttributeTypeAndValue::new(oid, any)])
    }

    #[test]
    fn test_name_prefix_not_equal() {
        // CN=TrustedCA, O=Corp, C=US
        let full_name = X509Name::new(
            vec![
                make_rdn(&[2, 5, 4, 3], b"TrustedCA"),
                make_rdn(&[2, 5, 4, 10], b"Corp"),
                make_rdn(&[2, 5, 4, 6], b"US"),
            ],
            &[],
        );
        // CN=TrustedCA (prefix of the above)
        let prefix_name = X509Name::new(vec![make_rdn(&[2, 5, 4, 3], b"TrustedCA")], &[]);

        assert!(!are_x509_name_equal(&prefix_name, &full_name));
        assert!(!are_x509_name_equal(&full_name, &prefix_name));
    }

    #[test]
    fn test_name_equal() {
        let name_a = X509Name::new(
            vec![
                make_rdn(&[2, 5, 4, 3], b"TrustedCA"),
                make_rdn(&[2, 5, 4, 10], b"Corp"),
            ],
            &[],
        );
        let name_b = X509Name::new(
            vec![
                make_rdn(&[2, 5, 4, 3], b"TrustedCA"),
                make_rdn(&[2, 5, 4, 10], b"Corp"),
            ],
            &[],
        );
        assert!(are_x509_name_equal(&name_a, &name_b));
    }

    #[test]
    fn test_empty_name_not_equal_to_nonempty() {
        let empty = X509Name::new(vec![], &[]);
        let nonempty = X509Name::new(vec![make_rdn(&[2, 5, 4, 3], b"TrustedCA")], &[]);

        assert!(!are_x509_name_equal(&empty, &nonempty));
        assert!(!are_x509_name_equal(&nonempty, &empty));
    }
}
