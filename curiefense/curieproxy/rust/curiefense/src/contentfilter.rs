use hyperscan::Matching;
use lazy_static::lazy_static;
use libinjection::{sqli, xss};
use std::collections::{HashMap, HashSet};

use crate::config::contentfilter::{
    rule_tags, ContentFilterEntryMatch, ContentFilterProfile, ContentFilterRules, ContentFilterSection, Section,
    SectionIdx,
};
use crate::interface::stats::{BStageAcl, BStageContentFilter, StatsCollect};
use crate::interface::{BDecision, BlockReason, Initiator, Location, Tags};
use crate::requestfields::RequestField;
use crate::utils::{masker, RequestInfo};
use crate::Logs;

lazy_static! {
    pub static ref LIBINJECTION_SQLI_TAGS: HashSet<String> = [
        "cf-rule-id:libinjection-sqli",
        "cf-rule-category:libinjection",
        "cf-rule-subcategory:libinjection-sqli",
        "cf-rule-risk:libinjection",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    pub static ref LIBINJECTION_XSS_TAGS: HashSet<String> = [
        "cf-rule-id:libinjection-xss",
        "cf-rule-category:libinjection",
        "cf-rule-subcategory:libinjection-xss",
        "cf-rule-risk:libinjection",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
}

#[derive(Default)]
struct Omitted {
    entries: Section<HashSet<String>>,
    exclusions: Section<HashMap<String, HashSet<String>>>,
}

fn get_section(idx: SectionIdx, rinfo: &RequestInfo) -> &RequestField {
    use SectionIdx::*;
    match idx {
        Headers => &rinfo.headers,
        Cookies => &rinfo.cookies,
        Args => &rinfo.rinfo.qinfo.args,
        Path => &rinfo.rinfo.qinfo.path_as_map,
    }
}

fn is_blocking(reasons: &[BlockReason]) -> bool {
    reasons.iter().any(|r| r.decision >= BDecision::Blocking)
}

pub struct CfBlock {
    pub blocking: bool,
    pub reasons: Vec<BlockReason>,
}

/// Runs the Content Filter part of curiefense
/// in case of matches, returns a pair (is_blocking, reasons)
pub fn content_filter_check(
    logs: &mut Logs,
    stats: StatsCollect<BStageAcl>,
    tags: &mut Tags,
    rinfo: &RequestInfo,
    profile: &ContentFilterProfile,
    mhsdb: Option<&ContentFilterRules>,
) -> (Result<(), CfBlock>, StatsCollect<BStageContentFilter>) {
    use SectionIdx::*;
    let mut omit = Default::default();

    // directly exit if omitted profile
    if tags.has_intersection(&profile.ignore) {
        logs.debug("content filter bypass because of global ignore");
        return (Ok(()), stats.no_content_filter());
    }

    // check section profiles
    for idx in &[Path, Headers, Cookies, Args] {
        if let Err(reason) = section_check(
            logs,
            tags,
            *idx,
            profile.sections.get(*idx),
            get_section(*idx, rinfo),
            profile.ignore_alphanum,
            &mut omit,
        ) {
            return (
                Err(CfBlock {
                    blocking: true,
                    reasons: vec![reason],
                }),
                stats.no_content_filter(),
            );
        }
    }

    let kept = profile.active.union(&profile.report).cloned().collect::<HashSet<_>>();
    let test_xss = LIBINJECTION_XSS_TAGS.intersection(&profile.ignore).next().is_none()
        && LIBINJECTION_XSS_TAGS.intersection(&kept).next().is_some();
    let test_sqli = LIBINJECTION_SQLI_TAGS.intersection(&profile.ignore).next().is_none()
        && LIBINJECTION_SQLI_TAGS.intersection(&kept).next().is_some();

    let mut hca_keys: HashMap<String, (SectionIdx, String)> = HashMap::new();

    // list of non whitelisted entries
    for idx in &[Path, Headers, Cookies, Args] {
        let section_content = get_section(*idx, rinfo)
            .iter()
            .filter(|(name, _)| !omit.entries.get(*idx).contains(*name))
            .map(|(name, value)| (value.to_string(), (*idx, name.to_string())));
        hca_keys.extend(section_content);
    }

    let iblock = if cfg!(fuzzing) {
        Vec::new()
    } else {
        injection_check(tags, &hca_keys, &omit, test_xss, test_sqli)
    };
    if is_blocking(&iblock) {
        return (
            Err(CfBlock {
                blocking: true,
                reasons: iblock,
            }),
            stats.no_content_filter(),
        );
    }

    let mut specific_tags = Tags::default();

    // finally, hyperscan check
    match mhsdb {
        Some(hsdb) => {
            let (scanresult, stats) = hyperscan(
                logs,
                stats,
                tags,
                &mut specific_tags,
                hca_keys,
                hsdb,
                &kept,
                &profile.active,
                &profile.report,
                &profile.ignore,
                &omit.exclusions,
            );
            match scanresult {
                Err(rr) => {
                    logs.error(|| rr.to_string());
                    (Ok(()), stats)
                }
                Ok(reasons) => {
                    tags.extend(specific_tags);
                    if reasons.is_empty() {
                        (Ok(()), stats)
                    } else {
                        (
                            Err(CfBlock {
                                blocking: is_blocking(&reasons),
                                reasons,
                            }),
                            stats,
                        )
                    }
                }
            }
        }
        None => {
            logs.warning(||format!("no hsdb found for profile {}, it probably means that no rules were matched by the active/report/ignore", profile.id));
            (Ok(()), stats.no_content_filter())
        }
    }
}

/// checks a section (headers, args, cookies) against the policy
fn section_check(
    logs: &mut Logs,
    tags: &Tags,
    idx: SectionIdx,
    section: &ContentFilterSection,
    params: &RequestField,
    ignore_alphanum: bool,
    omit: &mut Omitted,
) -> Result<(), BlockReason> {
    if idx != SectionIdx::Path && params.len() > section.max_count {
        if section.max_count > 0 {
            return Err(BlockReason::too_many_entries(idx, params.len(), section.max_count));
        } else {
            logs.warning(|| format!("In section {:?}, param_count = 0", idx));
        }
    }

    for (name, value) in params.iter() {
        // skip decoded parameters for length checks
        if !name.ends_with(":decoded") && value.len() > section.max_length {
            if section.max_length > 0 {
                return Err(BlockReason::entry_too_large(idx, name, value.len(), section.max_length));
            } else {
                logs.warning(|| format!("In section {:?}, max_length = 0", idx));
            }
        }

        // automatically ignored
        if ignore_alphanum && value.chars().all(|c| c.is_ascii_alphanumeric()) {
            omit.entries.at(idx).insert(name.to_string());
            continue;
        }

        // logic for checking an entry
        let mut check_entry = |name_entry: &ContentFilterEntryMatch| {
            let matched = if let Some(re) = &name_entry.reg {
                re.matches(value)
            } else {
                false
            };
            if matched {
                omit.entries.at(idx).insert(name.to_string());
            } else if name_entry.restrict {
                return Err(BlockReason::restricted(Location::from_value(idx, name, value)));
            } else if tags.has_intersection(&name_entry.exclusions) {
                omit.entries.at(idx).insert(name.to_string());
            } else if !name_entry.exclusions.is_empty() {
                let entry = omit.exclusions.at(idx).entry(name.to_string()).or_default();
                entry.extend(name_entry.exclusions.iter().cloned());
            }
            Ok(())
        };

        // check name rules
        if let Some(entry) = section.names.get(name) {
            check_entry(entry)?;
            // if an argument was matched by exact check, we do not try to match it against regex rules
            continue;
        }

        // // check regex rules
        for entry in section
            .regex
            .iter()
            .filter_map(|(re, v)| if re.is_match(name) { Some(v) } else { None })
        {
            check_entry(entry)?;
        }
    }

    Ok(())
}

/// TODO: This also populates the hca_keys map
/// this is stupid and needs to be changed
fn injection_check(
    tags: &mut Tags,
    hca_keys: &HashMap<String, (SectionIdx, String)>,
    omit: &Omitted,
    test_xss: bool,
    test_sqli: bool,
) -> Vec<BlockReason> {
    let mut out = Vec::new();
    for (value, (idx, name)) in hca_keys.iter() {
        let omit_tags = omit.exclusions.get(*idx).get(name);
        let rtest_xss = test_xss
            && !omit_tags
                .map(|tgs| LIBINJECTION_XSS_TAGS.intersection(tgs).next().is_some())
                .unwrap_or(false);
        let rtest_sqli = test_sqli
            && !omit_tags
                .map(|tgs| LIBINJECTION_SQLI_TAGS.intersection(tgs).next().is_some())
                .unwrap_or(false);
        if rtest_sqli {
            if let Some((b, fp)) = sqli(value) {
                if b {
                    let locs = Location::from_value(*idx, name, value);
                    tags.insert_qualified("cf-rule-id", "libinjection-sqli", locs.clone());
                    tags.insert_qualified("cf-rule-category", "libinjection", locs.clone());
                    tags.insert_qualified("cf-rule-subcategory", "libinjection-sqli", locs.clone());
                    tags.insert_qualified("cf-rule-risk", "libinjection", locs.clone());
                    out.push(BlockReason::sqli(locs, fp));
                }
            }
        }
        if rtest_xss {
            if let Some(b) = xss(value) {
                if b {
                    let locs = Location::from_value(*idx, name, value);
                    tags.insert_qualified("cf-rule-id", "libinjection-xss", locs.clone());
                    tags.insert_qualified("cf-rule-category", "libinjection", locs.clone());
                    tags.insert_qualified("cf-rule-subcategory", "libinjection-xss", locs.clone());
                    tags.insert_qualified("cf-rule-risk", "libinjection", locs.clone());
                    out.push(BlockReason::xss(locs));
                }
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn hyperscan(
    logs: &mut Logs,
    stats: StatsCollect<BStageAcl>,
    tags: &mut Tags,
    specific_tags: &mut Tags,
    hca_keys: HashMap<String, (SectionIdx, String)>,
    sigs: &ContentFilterRules,
    global_kept: &HashSet<String>,
    active: &HashSet<String>,
    report: &HashSet<String>,
    global_ignore: &HashSet<String>,
    exclusions: &Section<HashMap<String, HashSet<String>>>,
) -> (anyhow::Result<Vec<BlockReason>>, StatsCollect<BStageContentFilter>) {
    let scratch = match sigs.db.alloc_scratch() {
        Err(rr) => return (Err(rr), stats.no_content_filter()),
        Ok(s) => s,
    };
    // TODO: use `intersperse` when this stabilizes
    let to_scan = hca_keys.keys().cloned().collect::<Vec<_>>().join("\n");
    let mut found = false;
    if let Err(rr) = sigs.db.scan(&[to_scan], &scratch, |_, _, _, _| {
        found = true;
        Matching::Continue
    }) {
        return (Err(rr), stats.no_content_filter());
    }
    logs.debug(|| format!("matching content filter signatures: {}", found));

    if !found {
        return (Ok(Vec::new()), stats.cf_no_match(sigs.ids.len()));
    }

    let mut founds: HashSet<(&str, Location, BDecision, u8)> = HashSet::new();

    let mut matches = 0;
    let mut nactive = 0;
    // something matched! but what?
    for (k, (sid, name)) in hca_keys {
        // for some reason, from is always set to 0 in my tests, so we can't accurately capture substrings
        let scanr = sigs.db.scan(&[k.as_bytes()], &scratch, |id, from, to, _flags| {
            match sigs.ids.get(id as usize) {
                None => logs.error(|| format!("Should not happen, invalid hyperscan index {}", id)),
                Some(sig) => {
                    logs.debug(|| format!("signature matched [{}..{}] {:?}", from, to, sig));

                    // new specific tags are singleton hashsets, but we use the Tags structure to make sure
                    // they are properly converted
                    let (new_specific_tags, new_tags) = rule_tags(sig);
                    if (new_tags.has_intersection(global_kept) || new_specific_tags.has_intersection(global_kept))
                        && exclusions
                            .get(sid)
                            .get(&name)
                            .map(|ex| new_tags.has_intersection(ex) || new_specific_tags.has_intersection(ex))
                            != Some(true)
                        && !new_tags.has_intersection(global_ignore)
                        && !new_specific_tags.has_intersection(global_ignore)
                    {
                        matches += 1;
                        let location = Location::from_value(sid, &name, &k);
                        tags.merge(new_tags.with_loc(&location));
                        specific_tags.merge(new_specific_tags.with_loc(&location));
                        let decision = if specific_tags.has_intersection(active) {
                            nactive += 1;
                            BDecision::Blocking
                        } else if specific_tags.has_intersection(report) {
                            BDecision::Monitor
                        } else if tags.has_intersection(active) {
                            nactive += 1;
                            BDecision::Blocking
                        } else {
                            BDecision::Monitor
                        };
                        founds.insert((&sig.id, location, decision, sig.risk));
                    }
                }
            }
            Matching::Continue
        });
        if let Err(rr) = scanr {
            return (Err(rr), stats.cf_matches(sigs.ids.len(), matches, nactive));
        }
    }
    (
        Ok(founds
            .into_iter()
            .map(|(sigid, location, decision, risk_level)| BlockReason {
                initiator: Initiator::ContentFilter {
                    ruleid: sigid.to_string(),
                    risk_level,
                },
                location: std::iter::once(location).collect(),
                decision,
            })
            .collect()),
        stats.cf_matches(sigs.ids.len(), matches, nactive),
    )
}

fn mask_section(masking_seed: &[u8], sec: &mut RequestField, section: &ContentFilterSection) -> HashSet<Location> {
    let to_mask: Vec<String> = sec
        .iter()
        .filter(|&(name, _)| {
            if let Some(e) = section.names.get(name) {
                e.mask
            } else {
                section.regex.iter().any(|(re, e)| e.mask && re.is_match(name))
            }
        })
        .map(|(name, _)| name.to_string())
        .collect();
    to_mask.iter().flat_map(|n| sec.mask(masking_seed, n)).collect()
}

pub fn masking(masking_seed: &[u8], req: RequestInfo, profile: &ContentFilterProfile) -> RequestInfo {
    let mut ri = req;
    let mut to_mask = HashSet::new();

    to_mask.extend(mask_section(
        masking_seed,
        &mut ri.cookies,
        profile.sections.get(SectionIdx::Cookies),
    ));
    to_mask.extend(mask_section(
        masking_seed,
        &mut ri.rinfo.qinfo.args,
        profile.sections.get(SectionIdx::Args),
    ));
    to_mask.extend(mask_section(
        masking_seed,
        &mut ri.rinfo.qinfo.path_as_map,
        profile.sections.get(SectionIdx::Path),
    ));
    to_mask.extend(mask_section(
        masking_seed,
        &mut ri.headers,
        profile.sections.get(SectionIdx::Headers),
    ));

    for extra_mask in to_mask {
        use Location::*;
        match extra_mask {
            UriArgumentValue(_, v) => {
                let target = masker(masking_seed, &v);
                let npath = ri.rinfo.meta.path.replace(&v, &target);
                ri.rinfo.meta.path = npath;
                let nquery = ri.rinfo.qinfo.query.replace(&v, &target);
                ri.rinfo.qinfo.query = nquery;
            }
            RefererArgumentValue(_, v) => {
                let target = masker(masking_seed, &v);
                ri.headers.alter("referer", |r| r.replace(&v, &target));
            }
            Body => {
                ri.rinfo.qinfo.args.mask(masking_seed, "RAW_BODY");
            }
            _ => (),
        }
    }

    ri
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::interface::stats::Stats;
    use crate::interface::{jsonlog, Decision};
    use crate::utils::{map_request, RequestMeta};
    use crate::{Logs, RawRequest};

    fn test_request_info() -> RequestInfo {
        let meta = RequestMeta {
            authority: Some("myhost".to_string()),
            method: "GET".to_string(),
            path: "/foo?arg1=avalue1&arg2=a%20value2".to_string(),
            extra: HashMap::default(),
            requestid: None,
        };
        let mut logs = Logs::default();
        let headers = [("h1", "value1"), ("h2", "value2")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let raw_request = RawRequest {
            ipstr: "1.2.3.4".into(),
            mbody: None,
            headers,
            meta,
        };
        map_request(
            &mut logs,
            "a",
            "b",
            &[],
            b"CHANGEME",
            &[],
            &[],
            false,
            500,
            false,
            &raw_request,
            None,
        )
    }

    #[test]
    fn no_masking() {
        let rinfo = test_request_info();
        let profile = ContentFilterProfile::default_from_seed("test");
        let masked = masking(b"test", rinfo.clone(), &profile);
        assert_eq!(rinfo.headers, masked.headers);
        assert_eq!(rinfo.cookies, masked.cookies);
        assert_eq!(rinfo.rinfo.qinfo.args, masked.rinfo.qinfo.args);
    }

    fn maskentry() -> ContentFilterEntryMatch {
        ContentFilterEntryMatch {
            restrict: false,
            mask: true,
            exclusions: HashSet::default(),
            reg: None,
        }
    }

    fn masksecret() -> ContentFilterEntryMatch {
        ContentFilterEntryMatch {
            restrict: false,
            mask: true,
            exclusions: HashSet::default(),
            reg: Some(crate::config::matchers::Matching::from_str("SECRET", "SECRET".to_string()).unwrap()),
        }
    }

    #[test]
    fn masking_all_args_re() {
        let rinfo = test_request_info();
        let mut profile = ContentFilterProfile::default_from_seed("test");
        let asection = profile.sections.at(SectionIdx::Args);
        asection.regex = vec![(regex::Regex::new(".").unwrap(), maskentry())];
        let masked = masking(b"test", rinfo.clone(), &profile);
        assert_eq!(rinfo.headers, masked.headers);
        assert_eq!(rinfo.cookies, masked.cookies);
        assert_eq!(
            RequestField::raw_create(
                &[],
                &[
                    (
                        "arg1",
                        &Location::UriArgumentValue("arg1".to_string(), "avalue1".to_string()),
                        "MASKED{e8efcceb}"
                    ),
                    (
                        "arg2",
                        &Location::UriArgumentValue("arg2".to_string(), "a%20value2".to_string()),
                        "MASKED{42541ec7}"
                    )
                ]
            ),
            masked.rinfo.qinfo.args
        );
        assert_eq!(
            "/foo?arg1=MASKED{e8efcceb}&arg2=MASKED{c96a6118}",
            masked.rinfo.meta.path
        );
        assert_eq!("arg1=MASKED{e8efcceb}&arg2=MASKED{c96a6118}", masked.rinfo.qinfo.query);
        let (logged, _) = async_std::task::block_on(jsonlog(
            &Decision::pass(Vec::new()),
            Some(&masked),
            None,
            &Tags::default(),
            &Stats::default(),
            &Logs::default(),
            HashMap::new(),
        ));
        let log_string = String::from_utf8(logged).unwrap();
        if log_string.contains("avalue1") || log_string.contains("a value2") || log_string.contains("a%20value2") {
            panic!("log lacks masking: {}", log_string)
        }
    }

    #[test]
    fn masking_re_arg1() {
        let rinfo = test_request_info();
        let mut profile = ContentFilterProfile::default_from_seed("test");
        let asection = profile.sections.at(SectionIdx::Args);
        asection.regex = vec![(regex::Regex::new("1").unwrap(), maskentry())];
        let masked = masking(b"test", rinfo.clone(), &profile);
        assert_eq!(rinfo.headers, masked.headers);
        assert_eq!(rinfo.cookies, masked.cookies);
        assert_eq!(
            RequestField::raw_create(
                &[],
                &[
                    (
                        "arg1",
                        &Location::UriArgumentValue("arg1".to_string(), "avalue1".to_string()),
                        "MASKED{e8efcceb}"
                    ),
                    (
                        "arg2",
                        &Location::UriArgumentValue("arg2".to_string(), "a%20value2".to_string()),
                        "a value2"
                    )
                ]
            ),
            masked.rinfo.qinfo.args
        );
    }

    #[test]
    fn masking_named_arg1() {
        let rinfo = test_request_info();
        let mut profile = ContentFilterProfile::default_from_seed("test");
        let asection = profile.sections.at(SectionIdx::Args);
        asection.names = ["arg1"].iter().map(|k| (k.to_string(), maskentry())).collect();
        let masked = masking(b"test", rinfo.clone(), &profile);
        assert_eq!(rinfo.headers, masked.headers);
        assert_eq!(rinfo.cookies, masked.cookies);
        assert_eq!(
            RequestField::raw_create(
                &[],
                &[
                    (
                        "arg1",
                        &Location::UriArgumentValue("arg1".to_string(), "avalue1".to_string()),
                        "MASKED{e8efcceb}"
                    ),
                    (
                        "arg2",
                        &Location::UriArgumentValue("arg2".to_string(), "a%20value2".to_string()),
                        "a value2"
                    )
                ]
            ),
            masked.rinfo.qinfo.args
        );
    }

    #[test]
    fn masking_all_args_names() {
        let rinfo = test_request_info();
        let mut profile = ContentFilterProfile::default_from_seed("test");
        let asection = profile.sections.at(SectionIdx::Args);
        asection.names = ["arg1", "arg2"].iter().map(|k| (k.to_string(), maskentry())).collect();
        let masked = masking(b"test", rinfo.clone(), &profile);
        assert_eq!(rinfo.headers, masked.headers);
        assert_eq!(rinfo.cookies, masked.cookies);
        assert_eq!(
            RequestField::raw_create(
                &[],
                &[
                    (
                        "arg1",
                        &Location::UriArgumentValue("arg1".to_string(), "avalue1".to_string()),
                        "MASKED{e8efcceb}"
                    ),
                    (
                        "arg2",
                        &Location::UriArgumentValue("arg2".to_string(), "a%20value2".to_string()),
                        "MASKED{42541ec7}"
                    )
                ]
            ),
            masked.rinfo.qinfo.args
        );
    }

    #[test]
    fn complex_parent_masking() {
        let meta = RequestMeta {
            authority: Some("myhost".to_string()),
            method: "GET".to_string(),
            path: "/foo/pth/ddd?arg1=SECRETa1&arg2=U0VDUkVUYTI%3D".to_string(),
            extra: HashMap::default(),
            requestid: None,
        };
        let mut logs = Logs::default();
        let headers = [
            ("h1", "SECRETh1"),
            ("h2", "U0VDUkVUaDI="),
            ("content-type", "application/json"),
            ("cookie", "COOK=U0VDUkVUCg=="),
            ("referer", "https://another.site.com/with?a1=SECRETr1&a2=U0VDUkVUcjI="),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let raw_request = RawRequest {
            ipstr: "1.2.3.4".into(),
            mbody: Some(b"{\"arg1\": [\"SECRETb\"], \"arg2\": [\"U0VDUkVUYjI=\"]}"),
            headers,
            meta,
        };
        let rinfo = map_request(
            &mut logs,
            "a",
            "b",
            &[],
            b"CHANGEME",
            &[crate::config::contentfilter::Transformation::Base64Decode],
            &[crate::config::raw::ContentType::Json],
            true,
            50,
            false,
            &raw_request,
            None,
        );

        let mut profile = ContentFilterProfile::default_from_seed("test");
        let asection = profile.sections.at(SectionIdx::Args);
        asection.regex = vec![(regex::Regex::new(".*").unwrap(), masksecret())];
        let hsection = profile.sections.at(SectionIdx::Headers);
        hsection.regex = vec![(regex::Regex::new("^h.*").unwrap(), masksecret())];
        let csection = profile.sections.at(SectionIdx::Cookies);
        csection.regex = vec![(regex::Regex::new(".*").unwrap(), masksecret())];

        let masked = masking(b"test", rinfo, &profile);

        let (logged, _) = async_std::task::block_on(jsonlog(
            &Decision::pass(Vec::new()),
            Some(&masked),
            None,
            &Tags::default(),
            &Stats::default(),
            &Logs::default(),
            HashMap::new(),
        ));
        let log_string = String::from_utf8(logged).unwrap();
        if log_string.contains("SECRET") {
            panic!("SECRET found in {}", log_string);
        }
        if log_string.contains("U0VDU") {
            panic!("U0VDU found in {}", log_string);
        }
    }
}
