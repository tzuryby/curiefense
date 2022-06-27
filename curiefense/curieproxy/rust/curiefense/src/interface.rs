/// this file contains all the data type that are used when interfacing with a proxy
use self::stats::Stats;
use crate::config::contentfilter::SectionIdx;
use crate::config::raw::{RawAction, RawActionType};
use crate::grasshopper::{challenge_phase01, Grasshopper};
use crate::logs::Logs;
use crate::requestfields::RequestField;
use crate::utils::RequestInfo;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

pub mod stats;

#[derive(Debug, Clone)]
pub enum SimpleDecision {
    Pass,
    Action(SimpleAction, Vec<BlockReason>),
}

pub fn stronger_decision(d1: SimpleDecision, d2: SimpleDecision) -> SimpleDecision {
    match (&d1, &d2) {
        (SimpleDecision::Pass, _) => d2,
        (_, SimpleDecision::Pass) => d1,
        (SimpleDecision::Action(s1, _), SimpleDecision::Action(s2, _)) => {
            if s1.atype.priority() >= s2.atype.priority() {
                d1
            } else {
                d2
            }
        }
    }
}

#[derive(Debug)]
pub struct AnalyzeResult {
    pub decision: Decision,
    pub tags: Tags,
    pub rinfo: RequestInfo,
    pub stats: Stats,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub maction: Option<Action>,
    pub reasons: Vec<BlockReason>,
}

impl Decision {
    pub fn pass(reasons: Vec<BlockReason>) -> Self {
        Decision { maction: None, reasons }
    }

    pub fn action(action: Action, reasons: Vec<BlockReason>) -> Self {
        Decision {
            maction: Some(action),
            reasons,
        }
    }

    /// is the action blocking (not passed to the underlying server)
    pub fn is_blocking(&self) -> bool {
        self.maction.as_ref().map(|a| a.atype.is_blocking()).unwrap_or(false)
    }

    /// is the action final (no further processing)
    pub fn is_final(&self) -> bool {
        self.maction.as_ref().map(|a| a.atype.is_final()).unwrap_or(false)
    }

    pub fn to_legacy_json_raw(&self, request_map: serde_json::Value) -> (String, String) {
        let action_desc = match self.maction {
            None => "pass",
            Some(_) => "custom_response",
        };
        let response =
            serde_json::to_value(&self.maction).unwrap_or_else(|rr| serde_json::Value::String(rr.to_string()));
        let j = serde_json::json!({
            "action": action_desc,
            "response": response,
        });
        let l = serde_json::to_string(&j).unwrap_or_else(|_| "{}".to_string());
        let r = serde_json::to_string(&request_map).unwrap_or_else(|_| "{}".to_string());
        (l, r)
    }

    pub fn to_legacy_json(&self, rinfo: RequestInfo, tags: Tags, logs: Logs, stats: &Stats) -> (String, String) {
        let (request_map, _) = jsonlog(
            self,
            Some(&rinfo),
            self.maction.as_ref().map(|a| a.status),
            &tags,
            stats,
            &logs,
        );
        self.to_legacy_json_raw(request_map)
    }
}

// helper function that reproduces the envoy log format
pub fn jsonlog(
    dec: &Decision,
    mrinfo: Option<&RequestInfo>,
    rcode: Option<u32>,
    tags: &Tags,
    stats: &Stats,
    logs: &Logs,
) -> (serde_json::Value, chrono::DateTime<chrono::Utc>) {
    let now = chrono::Utc::now();
    let mut tgs = tags.clone();
    if let Some(action) = &dec.maction {
        if let Some(extra) = &action.extra_tags {
            for t in extra {
                tgs.insert(t, Location::Request);
            }
        }
    }
    let block_reason_desc = BlockReason::block_reason_desc(&dec.reasons);
    let greasons = BlockReason::regroup(&dec.reasons);
    let get_trigger = |k: &InitiatorKind| -> &[&BlockReason] { greasons.get(k).map(|v| v.as_slice()).unwrap_or(&[]) };

    let stats_counter = |kd: InitiatorKind| -> (usize, usize) {
        match greasons.get(&kd) {
            None => (0, 0),
            Some(v) => (v.len(), v.iter().filter(|r| r.decision == BDecision::Blocking).count()),
        }
    };
    let (acl, acl_active) = stats_counter(InitiatorKind::Acl);
    let (global_filters, global_filters_active) = stats_counter(InitiatorKind::GlobalFilter);
    let (flow_control, flow_control_active) = stats_counter(InitiatorKind::FlowControl);
    let (rate_limit, rate_limit_active) = stats_counter(InitiatorKind::GlobalFilter);
    let (content_filters, content_filters_active) = stats_counter(InitiatorKind::ContentFilter);

    let val = match mrinfo {
        Some(info) => serde_json::json!({
            "timestamp": now,
            "request_id": info.rinfo.meta.requestid,
            "security_config": {
                "revision": stats.revision,
                "acl_active": stats.secpol.acl_enabled,
                "cf_active": stats.secpol.content_filter_enabled,
                "cf_rules": stats.content_filter_total,
                "rate_limit_rules": stats.secpol.limit_amount,
                "global_filters_active": stats.secpol.globalfilters_amount
            },
            "arguments": info.rinfo.qinfo.args.to_json(),
            "authority": info.rinfo.meta.authority,
            "cookies": info.cookies.to_json(),
            "headers": info.headers.to_json(),
            "tags": tgs.to_json(),
            "uri": info.rinfo.meta.path,
            "ip": info.rinfo.geoip.ip,
            "method": info.rinfo.meta.method,
            "response_code": rcode,
            "logs": logs.to_stringvec(),

            "processing_stage": stats.processing_stage,
            "trigger_counters": {
                "acl": acl,
                "acl_active": acl_active,
                "global_filters": global_filters,
                "global_filters_active": global_filters_active,
                "flow_control": flow_control,
                "flow_control_active": flow_control_active,
                "rate_limit": rate_limit,
                "rate_limit_active": rate_limit_active,
                "content_filters": content_filters,
                "content_filters_active": content_filters_active,
            },
            "acl_triggers": get_trigger(&InitiatorKind::Acl),
            "rate_limit_triggers": get_trigger(&InitiatorKind::RateLimit),
            "flow_control_triggers": get_trigger(&InitiatorKind::FlowControl),
            "global_filter_triggers": get_trigger(&InitiatorKind::GlobalFilter),
            "content_filter_triggers": get_trigger(&InitiatorKind::ContentFilter),
            "proxy": {
                "location": info.rinfo.geoip.location
            },
            "reason": block_reason_desc,
            "profiling": {},
            "biometrics": {},
        }),
        None => serde_json::Value::Null,
    };

    (val, now)
}

/// a newtype representing tags, to make sure they are tagified when inserted
#[derive(Debug, Clone, Default)]
pub struct Tags(HashMap<String, HashSet<Location>>);

fn tagify(tag: &str) -> String {
    fn filter_char(c: char) -> char {
        if c.is_ascii_alphanumeric() || c == ':' {
            c
        } else {
            '-'
        }
    }
    tag.to_lowercase().chars().map(filter_char).collect()
}

impl Tags {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!(self.0.keys().collect::<Vec<_>>())
    }

    pub fn insert(&mut self, value: &str, loc: Location) {
        let locs = std::iter::once(loc).collect();
        self.0.insert(tagify(value), locs);
    }

    pub fn insert_locs(&mut self, value: &str, locs: HashSet<Location>) {
        self.0.insert(tagify(value), locs);
    }

    pub fn insert_qualified(&mut self, id: &str, value: &str, loc: Location) {
        let locs = std::iter::once(loc).collect();
        self.insert_qualified_locs(id, value, locs);
    }

    pub fn insert_qualified_locs(&mut self, id: &str, value: &str, locs: HashSet<Location>) {
        let mut to_insert = id.to_string();
        to_insert.push(':');
        to_insert += &tagify(value);
        self.0.insert(to_insert, locs);
    }

    pub fn extend(&mut self, other: Self) {
        self.0.extend(other.0)
    }

    pub fn from_slice(slice: &[(String, Location)]) -> Self {
        Tags(
            slice
                .iter()
                .map(|(s, l)| (tagify(s), std::iter::once(l.clone()).collect()))
                .collect(),
        )
    }

    pub fn contains(&self, s: &str) -> bool {
        self.0.contains_key(s)
    }

    pub fn get(&self, s: &str) -> Option<&HashSet<Location>> {
        self.0.get(s)
    }

    pub fn as_hash_ref(&self) -> &HashMap<String, HashSet<Location>> {
        &self.0
    }

    pub fn selector(&self) -> String {
        let mut tvec: Vec<&str> = self.0.keys().map(|s| s.as_ref()).collect();
        tvec.sort_unstable();
        tvec.join("*")
    }

    pub fn intersect(&self, other: &HashSet<String>) -> HashMap<String, HashSet<Location>> {
        let mut out = HashMap::new();
        for (k, v) in &self.0 {
            if other.contains(k) {
                out.insert(k.clone(), v.clone());
            }
        }

        out
    }

    pub fn intersect_tags(&self, other: &HashSet<String>) -> Self {
        Tags(self.intersect(other))
    }

    pub fn has_intersection(&self, other: &HashSet<String>) -> bool {
        other.iter().any(|t| self.0.contains_key(t))
    }

    pub fn merge(&mut self, other: Self) {
        for (k, v) in other.0.into_iter() {
            let e = self.0.entry(k).or_default();
            (*e).extend(v);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RawTags(HashSet<String>);

impl RawTags {
    pub fn insert(&mut self, value: &str) {
        self.0.insert(tagify(value));
    }

    pub fn insert_qualified(&mut self, id: &str, value: &str) {
        let mut to_insert = id.to_string();
        to_insert.push(':');
        to_insert += &tagify(value);
        self.0.insert(to_insert);
    }

    pub fn as_hash_ref(&self) -> &HashSet<String> {
        &self.0
    }

    pub fn intersect<'t>(
        &'t self,
        other: &'t HashSet<String>,
    ) -> std::collections::hash_set::Intersection<'t, std::string::String, std::collections::hash_map::RandomState>
    {
        self.0.intersection(other)
    }

    pub fn has_intersection(&self, other: &HashSet<String>) -> bool {
        self.intersect(other).next().is_some()
    }

    pub fn with_loc(self, locations: &Location) -> Tags {
        Tags(
            self.0
                .into_iter()
                .map(|k| (k, std::iter::once(locations.clone()).collect()))
                .collect(),
        )
    }
    pub fn with_locs(self, locations: &HashSet<Location>) -> Tags {
        Tags(self.0.into_iter().map(|k| (k, locations.clone())).collect())
    }
}

impl std::iter::FromIterator<String> for RawTags {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Self {
        let mut out = RawTags::default();
        for s in iter {
            out.insert(&s);
        }
        out
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Location {
    Request,
    Attributes,
    Ip,
    Uri,
    Path,
    Pathpart(usize),
    PathpartValue(usize, String),
    RefererPath,
    RefererPathpart(usize),
    RefererPathpartValue(usize, String),
    UriArgument(String),
    UriArgumentValue(String, String),
    RefererArgument(String),
    RefererArgumentValue(String, String),
    Body,
    BodyArgument(String),
    BodyArgumentValue(String, String),
    Headers,
    Header(String),
    HeaderValue(String, String),
    Cookies,
    Cookie(String),
    CookieValue(String, String),
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Location::*;
        match self {
            Request => write!(f, "request"),
            Attributes => write!(f, "attributes"),
            Ip => write!(f, "ip"),
            Uri => write!(f, "uri"),
            Path => write!(f, "path"),
            Pathpart(p) => write!(f, "path part {}", p),
            PathpartValue(p, v) => write!(f, "path part {}={}", p, v),
            UriArgument(a) => write!(f, "URI argument {}", a),
            UriArgumentValue(a, v) => write!(f, "URI argument {}={}", a, v),
            Body => write!(f, "body"),
            BodyArgument(a) => write!(f, "body argument {}", a),
            BodyArgumentValue(a, v) => write!(f, "body argument {}={}", a, v),
            Headers => write!(f, "headers"),
            Header(h) => write!(f, "header {}", h),
            HeaderValue(h, v) => write!(f, "header {}={}", h, v),
            Cookies => write!(f, "cookies"),
            Cookie(c) => write!(f, "cookie {}", c),
            CookieValue(c, v) => write!(f, "cookie {}={}", c, v),
            RefererArgument(a) => write!(f, "Referer argument {}", a),
            RefererArgumentValue(a, v) => write!(f, "Referer argument {}={}", a, v),
            RefererPath => write!(f, "referer path"),
            RefererPathpart(p) => write!(f, "referer path part {}", p),
            RefererPathpartValue(p, v) => write!(f, "referer path part {}={}", p, v),
        }
    }
}

impl Serialize for Location {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map: <S as serde::Serializer>::SerializeMap = serializer.serialize_map(None)?;
        self.serialize_with_parent::<S>(&mut map)?;
        map.end()
    }
}

impl Location {
    pub fn parent(&self) -> Option<Self> {
        use Location::*;
        match self {
            Request => None,
            Attributes => Some(Request),
            Ip => Some(Attributes),
            Uri => Some(Request),
            Path => Some(Uri),
            Pathpart(_) => Some(Path),
            PathpartValue(k, _) => Some(Pathpart(*k)),
            UriArgument(_) => Some(Uri),
            UriArgumentValue(n, _) => Some(UriArgument(n.clone())),
            Body => Some(Request),
            BodyArgument(_) => Some(Body),
            BodyArgumentValue(n, _) => Some(BodyArgument(n.clone())),
            Headers => Some(Request),
            Header(_) => Some(Headers),
            HeaderValue(n, _) => Some(Header(n.clone())),
            Cookies => Some(Request),
            Cookie(_) => Some(Cookies),
            CookieValue(n, _) => Some(Cookie(n.clone())),
            RefererArgument(_) => Some(Header("referer".to_string())),
            RefererArgumentValue(n, _) => Some(RefererArgument(n.clone())),
            RefererPath => Some(Header("referer".to_string())),
            RefererPathpart(_) => Some(RefererPath),
            RefererPathpartValue(k, _) => Some(RefererPathpart(*k)),
        }
    }

    pub fn get_locations(&self) -> HashSet<Self> {
        let mut out = HashSet::new();
        let mut start = self.clone();
        while let Some(p) = start.parent() {
            out.insert(start);
            start = p;
        }
        out.insert(start);
        out
    }

    pub fn request() -> HashSet<Self> {
        let mut out = HashSet::new();
        out.insert(Location::Request);
        out
    }

    pub fn body() -> HashSet<Self> {
        let mut out = HashSet::new();
        out.insert(Location::Body);
        out
    }

    pub fn from_value(idx: SectionIdx, name: &str, value: &str) -> Self {
        match idx {
            SectionIdx::Headers => Location::HeaderValue(name.to_string(), value.to_string()),
            SectionIdx::Cookies => Location::CookieValue(name.to_string(), value.to_string()),
            SectionIdx::Path => Location::Path,
            // TODO: track body / uri args
            SectionIdx::Args => Location::UriArgumentValue(name.to_string(), value.to_string()),
        }
    }
    pub fn from_name(idx: SectionIdx, name: &str) -> Self {
        match idx {
            SectionIdx::Headers => Location::Header(name.to_string()),
            SectionIdx::Cookies => Location::Cookie(name.to_string()),
            SectionIdx::Path => Location::Path,
            // TODO: track body / uri args
            SectionIdx::Args => Location::UriArgument(name.to_string()),
        }
    }
    pub fn from_section(idx: SectionIdx) -> Self {
        match idx {
            SectionIdx::Headers => Location::Headers,
            SectionIdx::Cookies => Location::Cookies,
            SectionIdx::Path => Location::Path,
            // TODO: track body / uri args
            SectionIdx::Args => Location::Uri,
        }
    }
    fn serialize_with_parent<S: serde::Serializer>(
        &self,
        map: &mut <S as serde::Serializer>::SerializeMap,
    ) -> Result<(), S::Error> {
        match self {
            Location::Request => (),
            Location::Attributes => {
                map.serialize_entry("section", "attributes")?;
            }
            Location::Ip => {
                map.serialize_entry("section", "ip")?;
            }
            Location::Uri => {
                map.serialize_entry("section", "uri")?;
            }
            Location::RefererPath => {
                map.serialize_entry("section", "referer path")?;
            }
            Location::RefererPathpart(part) => {
                map.serialize_entry("part", part)?;
            }
            Location::RefererPathpartValue(_, value) => {
                map.serialize_entry("value", value)?;
            }
            Location::Path => {
                map.serialize_entry("section", "path")?;
            }
            Location::Pathpart(part) => {
                map.serialize_entry("part", part)?;
            }
            Location::PathpartValue(_, value) => {
                map.serialize_entry("value", value)?;
            }
            Location::UriArgument(name) => {
                map.serialize_entry("name", name)?;
            }
            Location::UriArgumentValue(_, value) => {
                map.serialize_entry("value", value)?;
            }
            Location::RefererArgument(name) => {
                map.serialize_entry("name", name)?;
            }
            Location::RefererArgumentValue(_, value) => {
                map.serialize_entry("value", value)?;
            }
            Location::Body => {
                map.serialize_entry("section", "body")?;
            }
            Location::BodyArgument(name) => {
                map.serialize_entry("name", name)?;
            }
            Location::BodyArgumentValue(_, value) => {
                map.serialize_entry("value", value)?;
            }
            Location::Headers => {
                map.serialize_entry("section", "headers")?;
            }
            Location::Header(name) => {
                map.serialize_entry("name", name)?;
            }
            Location::HeaderValue(_, value) => {
                map.serialize_entry("value", value)?;
            }
            Location::Cookies => {
                map.serialize_entry("section", "cookies")?;
            }
            Location::Cookie(name) => {
                map.serialize_entry("name", name)?;
            }
            Location::CookieValue(_, value) => {
                map.serialize_entry("value", value)?;
            }
        }
        if let Some(p) = self.parent() {
            p.serialize_with_parent::<S>(map)?;
        }
        Ok(())
    }
}

/// computes all parents
pub fn all_parents(locs: HashSet<Location>) -> HashSet<Location> {
    let mut out = locs.clone();
    let mut to_compute = locs;
    loop {
        let to_compute_prime = to_compute.iter().filter_map(|l| l.parent()).collect::<HashSet<_>>();
        let diff = to_compute_prime.difference(&out).cloned().collect::<HashSet<_>>();
        if diff.is_empty() {
            break;
        }
        out.extend(diff.clone());
        to_compute = diff;
    }
    out
}

#[derive(Debug, Clone, Copy, Serialize, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AclStage {
    EnforceDeny,
    Bypass,
    AllowBot,
    DenyBot,
    Allow,
    Deny,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Initiator {
    GlobalFilter {
        id: String,
        name: String,
    },
    Acl {
        tags: Vec<String>,
        stage: AclStage,
    },
    ContentFilter {
        ruleid: String,
        risk_level: u8,
    },
    Limit {
        id: String,
        name: String,
        key: String,
        threshold: u64,
    },
    Flow {
        id: String,
        name: String,
        key: String,
    },
    BodyTooDeep {
        actual: usize,
        expected: usize,
    },
    BodyMissing,
    BodyMalformed(String),
    Phase01Fail(String),
    Phase02,
    Sqli(String),
    Xss,
    Restricted,
    TooManyEntries {
        actual: usize,
        expected: usize,
    },
    EntryTooLarge {
        actual: usize,
        expected: usize,
    },
}

impl std::fmt::Display for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Initiator::*;
        match self {
            GlobalFilter { id, name } => write!(f, "global filter {}[{}]", name, id),
            Acl { tags, stage } => write!(f, "acl {:?} {:?}", stage, tags),
            ContentFilter { ruleid, risk_level } => write!(f, "content filter {}[lvl{}]", ruleid, risk_level),
            Limit {
                id,
                name,
                key: _,
                threshold,
            } => write!(f, "rate limit {}[{}] threshold={}", name, id, threshold),
            Flow { id, name, key: _ } => write!(f, "flow control {}[{}]", name, id),
            BodyTooDeep { actual: _, expected } => write!(f, "body too deep threshhold={}", expected),
            BodyMissing => write!(f, "body is missing"),
            BodyMalformed(r) => write!(f, "body is malformed: {}", r),
            Phase01Fail(r) => write!(f, "grasshopper phase 1 error: {}", r),
            Phase02 => write!(f, "grasshopper phase 2"),
            Sqli(fp) => write!(f, "sql injection {}", fp),
            Xss => write!(f, "xss"),
            Restricted => write!(f, "restricted parameter"),
            TooManyEntries { actual, expected } => {
                write!(f, "too many entries, entries={} threshold={}", actual, expected)
            }
            EntryTooLarge { actual, expected } => write!(f, "too large, size={} threshold={}", actual, expected),
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitiatorKind {
    Acl,
    RateLimit,
    FlowControl,
    GlobalFilter,
    ContentFilter,
}

impl Initiator {
    pub fn to_kind(&self) -> InitiatorKind {
        use InitiatorKind::*;
        match self {
            Initiator::GlobalFilter { id: _, name: _ } => GlobalFilter,
            Initiator::Acl { tags: _, stage: _ } => Acl,
            Initiator::ContentFilter {
                ruleid: _,
                risk_level: _,
            } => ContentFilter,
            Initiator::Limit {
                id: _,
                name: _,
                key: _,
                threshold: _,
            } => RateLimit,
            Initiator::Flow { id: _, name: _, key: _ } => FlowControl,
            Initiator::BodyTooDeep { actual: _, expected: _ } => ContentFilter,
            Initiator::BodyMissing => ContentFilter,
            Initiator::BodyMalformed(_) => ContentFilter,
            Initiator::Phase01Fail(_) => Acl,
            Initiator::Phase02 => Acl,
            Initiator::Sqli(_) => ContentFilter,
            Initiator::Xss => ContentFilter,
            Initiator::Restricted => ContentFilter,
            Initiator::TooManyEntries { actual: _, expected: _ } => ContentFilter,
            Initiator::EntryTooLarge { actual: _, expected: _ } => ContentFilter,
        }
    }

    pub fn serialize_in_map<S: serde::Serializer>(
        &self,
        map: &mut <S as serde::Serializer>::SerializeMap,
    ) -> Result<(), S::Error> {
        match self {
            Initiator::GlobalFilter { id, name } => {
                map.serialize_entry("id", id)?;
                map.serialize_entry("name", name)?;
            }
            Initiator::Acl { tags, stage } => {
                map.serialize_entry("tags", tags)?;
                map.serialize_entry("type", stage)?;
            }
            Initiator::ContentFilter { ruleid, risk_level } => {
                map.serialize_entry("type", "signature")?;
                map.serialize_entry("ruleid", ruleid)?;
                map.serialize_entry("risk_level", risk_level)?;
            }
            Initiator::Flow { id, name, key: _ } => {
                map.serialize_entry("id", id)?;
                map.serialize_entry("name", name)?;
            }
            Initiator::Limit {
                id,
                name,
                key: _,
                threshold,
            } => {
                map.serialize_entry("id", id)?;
                map.serialize_entry("name", name)?;
                map.serialize_entry("threshold", threshold)?;
                map.serialize_entry("counter", &(threshold + 1))?;
            }
            Initiator::BodyTooDeep { actual, expected } => {
                map.serialize_entry("type", "body_too_deep")?;
                map.serialize_entry("actual", actual)?;
                map.serialize_entry("expected", expected)?;
            }
            Initiator::BodyMissing => {
                map.serialize_entry("type", "body_missing")?;
            }
            Initiator::BodyMalformed(_) => {
                map.serialize_entry("type", "body_malformed")?;
            }
            Initiator::Phase01Fail(r) => {
                map.serialize_entry("type", "phase1")?;
                map.serialize_entry("details", r)?;
            }
            Initiator::Phase02 => {
                map.serialize_entry("type", "phase2")?;
            }
            Initiator::Sqli(fp) => {
                map.serialize_entry("type", "xss")?;
                map.serialize_entry("fingerprint", fp)?;
            }
            Initiator::Xss => {
                map.serialize_entry("type", "xss")?;
            }
            Initiator::Restricted => {
                map.serialize_entry("type", "restricted_content")?;
            }
            Initiator::TooManyEntries { actual, expected } => {
                map.serialize_entry("type", "too_many_entries")?;
                map.serialize_entry("actual", actual)?;
                map.serialize_entry("expected", expected)?;
            }
            Initiator::EntryTooLarge { actual, expected } => {
                map.serialize_entry("type", "entry_too_large")?;
                map.serialize_entry("actual", actual)?;
                map.serialize_entry("expected", expected)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum BDecision {
    Monitor,
    InitiatorInactive,
    Blocking,
}

impl std::fmt::Display for BDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BDecision::Monitor => write!(f, "monitor"),
            BDecision::InitiatorInactive => write!(f, "inactive"),
            BDecision::Blocking => write!(f, "blocking"),
        }
    }
}

impl BDecision {
    pub fn from_blocking(blocking: bool) -> Self {
        if blocking {
            BDecision::Blocking
        } else {
            BDecision::Monitor
        }
    }

    pub fn inactive(&mut self) {
        if self == &BDecision::Blocking {
            *self = BDecision::InitiatorInactive;
        }
    }
}

impl Serialize for BDecision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            BDecision::Monitor => "monitor",
            BDecision::InitiatorInactive => "inactive",
            BDecision::Blocking => "block",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReason {
    pub initiator: Initiator,
    pub location: HashSet<Location>,
    pub decision: BDecision,
}

impl Serialize for BlockReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map: <S as serde::Serializer>::SerializeMap = serializer.serialize_map(None)?;
        self.serialize_in_map::<S>(&mut map)?;
        map.end()
    }
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} - {} - [", self.decision, self.initiator)?;
        let mut comma = false;
        for l in &self.location {
            if comma {
                write!(f, ", ")?;
            }
            comma = true;
            write!(f, "{}", l)?;
        }
        write!(f, "]")
    }
}

impl BlockReason {
    pub fn block_reason_desc(reasons: &[Self]) -> Option<String> {
        reasons
            .iter()
            .find(|r| r.decision == BDecision::Blocking)
            .map(|r| r.to_string())
    }

    pub fn global_filter(id: String, name: String) -> Self {
        BlockReason::nodetails(Initiator::GlobalFilter { id, name }, true)
    }

    pub fn limit(id: String, name: String, key: String, threshold: u64, is_blocking: bool) -> Self {
        BlockReason::nodetails(
            Initiator::Limit {
                id,
                name,
                key,
                threshold,
            },
            is_blocking,
        )
    }

    pub fn flow(id: String, name: String, key: String, is_blocking: bool) -> Self {
        BlockReason::nodetails(Initiator::Flow { id, name, key }, is_blocking)
    }

    pub fn phase01_unknown(reason: &str) -> Self {
        BlockReason::nodetails(Initiator::Phase01Fail(reason.to_string()), true)
    }

    pub fn phase02() -> Self {
        BlockReason::nodetails(Initiator::Phase02, true)
    }

    fn nodetails(initiator: Initiator, is_blocking: bool) -> Self {
        BlockReason {
            initiator,
            location: Location::request(),
            decision: BDecision::from_blocking(is_blocking),
        }
    }

    pub fn body_too_deep(actual: usize, expected: usize) -> Self {
        BlockReason {
            initiator: Initiator::BodyTooDeep { actual, expected },
            location: Location::body(),
            decision: BDecision::Blocking,
        }
    }
    pub fn body_too_large(actual: usize, expected: usize) -> Self {
        BlockReason {
            initiator: Initiator::EntryTooLarge { actual, expected },
            location: Location::body(),
            decision: BDecision::Blocking,
        }
    }
    pub fn body_missing() -> Self {
        BlockReason {
            initiator: Initiator::BodyMissing,
            location: Location::body(),
            decision: BDecision::Blocking,
        }
    }
    pub fn body_malformed(cause: &str) -> Self {
        BlockReason {
            initiator: Initiator::BodyMalformed(cause.to_string()),
            location: Location::body(),
            decision: BDecision::Blocking,
        }
    }
    pub fn sqli(location: Location, fp: String) -> Self {
        BlockReason {
            initiator: Initiator::Sqli(fp),
            location: std::iter::once(location).collect(),
            decision: BDecision::Blocking,
        }
    }
    pub fn xss(location: Location) -> Self {
        BlockReason {
            initiator: Initiator::Xss,
            location: std::iter::once(location).collect(),
            decision: BDecision::Blocking,
        }
    }
    pub fn too_many_entries(idx: SectionIdx, actual: usize, expected: usize) -> Self {
        BlockReason {
            initiator: Initiator::TooManyEntries { actual, expected },
            location: std::iter::once(Location::from_section(idx)).collect(),
            decision: BDecision::Blocking,
        }
    }
    pub fn entry_too_large(idx: SectionIdx, name: &str, actual: usize, expected: usize) -> Self {
        BlockReason {
            initiator: Initiator::EntryTooLarge { actual, expected },
            location: std::iter::once(Location::from_name(idx, name)).collect(),
            decision: BDecision::Blocking,
        }
    }
    pub fn restricted(location: Location) -> Self {
        BlockReason {
            initiator: Initiator::Restricted,
            location: std::iter::once(location).collect(),
            decision: BDecision::Blocking,
        }
    }
    pub fn acl(tags: Tags, stage: AclStage) -> Self {
        let mut tagv = Vec::new();
        let mut location = HashSet::new();
        for (k, v) in tags.0.into_iter() {
            tagv.push(k);
            location.extend(v);
        }
        let decision = match stage {
            AclStage::Allow | AclStage::Bypass | AclStage::AllowBot => BDecision::Monitor,
            AclStage::Deny | AclStage::EnforceDeny | AclStage::DenyBot => BDecision::Blocking,
        };

        BlockReason {
            initiator: Initiator::Acl { tags: tagv, stage },
            location,
            decision,
        }
    }

    pub fn regroup<'t>(reasons: &'t [Self]) -> HashMap<InitiatorKind, Vec<&'t Self>> {
        let mut out: HashMap<InitiatorKind, Vec<&'t Self>> = HashMap::new();

        for reason in reasons {
            let kind = reason.initiator.to_kind();
            let entry = out.entry(kind).or_default();
            entry.push(reason);
        }

        out
    }

    pub fn serialize_in_map<S: serde::Serializer>(
        &self,
        map: &mut <S as serde::Serializer>::SerializeMap,
    ) -> Result<(), S::Error> {
        self.initiator.serialize_in_map::<S>(map)?;
        for loc in &self.location {
            loc.serialize_with_parent::<S>(map)?;
        }
        map.serialize_entry("active", &Value::Bool(self.decision != BDecision::Monitor))?;
        Ok(())
    }
}

pub struct LegacyBlockReason<'t>(&'t BlockReason);

impl<'t> Serialize for LegacyBlockReason<'t> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map: <S as serde::Serializer>::SerializeMap = serializer.serialize_map(None)?;
        map.serialize_entry("initiator", &self.0.initiator.to_kind())?;
        self.0.serialize_in_map::<S>(&mut map)?;
        map.end()
    }
}

// an action, as formatted for outside consumption
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Action {
    pub atype: ActionType,
    pub ban: bool,
    pub block_mode: bool,
    pub status: u32,
    pub headers: Option<HashMap<String, String>>,
    pub content: String,
    pub extra_tags: Option<HashSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimpleActionT {
    Monitor,
    RequestHeader(HashMap<String, String>),
    Response(String),
    Redirect(String),
    Challenge,
    Default,
    Ban(Box<SimpleAction>, u64), // duration, ttl
}

impl SimpleActionT {
    fn priority(&self) -> u32 {
        use SimpleActionT::*;
        match self {
            Ban(sub, _) => sub.atype.priority(),
            Default => 8,
            Challenge => 6,
            Redirect(_) => 4,
            Response(_) => 3,
            RequestHeader(_) => 2,
            Monitor => 1,
        }
    }

    fn is_blocking(&self) -> bool {
        !matches!(self, SimpleActionT::RequestHeader(_) | SimpleActionT::Monitor)
    }
}

// an action with its semantic meaning
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleAction {
    pub atype: SimpleActionT,
    pub status: u32,
    pub reason: String,
}

impl std::default::Default for SimpleActionT {
    fn default() -> Self {
        SimpleActionT::Default
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Monitor,
    Block,
    AlterHeaders,
}

impl ActionType {
    /// is the action blocking (not passed to the underlying server)
    pub fn is_blocking(&self) -> bool {
        matches!(self, ActionType::Block)
    }

    /// is the action final (no further processing)
    pub fn is_final(&self) -> bool {
        !matches!(self, ActionType::Monitor)
    }
}

impl std::default::Default for Action {
    fn default() -> Self {
        Action {
            atype: ActionType::Block,
            block_mode: true,
            ban: false,
            status: 503,
            headers: None,
            content: "request denied".to_string(),
            extra_tags: None,
        }
    }
}

impl SimpleAction {
    pub fn from_reason(reason: String) -> Self {
        SimpleAction {
            atype: SimpleActionT::default(),
            status: 503,
            reason,
        }
    }

    pub fn resolve(rawaction: &RawAction) -> anyhow::Result<SimpleAction> {
        let atype = match rawaction.type_ {
            RawActionType::Default => SimpleActionT::Default,
            RawActionType::Monitor => SimpleActionT::Monitor,
            RawActionType::Ban => SimpleActionT::Ban(
                Box::new(
                    rawaction
                        .params
                        .action
                        .as_ref()
                        .and_then(|x| SimpleAction::resolve(x).ok())
                        .unwrap_or_else(|| {
                            SimpleAction::from_reason(rawaction.params.reason.clone().unwrap_or_else(|| "?".into()))
                        }),
                ),
                rawaction
                    .params
                    .duration
                    .as_ref()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(3600),
            ),
            RawActionType::RequestHeader => {
                SimpleActionT::RequestHeader(rawaction.params.headers.clone().unwrap_or_default())
            }
            RawActionType::Response => SimpleActionT::Response(
                rawaction
                    .params
                    .content
                    .clone()
                    .unwrap_or_else(|| "default content".into()),
            ),
            RawActionType::Challenge => SimpleActionT::Challenge,
            RawActionType::Redirect => SimpleActionT::Redirect(
                rawaction
                    .params
                    .location
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("no location for redirect in rule {:?}", rawaction))?,
            ),
        };
        let status = if let Some(sstatus) = &rawaction.params.status {
            match sstatus.parse::<u32>() {
                Ok(s) => s,
                Err(rr) => return Err(anyhow::anyhow!("Unparseable status: {} -> {}", sstatus, rr)),
            }
        } else {
            503
        };
        Ok(SimpleAction {
            atype,
            status,
            reason: rawaction.params.reason.clone().unwrap_or_else(|| "no reason".into()),
        })
    }

    /// returns None when it is a challenge, Some(action) otherwise
    fn to_action(&self, is_human: bool) -> Option<Action> {
        let mut action = Action::default();
        action.block_mode = action.atype.is_blocking();
        action.status = self.status;
        match &self.atype {
            SimpleActionT::Default => {}
            SimpleActionT::Monitor => action.atype = ActionType::Monitor,
            SimpleActionT::Ban(sub, _) => {
                action = sub.to_action(is_human).unwrap_or_default();
                action.ban = true;
            }
            SimpleActionT::RequestHeader(hdrs) => {
                action.headers = Some(hdrs.clone());
                action.atype = ActionType::AlterHeaders;
            }
            SimpleActionT::Response(content) => {
                action.atype = ActionType::Block;
                action.content = content.clone();
            }
            SimpleActionT::Challenge => {
                if !is_human {
                    return None;
                }
                action.atype = ActionType::Monitor;
            }
            SimpleActionT::Redirect(to) => {
                let mut headers = HashMap::new();
                action.content = "You are being redirected".into();
                headers.insert("Location".into(), to.clone());
                action.atype = ActionType::Block;
                action.headers = Some(headers);
            }
        }
        Some(action)
    }

    pub fn to_decision<GH: Grasshopper>(
        &self,
        is_human: bool,
        mgh: &Option<GH>,
        headers: &RequestField,
        reason: Vec<BlockReason>,
    ) -> Decision {
        let action = match self.to_action(is_human) {
            None => match (mgh, headers.get("user-agent")) {
                (Some(gh), Some(ua)) => return challenge_phase01(gh, ua, reason),
                _ => Action::default(),
            },
            Some(a) => a,
        };
        Decision::action(action, reason)
    }

    pub fn to_decision_no_challenge(&self, reason: Vec<BlockReason>) -> Decision {
        let action = match self.to_action(true) {
            None => Action::default(),
            Some(a) => a,
        };
        Decision::action(action, reason)
    }

    pub fn is_blocking(&self) -> bool {
        self.atype.is_blocking()
    }
}

impl SimpleDecision {
    pub fn into_decision_no_challenge(self) -> Decision {
        match self {
            SimpleDecision::Pass => Decision::pass(Vec::new()),
            SimpleDecision::Action(action, reason) => action.to_decision_no_challenge(reason),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn tag_selector() {
        let tags = Tags::from_slice(&[
            ("ccc".to_string(), Location::Request),
            ("bbb".to_string(), Location::Request),
            ("aaa".to_string(), Location::Request),
        ]);
        assert_eq!(tags.selector(), "aaa*bbb*ccc");
    }

    #[test]
    fn tag_selector_r() {
        let tags = Tags::from_slice(&[
            ("aaa".to_string(), Location::Request),
            ("ccc".to_string(), Location::Request),
            ("bbb".to_string(), Location::Request),
        ]);
        assert_eq!(tags.selector(), "aaa*bbb*ccc");
    }
}
