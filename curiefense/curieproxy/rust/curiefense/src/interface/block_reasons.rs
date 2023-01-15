/// this file contains all the data type that are used when interfacing with a proxy
use crate::config::contentfilter::SectionIdx;
use serde::ser::SerializeMap;
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::tagging::{Location, Tags};

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
        id: String,
        tags: Vec<String>,
        stage: AclStage,
    },
    ContentFilter {
        id: String,
        risk_level: u8,
    },
    Limit {
        id: String,
        name: String,
        threshold: u64,
    },
    Restriction {
        id: String,
        tpe: &'static str,
        actual: String,
        expected: String,
    },

    // TODO, these two are not serialized for now
    Phase01Fail(String),
    Phase02,
}

impl std::fmt::Display for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Initiator::*;
        match self {
            GlobalFilter { id, name } => write!(f, "global filter {}[{}]", name, id),
            Acl { id, tags, stage } => write!(f, "acl[{}] {:?} {:?}", id, stage, tags),
            ContentFilter { id, risk_level } => write!(f, "content filter {}[lvl{}]", id, risk_level),
            Limit { id, name, threshold } => write!(f, "rate limit {}[{}] threshold={}", name, id, threshold),
            Phase01Fail(r) => write!(f, "grasshopper phase 1 error: {}", r),
            Phase02 => write!(f, "grasshopper phase 2"),
            Restriction {
                id,
                tpe,
                actual,
                expected,
            } => write!(f, "restricted {}[{}][{}/{}]", tpe, id, actual, expected),
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitiatorKind {
    Acl,
    RateLimit,
    GlobalFilter,
    ContentFilter,
    Restriction,
}

impl Initiator {
    pub fn to_kind(&self) -> Option<InitiatorKind> {
        use InitiatorKind::*;
        match self {
            Initiator::GlobalFilter { .. } => Some(GlobalFilter),
            Initiator::Acl { .. } => Some(Acl),
            Initiator::ContentFilter { .. } => Some(ContentFilter),
            Initiator::Limit { .. } => Some(RateLimit),
            Initiator::Phase01Fail(_) => None,
            Initiator::Phase02 => None,
            Initiator::Restriction { .. } => Some(Restriction),
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
            Initiator::Acl { id, tags, stage } => {
                map.serialize_entry("id", id)?;
                map.serialize_entry("tags", tags)?;
                map.serialize_entry("stage", stage)?;
            }
            Initiator::ContentFilter { id, risk_level } => {
                map.serialize_entry("id", id)?;
                map.serialize_entry("risk_level", risk_level)?;
            }
            Initiator::Limit { id, name, threshold } => {
                map.serialize_entry("id", id)?;
                map.serialize_entry("limitname", name)?;
                map.serialize_entry("threshold", threshold)?;
            }
            Initiator::Restriction {
                id,
                tpe,
                actual,
                expected,
            } => {
                map.serialize_entry("id", id)?;
                map.serialize_entry("type", tpe)?;
                map.serialize_entry("actual", actual)?;
                map.serialize_entry("expected", expected)?;
            }

            // not serialized
            Initiator::Phase01Fail(r) => {
                map.serialize_entry("type", "phase1")?;
                map.serialize_entry("details", r)?;
            }
            Initiator::Phase02 => {
                map.serialize_entry("type", "phase2")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum BDecision {
    Skip,
    Monitor,
    AlterRequest,
    InitiatorInactive,
    Blocking,
}

impl std::fmt::Display for BDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BDecision::Skip => write!(f, "skip"),
            BDecision::Monitor => write!(f, "monitor"),
            BDecision::AlterRequest => write!(f, "alter_request"),
            BDecision::InitiatorInactive => write!(f, "inactive"),
            BDecision::Blocking => write!(f, "blocking"),
        }
    }
}

impl BDecision {
    pub fn inactive(&mut self) {
        if self == &BDecision::Blocking || self == &BDecision::AlterRequest {
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
            BDecision::Skip => "skip",
            BDecision::Monitor => "monitor",
            BDecision::AlterRequest => "alter_request",
            BDecision::InitiatorInactive => "inactive",
            BDecision::Blocking => "block",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReason {
    pub initiator: Initiator,
    pub location: Location,
    pub extra_locations: Vec<Location>,
    pub decision: BDecision,
    pub extra: Value,
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
        write!(f, "{} - {} - [{}]", self.decision, self.initiator, self.location)
    }
}

fn extra_locations<'t, I: Iterator<Item = &'t Location>>(i: I) -> (Location, Vec<Location>) {
    let mut liter = i.cloned();
    let location = liter.next().unwrap_or(Location::Request);
    let extra = liter.collect();
    (location, extra)
}

impl BlockReason {
    pub fn block_reason_desc(reasons: &[Self]) -> Option<String> {
        reasons
            .iter()
            .find(|r| r.decision == BDecision::Blocking)
            .map(|r| r.to_string())
    }

    pub fn global_filter(id: String, name: String, decision: BDecision, locs: &HashSet<Location>) -> Self {
        let initiator = Initiator::GlobalFilter { id, name };
        let (location, extra_locations) = extra_locations(locs.iter());
        BlockReason {
            decision,
            initiator,
            location,
            extra_locations,
            extra: Value::Null,
        }
    }

    pub fn limit(id: String, name: String, threshold: u64, decision: BDecision) -> Self {
        BlockReason::nodetails(Initiator::Limit { id, name, threshold }, decision)
    }

    pub fn phase01_unknown(reason: &str) -> Self {
        BlockReason::nodetails(Initiator::Phase01Fail(reason.to_string()), BDecision::Blocking)
    }

    pub fn phase02() -> Self {
        BlockReason::nodetails(Initiator::Phase02, BDecision::Blocking)
    }

    fn nodetails(initiator: Initiator, decision: BDecision) -> Self {
        BlockReason {
            initiator,
            location: Location::Request,
            decision,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }

    pub fn body_too_deep(id: String, actual: usize, expected: usize) -> Self {
        BlockReason {
            initiator: Initiator::Restriction {
                id,
                tpe: "too deep",
                actual: actual.to_string(),
                expected: expected.to_string(),
            },
            location: Location::Body,
            decision: BDecision::Blocking,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn body_too_large(id: String, actual: usize, expected: usize) -> Self {
        BlockReason {
            initiator: Initiator::Restriction {
                id,
                tpe: "too large",
                actual: actual.to_string(),
                expected: expected.to_string(),
            },
            location: Location::Body,
            decision: BDecision::Blocking,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn body_missing(id: String) -> Self {
        BlockReason {
            initiator: Initiator::Restriction {
                id,
                tpe: "missing body",
                actual: "missing".to_string(),
                expected: "something".to_string(),
            },
            location: Location::Body,
            decision: BDecision::Blocking,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn body_malformed(id: String, cause: &str) -> Self {
        BlockReason {
            initiator: Initiator::Restriction {
                id,
                tpe: "malformed body",
                actual: cause.to_string(),
                expected: "well-formed".to_string(),
            },
            location: Location::Body,
            decision: BDecision::Blocking,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn sqli(location: Location, fp: String) -> Self {
        BlockReason {
            initiator: Initiator::ContentFilter {
                id: format!("sqli:{}", fp),
                risk_level: 3,
            },
            location,
            decision: BDecision::Blocking,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn xss(location: Location) -> Self {
        BlockReason {
            initiator: Initiator::ContentFilter {
                id: "xss".to_string(),
                risk_level: 3,
            },
            location,
            decision: BDecision::Blocking,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn too_many_entries(id: String, idx: SectionIdx, actual: usize, expected: usize) -> Self {
        BlockReason {
            initiator: Initiator::Restriction {
                id,
                tpe: "too many",
                actual: actual.to_string(),
                expected: expected.to_string(),
            },
            location: Location::from_section(idx),
            decision: BDecision::Blocking,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn entry_too_large(id: String, idx: SectionIdx, name: &str, actual: usize, expected: usize) -> Self {
        BlockReason {
            initiator: Initiator::Restriction {
                id,
                tpe: "too large",
                actual: actual.to_string(),
                expected: expected.to_string(),
            },
            location: Location::from_name(idx, name),
            decision: BDecision::Blocking,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn restricted(id: String, location: Location, actual: String, expected: String) -> Self {
        BlockReason {
            initiator: Initiator::Restriction {
                id,
                tpe: "restricted",
                actual,
                expected,
            },
            location,
            decision: BDecision::Blocking,
            extra_locations: Vec::new(),
            extra: Value::Null,
        }
    }
    pub fn acl(id: String, tags: Tags, stage: AclStage) -> Self {
        let mut tagv = Vec::new();
        let mut locations = HashSet::new();
        for (k, v) in tags.tags.into_iter() {
            tagv.push(k);
            locations.extend(v);
        }
        let decision = match stage {
            AclStage::Allow | AclStage::Bypass | AclStage::AllowBot => BDecision::Monitor,
            AclStage::Deny | AclStage::EnforceDeny | AclStage::DenyBot => BDecision::Blocking,
        };
        let (location, extra_locations) = extra_locations(locations.iter());

        BlockReason {
            initiator: Initiator::Acl { id, tags: tagv, stage },
            location,
            decision,
            extra_locations,
            extra: Value::Null,
        }
    }

    pub fn regroup<'t>(reasons: &'t [Self]) -> HashMap<InitiatorKind, Vec<&'t Self>> {
        let mut out: HashMap<InitiatorKind, Vec<&'t Self>> = HashMap::new();

        for reason in reasons {
            if let Some(kind) = reason.initiator.to_kind() {
                let entry = out.entry(kind).or_default();
                entry.push(reason);
            }
        }

        out
    }

    pub fn serialize_in_map<S: serde::Serializer>(
        &self,
        map: &mut <S as serde::Serializer>::SerializeMap,
    ) -> Result<(), S::Error> {
        self.initiator.serialize_in_map::<S>(map)?;
        self.location.serialize_with_parent::<S>(map)?;
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
