use crate::config::raw::AclProfile;
use crate::interface::{BlockReason, Tags};

use std::collections::HashSet;

#[derive(Debug)]
pub struct AclDecision {
    pub allowed: bool,
    pub r: BlockReason,
}

#[derive(Debug)]
pub enum AclResult {
    /// passthrough found
    Passthrough(AclDecision),
    /// bots, human results
    Match(BotHuman),
}

#[derive(Debug)]
pub struct BotHuman {
    pub bot: Option<AclDecision>,
    pub human: Option<AclDecision>,
}

pub fn check_acl(tags: &Tags, acl: &AclProfile) -> AclResult {
    let subcheck = |checks: &HashSet<String>, allowed: bool| {
        let tags = tags.intersect_tags(checks);
        if tags.is_empty() {
            None
        } else {
            Some(AclDecision {
                allowed,
                r: BlockReason::acl(tags, allowed),
            })
        }
    };
    subcheck(&acl.force_deny, false)
        .map(AclResult::Passthrough)
        .or_else(|| subcheck(&acl.passthrough, true).map(AclResult::Passthrough))
        .unwrap_or_else(|| {
            let botresult = subcheck(&acl.allow_bot, true).or_else(|| subcheck(&acl.deny_bot, false));
            let humanresult = subcheck(&acl.allow, true).or_else(|| subcheck(&acl.deny, false));

            AclResult::Match(BotHuman {
                bot: botresult,
                human: humanresult,
            })
        })
}
