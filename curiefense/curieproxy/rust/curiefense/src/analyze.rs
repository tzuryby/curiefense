use std::collections::HashMap;

use crate::acl::{check_acl, AclDecision, AclResult, BotHuman};
use crate::config::contentfilter::ContentFilterRules;
use crate::config::flow::{FlowElement, SequenceKey};
use crate::config::hostmap::SecurityPolicy;
use crate::config::HSDB;
use crate::contentfilter::{content_filter_check, masking};
use crate::flow::flow_check;
use crate::grasshopper::{challenge_phase01, challenge_phase02, Grasshopper};
use crate::interface::{Action, ActionType, AnalyzeResult, BlockReason, Decision, Location, SimpleDecision, Tags};
use crate::limit::limit_check;
use crate::logs::Logs;
use crate::utils::{BodyDecodingResult, RequestInfo};

fn acl_block(blocking: bool, _code: i32, reasons: Vec<BlockReason>) -> Decision {
    Decision::action(
        Action {
            atype: if blocking {
                ActionType::Block
            } else {
                ActionType::Monitor
            },
            block_mode: blocking,
            ban: false,
            status: 403,
            headers: None,
            content: "access denied".to_string(),
            extra_tags: None,
        },
        reasons,
    )
}

pub enum CfRulesArg<'t> {
    Global,
    Get(Option<&'t ContentFilterRules>),
}

#[allow(clippy::too_many_arguments)]
pub async fn analyze<GH: Grasshopper>(
    logs: &mut Logs,
    mgh: Option<GH>,
    itags: Tags,
    secpolname: &str,
    securitypolicy: &SecurityPolicy,
    reqinfo: RequestInfo,
    is_human: bool,
    globalfilter_dec: SimpleDecision,
    flows: &HashMap<SequenceKey, Vec<FlowElement>>,
    cfrules: CfRulesArg<'_>,
) -> AnalyzeResult {
    let mut tags = itags;
    let masking_seed = &securitypolicy.content_filter_profile.masking_seed;

    logs.debug("request tagged");
    tags.insert_qualified("securitypolicy", secpolname, Location::Request);
    tags.insert_qualified("securitypolicy-entry", &securitypolicy.name, Location::Request);
    tags.insert_qualified("aclid", &securitypolicy.acl_profile.id, Location::Request);
    tags.insert_qualified("aclname", &securitypolicy.acl_profile.name, Location::Request);
    tags.insert_qualified(
        "contentfilterid",
        &securitypolicy.content_filter_profile.id,
        Location::Request,
    );
    tags.insert_qualified(
        "contentfiltername",
        &securitypolicy.content_filter_profile.name,
        Location::Request,
    );

    if !securitypolicy.content_filter_profile.content_type.is_empty()
        && reqinfo.rinfo.qinfo.body_decoding != BodyDecodingResult::ProperlyDecoded
    {
        let reason = if let BodyDecodingResult::DecodingFailed(rr) = &reqinfo.rinfo.qinfo.body_decoding {
            BlockReason::body_malformed(rr)
        } else {
            BlockReason::body_missing()
        };
        // we expect the body to be properly decoded
        let action = Action {
            status: 403,
            ..Action::default()
        };
        return AnalyzeResult {
            decision: Decision::action(action, vec![reason]),
            tags,
            rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
        };
    }

    if let Some(decision) = mgh
        .as_ref()
        .and_then(|gh| challenge_phase02(gh, &reqinfo.rinfo.qinfo.uri, &reqinfo.headers))
    {
        return AnalyzeResult {
            decision,
            tags,
            rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
        };
    }
    logs.debug("challenge phase2 ignored");

    let mut brs = Vec::new();

    if let SimpleDecision::Action(action, reason) = globalfilter_dec {
        logs.debug(|| format!("Global filter decision {:?}", reason));
        brs.extend(reason);
        let decision = action.to_decision(is_human, &mgh, &reqinfo.headers, brs);
        if decision.is_final() {
            return AnalyzeResult {
                decision,
                tags,
                rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
            };
        }
        // if the decision was not adopted, get the reason vector back
        brs = decision.reasons;
    }

    match flow_check(logs, flows, &reqinfo, &mut tags).await {
        Err(rr) => logs.error(|| rr.to_string()),
        Ok(SimpleDecision::Pass) => {}
        Ok(SimpleDecision::Action(a, curbrs)) => {
            brs.extend(curbrs);
            let decision = a.to_decision(is_human, &mgh, &reqinfo.headers, brs);
            if decision.is_final() {
                return AnalyzeResult {
                    decision,
                    tags,
                    rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
                };
            }
            // if the decision was not adopted, get the reason vector back
            brs = decision.reasons;
        }
    }
    logs.debug("flow checks done");

    // limit checks
    let limit_check = limit_check(logs, &securitypolicy.name, &reqinfo, &securitypolicy.limits, &mut tags);
    if let SimpleDecision::Action(action, curbrs) = limit_check.await {
        brs.extend(curbrs);
        let decision = action.to_decision(is_human, &mgh, &reqinfo.headers, brs);
        if decision.is_final() {
            return AnalyzeResult {
                decision,
                tags,
                rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
            };
        }
        // if the decision was not adopted, get the reason vector back
        brs = decision.reasons;
    }
    logs.debug(|| format!("limit checks done ({} limits)", securitypolicy.limits.len()));

    let acl_result = check_acl(&tags, &securitypolicy.acl_profile);
    logs.debug(|| format!("ACL result: {:?}", acl_result));
    // store the check_acl result here
    let blockcode: Option<i32> = match acl_result {
        AclResult::Passthrough(dec) => {
            if dec.allowed {
                logs.debug("ACL passthrough detected");
                return AnalyzeResult {
                    decision: Decision::pass(brs),
                    tags,
                    rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
                };
            } else {
                logs.debug("ACL force block detected");
                brs.push(dec.r);
                Some(0)
            }
        }
        // bot blocked, human blocked
        // effect would be identical to the following case except for logging purpose
        AclResult::Match(BotHuman {
            bot: Some(AclDecision {
                allowed: false,
                r: bot_reason,
            }),
            human: Some(AclDecision {
                allowed: false,
                r: human_reason,
            }),
        }) => {
            logs.debug("ACL human block detected");
            brs.push(human_reason);
            brs.push(bot_reason);
            Some(5)
        }
        // human blocked, always block, even if it is a bot
        AclResult::Match(BotHuman {
            bot: _,
            human: Some(AclDecision {
                allowed: false,
                r: human_reason,
            }),
        }) => {
            logs.debug("ACL human block detected");
            brs.push(human_reason);
            Some(5)
        }
        // robot blocked, should be challenged
        AclResult::Match(BotHuman {
            bot: Some(AclDecision {
                allowed: false,
                r: bot_reason,
            }),
            human: _,
        }) => {
            if is_human {
                None
            } else {
                match (reqinfo.headers.get("user-agent"), &mgh) {
                    (Some(ua), Some(gh)) => {
                        logs.debug("ACL challenge detected: challenged");
                        brs.push(bot_reason);
                        return AnalyzeResult {
                            decision: challenge_phase01(gh, ua, brs),
                            tags,
                            rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
                        };
                    }
                    (gua, ggh) => {
                        logs.debug(|| {
                            format!(
                                "ACL challenge detected: can't challenge, ua={} gh={}",
                                gua.is_some(),
                                ggh.is_some()
                            )
                        });
                        brs.push(bot_reason);
                        Some(3)
                    }
                }
            }
        }
        _ => None,
    };
    logs.debug(|| format!("ACL checks done {:?}", blockcode));

    // if the acl is active, and we had a block result, immediately block
    if securitypolicy.acl_active {
        if let Some(cde) = blockcode {
            return AnalyzeResult {
                decision: acl_block(true, cde, brs),
                tags,
                rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
            };
        }
    }

    let mut cfcheck =
        |mrls| content_filter_check(logs, &mut tags, &reqinfo, &securitypolicy.content_filter_profile, mrls);
    // otherwise, run content_filter_check
    let content_filter_result = match cfrules {
        CfRulesArg::Global => match HSDB.read() {
            Ok(rd) => cfcheck(rd.get(&securitypolicy.content_filter_profile.id)),
            Err(rr) => {
                logs.error(|| format!("Could not get lock on HSDB: {}", rr));
                Ok(())
            }
        },
        CfRulesArg::Get(r) => cfcheck(r),
    };
    logs.debug("Content Filter checks done");

    let decision = match content_filter_result {
        Ok(()) => Decision::pass(brs),
        Err(decision) => {
            brs.extend(decision.reasons.into_iter().map(|mut reason| {
                if !securitypolicy.content_filter_active {
                    reason.decision.inactive();
                }
                reason
            }));
            match decision.maction {
                None => Decision::pass(brs),
                Some(mut action) => {
                    action.block_mode &= securitypolicy.content_filter_active;
                    Decision::action(action, brs)
                }
            }
        }
    };
    AnalyzeResult {
        decision,
        tags,
        rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
    }
}
