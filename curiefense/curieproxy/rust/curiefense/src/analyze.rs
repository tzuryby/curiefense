use std::collections::HashMap;

use crate::acl::check_acl;
use crate::config::contentfilter::ContentFilterRules;
use crate::config::flow::{FlowElement, SequenceKey};
use crate::config::hostmap::SecurityPolicy;
use crate::config::HSDB;
use crate::contentfilter::{content_filter_check, masking};
use crate::flow::{flow_info, flow_process, flow_query, FlowCheck, FlowResult};
use crate::grasshopper::{challenge_phase01, challenge_phase02, Grasshopper};
use crate::interface::stats::{BStageMapped, StatsCollect};
use crate::interface::{
    AclStage, Action, ActionType, AnalyzeResult, BDecision, BlockReason, Decision, Location, SimpleDecision, Tags,
};
use crate::limit::{limit_info, limit_process, limit_query, LimitCheck, LimitResult};
use crate::logs::Logs;
use crate::utils::{BodyDecodingResult, RequestInfo};

fn acl_block(blocking: bool, reasons: Vec<BlockReason>) -> Decision {
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

pub struct AnalyzeEnv {
    is_human: bool,
    reqinfo: RequestInfo,
}

pub struct APhase1<'t> {
    reasons: Vec<BlockReason>,
    flow_checks: Vec<FlowCheck<'t>>,
    limit_checks: Vec<LimitCheck<'t>>,
    stats: StatsCollect<BStageMapped>,
    env: AnalyzeEnv,
    tags: Tags,
}

pub enum InitResult<'t> {
    Res(AnalyzeResult),
    Phase1(APhase1<'t>),
}

#[allow(clippy::too_many_arguments)]
pub fn analyze_init<'t, GH: Grasshopper>(
    logs: &mut Logs,
    stats: StatsCollect<BStageMapped>,
    mgh: Option<&GH>,
    itags: Tags,
    secpolname: &str,
    securitypolicy: &'t SecurityPolicy,
    reqinfo: RequestInfo,
    is_human: bool,
    globalfilter_dec: SimpleDecision,
    flows: &'t HashMap<SequenceKey, Vec<FlowElement>>,
) -> InitResult<'t> {
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
        return InitResult::Res(AnalyzeResult {
            decision: Decision::action(action, vec![reason]),
            tags,
            rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
            stats: stats.mapped_stage_build(),
        });
    }

    if let Some(decision) = mgh.and_then(|gh| challenge_phase02(gh, &reqinfo.rinfo.qinfo.uri, &reqinfo.headers)) {
        return InitResult::Res(AnalyzeResult {
            decision,
            tags,
            rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
            stats: stats.mapped_stage_build(),
        });
    }
    logs.debug("challenge phase2 ignored");

    let mut brs = Vec::new();

    if let SimpleDecision::Action(action, reason) = globalfilter_dec {
        logs.debug(|| format!("Global filter decision {:?}", reason));
        brs.extend(reason);
        let decision = action.to_decision(is_human, mgh, &reqinfo, &tags, brs);
        if decision.is_final() {
            return InitResult::Res(AnalyzeResult {
                decision,
                tags,
                rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
                stats: stats.mapped_stage_build(),
            });
        }
        // if the decision was not adopted, get the reason vector back
        brs = decision.reasons;
    }

    let limit_checks = limit_info(&securitypolicy.name, &reqinfo, &securitypolicy.limits, &tags);
    let flow_checks = flow_info(logs, flows, &reqinfo, &tags);
    InitResult::Phase1(APhase1 {
        reasons: brs,
        flow_checks,
        limit_checks,
        stats,
        env: AnalyzeEnv { is_human, reqinfo },
        tags,
    })
}

pub struct APhase2<'t> {
    reasons: Vec<BlockReason>,
    flow_results: Vec<(&'t FlowElement, FlowResult)>,
    limit_results: Vec<LimitResult<'t>>,
    stats: StatsCollect<BStageMapped>,
    env: AnalyzeEnv,
    tags: Tags,
}

pub async fn analyze_query<'t>(logs: &mut Logs, p1: APhase1<'t>) -> APhase2<'t> {
    let flow_results = match flow_query(p1.flow_checks).await {
        Err(rr) => {
            logs.error(|| rr.to_string());
            Vec::new()
        }
        Ok(r) => r,
    };
    logs.debug("flow checks done");

    let limit_results = limit_query(logs, &p1.limit_checks).await;
    logs.debug("limit checks done");

    APhase2 {
        reasons: p1.reasons,
        flow_results,
        limit_results,
        stats: p1.stats,
        env: p1.env,
        tags: p1.tags,
    }
}

pub fn analyze_finish<GH: Grasshopper>(
    logs: &mut Logs,
    mgh: Option<&GH>,
    securitypolicy: &SecurityPolicy,
    cfrules: CfRulesArg<'_>,
    p2: APhase2,
) -> AnalyzeResult {
    let mut tags = p2.tags;
    let mut brs = p2.reasons;
    let is_human = p2.env.is_human;
    let reqinfo = p2.env.reqinfo;
    let masking_seed = &securitypolicy.content_filter_profile.masking_seed;

    let stats = flow_process(p2.stats, 0, &p2.flow_results, &mut tags);
    let (limit_check, stats) = limit_process(logs, stats, 0, &p2.limit_results, &mut tags);

    if let SimpleDecision::Action(action, curbrs) = limit_check {
        brs.extend(curbrs);
        let decision = action.to_decision(is_human, mgh, &reqinfo, &tags, brs);
        if decision.is_final() {
            return AnalyzeResult {
                decision,
                tags,
                rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
                stats: stats.limit_stage_build(),
            };
        }
        // if the decision was not adopted, get the reason vector back
        brs = decision.reasons;
    }
    logs.debug(|| format!("limit checks done ({} limits)", securitypolicy.limits.len()));

    let acl_result = check_acl(&tags, &securitypolicy.acl_profile);
    logs.debug(|| format!("ACL result: {:?}", acl_result));

    let acl_decision = acl_result.decision(is_human);
    let stats = stats.acl(if acl_decision.is_some() { 1 } else { 0 });
    if let Some(decision) = acl_decision {
        let bypass = decision.stage == AclStage::Bypass;
        let mut br = BlockReason::acl(decision.tags, decision.stage);
        if !securitypolicy.acl_active {
            br.decision.inactive();
        }
        let blocking = br.decision == BDecision::Blocking;
        brs.push(br);

        if securitypolicy.acl_active && bypass {
            return AnalyzeResult {
                decision: Decision::pass(brs),
                tags,
                rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
                stats: stats.acl_stage_build(),
            };
        }

        if blocking {
            let decision = if decision.challenge {
                match (reqinfo.headers.get("user-agent"), mgh) {
                    (Some(ua), Some(gh)) => challenge_phase01(gh, ua, brs),
                    (gua, ggh) => {
                        logs.debug(|| {
                            format!(
                                "ACL challenge detected: can't challenge, ua={} gh={}",
                                gua.is_some(),
                                ggh.is_some()
                            )
                        });
                        acl_block(true, brs)
                    }
                }
            } else {
                acl_block(true, brs)
            };
            return AnalyzeResult {
                decision,
                tags,
                rinfo: masking(masking_seed, reqinfo, &securitypolicy.content_filter_profile),
                stats: stats.acl_stage_build(),
            };
        }
    }

    let mut cfcheck = |stats, mrls| {
        content_filter_check(
            logs,
            stats,
            &mut tags,
            &reqinfo,
            &securitypolicy.content_filter_profile,
            mrls,
        )
    };
    // otherwise, run content_filter_check
    let (content_filter_result, stats) = match cfrules {
        CfRulesArg::Global => match HSDB.read() {
            Ok(rd) => cfcheck(stats, rd.get(&securitypolicy.content_filter_profile.id)),
            Err(rr) => {
                logs.error(|| format!("Could not get lock on HSDB: {}", rr));
                (Ok(()), stats.no_content_filter())
            }
        },
        CfRulesArg::Get(r) => cfcheck(stats, r),
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
        stats: stats.cf_stage_build(),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn analyze<GH: Grasshopper>(
    logs: &mut Logs,
    stats: StatsCollect<BStageMapped>,
    mgh: Option<&GH>,
    itags: Tags,
    secpolname: &str,
    securitypolicy: &SecurityPolicy,
    reqinfo: RequestInfo,
    is_human: bool,
    globalfilter_dec: SimpleDecision,
    flows: &HashMap<SequenceKey, Vec<FlowElement>>,
    cfrules: CfRulesArg<'_>,
) -> AnalyzeResult {
    let init_result = analyze_init(
        logs,
        stats,
        mgh,
        itags,
        secpolname,
        securitypolicy,
        reqinfo,
        is_human,
        globalfilter_dec,
        flows,
    );
    match init_result {
        InitResult::Res(result) => result,
        InitResult::Phase1(p1) => {
            let p2 = analyze_query(logs, p1).await;
            analyze_finish(logs, mgh, securitypolicy, cfrules, p2)
        }
    }
}
