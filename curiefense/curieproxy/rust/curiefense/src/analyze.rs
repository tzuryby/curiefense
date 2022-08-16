use crate::acl::check_acl;
use crate::config::contentfilter::ContentFilterRules;
use crate::config::flow::FlowMap;
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

pub struct APhase0 {
    pub flows: FlowMap,
    pub globalfilter_dec: SimpleDecision,
    pub is_human: bool,
    pub itags: Tags,
    pub reqinfo: RequestInfo,
    pub secpolname: String,
    pub securitypolicy: SecurityPolicy,
    pub stats: StatsCollect<BStageMapped>,
}

#[derive(Clone)]
pub struct AnalysisInfo {
    is_human: bool,
    reasons: Vec<BlockReason>,
    reqinfo: RequestInfo,
    securitypolicy: SecurityPolicy,
    stats: StatsCollect<BStageMapped>,
    tags: Tags,
}

#[derive(Clone)]
pub struct AnalysisPhase<FLOW, LIMIT> {
    pub flows: Vec<FLOW>,
    pub limits: Vec<LIMIT>,
    info: AnalysisInfo,
}

impl<FLOW, LIMIT> AnalysisPhase<FLOW, LIMIT> {
    pub fn next<NFLOW, NLIMIT>(self, flows: Vec<NFLOW>, limits: Vec<NLIMIT>) -> AnalysisPhase<NFLOW, NLIMIT> {
        AnalysisPhase {
            flows,
            info: self.info,
            limits,
        }
    }
    pub fn new(flows: Vec<FLOW>, limits: Vec<LIMIT>, info: AnalysisInfo) -> Self {
        Self { flows, info, limits }
    }
}

pub type APhase1 = AnalysisPhase<FlowCheck, LimitCheck>;

pub enum InitResult {
    Res(AnalyzeResult),
    Phase1(APhase1),
}

#[allow(clippy::too_many_arguments)]
pub fn analyze_init<GH: Grasshopper>(logs: &mut Logs, mgh: Option<&GH>, p0: APhase0) -> InitResult {
    let stats = p0.stats;
    let mut tags = p0.itags;
    let secpolname = &p0.secpolname;
    let securitypolicy = p0.securitypolicy;
    let reqinfo = p0.reqinfo;
    let is_human = p0.is_human;
    let globalfilter_dec = p0.globalfilter_dec;
    let masking_seed = &securitypolicy.content_filter_profile.masking_seed;

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
    let flow_checks = flow_info(logs, &p0.flows, &reqinfo, &tags);
    let info = AnalysisInfo {
        is_human,
        reasons: brs,
        reqinfo,
        securitypolicy,
        stats,
        tags,
    };
    InitResult::Phase1(APhase1::new(flow_checks, limit_checks, info))
}

pub type APhase2 = AnalysisPhase<FlowResult, LimitResult>;

impl APhase2 {
    pub fn from_phase1(p1: APhase1, flow_results: Vec<FlowResult>, limit_results: Vec<LimitResult>) -> Self {
        p1.next(flow_results, limit_results)
    }
}

pub async fn analyze_query<'t>(logs: &mut Logs, p1: APhase1) -> APhase2 {
    let info = p1.info;
    let flow_results = match flow_query(p1.flows).await {
        Err(rr) => {
            logs.error(|| rr.to_string());
            Vec::new()
        }
        Ok(r) => r,
    };
    logs.debug("flow checks done");

    let limit_results = limit_query(logs, p1.limits).await;
    logs.debug("limit checks done");

    AnalysisPhase {
        flows: flow_results,
        limits: limit_results,
        info,
    }
}

pub fn analyze_finish<GH: Grasshopper>(
    logs: &mut Logs,
    mgh: Option<&GH>,
    cfrules: CfRulesArg<'_>,
    p2: APhase2,
) -> AnalyzeResult {
    // destructure the info structure, so that each field can be consumed independently
    let info = p2.info;
    let mut tags = info.tags;
    let mut brs = info.reasons;
    let is_human = info.is_human;
    let reqinfo = info.reqinfo;
    let secpol = info.securitypolicy;
    let masking_seed = &secpol.content_filter_profile.masking_seed;

    let stats = flow_process(info.stats, 0, &p2.flows, &mut tags);
    let (limit_check, stats) = limit_process(logs, stats, 0, &p2.limits, &mut tags);

    if let SimpleDecision::Action(action, curbrs) = limit_check {
        brs.extend(curbrs);
        let decision = action.to_decision(is_human, mgh, &reqinfo, &tags, brs);
        if decision.is_final() {
            return AnalyzeResult {
                decision,
                tags,
                rinfo: masking(masking_seed, reqinfo, &secpol.content_filter_profile),
                stats: stats.limit_stage_build(),
            };
        }
        // if the decision was not adopted, get the reason vector back
        brs = decision.reasons;
    }
    logs.debug("limit checks done");

    let acl_result = check_acl(&tags, &secpol.acl_profile);
    logs.debug(|| format!("ACL result: {:?}", acl_result));

    let acl_decision = acl_result.decision(is_human);
    let stats = stats.acl(if acl_decision.is_some() { 1 } else { 0 });
    if let Some(decision) = acl_decision {
        let bypass = decision.stage == AclStage::Bypass;
        let mut br = BlockReason::acl(decision.tags, decision.stage);
        if !secpol.acl_active {
            br.decision.inactive();
        }
        let blocking = br.decision == BDecision::Blocking;
        brs.push(br);

        if secpol.acl_active && bypass {
            return AnalyzeResult {
                decision: Decision::pass(brs),
                tags,
                rinfo: masking(masking_seed, reqinfo, &secpol.content_filter_profile),
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
                rinfo: masking(masking_seed, reqinfo, &secpol.content_filter_profile),
                stats: stats.acl_stage_build(),
            };
        }
    }

    let mut cfcheck =
        |stats, mrls| content_filter_check(logs, stats, &mut tags, &reqinfo, &secpol.content_filter_profile, mrls);
    // otherwise, run content_filter_check
    let (content_filter_result, stats) = match cfrules {
        CfRulesArg::Global => match HSDB.read() {
            Ok(rd) => cfcheck(stats, rd.get(&secpol.content_filter_profile.id)),
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
        Err(cfblock) => {
            brs.extend(cfblock.reasons.into_iter().map(|mut reason| {
                if !secpol.content_filter_active {
                    reason.decision.inactive();
                }
                reason
            }));
            if cfblock.blocking {
                let mut dec = secpol
                    .content_filter_profile
                    .action
                    .to_decision(is_human, mgh, &reqinfo, &tags, brs);
                if let Some(mut action) = dec.maction.as_mut() {
                    action.block_mode &= secpol.content_filter_active;
                }
                dec
            } else {
                Decision::pass(brs)
            }
        }
    };
    AnalyzeResult {
        decision,
        tags,
        rinfo: masking(masking_seed, reqinfo, &secpol.content_filter_profile),
        stats: stats.cf_stage_build(),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn analyze<GH: Grasshopper>(
    logs: &mut Logs,
    mgh: Option<&GH>,
    p0: APhase0,
    cfrules: CfRulesArg<'_>,
) -> AnalyzeResult {
    let init_result = analyze_init(logs, mgh, p0);
    match init_result {
        InitResult::Res(result) => result,
        InitResult::Phase1(p1) => {
            let p2 = analyze_query(logs, p1).await;
            analyze_finish(logs, mgh, cfrules, p2)
        }
    }
}
