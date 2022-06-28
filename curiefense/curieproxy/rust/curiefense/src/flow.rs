use crate::interface::stats::{BStageFlow, BStageMapped, StatsCollect};
use crate::redis::{extract_bannable_action, get_ban_key, is_banned, BanStatus};
use crate::Logs;
use std::collections::HashMap;

use crate::config::flow::{FlowElement, SequenceKey};
use crate::config::utils::RequestSelector;
use crate::interface::{stronger_decision, BlockReason, Location, SimpleDecision, Tags};
use crate::utils::{check_selector_cond, select_string, RequestInfo};

fn session_sequence_key(ri: &RequestInfo) -> SequenceKey {
    SequenceKey(ri.rinfo.meta.method.to_string() + &ri.rinfo.host + &ri.rinfo.qinfo.qpath)
}

fn build_redis_key(
    reqinfo: &RequestInfo,
    tags: &Tags,
    key: &[RequestSelector],
    entry_id: &str,
    entry_name: &str,
) -> Option<String> {
    let mut tohash = entry_id.to_string() + entry_name;
    for kpart in key.iter() {
        tohash += &select_string(reqinfo, kpart, tags)?;
    }
    Some(format!("{:X}", md5::compute(tohash)))
}

fn flow_match(reqinfo: &RequestInfo, tags: &Tags, elem: &FlowElement) -> bool {
    if elem.exclude.iter().any(|e| tags.contains(e)) {
        return false;
    }
    if !(elem.include.is_empty() || elem.include.iter().any(|e| tags.contains(e))) {
        return false;
    }
    elem.select.iter().all(|e| check_selector_cond(reqinfo, tags, e))
}

enum FlowResult {
    NonLast,
    LastOk,
    LastBlock,
}

async fn check_flow<CNX: redis::aio::ConnectionLike>(
    cnx: &mut CNX,
    redis_key: &str,
    step: u32,
    timeframe: u64,
    is_last: bool,
) -> anyhow::Result<FlowResult> {
    // first, read from REDIS how many steps already passed
    let mlistlen: Option<usize> = redis::cmd("LLEN").arg(redis_key).query_async(cnx).await?;
    let listlen = mlistlen.unwrap_or(0);

    if is_last {
        if step as usize == listlen {
            Ok(FlowResult::LastOk)
        } else {
            Ok(FlowResult::LastBlock)
        }
    } else {
        if step as usize == listlen {
            let (_, mexpire): ((), Option<i64>) = redis::pipe()
                .cmd("LPUSH")
                .arg(redis_key)
                .arg("foo")
                .cmd("TTL")
                .arg(redis_key)
                .query_async(cnx)
                .await?;
            let expire = mexpire.unwrap_or(-1);
            if expire < 0 {
                let _: () = redis::cmd("EXPIRE")
                    .arg(redis_key)
                    .arg(timeframe)
                    .query_async(cnx)
                    .await?;
            }
        }
        // never block if not the last step!
        Ok(FlowResult::NonLast)
    }
}

async fn ban_react<CNX: redis::aio::ConnectionLike>(
    logs: &mut Logs,
    cnx: &mut CNX,
    elem: &FlowElement,
    redis_key: &str,
    blocked: bool,
    bad: SimpleDecision,
) -> SimpleDecision {
    let ban_key = get_ban_key(redis_key);
    let banned = is_banned(cnx, &ban_key).await;
    if banned {
        logs.debug(|| format!("Key {} is banned!", ban_key));
    }
    if banned || blocked {
        let action = extract_bannable_action(
            cnx,
            logs,
            &elem.action,
            redis_key,
            &ban_key,
            if banned {
                BanStatus::AlreadyBanned
            } else {
                BanStatus::NewBan
            },
        )
        .await;
        let decision = action.atype.to_bdecision();
        stronger_decision(
            bad,
            SimpleDecision::Action(
                action,
                vec![BlockReason::flow(
                    elem.id.to_string(),
                    elem.name.to_string(),
                    redis_key.to_string(),
                    decision,
                )],
            ),
        )
    } else {
        bad
    }
}

pub async fn flow_check(
    logs: &mut Logs,
    stats: StatsCollect<BStageMapped>,
    flows: &HashMap<SequenceKey, Vec<FlowElement>>,
    reqinfo: &RequestInfo,
    tags: &mut Tags,
) -> (anyhow::Result<SimpleDecision>, StatsCollect<BStageFlow>) {
    let sequence_key = session_sequence_key(reqinfo);
    match flows.get(&sequence_key) {
        None => (Ok(SimpleDecision::Pass), stats.no_flow()),
        Some(elems) => {
            let mut bad = SimpleDecision::Pass;
            // do not establish the connection if unneeded
            let mut cnx = match crate::redis::redis_async_conn().await {
                Ok(x) => x,
                Err(rr) => return (Err(rr), stats.no_flow()),
            };
            let mut flow_checked = 0;
            let mut flow_matched = 0;
            for elem in elems.iter() {
                flow_checked += 1;
                if !flow_match(reqinfo, tags, elem) {
                    continue;
                }
                flow_matched += 1;
                logs.debug(|| format!("Testing flow control {} (step {})", elem.name, elem.step));
                match build_redis_key(reqinfo, tags, &elem.key, &elem.id, &elem.name) {
                    Some(redis_key) => {
                        match check_flow(&mut cnx, &redis_key, elem.step, elem.timeframe, elem.is_last).await {
                            Ok(FlowResult::LastOk) => {
                                tags.insert(&elem.name, Location::Request);
                                bad = ban_react(logs, &mut cnx, elem, &redis_key, false, bad).await;
                            }
                            Ok(FlowResult::LastBlock) => {
                                tags.insert(&elem.name, Location::Request);
                                bad = ban_react(logs, &mut cnx, elem, &redis_key, true, bad).await;
                            }
                            Ok(FlowResult::NonLast) => {}
                            Err(rr) => return (Err(rr), stats.flow(flow_checked, flow_matched)),
                        }
                    }
                    None => logs.warning(|| format!("Could not fetch key in flow control {}", elem.name)),
                }
            }
            (Ok(bad), stats.flow(flow_checked, flow_matched))
        }
    }
}
