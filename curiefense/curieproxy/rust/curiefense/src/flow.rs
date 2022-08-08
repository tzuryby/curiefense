use crate::interface::stats::{BStageFlow, BStageMapped, StatsCollect};
use crate::Logs;
use std::collections::HashMap;

use crate::config::flow::{FlowElement, SequenceKey};
use crate::config::matchers::RequestSelector;
use crate::interface::{Location, Tags};
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

pub enum FlowResult {
    NonLast,
    LastOk,
    LastBlock,
}

pub struct FlowCheck<'t> {
    redis_key: String,
    elem: &'t FlowElement,
}

async fn check_flow<'t, CNX: redis::aio::ConnectionLike>(
    cnx: &mut CNX,
    check: FlowCheck<'t>,
) -> anyhow::Result<FlowResult> {
    // first, read from REDIS how many steps already passed
    let mlistlen: Option<usize> = redis::cmd("LLEN").arg(&check.redis_key).query_async(cnx).await?;
    let listlen = mlistlen.unwrap_or(0);

    if check.elem.is_last {
        if check.elem.step as usize == listlen {
            Ok(FlowResult::LastOk)
        } else {
            Ok(FlowResult::LastBlock)
        }
    } else {
        if check.elem.step as usize == listlen {
            let (_, mexpire): ((), Option<i64>) = redis::pipe()
                .cmd("LPUSH")
                .arg(&check.redis_key)
                .arg("foo")
                .cmd("TTL")
                .arg(&check.redis_key)
                .query_async(cnx)
                .await?;
            let expire = mexpire.unwrap_or(-1);
            if expire < 0 {
                let _: () = redis::cmd("EXPIRE")
                    .arg(&check.redis_key)
                    .arg(check.elem.timeframe)
                    .query_async(cnx)
                    .await?;
            }
        }
        // never block if not the last step!
        Ok(FlowResult::NonLast)
    }
}

pub fn flow_info<'t>(
    logs: &mut Logs,
    flows: &'t HashMap<SequenceKey, Vec<FlowElement>>,
    reqinfo: &RequestInfo,
    tags: &Tags,
) -> Vec<FlowCheck<'t>> {
    let sequence_key = session_sequence_key(reqinfo);
    match flows.get(&sequence_key) {
        None => Vec::new(),
        Some(elems) => {
            let mut out = Vec::new();
            for elem in elems.iter() {
                if !flow_match(reqinfo, tags, elem) {
                    continue;
                }
                logs.debug(|| format!("Testing flow control {} (step {})", elem.name, elem.step));
                match build_redis_key(reqinfo, tags, &elem.key, &elem.id, &elem.name) {
                    Some(redis_key) => {
                        out.push(FlowCheck { redis_key, elem });
                    }
                    None => logs.warning(|| format!("Could not fetch key in flow control {}", elem.name)),
                }
            }
            out
        }
    }
}

pub async fn flow_query(checks: Vec<FlowCheck<'_>>) -> anyhow::Result<Vec<(&FlowElement, FlowResult)>> {
    if checks.is_empty() {
        return Ok(Vec::new());
    }
    let mut cnx = crate::redis::redis_async_conn().await?;
    let mut out = Vec::new();
    for check in checks {
        let elem = check.elem;
        let r = check_flow(&mut cnx, check).await?;
        out.push((elem, r));
    }
    Ok(out)
}

pub fn flow_process(
    stats: StatsCollect<BStageMapped>,
    flow_total: usize,
    results: &[(&FlowElement, FlowResult)],
    tags: &mut Tags,
) -> StatsCollect<BStageFlow> {
    for (elem, result) in results {
        match result {
            FlowResult::LastOk => {
                tags.insert(&elem.name, Location::Request);
            }
            FlowResult::LastBlock => {
                tags.insert(&elem.name, Location::Request);
                tags.insert(&elem.tag, Location::Request);
            }
            FlowResult::NonLast => {}
        }
    }
    stats.flow(flow_total, results.len())
}

pub async fn flow_check(
    logs: &mut Logs,
    stats: StatsCollect<BStageMapped>,
    flows: &HashMap<SequenceKey, Vec<FlowElement>>,
    reqinfo: &RequestInfo,
    tags: &mut Tags,
) -> (anyhow::Result<()>, StatsCollect<BStageFlow>) {
    let checks = flow_info(logs, flows, reqinfo, tags);
    let results = match flow_query(checks).await {
        Err(rr) => return (Err(rr), stats.no_flow()),
        Ok(r) => r,
    };
    (Ok(()), flow_process(stats, 0, &results, tags))
}
