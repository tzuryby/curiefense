use crate::interface::stats::{BStageFlow, BStageMapped, StatsCollect};
use crate::Logs;

use crate::config::flow::{FlowElement, FlowMap, SequenceKey};
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

#[derive(Clone)]
pub struct FlowResult {
    pub tp: FlowResultType,
    pub name: String,
    pub tags: Vec<String>,
}

#[derive(Clone, Copy)]
pub enum FlowResultType {
    NonLast,
    LastOk,
    LastBlock,
}

#[derive(Clone)]
pub struct FlowCheck {
    pub redis_key: String,
    pub step: u32,
    pub timeframe: u64,
    pub is_last: bool,
    pub name: String,
    pub tags: Vec<String>,
}

async fn check_flow<CNX: redis::aio::ConnectionLike>(cnx: &mut CNX, check: &FlowCheck) -> anyhow::Result<FlowResult> {
    // first, read from REDIS how many steps already passed
    let mlistlen: Option<usize> = redis::cmd("LLEN").arg(&check.redis_key).query_async(cnx).await?;
    let listlen = mlistlen.unwrap_or(0);

    let tp = if check.is_last {
        if check.step as usize == listlen {
            FlowResultType::LastOk
        } else {
            FlowResultType::LastBlock
        }
    } else {
        if check.step as usize == listlen {
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
                    .arg(check.timeframe)
                    .query_async(cnx)
                    .await?;
            }
        }
        // never block if not the last step!
        FlowResultType::NonLast
    };
    Ok(FlowResult {
        tp,
        name: check.name.clone(),
        tags: check.tags.clone(),
    })
}

pub fn flow_info(logs: &mut Logs, flows: &FlowMap, reqinfo: &RequestInfo, tags: &Tags) -> Vec<FlowCheck> {
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
                        out.push(FlowCheck {
                            redis_key,
                            step: elem.step,
                            timeframe: elem.timeframe,
                            is_last: elem.is_last,
                            name: elem.name.clone(),
                            tags: elem.tags.clone(),
                        });
                    }
                    None => logs.warning(|| format!("Could not fetch key in flow control {}", elem.name)),
                }
            }
            out
        }
    }
}

pub async fn flow_query(checks: Vec<FlowCheck>) -> anyhow::Result<Vec<FlowResult>> {
    if checks.is_empty() {
        return Ok(Vec::new());
    }
    let mut cnx = crate::redis::redis_async_conn().await?;
    let mut out = Vec::new();
    for check in checks {
        let r = check_flow(&mut cnx, &check).await?;
        out.push(r);
    }
    Ok(out)
}

pub fn flow_process(
    stats: StatsCollect<BStageMapped>,
    flow_total: usize,
    results: &[FlowResult],
    tags: &mut Tags,
) -> StatsCollect<BStageFlow> {
    for result in results {
        match result.tp {
            FlowResultType::LastOk => {
                tags.insert(&result.name, Location::Request);
            }
            FlowResultType::LastBlock => {
                tags.insert(&result.name, Location::Request);
                for tag in &result.tags {
                    tags.insert(tag, Location::Request);
                }
            }
            FlowResultType::NonLast => {}
        }
    }
    stats.flow(flow_total, results.len())
}

pub async fn flow_check(
    logs: &mut Logs,
    stats: StatsCollect<BStageMapped>,
    flows: &FlowMap,
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
