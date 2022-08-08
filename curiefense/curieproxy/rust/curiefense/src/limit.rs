use crate::interface::stats::{BStageFlow, BStageLimit, StatsCollect};
use crate::logs::Logs;
use crate::redis::{get_ban_key, is_banned};
use redis::RedisResult;

use crate::config::limit::Limit;
use crate::config::limit::LimitThreshold;
use crate::interface::{stronger_decision, BlockReason, Location, SimpleActionT, SimpleDecision, Tags};
use crate::redis::redis_async_conn;
use crate::utils::{select_string, RequestInfo};

fn build_key(security_policy_name: &str, reqinfo: &RequestInfo, tags: &Tags, limit: &Limit) -> Option<String> {
    let mut key = security_policy_name.to_string() + &limit.id;
    for kpart in limit.key.iter().map(|r| select_string(reqinfo, r, tags)) {
        key += &kpart?;
    }
    Some(format!("{:X}", md5::compute(key)))
}

#[allow(clippy::too_many_arguments)]
fn limit_pure_react(tags: &mut Tags, limit: &Limit, threshold: &LimitThreshold) -> SimpleDecision {
    tags.insert(&limit.name, Location::Request);
    let action = if let SimpleActionT::Ban(subaction, _) = &threshold.action.atype {
        *subaction.clone()
    } else {
        threshold.action.clone()
    };
    let decision = action.atype.to_bdecision();
    SimpleDecision::Action(
        action,
        vec![BlockReason::limit(
            limit.id.clone(),
            limit.name.clone(),
            threshold.limit,
            decision,
        )],
    )
}

async fn redis_get_limit<CNX: redis::aio::ConnectionLike>(
    cnx: &mut CNX,
    key: &str,
    timeframe: u64,
    pairvalue: Option<&str>,
) -> RedisResult<i64> {
    let (mcurrent, mexpire): (Option<i64>, Option<i64>) = match &pairvalue {
        None => {
            redis::pipe()
                .cmd("INCR")
                .arg(key)
                .cmd("TTL")
                .arg(key)
                .query_async(cnx)
                .await?
        }
        Some(pv) => {
            redis::pipe()
                .cmd("SADD")
                .arg(key)
                .arg(pv)
                .ignore()
                .cmd("SCARD")
                .arg(key)
                .cmd("TTL")
                .arg(key)
                .query_async(cnx)
                .await?
        }
    };
    let current = mcurrent.unwrap_or(0);
    let expire = mexpire.unwrap_or(-1);

    if expire < 0 {
        let _: () = redis::cmd("EXPIRE").arg(key).arg(timeframe).query_async(cnx).await?;
    }

    Ok(current)
}

fn limit_match(tags: &Tags, elem: &Limit) -> bool {
    if elem.exclude.iter().any(|e| tags.contains(e)) {
        return false;
    }
    if !(elem.include.is_empty() || elem.include.iter().any(|e| tags.contains(e))) {
        return false;
    }
    true
}

/// an item that needs to be checked in redis
pub struct LimitChecks<'t> {
    key: String,
    ban_key: String,
    pairvalue: Option<String>,
    limit: &'t Limit,
}

/// generate information that needs to be checked in redis for limit checks
pub fn limit_info<'t>(
    security_policy_name: &str,
    reqinfo: &RequestInfo,
    limits: &'t [Limit],
    tags: &mut Tags,
) -> Vec<LimitChecks<'t>> {
    let mut out = Vec::new();
    for limit in limits {
        if !limit_match(tags, limit) {
            continue;
        }
        let key = match build_key(security_policy_name, reqinfo, tags, limit) {
            // if we can't build the key, it usually means that a header is missing.
            // If that is the case, we continue to the next limit.
            None => continue,
            Some(k) => k,
        };
        let ban_key = get_ban_key(&key);
        let pairvalue = match &limit.pairwith {
            None => None,
            Some(sel) => match select_string(reqinfo, sel, tags) {
                None => continue,
                Some(x) => Some(x),
            },
        };
        out.push(LimitChecks {
            key,
            ban_key,
            pairvalue,
            limit,
        })
    }
    out
}

pub struct LimitResult<'t> {
    limit: &'t Limit,
    ban: bool,
    curcount: i64,
}

pub async fn limit_query<'t>(logs: &mut Logs, checks: &[LimitChecks<'t>]) -> Vec<LimitResult<'t>> {
    // early return to avoid redis connection
    if checks.is_empty() {
        logs.debug("no limits to check");
        return Vec::new();
    }

    // we connect once for all limit tests
    let mut redis = match redis_async_conn().await {
        Ok(c) => c,
        Err(rr) => {
            logs.error(|| format!("Could not connect to the redis server {}", rr));
            return Vec::new();
        }
    };

    let mut out = Vec::new();

    for check in checks {
        if is_banned(&mut redis, &check.ban_key).await {
            out.push(LimitResult {
                limit: check.limit,
                ban: true,
                curcount: 0,
            });
        } else {
            let curcount = if check.limit.thresholds.iter().all(|t| t.limit == 0) {
                Ok(1)
            } else {
                redis_get_limit(
                    &mut redis,
                    &check.key,
                    check.limit.timeframe,
                    check.pairvalue.as_deref(),
                )
                .await
            };
            match curcount {
                Err(rr) => logs.error(|| rr.to_string()),
                Ok(curcount) => {
                    // check for banning
                    if let Some(duration) = &check
                        .limit
                        .thresholds
                        .iter()
                        .filter(|th| curcount > th.limit as i64)
                        .filter_map(|th| {
                            if let SimpleActionT::Ban(_, duration) = th.action.atype {
                                Some(duration)
                            } else {
                                None
                            }
                        })
                        .next()
                    {
                        if let Err(rr) = redis::pipe()
                            .cmd("SET")
                            .arg(&check.ban_key)
                            .arg(1)
                            .cmd("EXPIRE")
                            .arg(&check.ban_key)
                            .arg(*duration)
                            .query_async::<_, ()>(&mut redis)
                            .await
                        {
                            logs.error(|| format!("Redis error {}", rr));
                        }
                    }
                    out.push(LimitResult {
                        limit: check.limit,
                        ban: false,
                        curcount,
                    })
                }
            }
        }
    }

    out
}

/// performs the redis requests and compute the proper reactions based on
pub fn limit_process(
    logs: &mut Logs,
    stats: StatsCollect<BStageFlow>,
    nlimits: usize,
    results: &[LimitResult<'_>],
    tags: &mut Tags,
) -> (SimpleDecision, StatsCollect<BStageLimit>) {
    let mut out = SimpleDecision::Pass;
    for result in results {
        if result.ban {
            logs.debug("is banned!");
            tags.insert(&result.limit.name, Location::Request);
            let ban_threshold: &LimitThreshold = result
                .limit
                .thresholds
                .iter()
                .find(|t| matches!(t.action.atype, SimpleActionT::Ban(_, _)))
                .unwrap_or(&result.limit.thresholds[0]);
            out = stronger_decision(out, limit_pure_react(tags, result.limit, ban_threshold));
        }

        if result.curcount > 0 {
            for threshold in &result.limit.thresholds {
                // Only one action with highest limit larger than current
                // counter will be applied, all the rest will be skipped.
                if result.curcount > threshold.limit as i64 {
                    out = stronger_decision(out, limit_pure_react(tags, result.limit, threshold));
                }
            }
        }
    }

    (out, stats.limit(nlimits, results.len()))
}

pub async fn limit_check(
    logs: &mut Logs,
    stats: StatsCollect<BStageFlow>,
    security_policy_name: &str,
    reqinfo: &RequestInfo,
    limits: &[Limit],
    tags: &mut Tags,
) -> (SimpleDecision, StatsCollect<BStageLimit>) {
    let checks = limit_info(security_policy_name, reqinfo, limits, tags);
    let qresults = limit_query(logs, &checks).await;
    limit_process(logs, stats, limits.len(), &qresults, tags)
}
