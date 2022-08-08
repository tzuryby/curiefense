use curiefense::grasshopper::DynGrasshopper;
use curiefense::grasshopper::Grasshopper;
use curiefense::interface::Tags;
use curiefense::utils::RequestMeta;
use mlua::prelude::*;
use mlua::FromLua;
use std::collections::HashMap;

use curiefense::content_filter_check_generic_request_map;
use curiefense::inspect_generic_request_map;
use curiefense::logs::Logs;
use curiefense::utils::{InspectionResult, RawRequest};

/// Utility to add the return status to the log string
fn lua_set_status_string(_lua: &Lua, args: (String, String)) -> LuaResult<String> {
    let (data, code) = args;
    match code.parse::<u32>() {
        Err(_) => Ok(data),
        Ok(cde) => match serde_json::from_str::<serde_json::Value>(&data) {
            Err(_) => Ok(data),
            Ok(mut value) => match value.as_object_mut() {
                None => Ok(data),
                Some(mp) => {
                    mp.insert(
                        "response_code".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(cde)),
                    );
                    Ok(serde_json::to_string(mp).unwrap_or(data))
                }
            },
        },
    }
}

// ******************************************
// Content Filter ONLY CHECKS
// ******************************************

/// Lua interface to the inspection function
///
/// args are
/// * meta (contains keys "method", "path", and optionally "authority")
/// * headers
/// * (opt) body
/// * ip addr
/// * (opt) grasshopper
#[allow(clippy::type_complexity)]
#[allow(clippy::unnecessary_wraps)]
fn lua_inspect_content_filter(
    _lua: &Lua,
    args: (
        HashMap<String, String>, // meta
        HashMap<String, String>, // headers
        Option<LuaString>,       // maybe body
        String,                  // ip
        String,                  // content_filter_id
    ),
) -> LuaResult<LuaInspectionResult> {
    let (meta, headers, lua_body, str_ip, content_filter_id) = args;

    let res = inspect_content_filter(
        "/cf-config/current/config",
        meta,
        headers,
        lua_body.as_ref().map(|s| s.as_bytes()),
        str_ip,
        content_filter_id,
    );
    Ok(LuaInspectionResult(res))
}

/// Rust-native inspection top level function
fn inspect_content_filter(
    configpath: &str,
    meta: HashMap<String, String>,
    headers: HashMap<String, String>,
    mbody: Option<&[u8]>,
    ip: String,
    content_filter_id: String,
) -> Result<InspectionResult, String> {
    let mut logs = Logs::default();
    logs.debug("Inspection init");
    let rmeta: RequestMeta = RequestMeta::from_map(meta)?;

    let raw = RawRequest {
        ipstr: ip,
        meta: rmeta,
        headers,
        mbody,
    };

    let (dec, reqinfo, tags, stats) =
        content_filter_check_generic_request_map(configpath, &raw, &content_filter_id, &mut logs);

    Ok(InspectionResult {
        decision: dec,
        tags: Some(tags),
        logs,
        err: None,
        rinfo: Some(reqinfo),
        stats,
    })
}

struct LuaInspectionResult(Result<InspectionResult, String>);
impl LuaInspectionResult {
    fn get_with_o<F, A>(&self, f: F) -> LuaResult<Option<A>>
    where
        F: FnOnce(&InspectionResult) -> Option<A>,
    {
        Ok(match &self.0 {
            Ok(res) => f(res),
            Err(_) => None,
        })
    }
    fn get_with<F, A>(&self, f: F) -> LuaResult<Option<A>>
    where
        F: FnOnce(&InspectionResult) -> A,
    {
        self.get_with_o(|r| Some(f(r)))
    }
}
impl mlua::UserData for LuaInspectionResult {
    fn add_fields<'lua, F: mlua::UserDataFields<'lua, Self>>(fields: &mut F) {
        fields.add_field_method_get("error", |_, this| {
            Ok(match &this.0 {
                Ok(res) => res.err.clone(),
                Err(r) => Some(r.clone()),
            })
        });
        fields.add_field_method_get("blocking", |_, this| {
            Ok(match &this.0 {
                Ok(r) => r.decision.is_blocking(),
                Err(_) => false,
            })
        });
        fields.add_field_method_get("tags", |_, this| {
            this.get_with(|r| {
                r.tags
                    .as_ref()
                    .map(|tgs: &Tags| tgs.as_hash_ref().keys().cloned().collect::<Vec<_>>())
            })
        });
        fields.add_field_method_get("logs", |_, this| this.get_with(|r| r.logs.to_stringvec()));
        fields.add_field_method_get("response", |_, this| this.get_with(|r| r.decision.response_json()));
        fields.add_field_method_get("request_map", |_, this| this.get_with(|r| r.log_json()));
    }
}

// ******************************************
// FULL CHECKS
// ******************************************

/// Lua interface to the inspection function
///
/// args are
/// * meta (contains keys "method", "path" and optionally "authority" and "x-request-id")
/// * headers
/// * (opt) body
/// * ip addr
fn lua_inspect_request(
    lua: &Lua,
    args: (
        LuaValue, // meta
        LuaValue, // headers
        LuaValue, // optional body
        LuaValue, // ip
    ),
) -> LuaResult<LuaInspectionResult> {
    let (vmeta, vheaders, vlua_body, vstr_ip) = args;
    let lerr = |rr| Ok(LuaInspectionResult(Err(rr)));
    let meta = match FromLua::from_lua(vmeta, lua) {
        Err(rr) => return lerr(format!("Could not convert the meta argument: {}", rr)),
        Ok(m) => m,
    };
    let headers = match FromLua::from_lua(vheaders, lua) {
        Err(rr) => return lerr(format!("Could not convert the headers argument: {}", rr)),
        Ok(h) => h,
    };
    let lua_body: Option<LuaString> = match FromLua::from_lua(vlua_body, lua) {
        Err(rr) => return lerr(format!("Could not convert the body argument: {}", rr)),
        Ok(b) => b,
    };
    let str_ip = match FromLua::from_lua(vstr_ip, lua) {
        Err(rr) => return lerr(format!("Could not convert the ip argument: {}", rr)),
        Ok(i) => i,
    };
    let grasshopper = &DynGrasshopper {};
    let res = inspect_request(
        "/cf-config/current/config",
        meta,
        headers,
        lua_body.as_ref().map(|b| b.as_bytes()),
        str_ip,
        Some(grasshopper),
    );
    Ok(LuaInspectionResult(res))
}

struct DummyGrasshopper {
    humanity: bool,
}

impl Grasshopper for DummyGrasshopper {
    fn js_app(&self) -> Option<std::string::String> {
        None
    }
    fn js_bio(&self) -> Option<std::string::String> {
        None
    }
    fn parse_rbzid(&self, _: &str, _: &str) -> Option<bool> {
        Some(self.humanity)
    }
    fn gen_new_seed(&self, _: &str) -> Option<std::string::String> {
        None
    }
    fn verify_workproof(&self, _: &str, _: &str) -> Option<std::string::String> {
        Some("ok".into())
    }
}

/// Lua TEST interface to the inspection function
/// allows settings the Grasshopper result!
///
/// args are
/// * meta (contains keys "method", "path", and optionally "authority")
/// * headers
/// * (opt) body
/// * ip addr
/// * (opt) grasshopper
#[allow(clippy::type_complexity)]
#[allow(clippy::unnecessary_wraps)]
fn lua_test_inspect_request(
    _lua: &Lua,
    args: (
        HashMap<String, String>, // meta
        HashMap<String, String>, // headers
        Option<LuaString>,       // maybe body
        String,                  // ip
        bool,                    // humanity
    ),
) -> LuaResult<LuaInspectionResult> {
    let (meta, headers, lua_body, str_ip, humanity) = args;
    let gh = DummyGrasshopper { humanity };
    let grasshopper = Some(&gh);

    let res = inspect_request(
        "/cf-config/current/config",
        meta,
        headers,
        lua_body.as_ref().map(|b| b.as_bytes()),
        str_ip,
        grasshopper,
    );
    Ok(LuaInspectionResult(res))
}

/// Rust-native inspection top level function
fn inspect_request<GH: Grasshopper>(
    configpath: &str,
    meta: HashMap<String, String>,
    headers: HashMap<String, String>,
    mbody: Option<&[u8]>,
    ip: String,
    grasshopper: Option<&GH>,
) -> Result<InspectionResult, String> {
    let mut logs = Logs::default();
    logs.debug("Inspection init");
    let rmeta: RequestMeta = RequestMeta::from_map(meta)?;

    let raw = RawRequest {
        ipstr: ip,
        meta: rmeta,
        headers,
        mbody,
    };
    let dec = inspect_generic_request_map(configpath, grasshopper, raw, &mut logs);

    Ok(InspectionResult {
        decision: dec.decision,
        tags: Some(dec.tags),
        logs,
        err: None,
        rinfo: Some(dec.rinfo),
        stats: dec.stats,
    })
}

#[mlua::lua_module]
fn curiefense(lua: &Lua) -> LuaResult<LuaTable> {
    let exports = lua.create_table()?;

    // end-to-end inspection
    exports.set("inspect_request", lua.create_function(lua_inspect_request)?)?;
    // end-to-end inspection (test)
    exports.set("test_inspect_request", lua.create_function(lua_test_inspect_request)?)?;
    // content filter inspection
    exports.set(
        "inspect_content_filter",
        lua.create_function(lua_inspect_content_filter)?,
    )?;
    // setting the HTTP status code
    exports.set("set_status_string", lua.create_function(lua_set_status_string)?)?;

    Ok(exports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curiefense::config::with_config;

    #[test]
    fn config_load() {
        let mut logs = Logs::default();
        let cfg = with_config("../../cf-config", &mut logs, |_, c| c.clone());
        if cfg.is_some() {
            match logs.logs.len() {
                4 => {
                    assert!(logs.logs[0].message.to_string().contains("CFGLOAD logs start"));
                    assert!(logs.logs[1].message.to_string().contains("manifest.json"));
                    assert!(logs.logs[2].message.to_string().contains("Loaded profile"));
                    assert!(logs.logs[3].message.to_string().contains("CFGLOAD logs end"));
                }
                12 => {
                    assert!(logs.logs[1]
                        .message
                        .to_string()
                        .contains("../../cf-config: No such file or directory"))
                }
                n => {
                    for r in logs.logs.iter() {
                        eprintln!("{}", r);
                    }
                    panic!("Invalid amount of logs: {}", n);
                }
            }
        }
    }
}
