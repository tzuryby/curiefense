local session_rust_envoy = {}
local cjson       = require "cjson"
local curiefense  = require "curiefense"
local accesslog   = require "lua.accesslog"
local utils       = require "lua.nativeutils"
local sfmt = string.format
local log_request = accesslog.envoy_log_request
local custom_response = utils.envoy_custom_response


local function detectip(xff, hops)
    local len_xff = #xff
    if hops < len_xff then
        return xff[len_xff-(hops-1)]
    else
        return xff[1]
    end
end


local function extract_ip(headers, metadata)
    local client_addr = "1.1.1.1"
    local xff = headers:get("x-forwarded-for")
    local hops = metadata:get("xff_trusted_hops") or "1"

    hops = tonumber(hops)
    local addrs = utils.map_fn(utils.split(xff, ","), utils.trim)

    client_addr = detectip(addrs, hops) or client_addr

    return client_addr
end


function session_rust_envoy.inspect(handle)
    local ip_str = extract_ip(handle:headers(), handle:metadata())

    local headers = {}
    local meta = {}
    for k, v in pairs(handle:headers()) do
        if utils.startswith(k, ":") then
            meta[k:sub(2):lower()] = v
        else
            headers[k] = v
        end
    end

    local hbody = handle:body()
    local body_content = nil
    if hbody then
        body_content = hbody:getBytes(0, hbody:length())
    end

    -- the meta table contains the following elements:
    --   * path : the full request uri
    --   * method : the HTTP verb
    --   * authority : optionally, the HTTP2 authority field
    local response, jrequest_map, err = curiefense.inspect_request(
        meta, headers, body_content, ip_str
    )

    log_request(handle, jrequest_map)

    if err then
        handle:logErr(sfmt("curiefense.inspect_request_map error %s", err))
    end

    if response then
        local response_table = cjson.decode(response)
        local request_map = cjson.decode(jrequest_map)
        handle:logDebug("decision " .. response)
        utils.log_envoy_messages(handle, request_map["logs"])
        if response_table["action"] == "custom_response" then
            custom_response(handle, response_table["response"])
        end
    end
end

return session_rust_envoy