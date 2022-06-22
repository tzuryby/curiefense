local session_rust_nginx = {}
local cjson       = require "cjson"
local curiefense  = require "curiefense"
local utils       = require "lua.nativeutils"
local sfmt = string.format
local custom_response = utils.nginx_custom_response

local function make_safe_headers(rheaders)
    local headers = {}

    for k, v in pairs(rheaders) do
        if type(v) == "table" then
            local new_v = v[1]
            for i = 2, #v do
                new_v = new_v .. "; " .. v[i]
            end
            headers[k] = new_v
        else
            headers[k] = v
        end
    end
    return headers
end

function session_rust_nginx.inspect(handle)
    local ip_str = handle.var.remote_addr

    local rheaders, err = handle.req.get_headers()
    if err == "truncated" then
        handle.log(handle.ERR, "truncated headers: " .. err)
    end

    local headers = make_safe_headers(rheaders)

    handle.log(handle.INFO, cjson.encode(headers))

    handle.req.read_body()
    local body_content = handle.req.get_body_data()
    if body_content ~= nil then
        handle.ctx.body_len = body_content:len()
    else
        handle.ctx.body_len = 0
    end
    local meta = { path=handle.var.request_uri, method=handle.req.get_method(), authority=nil }

    -- the meta table contains the following elements:
    --   * path : the full request uri
    --   * method : the HTTP verb
    --   * authority : optionally, the HTTP2 authority field
    local response
    response, err = curiefense.inspect_request(
        meta, headers, body_content, ip_str
    )

    if err then
        handle.log(handle.ERR, sfmt("curiefense.inspect_request_map error %s", err))
    end

    if response then
        local response_table = cjson.decode(response)
        handle.ctx.response = response_table
        handle.log(handle.DEBUG, "decision: " .. response)
        utils.log_nginx_messages(handle, response_table["logs"])
        if response_table["action"] == "custom_response" then
            custom_response(handle, response_table["response"])
        end
    end
end

-- log block stage processing
function session_rust_nginx.log(handle)
    local response = handle.ctx.response
    handle.ctx.response = nil
    local request_map = response.request_map
    handle.var.request_map = cjson.encode(request_map)
end

return session_rust_nginx
