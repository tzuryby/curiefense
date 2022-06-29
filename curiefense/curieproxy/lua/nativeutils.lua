local nativeutils = {}
-- helpers for native rust libraries
local cjson       = require "cjson"

function nativeutils.trim(s)
    return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end

function nativeutils.startswith(str, arg)
    if str and arg and type(str) == "string" and type(arg) == "string" then
        return string.find(str, arg, 1, true) == 1
    end
end

function nativeutils.endswith(str, arg)
    if str and arg then
        return string.find(str, arg, #str - #arg + 1, true) == #str - #arg + 1
    end
end

-- source http://lua-users.org/wiki/SplitJoin
function nativeutils.split(input, sSeparator, nMax, bRegexp)
    local aRecord = {}

    if sSeparator ~= '' then
      if (nMax == nil or nMax >= 1)then
        if input ~= nil then
          if input:len() > 0 then
            local bPlain = not bRegexp
            nMax = nMax or -1

            local nField=1
            local nStart=1
            local nFirst,nLast = input:find(sSeparator, nStart, bPlain)
            while nFirst and nMax ~= 0 do
                aRecord[nField] = input:sub(nStart, nFirst-1)
                nField = nField+1
                nStart = nLast+1
                nFirst,nLast = input:find(sSeparator, nStart, bPlain)
                nMax = nMax-1
            end
            aRecord[nField] = input:sub(nStart)
          end
        end
      end
    end

    return aRecord
end

function nativeutils.map_fn (T, fn)
    T = T or {}
    local ret = {}
    for _, v in ipairs(T) do
        local new_value = fn(v)
        table.insert(ret, new_value)
    end
    return ret
end

function nativeutils.nginx_custom_response(handle, action_params)
    if not action_params then action_params = {} end
    local block_mode = action_params.block_mode
    -- if not block_mode then block_mode = true end

    if action_params.atype == "alter_headers" and block_mode then
        handle.log(handle.ERR, cjson.encode(action_params))
        for k, v in pairs(action_params.headers) do
            handle.req.set_header(k, v)
        end
        return
    end

    if action_params["headers"] and action_params["headers"] ~= cjson.null then
        for k, v in pairs(action_params["headers"]) do
            handle.header[k] = v
        end
    end

    if action_params["status"] then
        local raw_status = action_params["status"]
        local status = tonumber(raw_status) or raw_status
        handle.status = status
    end

    handle.log(handle.ERR, cjson.encode(action_params))

    if block_mode then
        if action_params["content"] then handle.say(action_params["content"]) end
        handle.exit(handle.HTTP_OK)
    end

end

function nativeutils.log_nginx_messages(handle, logs)
    for _, log in ipairs(logs) do
        handle.log(handle.DEBUG, log)
    end
end

function nativeutils.envoy_custom_response(handle, action_params)
    if not action_params then action_params = {} end
    local block_mode = action_params.block_mode
    -- if not block_mode then block_mode = true end

    if action_params.atype == "alter_headers" and block_mode then
        handle:logDebug("altering the request")
        local headers = handle:headers()
        for k, v in pairs(action_params.headers) do
            headers:replace(k, v)
        end
        return
    end

    local response = {
        [ "status" ] = "503",
        [ "headers"] = { [":status"] = "503" },
        [ "reason" ] = { initiator = "undefined", reason = "undefined"},
        [ "content"] = "request denied"
    }

    -- override defaults
    if action_params["status"] then response["status"] = action_params["status"] end
    if action_params["headers"] and action_params["headers"] ~= cjson.null then
        response["headers"] = action_params["headers"]
    end
    if action_params["reason" ] then response["reason" ] = action_params["reason" ] end
    if action_params["content"] then response["content"] = action_params["content"] end

    response["headers"][":status"] = response["status"]

    if block_mode then
        handle:logDebug(cjson.encode(response))
        handle:respond( response["headers"], response["content"])
    end

end


function nativeutils.log_envoy_messages(handle, logs)
    for _, log in ipairs(logs) do
        handle:logDebug(log)
    end
end

return nativeutils
