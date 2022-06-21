local accesslog = {}
local cjson = require "cjson"
local json_encode   = cjson.encode

-- dynamic metadata filter name
local DMFN = "com.reblaze.curiefense"
local LOG_KEY = "request.info"

local function get_log_str_map(request_map)
  local str_map = json_encode(request_map)
  return str_map
end

function accesslog.envoy_log_request(handle, request_map)
  local str_map = get_log_str_map(request_map)
  handle:logDebug(str_map)
  handle:streamInfo():dynamicMetadata():set(DMFN, LOG_KEY, str_map)
end

return accesslog