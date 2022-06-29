local accesslog = {}

-- dynamic metadata filter name
local DMFN = "com.reblaze.curiefense"
local LOG_KEY = "request.info"

function accesslog.envoy_log_request(handle, request_map)
  handle:logDebug(request_map)
  handle:streamInfo():dynamicMetadata():set(DMFN, LOG_KEY, request_map)
end

return accesslog