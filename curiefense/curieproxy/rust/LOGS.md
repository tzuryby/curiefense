The log is by default sent to stdout. In the Curieproxy containers, it is piped to *filebeat* that will store it
in ElasticSearch.

The log file is a JSON encoded data structure, where the top level is an object with the following members:

 * `timestamp`: time when the request started to be processed, encoded as a string
 * `curiesession`: a session identifier (a string),
 * `curiesession_ids`: extra session identifiers (a list of NV items, see below),
 * `request_id`: unique identifier for the request, provided by either envoy or Nginx `ngx.var.request_id`
 * `security_config`: see the *security config* section
 * `arguments`: a list of NV items representing arguments
 * ~~`uri`: request URI, as a string~~
 * `path`: query path
	 * raw as submitted
 * `query`: Query string
	 * raw as submitted (with the "?" when presented)
 * `path_parts`: a list of NV items representing path parts,
	 * decoded
 * `authority`: the `:authority` meta data, if it exists, or the *host* header
 * `cookies`: a list of NV items representing cookies
 * `headers`: a list of NV items representing headers
 * `tags`: a list of strings, representing the request tags
 * `ip`: request IP, as a string
 * `method`: request method verb, as a string (uppercased)
 * `response_code`: the response code that was served to the user (integer)
 * `logs`: a list of string, destined for human consumption, with an unspecified format,
 * `processing_stage`: a number representing the stage where the request stopped being processed:
    * 0: initialization, should never happen,
    * 1: security policy level, this means no security policy could be selected,
    * 2: global filter stage,
    * 3: flow control stage,
    * 4: rate limit stage,
    * 5: ACL stage,
    * 6: content filter stage.
 * `trigger_counters`: a list of KV items of the form:
    * `TRIGGER`: length of the `TRIGGER` list,
    * `TRIGGER_active`: amount of items in the `TRIGGER` list that would cause a block.
    Here, `TRIGGER` can be `acl`, `global_filters`, `flow_control`, `rate_limit` or `content_filters`.

 * `acl_triggers`: triggers for the `acl` trigger type (see below),
 * `rate_limit_triggers`: triggers for the `rate_limit` trigger type (see below),
 * `flow_control_triggers`: triggers for the `flow_control` trigger type (see below),
 * `global_filter_triggers`: triggers for the `global_filter` trigger type (see below),
 * `content_filter_triggers`: triggers for the `content_filter` trigger type (see below),
 * `proxy`: an object with a single key, `location`, containing a pair of floating values, representing the geo localized coordinates, when available,
 * `reason`: a string describing why a decision was reached,
 * `profiling`: for now, an empty object,
 * `biometrics`: for now, an empty object.

## list of NV items

This represents a dictionary as a list of name/values items, in order to be easier to query by databases. Example:

```json
  "headers": [
    {
      "name": "user-agent",
      "value": "curl/7.68.0"
    },
    {
      "name": "x-forwarded-for",
      "value": "199.0.0.1"
    },
    {
      "name": "host",
      "value": "www.example.com"
    },
    {
      "name": "accept",
      "value": "*/*"
    }
  ]
```

## Security configuration object

This is an object representing the security configuration when the request was matched:

 * `revision`: string, the revision, from the manifest file,
 * `acl_active`: boolean, true if ACL is enabled,
 * `cf_active`: boolean, true if content filters are enabled,
 * `cf_rules`: number of content filter rules that were matched against the request,
 * `rl_rules`: number of "Active" rate limit rules included with the session processing (global or path mathced)
 * `gf_rules`: number of global filters included with the session processing

## Trigger lists

The fields named `TYPE_triggers` are lists of objects, representing the filter elements that were triggered.
Each of these objects contain information about the part of the request that triggered, as well as information
specific to the type of trigger.

* `trigger_id`
* `trigger_name`
* `action`: string representing 

### Location data

The following entries are **all optional**:
 * `section`, can be `attributes [ip/uri/referer_path/etc.]`, `path`, `headers`, `body` or `plugins`;
	 * *SAMPLES*:
		 * 
 * `part`, indicate a "path part". Path parts are elements separated by slashes;
 * `name`, name of the argument, header or cookie that triggered the response;
 * `value`, actual value that triggered the response.


### Trigger specific entries

The following triggers are defined:

#### ACL triggers

Contains:
  * `tags`, list of strings, the list of tags that matched the ACL column
  * `acl_action`, a string, the ACL column

#### Rate limit triggers

Contains:
  * `threshold`, a number, representing the limit threshold

#### Global filter triggers

no specific fileds for global filter

#### Content filter rules triggers

Contains:

  * `ruleid`, a string, the id of the matching rule,
  * `risk_level`, a number, the risk level of the matching rule.

#### Content filter restriction triggers

Contains:

  * `type`, a string, can be `too deep`, `too large`, `missing body`, `malformed body`, `too many`, `too large`, `restricted`
  * `actual`, a string
  * `expected`, a string

# Sample log

```json
{
  "action": "custom",
  "acl_triggers": [],
  "arguments": [
    {
      "name": "lapin",
      "value": "xp_cmdshell"
    }
  ],
  "authority": "example.com",
  "biometric": {},
  "content_filter_triggers": [
    {
      "id": "dqssdqs",
      "active": true,
      "name": "lapin",
      "risk_level": 5,
      "ruleid": "100016",
      "section": "uri",
      "value": "xp_cmdshell"
    }
  ],
  "cookies": [],
  "curiesession": "50d7a17f95cd53700ab8af62f2faa54a570bfd5462c04bd1146750dc",
  "curiesession_ids": [
    {
      "name": "ip",
      "value": "50d7a17f95cd53700ab8af62f2faa54a570bfd5462c04bd1146750dc"
    },
    {
      "name": "header_foo",
      "value": "871b96ad16b704cde4b95bc6b52db116bfbf96c266d8daaf41646580"
    },
    {
      "name": "argument_lapin",
      "value": "9d23728b5d02834e40489ae9e0a355a6aedbd871ef680985b27a3841"
    }
  ],
  "global_filter_triggers": [
    {
      "active": false,
      "id": "xlbp148c",
      "name": "API Discovery"
    }
  ],
  "headers": [
    {
      "name": "user-agent",
      "value": "curl/7.68.0"
    },
    {
      "name": "x-forwarded-for",
      "value": "199.0.0.1"
    },
    {
      "name": "host",
      "value": "www.example.com"
    },
    {
      "name": "accept",
      "value": "*/*"
    },
    {
      "name": "foo",
      "value": "DQSSDD"
    }
  ],
  "ip": "199.0.0.1",
  "logs": [
    "D 23µs Loading configuration from /cf-config/current/config",
    "D 3623004µs Loaded profile __default__ with 188 rules"
  ],
  "method": "POST",
  "path": "/login",
  "path_parts": [
    {
      "name": "part1",
      "value": "login"
    },
    {
      "name": "path",
      "value": "/login"
    }
  ],
  "processing_stage": 6,
  "profiling": {},
  "proxy": [
    {
      "name": "geo_long",
      "value": 37.751
    },
    {
      "name": "geo_lat",
      "value": -97.822
    }
  ],
  "rate_limit_triggers": [],
  "reason": null,
  "request_id": null,
  "response_code": 503,

  "tags": [
    "flowc",
    "cf-rule-subcategory:built-in-function-invocation",
    "cf-rule-id:100016",
    "headers:5",
    "geo-org:sprintlink",
    "ip:199-0-0-1",
    "host:www-example-com",
    "aclname:default-acl",
    "cf-rule-category:sqli",
    "securitypolicy:default-entry",
    "geo-continent-name:north-america",
    "securitypolicy-entry:default",
    "aclid:--default--",
    "geo-country:united-states",
    "cookies:0",
    "api",
    "geo-region:nil",
    "geo-city:nil",
    "args:1",
    "contentfilterid:--default--",
    "geo-asn:1239",
    "contentfiltername:default-contentfilter",
    "flow-control-policy-example",
    "all",
    "cf-rule-risk:5",
    "geo-continent-code:na",
    "geo-subregion:nil",
    "bot",
    "status:503",
    "status-class:5xx"
  ],
  "timestamp": "2022-10-03T09:58:41.951745024Z",
  "security_config": {
    "acl_active": false,
    "cf_active": false,
    "cf_rules": 188,
    "global_filters_active": 1,
    "rate_limit_rules": 0,
    "revision": "216e288ba637dbaacec03d97cbb94b183d8b1c1f"
  },  
  "trigger_counters": {
    "acl": 0,
    "content_filters": 1,
    "global_filters": 1,
    "rate_limit": 1
  },
  "uri": "/login?lapin=xp_cmdshell"
}
```
