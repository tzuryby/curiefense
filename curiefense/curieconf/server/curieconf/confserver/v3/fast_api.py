import datetime
import typing
from typing import Optional, List, Union

from fastapi import FastAPI, Request
from pydantic import BaseModel, Field, validator
import random  # needed for generating a random number for an API
import uvicorn  # optional if you run it directly from terminal
import jsonschema

# monkey patch to force RestPlus to use Draft3 validator to benefit from "any" json type
jsonschema.Draft4Validator = jsonschema.Draft3Validator

from curieconf import utils
from curieconf.utils import cloud
from curieconf.confserver import app

import requests
from jsonschema import validate
from pathlib import Path
import json

# api_bp = Blueprint("api_v3", __name__)
# api = Api(api_bp, version="3.0", title="Curiefense configuration API server v3.0")

# ns_configs = api.namespace("configs", description="Configurations")
# ns_db = api.namespace("db", description="Database")
# ns_tools = api.namespace("tools", description="Tools")


##############
### MODELS ###
##############


### Models for documents
anyTypeUnion = Union[int, float, bool, object, list, None]
anyOp = Optional[object]
anyType = ["number", "string", "boolean", "object", "array", "null"]


# class AnyType(fields.Raw):
#     __schema_type__ = ["number", "string", "boolean", "object", "array", "null"]


# limit

class Threshold(BaseModel):
    limit: int
    action: str


# m_threshold = api.model(
#     "Rate Limit Threshold",
#     {
#         "limit": fields.Integer(required=True),
#         "action": fields.String(required=True),
#     },
# )

class Limit(BaseModel):
    id: str
    name: str
    description: Optional[str]
    _global: bool = Field(alias="global")
    active: bool
    timeframe: int
    thresholds: List[Threshold]
    include: typing.Any
    exclude: typing.Any
    key: anyTypeUnion
    pairwith: typing.Any
    tags: List[str]


# m_limit = api.model(
#     "Rate Limit",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "description": fields.String(),
#         "global": fields.Boolean(required=True),
#         "active": fields.Boolean(required=True),
#         "timeframe": fields.Integer(required=True),
#         "thresholds": fields.List(fields.Nested(m_threshold)),
#         "include": fields.Raw(required=True),
#         "exclude": fields.Raw(required=True),
#         "key": AnyType(required=True),
#         "pairwith": fields.Raw(required=True),
#         "tags": fields.List(fields.String()),
#     },
# )

# securitypolicy
class SecProfileMap(BaseModel):
    id: str
    name: str
    description: str
    match: str
    acl_profile: str
    acl_active: bool
    content_filter_profile: str
    content_filter_active: bool
    limit_ids: Optional[list]


# m_secprofilemap = api.model(
#     "Security Profile Map",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "description": fields.String(),
#         "match": fields.String(required=True),
#         "acl_profile": fields.String(required=True),
#         "acl_active": fields.Boolean(required=True),
#         "content_filter_profile": fields.String(required=True),
#         "content_filter_active": fields.Boolean(required=True),
#         "limit_ids": fields.List(fields.Raw()),
#     },
# )

# TODO  = deprecated?
# m_map = api.model(
#     "Security Profile Map", {"*": fields.Wildcard(fields.Nested(m_secprofilemap))}
# )

class SecurityPolicy(BaseModel):
    id: str
    name: str
    description: str
    tags: List[str]
    match: str
    session: anyTypeUnion
    session_ids: anyTypeUnion
    map: List[SecProfileMap]


# m_securitypolicy = api.model(
#     "Security Policy",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "description": fields.String(),
#         "tags": fields.List(fields.String()),
#         "match": fields.String(required=True),
#         "session": AnyType(),
#         "session_ids": AnyType(),
#         "map": fields.List(fields.Nested(m_secprofilemap)),
#     },
# )

# content filter rule

class ContentFilterRule(BaseModel):
    id: str
    name: str
    msg: str
    operand: str
    severity: int
    certainity: int
    category: str
    subcategory: str
    risk: int
    tags: Optional[List[str]]
    description: Optional[str]


# m_contentfilterrule = api.model(
#     "Content Filter Rule",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "msg": fields.String(required=True),
#         "operand": fields.String(required=True),
#         "severity": fields.Integer(required=True),
#         "certainity": fields.Integer(required=True),
#         "category": fields.String(required=True),
#         "subcategory": fields.String(required=True),
#         "risk": fields.Integer(required=True),
#         "tags": fields.List(fields.String()),
#         "description": fields.String(),
#     },
# )

# content filter profile
class ContentFilterProfile(BaseModel):
    id: str
    name: str
    description: Optional[str]
    ignore_alphanum: bool
    args: typing.Any
    headers: typing.Any
    cookies: typing.Any
    path: typing.Any
    allsections: typing.Any
    decoding: typing.Any
    masking_seed: str
    content_type: Optional[List[str]]
    active: Optional[List[str]]
    report: Optional[List[str]]
    ignore: Optional[List[str]]
    tags: Optional[List[str]]
    action: Optional[str]
    ignore_body: bool


# m_contentfilterprofile = api.model(
#     "Content Filter Profile",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "description": fields.String(),
#         "ignore_alphanum": fields.Boolean(required=True),
#         "args": fields.Raw(required=True),
#         "headers": fields.Raw(required=True),
#         "cookies": fields.Raw(required=True),
#         "path": fields.Raw(required=True),
#         "allsections": fields.Raw(),
#         "decoding": fields.Raw(required=True),
#         "masking_seed": fields.String(required=True),
#         "content_type": fields.List(fields.String()),
#         "active": fields.List(fields.String()),
#         "report": fields.List(fields.String()),
#         "ignore": fields.List(fields.String()),
#         "tags": fields.List(fields.String()),
#         "action": fields.String(),
#         "ignore_body": fields.Boolean(required=True),
#     },
# )

# aclprofile
class ACLProfile(BaseModel):
    id: str
    name: str
    description: Optional[str]
    allow: Optional[List[str]]
    allow_bot: Optional[List[str]]
    deny_bot: Optional[List[str]]
    passthrough: Optional[List[str]]
    deny: Optional[List[str]]
    force_deny: Optional[List[str]]
    tags: Optional[List[str]]
    action: Optional[str]


# m_aclprofile = api.model(
#     "ACL Profile",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "description": fields.String(),
#         "allow": fields.List(fields.String()),
#         "allow_bot": fields.List(fields.String()),
#         "deny_bot": fields.List(fields.String()),
#         "passthrough": fields.List(fields.String()),
#         "deny": fields.List(fields.String()),
#         "force_deny": fields.List(fields.String()),
#         "tags": fields.List(fields.String()),
#         "action": fields.String(),
#     },
# )

# Global Filter
class GlobalFilter(BaseModel):
    id: str
    name: str
    source: str
    mdate: str
    description: str
    active: bool
    action: typing.Any
    tags: Optional[List[str]]
    rule: anyTypeUnion


# m_glbalfilter = api.model(
#     "Global Filter",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "source": fields.String(required=True),
#         "mdate": fields.String(required=True),
#         "description": fields.String(),
#         "active": fields.Boolean(required=True),
#         "action": fields.Raw(required=True),
#         "tags": fields.List(fields.String()),
#         "rule": AnyType(),
#     },
# )

# Flow Control

class FlowControl(BaseModel):
    id: str
    name: str
    timeframe: int
    key: List[typing.Any]
    sequence: List[typing.Any]
    tags: Optional[List[str]]
    include: Optional[List[str]]
    exclude: Optional[List[str]]
    description: Optional[str]
    active: bool


#
# m_flowcontrol = api.model(
#     "Flow Control",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "timeframe": fields.Integer(required=True),
#         "key": fields.List(fields.Raw(required=True)),
#         "sequence": fields.List(fields.Raw(required=True)),
#         "tags": fields.List(fields.String()),
#         "include": fields.List(fields.String()),
#         "exclude": fields.List(fields.String()),
#         "description": fields.String(),
#         "active": fields.Boolean(required=True),
#     },
# )

# Action

class Action(BaseModel):
    id: str
    name: str
    description: Optional[str]
    tags: List[str]
    params: typing.Any
    type: str


# m_action = api.model(
#     "Action",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "description": fields.String(),
#         "tags": fields.List(fields.String(required=True)),
#         "params": fields.Raw(),
#         "type": fields.String(required=True),
#     },
# )

# Virtual Tag
class VirtualTag(BaseModel):
    id: str
    name: str
    description: Optional[str]
    match: List[typing.Any]


#
# m_virtualtag = api.model(
#     "Virtual Tag",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "description": fields.String(),
#         "match": fields.List(fields.Raw(required=True)),
#     },
# )

# custom
class Custom(BaseModel):
    id: str
    name: str


# m_custom = api.model(
#     "Custom",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "*": fields.Wildcard(fields.Raw()),
#     },
# )

### mapping from doc name to model

models = {
    "ratelimits": Limit,
    "securitypolicies": SecurityPolicy,
    "contentfilterrules": ContentFilterRule,
    "contentfilterprofiles": ContentFilterProfile,
    "aclprofiles": ACLProfile,
    "globalfilters": GlobalFilter,
    "flowcontrol": FlowControl,
    "actions": Action,
    "virtualtags": Custom,
    "custom": Custom,
}


### Other models
class DocumentMask(BaseModel):
    id: str
    name: str
    description: str
    map: Optional[List[SecProfileMap]]
    include: Optional[List[typing.Any]]
    exclude: Optional[List[typing.Any]]
    tags: Optional[List[str]]
    active: Optional[List[typing.Any]]
    action: typing.Any
    sequence: Optional[List[typing.Any]]
    timeframe: Optional[int]
    thresholds: Optional[List[Threshold]]
    pairwith: typing.Any
    content_type: Optional[List[str]]
    params: typing.Any
    decoding: typing.Any
    category: Optional[str]
    subcategory: Optional[str]
    risk: Optional[int]
    allow: Optional[List[str]]
    allow_bot: Optional[List[str]]
    deny_bot: Optional[List[str]]
    passthrough: Optional[List[str]]
    deny: Optional[List[str]]
    force_deny: Optional[List[str]]
    match: Optional[str] = "j"
    _type: Optional[str] = Field(alias="type")
    _star: Optional[List[typing.Any]] = Field(alias="*")


# m_document_mask = api.model(
#     "Mask for document",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "description": fields.String(required=True),
#         "map": fields.List(fields.Nested(m_secprofilemap)),
#         "include": fields.Wildcard(fields.Raw()),
#         "exclude": fields.Wildcard(fields.Raw()),
#         "tags": fields.List(fields.String()),
#         "active": fields.Wildcard(fields.Raw()),
#         "action": fields.Raw(),
#         "sequence": fields.List(fields.Raw()),
#         "timeframe": fields.Integer(),
#         "thresholds": fields.List(fields.Nested(m_threshold)),
#         "pairwith": fields.Raw(),
#         "content_type": fields.List(fields.String()),
#         "params": fields.Raw(),
#         "decoding": fields.Raw(),
#         "category": fields.String(),
#         "subcategory": fields.String(),
#         "risk": fields.Integer(),
#         "allow": fields.List(fields.String()),
#         "allow_bot": fields.List(fields.String()),
#         "deny_bot": fields.List(fields.String()),
#         "passthrough": fields.List(fields.String()),
#         "deny": fields.List(fields.String()),
#         "force_deny": fields.List(fields.String()),
#         "match": fields.String(),
#         "type": fields.String(),
#         "*": fields.Wildcard(fields.Raw()),
#     },
# )

class VersionLog(BaseModel):
    version: Optional[str]
    # TODO - dt_format="iso8601"
    date: Optional[datetime.datetime]
    _star: Optional[List[typing.Any]] = Field(alias="*")


#
# m_version_log = api.model(
#     "Version log",
#     {
#         "version": fields.String(),
#         "date": fields.DateTime(dt_format="iso8601"),
#         "*": fields.Wildcard(fields.Raw()),
#     },
# )

class Meta(BaseModel):
    id: str
    description: str
    date: Optional[datetime.datetime]
    logs: Optional[List[VersionLog]] = []
    version: Optional[str]


# m_meta = api.model(
#     "Meta",
#     {
#         "id": fields.String(required=True),
#         "description": fields.String(required=True),
#         "date": fields.DateTime(),
#         "logs": fields.List(fields.Nested(m_version_log), default=[]),
#         "version": fields.String(),
#     },
# )

class BlobEntry(BaseModel):
    format: str
    blob: anyTypeUnion


# m_blob_entry = api.model(
#     "Blob Entry",
#     {
#         "format": fields.String(required=True),
#         "blob": AnyType(),
#     },
# )

class BlobListEntry(BaseModel):
    name: Optional[str]


# m_blob_list_entry = api.model(
#     "Blob ListEntry",
#     {
#         "name": fields.String(),
#     },
# )

class DocumentListEntry(BaseModel):
    name: Optional[str]
    entries: Optional[int]


# m_document_list_entry = api.model(
#     "Document ListEntry",
#     {
#         "name": fields.String(),
#         "entries": fields.Integer(),
#     },
# )

class ConfigDocuments(BaseModel):
    ratelimits: Optional[List[models["ratelimits"]]] = []
    securitypolicies: Optional[List[models["securitypolicies"]]] = []
    contentfilterrules: Optional[List[models["contentfilterrules"]]] = []
    contentfilterprofiles: Optional[List[models["contentfilterprofiles"]]] = []
    aclprofiles: Optional[List[models["aclprofiles"]]] = []
    globalfilters: Optional[List[models["globalfilters"]]] = []
    flowcontrol: Optional[List[models["flowcontrol"]]] = []
    actions: Optional[List[models["actions"]]] = []
    virtualtags: Optional[List[models["virtualtags"]]] = []
    custom: Optional[List[models["custom"]]] = []


# m_config_documents = api.model(
#     "Config Documents",
#     {x: fields.List(fields.Nested(models[x], default=[])) for x in models},
# )


class ConfigBlobs(BaseModel):
    geolite2asn: Optional[List[Optional[BlobEntry]]]
    geolite2country: Optional[List[Optional[BlobEntry]]]
    geolite2city: Optional[List[Optional[BlobEntry]]]
    customconf: Optional[List[Optional[BlobEntry]]]


# m_config_blobs = api.model(
#     "Config Blobs",
#     {x: fields.Nested(m_blob_entry, default={}) for x in utils.BLOBS_PATH},
# )

class ConfigDeleteBlobs(BaseModel):
    geolite2asn: Optional[bool]
    geolite2country: Optional[bool]
    geolite2city: Optional[bool]
    customconf: Optional[bool]


# m_config_delete_blobs = api.model(
#     "Config Delete Blobs", {x: fields.Boolean() for x in utils.BLOBS_PATH}
# )

class Config(BaseModel):
    meta: Meta = {}
    documents: ConfigDocuments = {}
    blobs: ConfigBlobs = {}
    delete_documents: ConfigDocuments = {}
    delete_blobs: ConfigDeleteBlobs = {}


# m_config = api.model(
#     "Config",
#     {
#         "meta": fields.Nested(m_meta, default={}),
#         "documents": fields.Nested(m_config_documents, default={}),
#         "blobs": fields.Nested(m_config_blobs, default={}),
#         "delete_documents": fields.Nested(m_config_documents, default={}),
#         "delete_blobs": fields.Nested(m_config_delete_blobs, default={}),
#     },
# )

class Edit(BaseModel):
    path: str
    value: str


# m_edit = api.model(
#     "Edit",
#     {
#         "path": fields.String(required=True),
#         "value": fields.String(required=True),
#     },
# )

class BasicEntry(BaseModel):
    id: str
    name: str
    description: Optional[str]


# m_basic_entry = api.model(
#     "Basic Document Entry",
#     {
#         "id": fields.String(required=True),
#         "name": fields.String(required=True),
#         "description": fields.String(),
#     },
# )

### Publish

class Bucket(BaseModel):
    name: str
    url: str


# m_bucket = api.model(
#     "Bucket",
#     {
#         "name": fields.String(required=True),
#         "url": fields.String(required=True),
#     },
# )

### Git push & pull

class GitUrl(BaseModel):
    giturl: str


# m_giturl = api.model(
#     "GitUrl",
#     {
#         "giturl": fields.String(required=True),
#     },
# )

### Db
class DB(BaseModel):
    pass


# m_db = api.model("db", {})


### Document Schema validation


def validateJson(json_data, schema_type):
    try:
        validate(instance=json_data, schema=schema_type_map[schema_type])
    except jsonschema.exceptions.ValidationError as err:
        print(str(err))
        return False, str(err)
    return True, ""


### DB Schema validation


def validateDbJson(json_data, schema):
    try:
        validate(instance=json_data, schema=schema)
    except jsonschema.exceptions.ValidationError as err:
        print(str(err))
        return False
    return True


### Set git actor according to config & defined HTTP headers


def get_gitactor(request):
    email, username = "", ""
    email_header = app.options.get("trusted_email_header", None)
    if email_header:
        email = request.headers.get(email_header, "")
    username_header = app.options.get("trusted_username_header", None)
    if username_header:
        username = request.headers.get(username_header, "")
    return app.backend.prepare_actor(username, email)


base_path = Path(__file__).parent
# base_path = "/etc/curiefense/json/"
acl_profile_file_path = (base_path / "./json/acl-profile.schema").resolve()
with open(acl_profile_file_path) as json_file:
    acl_profile_schema = json.load(json_file)
ratelimits_file_path = (base_path / "./json/rate-limits.schema").resolve()
with open(ratelimits_file_path) as json_file:
    ratelimits_schema = json.load(json_file)
securitypolicies_file_path = (base_path / "./json/security-policies.schema").resolve()
with open(securitypolicies_file_path) as json_file:
    securitypolicies_schema = json.load(json_file)
content_filter_profile_file_path = (
        base_path / "./json/content-filter-profile.schema"
).resolve()
with open(content_filter_profile_file_path) as json_file:
    content_filter_profile_schema = json.load(json_file)
globalfilters_file_path = (base_path / "./json/global-filters.schema").resolve()
with open(globalfilters_file_path) as json_file:
    globalfilters_schema = json.load(json_file)
flowcontrol_file_path = (base_path / "./json/flow-control.schema").resolve()
with open(flowcontrol_file_path) as json_file:
    flowcontrol_schema = json.load(json_file)
content_filter_rule_file_path = (
        base_path / "./json/content-filter-rule.schema"
).resolve()
with open(content_filter_rule_file_path) as json_file:
    content_filter_rule_schema = json.load(json_file)
action_file_path = (base_path / "./json/action.schema").resolve()
with open(action_file_path) as json_file:
    action_schema = json.load(json_file)
virtualtag_file_path = (base_path / "./json/virtual-tags.schema").resolve()
with open(virtualtag_file_path) as json_file:
    virtual_tags_schema = json.load(json_file)
custom_file_path = (base_path / "./json/custom.schema").resolve()
with open(custom_file_path) as json_file:
    custom_schema = json.load(json_file)
schema_type_map = {
    "ratelimits": ratelimits_schema,
    "securitypolicies": securitypolicies_schema,
    "contentfilterprofiles": content_filter_profile_schema,
    "aclprofiles": acl_profile_schema,
    "globalfilters": globalfilters_schema,
    "flowcontrol": flowcontrol_schema,
    "contentfilterrules": content_filter_rule_schema,
    "actions": action_schema,
    "virtualtags": virtual_tags_schema,
    "custom": custom_schema,
}





if __name__ == '__main__':
    print("hi")
