#!/usr/bin/env python3

# Python requirements: pytest requests requests_toolbelt
# install curieconfctl:
# (cd ../curiefense/curieconf/utils ; pip3 install .)
# (cd ../curiefense/curieconf/client ; pip3 install .)
#
# To run this with minikube (does not support IPv6):
#
# pytest --base-protected-url http://$(minikube ip):30081 --base-conf-url http://$(minikube ip):30000/api/v3/ --base-ui-url http://$(minikube ip):30080 --elasticsearch-url http://$IP:30200 .      # pylint: disable=line-too-long
#
# To run this with docker-compose:
# pytest --base-protected-url http://localhost:30081/ --base-conf-url http://localhost:30000/api/v3/ --base-ui-url http://localhost:30080 --elasticsearch-url http://localhost:9200 .      # pylint: disable=line-too-long

from typing import Any, Dict, Iterator
import argparse
import json
import logging
import os
import re
import subprocess
import time
import requests
import sys

# --- Helpers ---
TEST_CONFIG_NAME = "master"


class CliHelper:
    def __init__(self, base_url: str):
        self._base_url = base_url
        self._initial_version_cache = None

    def call(self, args: str, inputjson: Any = None) -> Any:
        logging.info("Calling CLI with arguments: %s", args)
        cmd = ["curieconfctl", "-u", self._base_url, "-o", "json"]
        cmd += args.split(" ")
        indata = None
        if inputjson:
            indata = json.dumps(inputjson).encode("utf-8")

        try:
            process = subprocess.run(
                cmd,
                shell=False,
                input=indata,
                check=True,
                capture_output=True,
            )
            if process.stdout:
                logging.debug("CLI output: %s", process.stdout)

                try:
                    return json.loads(process.stdout.decode("utf-8"))
                except json.JSONDecodeError:
                    return process.stdout.decode("utf-8")
            else:
                return []
        except subprocess.CalledProcessError as e:
            print("stdout:" + e.stdout.decode("utf-8", errors="ignore"))
            print("stderr:" + e.stderr.decode("utf-8", errors="ignore"))
            raise e

    def delete_test_config(self):
        self.call("conf delete test")

    def initial_version(self):
        if not self._initial_version_cache:
            versions = self.call("conf list-versions master")
            if "version" not in versions[-3]:
                print("Unsupported curieconfctl output", versions)
                raise TypeError("Unsupported curieconfctl output")
            self._initial_version_cache = versions[-3]["version"]
        return self._initial_version_cache

    def empty_acl(self):
        version = self.initial_version()
        return self.call(f"doc get master aclprofiles --version {version}")

    def publish_and_apply(self):
        buckets = self.call("key get system publishinfo")

        url = "????"
        for bucket in buckets["buckets"]:
            if bucket["name"] == "prod":
                url = bucket["url"]
        self.call(f"tool publish master {url}")
        time.sleep(20)

    def set_configuration(self, luatests_path: str):
        # acl-profiles.json  actions.json  contentfilter-profiles.json  contentfilter-rules.json  flow-control.json  globalfilter-lists.json  limits.json  securitypolicy.json
        for (cmdname, path) in [
            ("actions", "actions.json"),
            ("aclprofiles", "acl-profiles.json"),
            ("contentfilterprofiles", "contentfilter-profiles.json"),
            ("contentfilterrules", "contentfilter-rules.json"),
            ("flowcontrol", "flow-control.json"),
            ("globalfilters", "globalfilter-lists.json"),
            ("ratelimits", "limits.json"),
            ("securitypolicies", "securitypolicy.json"),
        ]:
            cfgpath = os.path.join(luatests_path, "config", "json", path)
            ret = self.call(f"doc delete {TEST_CONFIG_NAME} {cmdname}")
            assert ret == {"ok": True}
            ret = self.call(f"doc create {TEST_CONFIG_NAME} {cmdname} {cfgpath}")
            assert ret == {"ok": True}
        self.publish_and_apply()


parser = argparse.ArgumentParser(description="Curiefense E2E tests")
parser.add_argument("--base-protected-url", nargs="+", required=True)
parser.add_argument("--base-conf-url", required=True)
parser.add_argument("--base-ui-url", required=True)
parser.add_argument("--elasticsearch-url", required=True)
parser.add_argument("--luatests-path", required=True)
parser.add_argument("--log-level", required=False)
parser.add_argument(
    "--ignore-config",
    action="store_true",
    help="Ignore configuration phase, run the tests on the current configuration",
)
parser.add_argument("match", help="regex for filtering the test name", nargs="*")
args = parser.parse_args()

logging.basicConfig(level=logging.INFO)
if args.log_level == "DEBUG":
    logging.basicConfig(level=logging.DEBUG)
if args.log_level == "WARN":
    logging.basicConfig(level=logging.WARN)
if args.log_level == "ERROR":
    logging.basicConfig(level=logging.ERROR)

if not args.ignore_config:
    cli = CliHelper(args.base_conf_url)
    cli.set_configuration(args.luatests_path)


def testcase_load(path: str) -> Iterator[Any]:
    for file in os.listdir(os.path.join(args.luatests_path, path)):
        if not file.endswith(".json"):
            continue
        with open(os.path.join(args.luatests_path, path, file)) as f:
            yield (file, json.load(f))


def run_request(base_url: str, req: Any) -> requests.Response:
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = {}

    for (k, v) in req["headers"].items():
        if k.startswith(":"):
            if k == ":method":
                method = v
            elif k == ":authority":
                headers["Host"] = v
            elif k == ":path":
                path = v
        else:
            headers[k] = v
    return requests.request(
        method=method,
        headers=headers,
        data=req["body"] if "body" in req else None,
        url=base_url + path,
    )


def skipped(identifier: str) -> bool:
    if args.match:
        return not any([re.search(mtch, identifier) for mtch in args.match])
    else:
        return False


max_time_limit = 0
with open(
    os.path.join(args.luatests_path, "config", "json", "limits.json"), "r"
) as lfile:
    for limit in json.load(lfile):
        for t in limit["thresholds"]:
            max_time_limit = max(max_time_limit, t["limit"])
with open(
    os.path.join(args.luatests_path, "config", "json", "flow-control.json"), "r"
) as lfile:
    for flow in json.load(lfile):
        max_time_limit = max(max_time_limit, flow["timeframe"])
logging.debug("Maximum time limit: %d", max_time_limit)

good = True
for base_url in args.base_protected_url:
    logging.info("URL: %s", base_url)
    for (fname, elements) in testcase_load("raw_requests"):
        logging.info("%s ->", fname)
        for req in elements:
            if skipped(req["name"]):
                continue
            logging.info("  %s", req["name"])
            if "human" in req and req["human"]:
                logging.debug(
                    "Ignoring test raw_requests/%s/%s because of humanity test"
                    % (fname, req["name"])
                )
            res = run_request(base_url, req)
            response = req["response"]
            if "block_mode" in response and response["block_mode"]:
                expected = (
                    response["real_status"]
                    if "real_status" in response
                    else response["status"]
                )
            else:
                expected = 200
            if expected != res.status_code:
                logging.error(
                    "raw_requests/%s/%s failed %d != %d",
                    fname,
                    req["name"],
                    expected,
                    res.status_code,
                )
                good = False

    for (fname, elements) in testcase_load("ratelimit"):
        if skipped(fname):
            continue
        logging.info("%s ->", fname)
        for (step, req) in enumerate(elements):
            logging.info("  step %d", step)
            res = run_request(base_url, req)
            if req["pass"]:
                if res.status_code != 200:
                    logging.error(
                        "limits/%s/%d failed, did not pass, status=%d",
                        fname,
                        step,
                        res.status_code,
                    )
                    good = False
            else:
                if res.status_code == 200:
                    logging.error("limits/%s/%d failed, did pass, got 200", fname, step)
                    good = False
            if "delay" in req:
                time.sleep(req["delay"])
        time.sleep(max_time_limit)

    for (fname, elements) in testcase_load("flows"):
        if skipped(fname):
            continue
        logging.info("%s ->", fname)
        for (step, req) in enumerate(elements):
            logging.info("  step %d", step)
            res = run_request(base_url, req)
            if req["pass"]:
                if res.status_code != 200:
                    logging.error(
                        "limits/%s/%d failed, did not pass, status=%d",
                        fname,
                        step,
                        res.status_code,
                    )
                    good = False
            else:
                if res.status_code == 200:
                    logging.error("limits/%s/%d failed, did pass, got 200", fname, step)
                    good = False
            if "delay" in req:
                time.sleep(req["delay"])
        time.sleep(max_time_limit)

if not good:
    sys.exit(1)
