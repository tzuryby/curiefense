#! /usr/bin/env python3

import os
from .backend import Backends
import uvicorn
from curieconf.confserver.v3 import api
from prometheus_flask_exporter import PrometheusMetrics

from fastapi import FastAPI

app = FastAPI()
app.include_router(api.router)


def drop_into_pdb(app, exception):
    import sys
    import pdb
    import traceback

    traceback.print_exc()
    pdb.post_mortem(sys.exc_info()[2])


def main(args=None):
    # only called when running manually, not through uwsgi
    global mongo
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--dbpath", "--db", help="API server db path", required=True)
    parser.add_argument("-d", "--debug", action="store_true", default=False)
    parser.add_argument("--pdb", action="store_true", default=False)
    parser.add_argument(
        "-H", "--host", default=os.environ.get("CURIECONF_HOST", "127.0.0.1")
    )
    parser.add_argument(
        "-p", "--port", type=int, default=int(os.environ.get("CURIECONF_PORT", "5000"))
    )
    parser.add_argument(
        "--trusted-username-header",
        type=str,
        default=os.environ.get("CURIECONF_TRUSTED_USERNAME_HEADER", ""),
    )
    parser.add_argument(
        "--trusted-email-header",
        type=str,
        default=os.environ.get("CURIECONF_TRUSTED_EMAIL_HEADER", ""),
    )

    options = parser.parse_args(args)

    #TODO - find replacements for got_request_exception and prometheus_flask_exporter
    # if options.pdb:
    #     flask.got_request_exception.connect(drop_into_pdb)
    # metrics = PrometheusMetrics(app)

    try:
        app.backend = Backends.get_backend(app, options.dbpath)
        app.options = options.__dict__
        uvicorn.run(app, host=options.host, port=options.port)

    #        app.run(debug=options.debug, host=options.host, port=options.port)
    finally:
        pass
