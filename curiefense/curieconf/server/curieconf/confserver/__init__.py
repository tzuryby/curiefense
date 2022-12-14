#! /usr/bin/env python3

import os
import flask
from flask import Flask, current_app
from .backend import Backends

from flask_cors import CORS
from prometheus_flask_exporter import PrometheusMetrics


## Import all versions
from .v3 import api as api_v3

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*"}})

app.register_blueprint(api_v3.api_bp, url_prefix=os.environ.get("SWAGGER_BASE_PATH", "/api/v3"))


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

    if options.pdb:
        flask.got_request_exception.connect(drop_into_pdb)

    metrics = PrometheusMetrics(app)

    try:
        with app.app_context():
            current_app.backend = Backends.get_backend(app, options.dbpath)
            current_app.options = options.__dict__
            app.run(debug=options.debug, host=options.host, port=options.port)
    finally:
        pass


if __name__ == "__main__":
    main()
