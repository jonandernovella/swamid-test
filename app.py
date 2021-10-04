from swamid import get_swamid_client
from flask import Flask
from flask import redirect
from flask import request
from saml2 import (
    entity,
)

import logging
import os
import uuid

app = Flask(__name__)
app.secret_key = str(uuid.uuid4())
logging.basicConfig(level=logging.INFO)

global METADATA


@app.route("/")
def main_page():
    return "<a href=/login/federated> SWAMID</a>"


@app.route("/swamid", methods=["POST"])
def parse_swamid_response():
    try:
        swamid_client = get_swamid_client()
        authn_response = swamid_client.parse_authn_request_response(
            request.form["SAMLResponse"], entity.BINDING_HTTP_POST
        )
        authn_response.get_identity()
        user_info = authn_response.get_subject()
        username = user_info.text
    except Exception as ex:
        logging.error(ex)
        return b"<h3> Login response parsing failed </h3>", 401
    return f"<h2> Welcome {username}! </h2>", 200


@app.route("/login/federated")
def init_swamid_login():
    try:
        swamid_client = get_swamid_client()
        logging.info("The authentication STOPS here for now, the next line fails!")
        reqid, info = swamid_client.prepare_for_authenticate()

        redirect_url = None
        for key, value in info["headers"].items():
            if key == "Location":
                redirect_url = value
        assert redirect_url is not None
        logging.info("Redirect URL is %s" % redirect_url)

        response = redirect(redirect_url, code=302)
        response.headers["Cache-Control"] = "no-cache, no-store"
        response.headers["Pragma"] = "no-cache"
    except Exception as ex:
        logging.error(ex)
        return b"<h3> Login init failed </h3>", 401
    return response


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    if port == 5000:
        app.debug = True
    app.run(host="0.0.0.0", port=port)
