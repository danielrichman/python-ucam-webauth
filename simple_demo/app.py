from __future__ import unicode_literals, print_function

import os
import inspect
import logging
from datetime import datetime

import ucam_webauth
import raven
import raven.demoserver
import raven.flask_glue

import flask
from flask import Flask, request, render_template, redirect, \
                  url_for, abort, session, flash

class Request(flask.Request):
    trusted_hosts = {'localhost', '127.0.0.1'}

app = Flask(__name__)

app.request_class = Request
app.config["SECRET_KEY"] = os.urandom(16)

app.add_template_global(repr, name="repr")
app.add_template_global(getattr, name="getattr")

modules = {"ucam_webauth": ucam_webauth,
           "raven": raven, "raven.demoserver": raven.demoserver}

auth_decorator = raven.flask_glue.AuthDecorator()

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/decorated")
@auth_decorator
def decorated():
    return render_template("decorated.html", a=auth_decorator)

app.add_url_rule('/decorated/logout', 'decorated_logout',
                 auth_decorator.logout)

@app.route("/request/new")
def request_form():
    return render_template("form.html")

@app.route("/request/build", methods=["POST"])
def request_build():
    module = request.form["module"]
    cls = modules[module].Request

    args = {}
    for key in ("desc", "msg", "params"):
        if request.form[key]:
            args[key] = request.form[key]
    if request.form["aauth"] == "pwd":
        args["aauth"] = set([ucam_webauth.ATYPE_PWD])
    if request.form["iact"] == "yes":
        args["iact"] = True
    elif request.form["iact"] == "no":
        args["iact"] = False
    if request.form.get("fail", None) == "yes":
        args["fail"] = True

    args["url"] = url_for('response', module=module, _external=True)
    req = cls(**args)

    args_order = ['url', 'desc', 'aauth', 'iact', 'msg', 'params',
                  'fail', 'encode_strings']
    args_str = ", ".join("{0}={1!r}".format(key, args[key])
                         for key in args_order if key in args)

    if request.form.get("redirect", None):
        if module == "ucam_webauth":
            abort(400)
        return redirect(str(req))
    else:
        return render_template("built.html",
                args=args, args_str=args_str, module=module, request=req)

@app.route("/response/<module>")
def response(module):
    cls = modules[module].Response
    string = request.args["WLS-Response"]
    response = cls(string)
    fields = ['ver', 'status', 'msg', 'issue', 'id', 'url',
              'principal', 'ptags', 'auth', 'sso', 'life', 'params',
              'kid', 'signed']
    # so that print_thing may iterate over it
    thing = dict( (k, getattr(response, k)) for k in fields )
    return render_template("response.html",
                           module=module, string=string, response=thing)

@app.route("/integration")
def integration_home():
    session_ = session.copy()
    if "_ucam_webauth" in session_:
        del session_["_ucam_webauth"]
    if "_flashes" in session_:
        del session_["_flashes"]
    return render_template("integration.html", session=session_)

@app.route("/integration/login_username", methods=["POST"])
def integration_login_username():
    session["user"] = request.form["username"]
    session["auth"] = "some other method"
    flash("Successfully logged in as {0}".format(session["user"]))
    return redirect(url_for("integration_home"))

@app.route("/integration/login_raven")
def integration_login_raven():
    u = url_for("integration_login_raven_response", _external=True)
    r = raven.Request(url=u, desc="python-raven simple_demo")
    return redirect(str(r))

@app.route("/integration/login_raven/response")
def integration_login_raven_response():
    r = raven.Response(request.args["WLS-Response"])
    if r.url != request.base_url:
        print("Bad url")
        abort(400)

    issue_delta = (datetime.utcnow() - r.issue).total_seconds()
    if not -5 < issue_delta < 15:
        print("Bad issue")
        abort(403)

    if r.success:
        # a no-op here, but important if you set iact or aauth
        if not r.check_iact_aauth(None, None):
            print("check_iact_aauth failed")
            abort(403)

        session["user"] = r.principal
        session["auth"] = "raven"
        flash("Successfully logged in as {0}".format(r.principal))
        return redirect(url_for("integration_home"))
    else:
        flash("Raven authentication failed")
        return redirect(url_for("integration_home"))

@app.route("/integration/logout")
def integration_logout():
    del session["user"]
    del session["auth"]
    if request.args.get("also_raven", False):
        return redirect(raven.RAVEN_LOGOUT)
    else:
        return redirect(url_for("integration_home"))

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    app.config['TRAP_BAD_REQUEST_ERRORS'] = True
    app.run(debug=True)
