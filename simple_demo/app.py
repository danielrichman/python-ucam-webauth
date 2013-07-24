import os
import inspect

import ucam_webauth
import raven
import raven.demoserver
import raven.flask_glue

from flask import Flask, request, render_template, redirect, url_for, abort
app = Flask(__name__)

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
    return "principal: {a.principal}, ptags: {a.ptags}, " \
            "issue: {a.issue}, life: {a.life}" \
                .format(a=auth_decorator)

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
    return render_template("response.html", 
            module=module, string=string, fields=fields, response=response)

if __name__ == "__main__":
    app.config['TRAP_BAD_REQUEST_ERRORS'] = True
    app.run(debug=True)
