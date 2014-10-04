Quickstart
==========

Using the flask decorator
-------------------------

::

    import flask
    from flask import Flask
    from raven.flask_glue import AuthDecorator

    # Werkzeug deduces the hostname from the 'Host' or
    # 'X-Forwarded-Host' headers, so we need a whitelist
    class R(flask.Request):
        trusted_hosts = {'your-domain.com', 'www.your-domain.com'}

    app = Flask(__name__)
    app.request_class = R
    app.secret_key = "a secret key"
    auth_decorator = AuthDecorator(desc="My website")

    @app.route("/some_url")
    @auth_decorator
    def my_view():
        return "You are " + auth_decorator.principal

    if __name__ == '__main__':
        app.run()

Requiring all flask requests be authenticated
---------------------------------------------

::

    import flask
    from flask import Flask
    from raven.flask_glue import AuthDecorator

    # Werkzeug deduces the hostname from the 'Host' or
    # 'X-Forwarded-Host' headers, so we need a whitelist
    class R(flask.Request):
        trusted_hosts = {'your-domain.com', 'www.your-domain.com'}

    app = Flask(__name__)
    app.request_class = R
    app.secret_key = "a secret key"
    auth_decorator = AuthDecorator()

    app.before_request(auth_decorator.before_request)

    @app.route("/")
    def home():
        return "You are " + auth_decorator.principal

    if __name__ == '__main__':
        app.run()

Manual request building and response parsing
--------------------------------------------

To create requests::

    >>> from raven import Request, Response
    >>> r = Request(url="http://host/response/path", desc="My website")
    >>> print str(r)
    https://raven.cam.ac.uk/auth/authenticate.html?url=http%3A%2F%2Fhost%2Fresponse%2Fpath&ver=3&desc=My+website

And parse responses::

    >>> r = Response("3!200!!20130705T150000Z!1373000000-00000-00!"
                     "http%3A%2F%2Fhost%2Fpath!djr61!current!pwd!!"
                     "36000!!2!signature-omitted")
    >>> r.success
    True
    >>> r.principal
    "djr61"
    >>> r.ptags
    set(["current"])

Warning
"""""""

You must check various properties of received responses.
See :ref:`checking-response-values`

Integrating with existing authentication or session management
--------------------------------------------------------------

.. code-block:: python

    import raven
    from datetime import datetime
    from flask import Flask, session, flash, url_for, redirect, abort, request

    app = Flask(__name__)
    app.secret_key = "a secret key"

    @app.route("/")
    def home():
        return "<a href='{0}'>Log in</a>".format(url_for('login'))

    @app.route("/login")
    def login():
        u = url_for("response", _external=True)
        r = raven.Request(url=u)
        return redirect(str(r))

    @app.route("/response")
    def response():
        r = raven.Response(request.args["WLS-Response"])

        # checking url, issue, iact and aauth is very important!
        # Werkzeug deduces the hostname from the 'Host' or
        # 'X-Forwarded-Host' headers, so we need a whitelist
        request.trusted_hosts = {'www.your-domain.com', 'your-domain.com'}
        if r.url != request.base_url:
            print "Bad url"
            abort(400)

        issue_delta = (datetime.utcnow() - r.issue).total_seconds()
        if not -5 < issue_delta < 15:
            print "Bad issue"
            abort(403)

        if r.success:
            # a no-op here, but important if you set iact or aauth
            if not r.check_iact_aauth(None, None):
                print "check_iact_aauth failed"
                abort(403)

            session["user"] = r.principal

            return redirect(url_for("secrets"))
        else:
            return redirect(url_for("home"))

    @app.route("/secrets")
    def secrets():
        if session.get("user", None) is None:
            abort(401)
        return "You are {0}".format(session["user"])

    if __name__ == "__main__":
        app.run(debug=True)

Warning
"""""""

You must check various properties of received responses.
See :ref:`checking-response-values`

See also
--------

The included `simple_demo flask app
<https://github.com/danielrichman/python-raven/tree/master/simple_demo>`_
serves as a far more comprehensive example, including:

* decorator usage
* integration with existing authentication (i.e., user is offered to
  log in via Raven or some other method)
* full Raven logout
* message flashing

