Security
========

.. _checking-response-values:

Checking response values
------------------------

You *must* check the `url`, `issue`, `auth` and `sso` attributes of the
response:

* check that `url` matches the current URL being requested / is what you
  expect.

  Not checking `url` will allow another evil website administrator to replay
  responses produced by Raven log-ins to her website to yours, thereby
  impersonating someone else.
  (Using params as a token (below) doesn't help, since the attacker can
  obtain a matching `(cookie, params)` pair from you first, and then ask
  the victim to authenticate with `params` set to that value.)

  Some frameworks, notably Werkzeug, deduce the current hostname from
  the `Host` or `X-Forwarded-Host` headers (with the latter taking
  precedence).
  
  .. seealso::
        `werkzeug#609 <https://github.com/mitsuhiko/werkzeug/issues/609>`_ and
        `issue 5 <https://github.com/danielrichman/python-raven/issues/5>`_

  This technique may be used to whitelist domains in Flask::

      class R(flask.Request):
          trusted_hosts = {'www.danielrichman.co.uk'}
      app.request_class = R

  Alternatively, you could sanitise `Host` and `X-Forwarded-Host` in your
  web-server.

* check `issue` is within an acceptable range of *now*

  ... lest someone replay an old response to log in again

* check `auth` and `sso` match `iact` and `aauth`

  see :meth:`ucam_webauth.Response.check_iact_aauth`

  Not checking `iact`/`aauth` will allow those restrictions to be bypassed
  by crafting a custom request to the WLS.

Using params as a token
-----------------------

You might like to set a random nonce in the Request's `params`, save
a hashed (with secret salt) or signed copy in a cookie, and check that they
match in the `Response`.

This is *not* a substitute for any of the checks above, but does make the
`WLS-Response` values in your web server access logs useless.

:class:`ucam_webauth.flask_glue.AuthDecorator` does this.

Signing keys
------------

The keys used by Raven to sign responses are included with `python-raven`.
I took care in retrieving them, however you should trust neither me nor the
method by which you installed this package.
*You should check that the copies of the certificates you have are
correct / match the files at the links below* (and audit the code you've
just installed, I guess).

* ``pubkey2`` from `<https://raven.cam.ac.uk/project/keys/>`_
* ``pubkey901`` from `<https://raven.cam.ac.uk/project/keys/demo_server/>`_

