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

  Some frameworks, notably Werkzeug, deduce the current hostname from
  the `Host` or `X-Forwarded-Host` headers (with the latter taking
  precedence). If you are not checking the `Host` header / doing virtual
  hosting *and* wiping the `X-Forwarded-Host` header in your web server,
  you need to check the host against a whitelist in your application.

  This may be used to whitelist domains in Flask::

      class R(flask.Request):
          trusted_hosts = {'www.danielrichman.co.uk'}
      app.request_class = R

  You may forgo checking `url` *if* you instead use a token in `params`
  as described below.

* check `issue` is within an acceptable range of *now*

  ... lest someone replay an old response to log in again

* check `auth` and `sso` match `iact` and `aauth`

  see :meth:`ucam_webauth.Response.check_iact_aauth`

  Not checking `iact`/`aauth` will allow those restrictions to be bypassed
  by crafting a custom request to the WLS.

Using params as a token
-----------------------

If checking `url` (above) is a pain, you could:

* generate a random string just before you redirect to Raven
* set a cookie on the client with that string
* include that string as `params` in the :class:`ucam_webauth.Request`
* check that they match in the :class:`ucam_webauth.Response`

The principle is similar to that of an CSRF token for submitting forms.

This is what :class:`ucam_webauth.flask_glue.AuthDecorator` does.

Signing keys
------------

The keys used by Raven to sign responses are included with `python-raven`.
I took care in retrieving them, however you should trust neither me nor the
method by which you installed this package.
**You should check that the copies of the certificates you have are
correct / match the files at the links below**.

* ``pubkey2`` from `<https://raven.cam.ac.uk/project/keys/>`_
* ``pubkey901`` from `<https://raven.cam.ac.uk/project/keys/demo_server/>`_

