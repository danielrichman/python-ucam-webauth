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
  impersonating someone else

* check `issue` is within an acceptable range of *now*

  ... lest someone replay an old response to log in again

* check `auth` and `sso` match `iact` and `aauth`

  see :meth:`ucam_webauth.Response.check_iact_aauth`

  Not checking `iact`/`aauth` will allow those restrictions to be bypassed
  by crafting a custom request to the WLS.

Signing keys
------------

The keys used by Raven to sign responses are included with `python-raven`.
I took care in retrieving them, however you should trust me neither the method
by which you installed this package. **You should check that the copies of the
certificates you have are correct / match the files at the links below**.

* ``pubkey2.crt`` from `<https://raven.cam.ac.uk/project/keys/>`_
* ``pubkey901.crt`` from
  `<https://raven.cam.ac.uk/project/keys/demo_server/>`_

