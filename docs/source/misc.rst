Misc
====

.. _cancel_url:

Response URL for "cancels"
--------------------------

The short story is that when the WLS wants to send a "response" to the WAA, it
takes the URL you provided in the request, adds a `WLS-Response` query
parameter, and redirects the client to that URL.

Happily, it guarantees that this will be done by appending
`(?|&)WLS-Response=...` to the URL (which means that this process is easy to
undo, which is a necessary part of :ref:`checking-response-values`).

However: while in version 3 it preserves any query parameters that were already
in the request URL, in version 1 of the protocol it will not: that is, it
deletes the query component before appending `?WLS-Response...`. Furthermore,
while the current version of the WLS appears to reply with version 3 upon
success, if you click "cancel" then it will use version 1, presumably because
of reasons.

The WLS does include in its response a copy of some of the request parameters,
in particular, the return URL. It is possible to extract this from the
response, and after inspecting WLS-Response, perform a redirect to it,
recovering the deleted query parameters. The `flask_glue` does exactly this,
and so hopefully you should not suffer problems on account of this behaviour.

Note that if you for some reason had the requirement that requests to a certain
page need only be Raven authenticated if a certain query parameter is present,
then something like this would not work correctly::

    def my_before_request():
        if "special" in request.args:
            return flask_glue.before_request()
        else:
            return None

... since if a user clicks Cancel, the special query parameter would not be
set, so the `before_request` function would run, and the response from the WLS
would not be handled. Instead, something like this would be necessary::

    def my_before_request():
        if "special" in request.args or "WLS-Response" in request.args:
            return flask_glue.before_request()
        else:
            return None

If you are not using the `flask_glue`, I suggest where possible just avoiding
having significant query parameters on the URL that you use to perform Raven
authentication, and then simply check that `request.base_url` matches the URL
in the signed response. Otherwise, have a look at the implementation of
`flask_glue` for inspiration.
