# python-raven - Ucam-webauth and Raven application agent in Python

## Python dependencies

 - M2Crypto (`apt-get install python-m2crypto`; far easier than via pip)
 - nose (for unit testing only)
 - flask (for `simple_demo/`)

## License

GNU LGPLv3, see COPYING

## Quickstart

### Flask decorator

TODO

### Manual request building and response parsing

```python
from raven import Request, Response

r = Request(url="http://host/response/path", desc="My website")
# str(r) == "https://raven.cam.ac.uk/auth/authenticate.html?" \
#           "url=http%3A%2F%2Fhost%2Fresponse%2Fpath&ver=3&desc=My+website"
redirect(str(r))

r = Response("3!200!!20130705T150000Z!1373000000-00000-00!"
             "http%3A%2F%2Fhost%2Fpath!djr61!current!pwd!!"
             "36000!!2!signature-ommitted")
# r.success == True
# r.principal == "djr61"
# r.ptags == set(["current"])
```

## Documentation

TODO; until then, see docstrings

## Misc

### Demo server

Use `raven.demoserver.Request` and `raven.demoserver.Response` to get the
demo server's URLs and pubilc key.

Configuring a custom WLS is described in the docs for ucam_webauth.

