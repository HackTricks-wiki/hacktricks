# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Basic Payloads

- **Simple List:** Just a list containing an entry in each line
- **Runtime File:** A list read in runtime (not loaded in memory). For supporting big lists.
- **Case Modification:** Apply some changes to a list of strings(No change, to lower, to UPPER, to Proper name - First capitalized and the rest to lower-, to Proper Name -First capitalized an the rest remains the same-.
- **Numbers:** Generate numbers from X to Y using Z step or randomly.
- **Brute Forcer:** Character set, min & max length.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload to execute commands and grab the output via DNS requests to burpcollab.


{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

---

## Burp Variables (BApp) — Project-scoped placeholders in requests

Burp Variables is a Burp Suite extension that adds first-class, project-scoped variable handling to outgoing HTTP requests (similar to Postman/Insomnia environment placeholders).

- Define name:value pairs once in a new Variables tab
- Reference them anywhere in a request using the syntax: ((variableName))
- Substitution happens at send time in Repeater and, optionally, in Proxy (with scope gating)
- Requests you edit keep placeholders; the on-the-wire request contains the replaced values
- Import/Export lets you migrate variable sets between Burp projects

Example usage:

```http
POST /api/v2/profile HTTP/1.1
Host: target.tld
Authorization: Bearer ((token))
Content-Type: application/json

{"id": ((userId)), "email": "test+((userId))@example.com"}
```

### Installation

- Install from the BApp Store (Extender ➜ BApp Store ➜ search for "Variables")
- Or load the latest .jar from GitHub Releases: https://github.com/0xceba/burp_variables

### Quick start

1) Open the extension’s Variables tab and add pairs like:
   - token: eyJhbGciOiJIUzI1Ni...
   - csrf: 9f96c9...
   - userId: 42
2) Insert references in requests via context menu or by typing ((token)), ((csrf)), ((userId)) in headers, query, or body
3) Send the request; verify replacements in Burp’s Logger, which shows the final on-the-wire request

### Proxy replacement and scope safety

If you enable substitutions on Proxy traffic, restrict replacements to in-scope targets:

- Define a proper Project scope first (Target ➜ Scope)
- Enable Proxy modification only after scope is set so secrets don’t leak to out-of-scope hosts
- Validate the final traffic in Logger; placeholders should be replaced only for in-scope requests

### Good practices

- Use consistent names (token, csrf, accountId, session, etc.) across projects
- Keep variables project-scoped and clear sensitive values when finishing/switching projects
- Use Import/Export to move variable sets across projects and maintain hygiene
- Combine with Repeater groups and Logger to quickly rotate credentials/IDs across many saved requests

### When to use vs. Session Handling Rules

Burp Variables is great for explicit, human-managed placeholders across many saved requests. For automatic extraction/refresh of tokens from responses, Burp’s Session Handling Rules can complement variables.

## References

- [Burp Variables: A Burp Suite Extension (Bishop Fox blog)](https://bishopfox.com/blog/burp-variables-burp-suite-extension)
- [burp_variables on GitHub](https://github.com/0xceba/burp_variables)
- [BApp Store](https://portswigger.net/bappstore)

{{#include ../banners/hacktricks-training.md}}