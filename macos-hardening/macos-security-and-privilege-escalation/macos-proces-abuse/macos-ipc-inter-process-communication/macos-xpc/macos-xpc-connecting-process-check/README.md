# macOS XPC Connecting Process Check

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## XPC Connecting Process Check

When a connection is stablished to an XPC service, the server will check if the connection is allowed. These are the checks it would usually perform:

1. Check if the connecting **process is signed with an Apple-signed** certificate (only given out by Apple).
   * If this **isn't verified**, an attacker could create a **fake certificate** to match any other check.
2. Check if the connecting process is signed with the **organization’s certificate**, (team ID verification).
   * If this **isn't verified**, **any developer certificate** from Apple can be used for signing, and connect to the service.
3. Check if the connecting process **contains a proper bundle ID**.
   * If this **isn't verified**, any tool **signed by the same org** could be used to interact with the XPC service.
4. (4 or 5) Check if the connecting process has a **proper software version number**.
   * If this **isn't verified,** an old, insecure clients, vulnerable to process injection could be used to connect to the XPC service even with the other checks in place.
5. (4 or 5) Check if the connecting process has hardened runtime without dangerous entitlements (like the ones that allows to load arbitrary libraries or use DYLD env vars)
   1. If this **isn't verified,** the client might be **vulnerable to code injection**
6. Check if the connecting process has an **entitlement** that allows it to connect to the service. This is applicable for Apple binaries.
7. The **verification** must be **based** on the connecting **client’s audit token** **instead** of its process ID (**PID**) since the former prevents **PID reuse attacks**.
   * Developers **rarely use the audit token** API call since it’s **private**, so Apple could **change** at any time. Additionally, private API usage is not allowed in Mac App Store apps.
     * If the method **`processIdentifier`** is used, it might be vulnerable
     * **`xpc_dictionary_get_audit_token`** should be used instead of **`xpc_connection_get_audit_token`**, as the latest could also be [vulnerable in certain situations](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Communication Attacks

For more information about the PID reuse attack check:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

For more information **`xpc_connection_get_audit_token`** attack check:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Downgrade Attacks Prevention

Trustcache is a defensive method introduced in Apple Silicon machines that stores a database of CDHSAH of Apple binaries so only allowed non modified binaries can be executed. Which prevent the execution of downgrade versions.

### Code Examples

The server will implement this **verification** in a function called **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    //Check connection
    return YES;
}
```
{% endcode %}

The object NSXPCConnection has a **private** property **`auditToken`** (the one that should be used but could change) and a the **public** property **`processIdentifier`** (the one that shouldn't be used).

The connecting process could be verified with something like:

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
{% endcode %}

If a developer doesn't want to check the version of the client, he could check that the client is not vulnerable to process injection at least:

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page. 
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
    return Yes; // Accept connection
}
```
{% endcode %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
