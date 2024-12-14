# macOS xpc\_connection\_get\_audit\_token Attack

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

**For further information check the original post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). This is a summary:

## Mach Messages Basic Info

If you don't know what Mach Messages are start checking this page:

{% content-ref url="../../" %}
[..](../../)
{% endcontent-ref %}

For the moment remember that ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages are sent over a _mach port_, which is a **single receiver, multiple sender communication** channel built into the mach kernel. **Multiple processes can send messages** to a mach port, but at any point **only a single process can read from it**. Just like file descriptors and sockets, mach ports are allocated and managed by the kernel and processes only see an integer, which they can use to indicate to the kernel which of their mach ports they want to use.

## XPC Connection

If you don't know how a XPC connection is established check:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Vuln Summary

What is interesting for you to know is that **XPC’s abstraction is a one-to-one connection**, but it is based on top of a technology which **can have multiple senders, so:**

* Mach ports are single receiver, **multiple sender**.
* An XPC connection’s audit token is the audit token of **copied from the most recently received message**.
* Obtaining the **audit token** of an XPC connection is critical to many **security checks**.

Although the previous situation sounds promising there are some scenarios where this is not going to cause problems ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Audit tokens are often used for an authorization check to decide whether to accept a connection. As this happens using a message to the service port, there is **no connection established yet**. More messages on this port will just be handled as additional connection requests. So any **checks before accepting a connection are not vulnerable** (this also means that within `-listener:shouldAcceptNewConnection:` the audit token is safe). We are therefore **looking for XPC connections that verify specific actions**.
* XPC event handlers are handled synchronously. This means that the event handler for one message must be completed before calling it for the next one, even on concurrent dispatch queues. So inside an **XPC event handler the audit token can not be overwritten** by other normal (non-reply!) messages.

Two different methods this might be exploitable:

1. Variant1:
   * **Exploit** **connects** to service **A** and service **B**
     * Service **B** can call a **privileged functionality** in service A that the user cannot
   * Service **A** calls **`xpc_connection_get_audit_token`** while _**not**_ inside the **event handler** for a connection in a **`dispatch_async`**.
     * So a **different** message could **overwrite the Audit Token** because it's being dispatched asynchronously outside of the event handler.
   * The exploit passes to **service B the SEND right to service A**.
     * So svc **B** will be actually **sending** the **messages** to service **A**.
   * The **exploit** tries to **call** the **privileged action.** In a RC svc **A** **checks** the authorization of this **action** while **svc B overwrote the Audit token** (giving the exploit access to call the privileged action).
2. Variant 2:
   * Service **B** can call a **privileged functionality** in service A that the user cannot
   * Exploit connects with **service A** which **sends** the exploit a **message expecting a response** in a specific **replay** **port**.
   * Exploit sends **service** B a message passing **that reply port**.
   * When service **B replies**, it s**ends the message to service A**, **while** the **exploit** sends a different **message to service A** trying to **reach a privileged functionality** and expecting that the reply from service B will overwrite the Audit token in the perfect moment (Race Condition).

## Variant 1: calling xpc\_connection\_get\_audit\_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

* Two mach services **`A`** and **`B`** that we can both connect to (based on the sandbox profile and the authorization checks before accepting the connection).
* _**A**_ must have an **authorization check** for a specific action that **`B`** can pass (but our app can’t).
  * For example, if B has some **entitlements** or is running as **root**, it might allow him to ask A to perform a privileged action.
* For this authorization check, **`A`** obtains the audit token asynchronously, for example by calling `xpc_connection_get_audit_token` from **`dispatch_async`**.

{% hint style="danger" %}
In this case an attacker could trigger a **Race Condition** making a **exploit** that **asks A to perform an action** several times while making **B send messages to `A`**. When the RC is **successful**, the **audit token** of **B** will be copied in memory **while** the request of our **exploit** is being **handled** by A, giving it **access to the privilege action only B could request**.
{% endhint %}

This happened with **`A`** as `smd` and **`B`** as `diagnosticd`. The function [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) from smb an be used to install a new privileged helper toot (as **root**). If a **process running as root contact** **smd**, no other checks will be performed.

Therefore, the service **B** is **`diagnosticd`** because it runs as **root** and can be used to **monitor** a process, so once monitoring has started, it will **send multiple messages per second.**

To perform the attack:

1. Initiate a **connection** to the service named `smd` using the standard XPC protocol.
2. Form a secondary **connection** to `diagnosticd`. Contrary to normal procedure, rather than creating and sending two new mach ports, the client port send right is substituted with a duplicate of the **send right** associated with the `smd` connection.
3. As a result, XPC messages can be dispatched to `diagnosticd`, but responses from `diagnosticd` are rerouted to `smd`. To `smd`, it appears as though the messages from both the user and `diagnosticd` are originating from the same connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. The next step involves instructing `diagnosticd` to initiate monitoring of a chosen process (potentially the user's own). Concurrently, a flood of routine 1004 messages is sent to `smd`. The intent here is to install a tool with elevated privileges.
5. This action triggers a race condition within the `handle_bless` function. The timing is critical: the `xpc_connection_get_pid` function call must return the PID of the user's process (as the privileged tool resides in the user's app bundle). However, the `xpc_connection_get_audit_token` function, specifically within the `connection_is_authorized` subroutine, must reference the audit token belonging to `diagnosticd`.

## Variant 2: reply forwarding

In an XPC (Cross-Process Communication) environment, although event handlers don't execute concurrently, the handling of reply messages has a unique behavior. Specifically, two distinct methods exist for sending messages that expect a reply:

1. **`xpc_connection_send_message_with_reply`**: Here, the XPC message is received and processed on a designated queue.
2. **`xpc_connection_send_message_with_reply_sync`**: Conversely, in this method, the XPC message is received and processed on the current dispatch queue.

This distinction is crucial because it allows for the possibility of **reply packets being parsed concurrently with the execution of an XPC event handler**. Notably, while `_xpc_connection_set_creds` does implement locking to safeguard against the partial overwrite of the audit token, it does not extend this protection to the entire connection object. Consequently, this creates a vulnerability where the audit token can be replaced during the interval between the parsing of a packet and the execution of its event handler.

To exploit this vulnerability, the following setup is required:

* Two mach services, referred to as **`A`** and **`B`**, both of which can establish a connection.
* Service **`A`** should include an authorization check for a specific action that only **`B`** can perform (the user's application cannot).
* Service **`A`** should send a message that anticipates a reply.
* The user can send a message to **`B`** that it will respond to.

The exploitation process involves the following steps:

1. Wait for service **`A`** to send a message that expects a reply.
2. Instead of replying directly to **`A`**, the reply port is hijacked and used to send a message to service **`B`**.
3. Subsequently, a message involving the forbidden action is dispatched, with the expectation that it will be processed concurrently with the reply from **`B`**.

Below is a visual representation of the described attack scenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

* **Difficulties in Locating Instances**: Searching for instances of `xpc_connection_get_audit_token` usage was challenging, both statically and dynamically.
* **Methodology**: Frida was employed to hook the `xpc_connection_get_audit_token` function, filtering calls not originating from event handlers. However, this method was limited to the hooked process and required active usage.
* **Analysis Tooling**: Tools like IDA/Ghidra were used for examining reachable mach services, but the process was time-consuming, complicated by calls involving the dyld shared cache.
* **Scripting Limitations**: Attempts to script the analysis for calls to `xpc_connection_get_audit_token` from `dispatch_async` blocks were hindered by complexities in parsing blocks and interactions with the dyld shared cache.

## The fix <a href="#the-fix" id="the-fix"></a>

* **Reported Issues**: A report was submitted to Apple detailing the general and specific issues found within `smd`.
* **Apple's Response**: Apple addressed the issue in `smd` by substituting `xpc_connection_get_audit_token` with `xpc_dictionary_get_audit_token`.
* **Nature of the Fix**: The `xpc_dictionary_get_audit_token` function is considered secure as it retrieves the audit token directly from the mach message tied to the received XPC message. However, it's not part of the public API, similar to `xpc_connection_get_audit_token`.
* **Absence of a Broader Fix**: It remains unclear why Apple didn't implement a more comprehensive fix, such as discarding messages not aligning with the saved audit token of the connection. The possibility of legitimate audit token changes in certain scenarios (e.g., `setuid` usage) might be a factor.
* **Current Status**: The issue persists in iOS 17 and macOS 14, posing a challenge for those seeking to identify and understand it.

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

