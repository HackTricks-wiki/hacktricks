# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Vir verdere inligting, kyk na die oorspronklike post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dit is 'n opsomming:

## Mach Messages Basic Info

As jy nie weet wat Mach Messages is nie, begin deur hierdie bladsy te lees:


{{#ref}}
../../
{{#endref}}

Onthou vir eers dat ([definisie hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages word oor 'n _mach port_ gestuur, wat 'n **enkele ontvanger, veelvuldige senders-kommunikasiekanaal** is wat in die mach-kernel ingebou is. **Veelvuldige prosesse kan messages** na 'n mach port stuur, maar op enige gegewe tydstip **kan slegs een proses daaruit lees**. Net soos file descriptors en sockets word mach ports deur die kernel toegeken en bestuur, en prosesse sien slegs 'n heelgetal wat hulle kan gebruik om aan die kernel aan te dui watter van hul mach ports hulle wil gebruik.

## XPC Connection

As jy nie weet hoe 'n XPC connection gevestig word nie, kyk:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Wat vir jou belangrik is om te weet, is dat **XPC se abstraksie 'n een-tot-een connection is**, maar dit bo-op 'n tegnologie gebaseer is wat **veelvuldige senders kan hê, dus:**

- Mach ports is enkelontvanger, **veelvuldige senders**.
- 'n XPC connection se audit token is die audit token wat **gekopieer is vanaf die mees onlangs ontvangde message**.
- Die verkryging van die **audit token** van 'n XPC connection is krities vir baie **security checks**.<sup>[[1]](#references)</sup>

Hoewel die vorige situasie belowend klink, is daar sommige scenario's waar dit nie probleme sal veroorsaak nie ([hier vandaan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens word dikwels vir 'n authorization check gebruik om te besluit of 'n connection aanvaar moet word. Omdat dit met behulp van 'n message na die service port gebeur, is **geen connection nog gevestig nie**. Verdere messages op hierdie port sal bloot as bykomende connection requests hanteer word. Dus is enige **checks voordat 'n connection aanvaar word nie vulnerable nie** (dit beteken ook dat die audit token binne `-listener:shouldAcceptNewConnection:` veilig is). Ons **soek dus XPC connections wat spesifieke actions verifieer**.
- XPC event handlers word sinchronies hanteer. Dit beteken dat die event handler vir een message voltooi moet wees voordat dit vir die volgende een geroep word, selfs op concurrent dispatch queues. Dus kan die audit token binne 'n **XPC event handler nie deur ander normale (nie-reply!) messages oorskryf word nie**.<sup>[[1]](#references)</sup>

Twee verskillende metodes waarop dit exploitable kan wees:

1. Variant1:
- **Exploit** **connect** met service **A** en service **B**
- Service **B** kan 'n **privileged functionality** in service A aanroep wat die user nie kan nie
- Service **A** roep **`xpc_connection_get_audit_token`** aan terwyl dit _**nie**_ binne die **event handler** vir 'n connection in 'n **`dispatch_async`** is nie.
- Dus kan 'n **ander** message die **Audit Token** **oorskryf**, omdat dit asynchroon buite die event handler gedispatch word.
- Die exploit gee aan **service B die SEND-reg op service A**.
- Svc **B** sal dus eintlik die **messages** na service **A** **stuur**.
- Die **exploit** probeer om die **privileged action** aan te roep. In 'n RC **check** svc **A** die authorization van hierdie **action** terwyl **svc B die Audit token oorskryf** (wat die exploit toegang gee om die privileged action aan te roep).
2. Variant 2:
- Service **B** kan 'n **privileged functionality** in service A aanroep wat die user nie kan nie
- Exploit connect met **service A**, wat vir die exploit 'n **message stuur wat 'n response** op 'n spesifieke **replay** **port** verwag.
- Exploit stuur vir **service** B 'n message wat **daardie reply port** deurgee.
- Wanneer service **B** antwoord, **stuur dit die message na service A**, **terwyl** die **exploit** 'n ander **message na service A** stuur om 'n **privileged functionality** te probeer bereik en verwag dat die reply van service B die Audit token op die perfekte oomblik sal oorskryf (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Twee mach services **`A`** en **`B`** waarmee ons albei kan connect (gebaseer op die sandbox profile en die authorization checks voordat die connection aanvaar word).
- _**A**_ moet 'n **authorization check** vir 'n spesifieke action hê wat **`B`** kan slaag (maar ons app nie).
- Byvoorbeeld, as B sekere **entitlements** het of as **root** loop, kan dit hom toelaat om A te vra om 'n privileged action uit te voer.
- Vir hierdie authorization check verkry **`A`** die audit token asynchroon, byvoorbeeld deur `xpc_connection_get_audit_token` vanuit `dispatch_async` aan te roep.

> [!CAUTION]
> In hierdie geval kan 'n aanvaller 'n **Race Condition** trigger deur 'n **exploit** te maak wat A verskeie kere vra om 'n action uit te voer, terwyl **B messages na `A` stuur**. Wanneer die RC **suksesvol** is, sal die **audit token** van **B** in memory gekopieer word **terwyl** die request van ons **exploit** deur A **hanteer** word, wat dit toegang gee tot die privileged action wat slegs B kon request.

Dit het gebeur met **`A`** as `smd` en **`B`** as `diagnosticd`. Die funksie [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) vanaf smb an be used to install a new privileged helper toot (as **root**). If a **process running as root contact** **smd**, no other checks will be performed.

Therefore, the service **B** is **`diagnosticd`** because it runs as **root** and can be used to **monitor** a process, so once monitoring has started, it will **send multiple messages per second.**

To perform the attack:

1. Initiate a **connection** to the service named `smd` using the standard XPC protocol.
2. Form a secondary **connection** to `diagnosticd`. Contrary to normal procedure, rather than creating and sending two new mach ports, the client port send right is substituted with a duplicate of the **send right** associated with the `smd` connection.
3. As a result, XPC messages can be dispatched to `diagnosticd`, but responses from `diagnosticd` are rerouted to `smd`. To `smd`, it appears as though the messages from both the user and `diagnosticd` are originating from the same connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. The next step involves instructing `diagnosticd` to initiate monitoring of a chosen process (potentially the user's own). Concurrently, a flood of routine 1004 messages is sent to `smd`. The intent here is to install a tool with elevated privileges.
5. This action triggers a race condition within the `handle_bless` function. The timing is critical: the `xpc_connection_get_pid` function call must return the PID of the user's process (as the privileged tool resides in the user's app bundle). However, the `xpc_connection_get_audit_token` function, specifically within the `connection_is_authorized` subroutine, must reference the audit token belonging to `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

In an XPC (Cross-Process Communication) environment, although event handlers don't execute concurrently, the handling of reply messages has a unique behavior. Specifically, two distinct methods exist for sending messages that expect a reply:

1. **`xpc_connection_send_message_with_reply`**: Here, the XPC message is received and processed on a designated queue.
2. **`xpc_connection_send_message_with_reply_sync`**: Conversely, in this method, the XPC message is received and processed on the current dispatch queue.

This distinction is crucial because it allows for the possibility of **reply packets being parsed concurrently with the execution of an XPC event handler**. Notably, while `_xpc_connection_set_creds` does implement locking to safeguard against the partial overwrite of the audit token, it does not extend this protection to the entire connection object. Consequently, this creates a vulnerability where the audit token can be replaced during the interval between the parsing of a packet and the execution of its event handler.

To exploit this vulnerability, the following setup is required:

- Two mach services, referred to as **`A`** and **`B`**, both of which can establish a connection.
- Service **`A`** should include an authorization check for a specific action that only **`B`** can perform (the user's application cannot).
- Service **`A`** should send a message that anticipates a reply.
- The user can send a message to **`B`** that it will respond to.

The exploitation process involves the following steps:

1. Wait for service **`A`** to send a message that expects a reply.
2. Instead of replying directly to **`A`**, the reply port is hijacked and used to send a message to service **`B`**.
3. Subsequently, a message involving the forbidden action is dispatched, with the expectation that it will be processed concurrently with the reply from **`B`**.<sup>[[1]](#references)</sup>

Below is a visual representation of the described attack scenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Difficulties in Locating Instances**: Searching for instances of `xpc_connection_get_audit_token` usage was challenging, both statically and dynamically.
- **Methodology**: Frida was employed to hook the `xpc_connection_get_audit_token` function, filtering calls not originating from event handlers. However, this method was limited to the hooked process and required active usage.
- **Analysis Tooling**: Tools like IDA/Ghidra were used for examining reachable mach services, but the process was time-consuming, complicated by calls involving the dyld shared cache.
- **Scripting Limitations**: Attempts to script the analysis for calls to `xpc_connection_get_audit_token` from `dispatch_async` blocks were hindered by complexities in parsing blocks and interactions with the dyld shared cache.<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: A report was submitted to Apple detailing the general and specific issues found within `smd`.
- **Apple's Response**: Apple addressed the issue in `smd` by substituting `xpc_connection_get_audit_token` with `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: The `xpc_dictionary_get_audit_token` function is considered secure as it retrieves the audit token directly from the mach message tied to the received XPC message. However, it's not part of the public API, similar to `xpc_connection_get_audit_token`.
- **Absence of a Broader Fix**: It remains unclear why Apple didn't implement a more comprehensive fix, such as discarding messages not aligning with the saved audit token of the connection. The possibility of legitimate audit token changes in certain scenarios (e.g., `setuid` usage) might be a factor.
- **Current Status**: The issue persists in iOS 17 and macOS 14, posing a challenge for those seeking to identify and understand it.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

When auditing XPC services for this bug class, focus on authorization performed outside the message’s event handler or concurrently with reply processing.

Static triage hints:
- Search for calls to `xpc_connection_get_audit_token` reachable from blocks queued via `dispatch_async`/`dispatch_after` or other worker queues that run outside the message handler.
- Look for authorization helpers that mix per-connection and per-message state (e.g., fetch PID from `xpc_connection_get_pid` but audit token from `xpc_connection_get_audit_token`).
- In NSXPC code, verify that checks are done in `-listener:shouldAcceptNewConnection:` or, for per-message checks, that the implementation uses a per-message audit token (e.g., the message’s dictionary via `xpc_dictionary_get_audit_token` in lower-level code).

Dynamic triage tips:
- Hook `xpc_connection_get_audit_token` and flag invocations whose user stack does not include the event-delivery path (e.g., `_xpc_connection_mach_event`). Example Frida hook:
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
Notes:
- Op macOS kan instrumentering van protected/Apple binaries vereis dat SIP gedeaktiveer is of dat ’n development environment gebruik word; verkies om jou eie builds of userland services te toets.
- Vir reply-forwarding races (Variant 2), monitor gelyktydige parsing van reply packets deur die timings van `xpc_connection_send_message_with_reply` teenoor normale requests te fuzz en te kontroleer of die effektiewe audit token wat tydens authorization gebruik word, beïnvloed kan word.

## Exploitation primitives wat jy waarskynlik sal benodig

- Multi-sender-opstelling (Variant 1): skep connections na A en B; dupliseer die send right van A se client port en gebruik dit as B se client port sodat B se replies aan A gelewer word.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): capture the send-once right from A’s pending request (reply port), then send a crafted message to B using that reply port so B’s reply lands on A while your privileged request is being parsed.

Hierdie vereis laevlak mach message crafting vir die XPC bootstrap en message-formate; hersien die mach/XPC primer pages in hierdie afdeling vir die presiese packet layouts en flags.

## Nuttige tooling

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) kan help om connections op te som en traffic waar te neem om multi-sender setups en timing te valideer. Example: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing vir libxpc: interpose op `xpc_connection_send_message*` en `xpc_connection_get_audit_token` om call sites en stacks tydens black-box testing te log.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
