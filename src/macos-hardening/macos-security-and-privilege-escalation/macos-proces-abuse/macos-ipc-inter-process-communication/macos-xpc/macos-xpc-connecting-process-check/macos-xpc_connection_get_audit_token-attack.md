# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Vir verdere inligting, raadpleeg die oorspronklike plasing:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dit is 'n opsomming:<sup>[[1]](#references)</sup>

## Basiese inligting oor Mach Messages

As jy nie weet wat Mach Messages is nie, begin deur hierdie bladsy te lees:


{{#ref}}
../../
{{#endref}}

Onthou vir eers dat ([definisie hieruit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Mach messages word oor 'n _mach port_ gestuur, wat 'n **enkele ontvanger, veelvuldige senders-kommunikasie**-kanaal is wat in die mach-kern ingebou is. **Veelvuldige prosesse kan messages** na 'n mach port stuur, maar op enige gegewe tydstip **kan slegs een proses daaruit lees**. Net soos file descriptors en sockets word mach ports deur die kern toegewys en bestuur, en prosesse sien slegs 'n heelgetal wat hulle kan gebruik om aan die kern aan te dui watter van hul mach ports hulle wil gebruik.

## XPC Connection

As jy nie weet hoe 'n XPC connection gevestig word nie, kyk hier:


{{#ref}}
../
{{#endref}}

## Opsomming van die kwesbaarheid

Wat vir jou belangrik is om te weet, is dat **XPC se abstraksie 'n een-tot-een-connection is**, maar dit bo-op 'n tegnologie gebaseer is wat **veelvuldige senders kan hê, dus:**

- Mach ports het een ontvanger en **veelvuldige senders**.
- 'n XPC connection se audit token is die audit token wat **gekopieer is vanaf die mees onlangs ontvangde message**.
- Die verkryging van die **audit token** van 'n XPC connection is krities vir baie **security checks**.<sup>[[1]](#references)</sup>

Hoewel die vorige situasie belowend klink, is daar scenario's waar dit nie probleme sal veroorsaak nie ([hieruit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Audit tokens word dikwels vir 'n authorization check gebruik om te besluit of 'n connection aanvaar moet word. Omdat dit met 'n message na die service port gebeur, is **geen connection nog gevestig nie**. Meer messages op hierdie port sal bloot as bykomende connection requests hanteer word. Dus is **geen checks voor die aanvaarding van 'n connection kwesbaar nie** (dit beteken ook dat die audit token binne `-listener:shouldAcceptNewConnection:` veilig is). Ons **soek dus XPC connections wat spesifieke aksies verifieer**.
- XPC event handlers word sinchronies hanteer. Dit beteken dat die event handler vir een message voltooi moet wees voordat dit vir die volgende een geroep word, selfs op gelyktydige dispatch queues. Dus kan die audit token **binne 'n XPC event handler nie deur ander normale (nie-reply!) messages oorskryf word nie**.<sup>[[1]](#references)</sup>

Twee verskillende metodes waarop dit moontlik uitgebuit kan word:

1. Variant1:
- **Exploit** **connect** met service **A** en service **B**
- Service **B** kan 'n **bevoorregte funksionaliteit** in service A oproep wat die gebruiker nie kan nie
- Service **A** roep **`xpc_connection_get_audit_token`** aan terwyl dit _**nie**_ binne die **event handler** vir 'n connection in 'n **`dispatch_async`** is nie.
- Dus kan 'n **ander** message die **Audit Token** **oorskryf**, omdat dit asynchronies buite die event handler gedispatch word.
- Die exploit gee aan **service B** die **SEND-reg** na service A.
- Svc **B** sal dus werklik die **messages** na service **A** **stuur**.
- Die **exploit** probeer om die **bevoorregte aksie** aan te roep. In 'n RC **kontroleer** svc **A** die authorization van hierdie **aksie** terwyl **svc B die Audit token oorgeskryf het** (wat die exploit toegang gee om die bevoorregte aksie aan te roep).
2. Variant 2:
- Service **B** kan 'n **bevoorregte funksionaliteit** in service A oproep wat die gebruiker nie kan nie
- Exploit connect met **service A**, wat vir die exploit 'n **message stuur wat 'n response verwag** in 'n spesifieke **replay** **port**.
- Exploit stuur vir **service** B 'n message wat **daardie reply port** deurgee.
- Wanneer service **B** antwoord, **stuur** dit die message na service A, **terwyl** die **exploit** 'n ander **message na service A stuur** om 'n **bevoorregte funksionaliteit** te probeer bereik, met die verwagting dat die antwoord van service B die Audit token op die perfekte oomblik sal oorskryf (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Twee mach services **`A`** en **`B`** waarmee ons albei kan connect (gebaseer op die sandbox profile en die authorization checks voordat die connection aanvaar word).
- _**A**_ moet 'n **authorization check** vir 'n spesifieke aksie hê wat **`B`** kan slaag (maar ons app nie).
- Byvoorbeeld, as B sekere **entitlements** het of as **root** loop, kan dit hom toelaat om A te vra om 'n bevoorregte aksie uit te voer.
- Vir hierdie authorization check verkry **`A`** die audit token asynchronies, byvoorbeeld deur `xpc_connection_get_audit_token` vanuit `dispatch_async` aan te roep.

> [!CAUTION]
> In hierdie geval kan 'n aanvaller 'n **Race Condition** veroorsaak deur 'n **exploit** te maak wat A verskeie kere vra om 'n aksie uit te voer, terwyl **B messages na `A` stuur**. Wanneer die RC **suksesvol** is, sal die **audit token** van **B** in die geheue gekopieer word **terwyl** die versoek van ons **exploit** deur A **hanteer** word, wat dit toegang gee tot die bevoorregte aksie wat slegs B kon versoek.

Dit het gebeur met **`A`** as `smd` en **`B`** as `diagnosticd`. Die funksie [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) vanaf smb kan gebruik word om 'n nuwe bevoorregte helper tool (as **root**) te installeer. As 'n **proses wat as root loop met** **smd contact** maak, sal geen ander checks uitgevoer word nie.

Daarom is die service **B** **`diagnosticd`**, omdat dit as **root** loop en gebruik kan word om 'n proses te **monitor**; sodra monitoring begin het, sal dit **verskeie messages per sekonde stuur**.

Om die aanval uit te voer:

1. Begin 'n **connection** na die service genaamd `smd` met die standaard XPC-protokol.
2. Skep 'n sekondêre **connection** na `diagnosticd`. In teenstelling met die normale prosedure, skep en stuur die client nie twee nuwe mach ports nie; die client port send right word vervang met 'n duplikaat van die **send right** wat met die `smd`-connection geassosieer word.
3. Gevolglik kan XPC messages na `diagnosticd` gedispatch word, maar responses van `diagnosticd` word teruggestuur na `smd`. Vir `smd` lyk dit asof die messages van beide die gebruiker en `diagnosticd` van dieselfde connection afkomstig is.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Die volgende stap behels dat **`diagnosticd`** opdrag gegee word om 'n gekose proses te begin monitor (moontlik die gebruiker se eie proses). Terselfdertyd word 'n vloed van gewone 1004 messages na `smd` gestuur. Die doel is om 'n tool met verhoogde privileges te installeer.
5. Hierdie aksie veroorsaak 'n race condition binne die `handle_bless`-funksie. Die tydsberekening is krities: die `xpc_connection_get_pid`-funksieaanroep moet die PID van die gebruiker se proses teruggee (omdat die bevoorregte tool in die gebruiker se app bundle geleë is). Die `xpc_connection_get_audit_token`-funksie, spesifiek binne die `connection_is_authorized`-subroetine, moet egter na die audit token van `diagnosticd` verwys.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

In 'n XPC (Cross-Process Communication)-omgewing, hoewel event handlers nie gelyktydig uitgevoer word nie, het die hantering van reply messages unieke gedrag. Spesifiek bestaan daar twee verskillende metodes om messages te stuur wat 'n reply verwag:

1. **`xpc_connection_send_message_with_reply`**: Hier word die XPC message op 'n aangewese queue ontvang en verwerk.
2. **`xpc_connection_send_message_with_reply_sync`**: In hierdie metode word die XPC message daarenteen op die huidige dispatch queue ontvang en verwerk.

Hierdie onderskeid is belangrik omdat dit die moontlikheid skep dat **reply packets gelyktydig met die uitvoering van 'n XPC event handler geparse kan word**. Hoewel `_xpc_connection_set_creds` wel locking implementeer om teen die gedeeltelike oorskryf van die audit token te beskerm, brei dit nie hierdie beskerming na die hele connection object uit nie. Dit skep gevolglik 'n kwesbaarheid waar die audit token vervang kan word gedurende die interval tussen die parsing van 'n packet en die uitvoering van sy event handler.

Om hierdie kwesbaarheid uit te buit, word die volgende opstelling vereis:

- Twee mach services, waarna verwys word as **`A`** en **`B`**, wat albei 'n connection kan vestig.
- Service **`A`** moet 'n authorization check vir 'n spesifieke aksie insluit wat slegs **`B`** kan uitvoer (die gebruiker se application kan nie).
- Service **`A`** moet 'n message stuur wat 'n reply verwag.
- Die gebruiker moet 'n message na **`B`** kan stuur waarop dit sal reageer.

Die exploitation-proses behels die volgende stappe:

1. Wag totdat service **`A`** 'n message stuur wat 'n reply verwag.
2. In plaas daarvan om direk aan **`A`** te antwoord, word die reply port gekaap en gebruik om 'n message na service **`B`** te stuur.
3. Vervolgens word 'n message wat die verbode aksie bevat gedispatch, met die verwagting dat dit gelyktydig met die reply van **`B`** verwerk sal word.<sup>[[1]](#references)</sup>

Hieronder is 'n visuele voorstelling van die beskryfde aanvalscenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Ontdekkingsprobleme

- **Moeilikhede om gevalle te vind**: Dit was moeilik om gevalle op te spoor waar `xpc_connection_get_audit_token` gebruik word, beide staties en dinamies.
- **Metodologie**: Frida is gebruik om die `xpc_connection_get_audit_token`-funksie te hook en calls te filter wat nie uit event handlers afkomstig is nie. Hierdie metode was egter beperk tot die ge-hookte proses en het aktiewe gebruik vereis.
- **Analysis Tooling**: Tools soos IDA/Ghidra is gebruik om bereikbaar mach services te ondersoek, maar die proses was tydrowend en is bemoeilik deur calls wat die dyld shared cache betrek.
- **Beperkings van scripting**: Pogings om die analysis vir calls na `xpc_connection_get_audit_token` vanuit `dispatch_async`-blocks te script, is belemmer deur kompleksiteite met die parsing van blocks en interaksies met die dyld shared cache.<sup>[[1]](#references)</sup>

## Die oplossing <a href="#the-fix" id="the-fix"></a>

- **Gerapporteerde probleme**: 'n Report is aan Apple voorgelê waarin die algemene en spesifieke probleme binne `smd` uiteengesit is.
- **Apple se reaksie**: Apple het die probleem in `smd` aangespreek deur `xpc_connection_get_audit_token` met `xpc_dictionary_get_audit_token` te vervang.<sup>[[1]](#references)[[2]](#references)</sup>
- **Aard van die oplossing**: Die `xpc_dictionary_get_audit_token`-funksie word as veilig beskou omdat dit die audit token direk uit die mach message verkry wat aan die ontvangde XPC message gekoppel is. Dit is egter nie deel van die public API nie, net soos `xpc_connection_get_audit_token`.
- **Afwesigheid van 'n breër oplossing**: Dit bly onduidelik waarom Apple nie 'n meer omvattende oplossing geïmplementeer het nie, soos om messages weg te gooi wat nie met die gestoorde audit token van die connection ooreenstem nie. Die moontlikheid van wettige audit token-veranderings in sekere scenario's (bv. gebruik van `setuid`) kan 'n faktor wees.
- **Huidige status**: Die probleem bestaan steeds in iOS 17 en macOS 14, wat 'n uitdaging skep vir diegene wat dit wil identifiseer en verstaan.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

Wanneer jy XPC services vir hierdie bug class audit, fokus op authorization wat buite die message se event handler of gelyktydig met reply processing uitgevoer word.

Static triage-hints:
- Soek na calls na `xpc_connection_get_audit_token` wat bereikbaar is vanuit blocks wat via `dispatch_async`/`dispatch_after` of ander worker queues gequeue word en buite die message handler loop.
- Soek authorization helpers wat per-connection- en per-message-state meng (bv. haal PID uit `xpc_connection_get_pid`, maar audit token uit `xpc_connection_get_audit_token`).
- Verifieer in NSXPC-code dat checks in `-listener:shouldAcceptNewConnection:` uitgevoer word of, vir per-message checks, dat die implementation 'n per-message audit token gebruik (bv. die message se dictionary via `xpc_dictionary_get_audit_token` in lower-level code).

Dynamic triage-hints:
- Hook `xpc_connection_get_audit_token` en merk invocations waarvan die user stack nie die event-delivery path insluit nie (bv. `_xpc_connection_mach_event`). Voorbeeld van 'n Frida hook:
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
Notas:
- Op macOS kan instrumentering van beskermde/Apple binaries vereis dat SIP gedeaktiveer word of dat ’n development environment gebruik word; verkieslik moet jy jou eie builds of userland services toets.
- Vir reply-forwarding races (Variant 2), monitor gelyktydige parsing van reply packets deur die timing van `xpc_connection_send_message_with_reply` teenoor normale requests te fuzz en te kontroleer of die effektiewe audit token wat tydens authorization gebruik word, beïnvloed kan word.

## Exploitation primitives wat jy waarskynlik sal benodig

- Multi-sender setup (Variant 1): skep connections na A en B; dupliseer die send right van A se client port en gebruik dit as B se client port sodat B se replies aan A gelewer word.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): capture the send-once right from A’s pending request (reply port), then send a crafted message to B using that reply port so B’s reply lands on A while your privileged request is being parsed.

These require low-level mach message crafting for the XPC bootstrap and message formats; review the mach/XPC primer pages in this section for the exact packet layouts and flags.

## Nuttige tooling

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) can help enumerate connections and observe traffic to validate multi-sender setups and timing. Example: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose on `xpc_connection_send_message*` and `xpc_connection_get_audit_token` to log call sites and stacks during black-box testing.



## Verwysings

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
