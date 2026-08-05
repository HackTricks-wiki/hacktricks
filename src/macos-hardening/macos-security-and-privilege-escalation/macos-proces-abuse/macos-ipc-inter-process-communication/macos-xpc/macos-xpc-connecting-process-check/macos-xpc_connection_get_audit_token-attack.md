# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Vir verdere inligting, kyk na die oorspronklike plasing:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dit is 'n opsomming:

## Mach Messages Basic Info

As jy nie weet wat Mach Messages is nie, begin deur hierdie bladsy te lees:


{{#ref}}
../../
{{#endref}}

Onthou vir eers dat ([definisie hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages word oor 'n _mach port_ gestuur, wat 'n **enkele ontvanger, veelvuldige senders-kommunikasie**-kanaal is wat in die mach-kernel ingebou is. **Veelvuldige prosesse kan messages** na 'n mach port stuur, maar op enige gegewe tydstip **kan slegs een proses daaruit lees**. Net soos file descriptors en sockets word mach ports deur die kernel toegeken en bestuur, en prosesse sien slegs 'n heelgetal wat hulle kan gebruik om aan die kernel aan te dui watter van hul mach ports hulle wil gebruik.

## XPC Connection

As jy nie weet hoe 'n XPC connection gevestig word nie, kyk hier:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Wat vir jou belangrik is om te weet, is dat **XPC se abstraksie 'n een-tot-een-connection is**, maar dit bo-op 'n tegnologie gebou is wat **veelvuldige senders kan hê, dus:**

- Mach ports is enkele ontvanger, **veelvuldige senders**.
- 'n XPC connection se audit token is die audit token wat **gekopieer is vanaf die mees onlangs ontvangde message**.
- Die verkryging van 'n XPC connection se **audit token** is krities vir baie **security checks**.<sup>[1]</sup>

Alhoewel die vorige situasie belowend klink, is daar sommige scenario's waar dit nie probleme sal veroorsaak nie ([hier vandaan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens word dikwels vir 'n authorization check gebruik om te besluit of 'n connection aanvaar moet word. Aangesien dit deur middel van 'n message na die service port gebeur, is **geen connection nog gevestig nie**. Verdere messages op hierdie port sal bloot as addisionele connection requests hanteer word. Dus is **enige checks voordat 'n connection aanvaar word nie kwesbaar nie** (dit beteken ook dat die audit token binne `-listener:shouldAcceptNewConnection:` veilig is). Ons **soek dus na XPC connections wat spesifieke aksies verifieer**.
- XPC event handlers word sinchronies hanteer. Dit beteken dat die event handler vir een message voltooi moet wees voordat dit vir die volgende een geroep word, selfs op gelyktydige dispatch queues. Dus kan die audit token binne 'n **XPC event handler nie deur ander normale (nie-reply!) messages oorskryf word nie**.<sup>[1]</sup>

Twee verskillende metodes waarop dit moontlik uitgebuit kan word:

1. Variant1:
- **Exploit** **connect** met service **A** en service **B**
- Service **B** kan 'n **privileged functionality** in service A oproep wat die gebruiker nie kan nie
- Service **A** roep **`xpc_connection_get_audit_token`** op terwyl dit _**nie**_ binne die **event handler** vir 'n connection in 'n **`dispatch_async`** is nie.
- Dus kan 'n **ander** message die **Audit Token oorskryf**, omdat dit asinkroon buite die event handler gedispatch word.
- Die exploit gee aan **service B** die SEND-reg na service A.
- Dus sal svc **B** die **messages** werklik na service **A** **stuur**.
- Die **exploit** probeer om die **privileged action** op te roep. In 'n RC **kontroleer** svc **A** die authorization van hierdie **action** terwyl **svc B die Audit token oorskryf** (wat die exploit toegang gee om die privileged action op te roep).
2. Variant 2:
- Service **B** kan 'n **privileged functionality** in service A oproep wat die gebruiker nie kan nie
- Exploit connect met **service A**, wat vir die exploit 'n **message stuur wat 'n response** op 'n spesifieke **replay**-**port** verwag.
- Exploit stuur vir **service** B 'n message waarin **daardie reply port** gestuur word.
- Wanneer service **B** antwoord, **stuur dit die message na service A**, terwyl die **exploit** 'n ander **message na service A** stuur om 'n **privileged functionality** te bereik en verwag dat die reply van service B die Audit token op die perfekte oomblik sal oorskryf (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Twee mach services **`A`** en **`B`** waarmee ons albei kan connect (gebaseer op die sandbox profile en die authorization checks voordat die connection aanvaar word).
- _**A**_ moet 'n **authorization check** hê vir 'n spesifieke aksie wat **B** kan slaag (maar ons app nie).
- Byvoorbeeld, as B sekere **entitlements** het of as **root** loop, kan dit hom toelaat om A te vra om 'n privileged action uit te voer.
- Vir hierdie authorization check verkry **A** die audit token asinkroon, byvoorbeeld deur `xpc_connection_get_audit_token` vanuit `dispatch_async` op te roep.

> [!CAUTION]
> In hierdie geval kan 'n aanvaller 'n **Race Condition** veroorsaak deur 'n **exploit** te maak wat **A vra om 'n aksie verskeie kere uit te voer**, terwyl **B messages na `A` stuur**. Wanneer die RC **suksesvol** is, sal die **audit token** van **B** in die geheue gekopieer word **terwyl** die request van ons **exploit** deur A hanteer word, wat dit toegang gee tot die privileged action waarvoor slegs B 'n request kon stuur.

Dit het gebeur met **`A`** as `smd` en **`B`** as `diagnosticd`. Die funksie [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) vanaf smb kan gebruik word om 'n nuwe privileged helper tool (as **root**) te installeer. As 'n **proses wat as root loop met** **smd** contact, sal geen ander checks uitgevoer word nie.

Daarom is die service **B** **`diagnosticd`**, omdat dit as **root** loop en gebruik kan word om 'n proses te **monitor**; sodra monitoring begin het, sal dit **veelvuldige messages per sekonde stuur.**

Om die aanval uit te voer:

1. Inisialiseer 'n **connection** met die service genaamd `smd` deur die standaard XPC-protokol te gebruik.
2. Vorm 'n sekondêre **connection** met `diagnosticd`. In teenstelling met die normale prosedure, eerder as om twee nuwe mach ports te skep en te stuur, word die client port send right vervang met 'n duplikaat van die **send right** wat met die `smd`-connection geassosieer word.
3. Gevolglik kan XPC messages na `diagnosticd` gedispatch word, maar responses van `diagnosticd` word terug na `smd` herlei. Vir `smd` lyk dit asof die messages van beide die gebruiker en `diagnosticd` vanaf dieselfde connection afkomstig is.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Die volgende stap behels dat `diagnosticd` opdrag gegee word om monitoring van 'n gekose proses te begin (moontlik die gebruiker se eie proses). Terselfdertyd word 'n vloed van roetine-1004 messages na `smd` gestuur. Die doel is om 'n tool met verhoogde privileges te installeer.
5. Hierdie aksie veroorsaak 'n race condition binne die `handle_bless`-funksie. Die tydsberekening is krities: die `xpc_connection_get_pid`-funksie-oproep moet die PID van die gebruiker se proses teruggee (omdat die privileged tool in die gebruiker se app bundle is). Die `xpc_connection_get_audit_token`-funksie moet egter, spesifiek binne die `connection_is_authorized`-subroetine, verwys na die audit token wat aan `diagnosticd` behoort.<sup>[1]</sup>

## Variant 2: reply forwarding

In 'n XPC (Cross-Process Communication)-omgewing, alhoewel event handlers nie gelyktydig uitgevoer word nie, het die hantering van reply messages unieke gedrag. Daar bestaan spesifiek twee verskillende metodes om messages te stuur wat 'n reply verwag:

1. **`xpc_connection_send_message_with_reply`**: Hier word die XPC message op 'n aangewese queue ontvang en verwerk.
2. **`xpc_connection_send_message_with_reply_sync`**: In teenstelling hiermee word die XPC message met hierdie metode op die huidige dispatch queue ontvang en verwerk.

Hierdie onderskeid is belangrik omdat dit die moontlikheid skep dat **reply packets gelyktydig met die uitvoering van 'n XPC event handler geparse kan word**. Hoewel `_xpc_connection_set_creds` wel locking implementeer om teen die gedeeltelike oorskryf van die audit token te beskerm, brei dit hierdie beskerming nie na die hele connection object uit nie. Gevolglik skep dit 'n kwesbaarheid waar die audit token vervang kan word gedurende die interval tussen die parsing van 'n packet en die uitvoering van sy event handler.

Om hierdie kwesbaarheid uit te buit, word die volgende opstelling vereis:

- Twee mach services, waarna verwys word as **`A`** en **`B`**, wat albei 'n connection kan vestig.
- Service **`A`** moet 'n authorization check bevat vir 'n spesifieke aksie wat slegs deur **`B`** uitgevoer kan word (die gebruiker se application kan dit nie doen nie).
- Service **`A`** moet 'n message stuur wat 'n reply verwag.
- Die gebruiker moet 'n message na **`B`** kan stuur waarop dit sal antwoord.

Die exploitation process behels die volgende stappe:

1. Wag vir service **`A`** om 'n message te stuur wat 'n reply verwag.
2. In plaas daarvan om direk aan **`A`** te antwoord, word die reply port gekaap en gebruik om 'n message na service **`B`** te stuur.
3. Vervolgens word 'n message wat die verbode aksie behels, gedispatch, met die verwagting dat dit gelyktydig met die reply van **`B`** verwerk sal word.<sup>[1]</sup>

Hieronder is 'n visuele voorstelling van die beskryfde aanvalscenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Moeilikhede om gevalle te vind**: Dit was uitdagend om gevalle te vind waar `xpc_connection_get_audit_token` gebruik word, beide staties en dinamies.
- **Metodologie**: Frida is gebruik om die `xpc_connection_get_audit_token`-funksie te hook, en calls wat nie uit event handlers afkomstig is nie, te filter. Hierdie metode was egter beperk tot die ge-hookte proses en het aktiewe gebruik vereis.
- **Analysis Tooling**: Tools soos IDA/Ghidra is gebruik om bereikbare mach services te ondersoek, maar die proses was tydrowend en is bemoeilik deur calls wat die dyld shared cache betrek.
- **Scripting Limitations**: Pogings om die analysis te script vir calls na `xpc_connection_get_audit_token` vanuit `dispatch_async`-blocks is belemmer deur kompleksiteite met die parsing van blocks en interaksies met die dyld shared cache.<sup>[1]</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: 'n Report is aan Apple voorgelê waarin die algemene en spesifieke issues binne `smd` uiteengesit is.
- **Apple's Response**: Apple het die issue in `smd` aangespreek deur `xpc_connection_get_audit_token` met `xpc_dictionary_get_audit_token` te vervang.<sup>[1][2]</sup>
- **Nature of the Fix**: Die `xpc_dictionary_get_audit_token`-funksie word as secure beskou, omdat dit die audit token direk uit die mach message verkry wat aan die ontvangde XPC message gekoppel is. Dit is egter nie deel van die publieke API nie, net soos `xpc_connection_get_audit_token`.
- **Absence of a Broader Fix**: Dit bly onduidelik waarom Apple nie 'n meer omvattende fix geïmplementeer het nie, soos om messages weg te gooi wat nie met die connection se gestoorde audit token ooreenstem nie. Die moontlikheid van wettige audit token-veranderinge in sekere scenario's (byvoorbeeld die gebruik van `setuid`) kan 'n faktor wees.
- **Current Status**: Die issue bestaan steeds in iOS 17 en macOS 14, wat 'n uitdaging skep vir diegene wat dit wil identifiseer en verstaan.<sup>[1]</sup>

## Finding vulnerable code paths in practice (2024–2025)

Wanneer XPC services vir hierdie bug class ge-audit word, fokus op authorization wat buite die message se event handler uitgevoer word of gelyktydig met reply processing plaasvind.

Static triage hints:
- Soek na calls na `xpc_connection_get_audit_token` wat bereikbaar is vanuit blocks wat via `dispatch_async`/`dispatch_after` of ander worker queues ge-queue word en buite die message handler loop.
- Soek authorization helpers wat per-connection- en per-message-state meng (byvoorbeeld, haal PID uit `xpc_connection_get_pid`, maar audit token uit `xpc_connection_get_audit_token`).
- In NSXPC-code, verifieer dat checks in `-listener:shouldAcceptNewConnection:` gedoen word of, vir per-message checks, dat die implementering 'n per-message audit token gebruik (byvoorbeeld die message se dictionary via `xpc_dictionary_get_audit_token` in lower-level code).

Dynamic triage tips:
- Hook `xpc_connection_get_audit_token` en merk invocations waarvan die user stack nie die event-delivery path insluit nie (byvoorbeeld `_xpc_connection_mach_event`). Voorbeeld van Frida hook:
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
- Op macOS kan instrumentering van protected/Apple binaries vereis dat SIP gedeaktiveer is of dat ’n development environment gebruik word; verkies om jou eie builds of userland services te toets.
- Vir reply-forwarding races (Variant 2), monitor gelyktydige parsing van reply packets deur die timings van `xpc_connection_send_message_with_reply` teenoor normale requests te fuzz en te kontroleer of die effektiewe audit token wat tydens authorization gebruik word, beïnvloed kan word.

## Exploitation primitives wat jy waarskynlik sal benodig

- Multi-sender setup (Variant 1): skep connections na A en B; duplicate die send right van A se client port en gebruik dit as B se client port sodat B se replies by A afgelewer word.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): vang die send-once right van A se hangende versoek (reply port) vas, en stuur dan ’n crafted message na B met daardie reply port sodat B se antwoord by A land terwyl jou privileged request ontleed word.

Dit vereis laevlak mach message crafting vir die XPC bootstrap en message-formate; hersien die mach/XPC primer-bladsye in hierdie afdeling vir die presiese packet-uitlegte en flags.

## Nuttige tooling

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) kan help om connections op te som en traffic waar te neem om multi-sender-opstellings en timing te valideer. Voorbeeld: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose op `xpc_connection_send_message*` en `xpc_connection_get_audit_token` om call sites en stacks tydens black-box testing aan te teken.



## Verwysings

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
