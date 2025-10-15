# macOS xpc_connection_get_audit_token Aanval

{{#include ../../../../../../banners/hacktricks-training.md}}

**Vir verdere inligting, kyk die oorspronklike pos:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dit is 'n opsomming:

## Mach Messages Basiese Inligting

As jy nie weet wat Mach Messages is nie, begin om hierdie bladsy te kyk:


{{#ref}}
../../
{{#endref}}

Vir nou onthou dat ([definisie van hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages word gestuur oor 'n _mach port_, wat 'n **single receiver, multiple sender communication** kanaal is ingebou in die mach kernel. **Meerdere prosesse kan boodskappe stuur** na 'n mach port, maar op enige oomblik kan **slegs een proses daaruit lees**. Net soos file descriptors en sockets, word mach ports deur die kernel toegeken en bestuur en prosesse sien slegs 'n integer wat hulle aan die kernel kan deurgee om aan te dui watter van hul mach ports hulle wil gebruik.

## XPC Connection

As jy nie weet hoe 'n XPC connection gevestig word nie, kyk:


{{#ref}}
../
{{#endref}}

## Kwesbaarheid Opsomming

Wat interessant is om te weet is dat **XPC se abstraksie 'n one-to-one connection is**, maar dit is gegrond op 'n tegnologie wat **meerdere senders kan hê, dus:**

- Mach ports is single receiver, **multiple sender**.
- 'n XPC connection se audit token is die audit token wat **gekopieer is vanaf die mees onlangs ontvangde boodskap**.
- Om die **audit token** van 'n XPC connection te kry is kritiek vir baie **sekuriteitskontroles**.

Alhoewel die vorige situasie belowend klink, is daar scenario's waar dit nie 'n probleem gaan veroorsaak nie ([van hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens word dikwels gebruik vir 'n autorisasie-check om te besluit of 'n connection aanvaar moet word. Aangesien dit gebeur deur 'n boodskap na die service port, is daar **nog geen connection gevestig nie**. Meer boodskappe op hierdie port sal net as addisionele verbindingsversoeke hanteer word. Dus is enige **kontroles voor die aanvaarding van 'n verbinding nie kwesbaar nie** (dit beteken ook dat binne `-listener:shouldAcceptNewConnection:` die audit token veilig is). Ons soek dus **XPC connections wat spesifieke aksies verifieer**.
- XPC event handlers word sinchronies hanteer. Dit beteken dat die event handler vir een boodskap voltooi moet wees voordat dit vir die volgende aangeroep word, selfs op concurrent dispatch queues. Dus binne 'n **XPC event handler kan die audit token nie oor-skryf word** deur ander normale (nie-reply!) boodskappe nie.

Twee verskillende metodes hoe dit moontlik benut kan word:

1. Variant 1:
- Die **exploit** **connect** met service **A** en service **B**
- Service **B** kan 'n **privileged functionality** in service A aanroep wat die gebruiker nie kan nie
- Service **A** roep **`xpc_connection_get_audit_token`** aan terwyl dit _**nie**_ binne die **event handler** vir 'n connection in 'n **`dispatch_async`** is.
- Dus kan 'n **ander** boodskap die **Audit Token oor-skryf** omdat dit asinchronies buite die event handler gedisperseer word.
- Die exploit gee aan **service B die SEND right na service A**.
- Dus sal svc **B** eintlik die **boodskappe** aan service **A** **stuur**.
- Die **exploit** probeer die **privileged action** **aanroep.** In 'n RC svc **A** **kontroleer** die die autorisasie van hierdie **aksie** terwyl **svc B die Audit token oor-geskryf het** (waardeur die exploit toegang kry om die privileged action te roep).
2. Variant 2:
- Service **B** kan 'n **privileged functionality** in service A aanroep wat die gebruiker nie kan nie
- Exploit verbind met **service A** wat 'n **boodskap** stuur wat 'n **response** in 'n spesifieke **reply** **port** verwag.
- Exploit stuur **service B** 'n boodskap wat daardie reply port deurgee.
- Wanneer service **B** antwoord, **stuur dit die boodskap na service A**, **terwyl** die **exploit** 'n ander **boodskap** aan service **A** stuur wat probeer 'n **privileged functionality** bereik en verwag dat die reply van service B op die perfekte oomblik die Audit token oor-skryf (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Twee mach services **`A`** en **`B`** waaroor ons albei kan verbind (gebaseer op die sandbox profiel en die autorisasie-kontroles voor die aanvaarding van die verbinding).
- _**A**_ moet 'n **autorisasie-check** hê vir 'n spesifieke aksie wat **`B`** kan slaag (maar ons app nie).
- Byvoorbeeld, as B sekere **entitlements** het of as root loop, kan dit hom toelaat om A te vra om 'n privileged action uit te voer.
- Vir hierdie autorisasie-check verkry **`A`** die audit token asinchronies, byvoorbeeld deur `xpc_connection_get_audit_token` vanuit **`dispatch_async`** aan te roep.

> [!CAUTION]
> In hierdie geval kan 'n aanvaller 'n **Race Condition** veroorsaak deur 'n **exploit** te skep wat A vra om 'n aksie te verrig verskeie kere terwyl B **boodskappe na `A` stuur**. Wanneer die RC **suksesvol** is, sal die **audit token** van **B** in geheue **gekopieer** word **terwyl** die versoek van ons **exploit** deur A **verwerk** word, wat dit **toegang gee tot die privileged action wat slegs B kon versoek**.

Dit het voorgekom met **`A`** as `smd` en **`B`** as `diagnosticd`. Die funksie [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) van smb kan gebruik word om 'n nuwe privileged helper tool te installeer (as **root**). As 'n **proses wat as root loop** `smd` kontak, sal geen extra kontroles uitgevoer word nie.

Daarom is die service **B** **`diagnosticd`** omdat dit as **root** loop en gebruik kan word om 'n proses te **monitor**, so sodra monitoring begin het, sal dit **meerdere boodskappe per sekonde** stuur.

Om die aanval uit te voer:

1. Inisieer 'n **connection** na die service met die naam `smd` met die standaard XPC-protokol.
2. Vorm 'n sekondêre **connection** na `diagnosticd`. Anders as normale prosedure, in plaas daarvan om twee nuwe mach ports te skep en te stuur, word die client port send right vervang met 'n duplikaat van die **send right** geassosieer met die `smd` connection.
3. Gevolglik kan XPC-boodskappe na `diagnosticd` gedisperseer word, maar antwoorde van `diagnosticd` word herlei na `smd`. Vir `smd` lyk dit asof die boodskappe van beide die gebruiker en `diagnosticd` uit dieselfde verbinding afkomstig is.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Die volgende stap behels om `diagnosticd` te instrueer om monitoring te begin op 'n gekose proses (miskien die gebruiker se eie). Tegelyk word 'n vloed van roetine 1004-boodskappe na `smd` gestuur. Die doel hier is om 'n hulpmiddel met verhoogde voorregte te installeer.
5. Hierdie aksie veroorsaak 'n wedlooptoestand in die `handle_bless` funksie. Die tyding is kritiek: die oproep na `xpc_connection_get_pid` moet die PID van die gebruiker se proses teruggee (aangesien die privileged tool in die gebruiker se app bundle is). Maar die oproep na `xpc_connection_get_audit_token`, spesifiek binne die `connection_is_authorized` subprogram, moet na die audit token van `diagnosticd` verwys.

## Variant 2: reply forwarding

In 'n XPC (Cross-Process Communication) omgewing, alhoewel event handlers nie terselfdertyd uitvoer nie, het die hantering van reply-boodskappe 'n unieke gedrag. Spesifiek bestaan daar twee verskillende metodes om boodskappe te stuur wat 'n reply verwag:

1. **`xpc_connection_send_message_with_reply`**: Hier word die XPC-boodskap op 'n aangewese queue ontvang en verwerk.
2. **`xpc_connection_send_message_with_reply_sync`**: Omgekeerd, in hierdie metode word die XPC-boodskap op die huidige dispatch queue ontvang en verwerk.

Hierdie onderskeid is kritiek omdat dit die moontlikheid skep dat **reply packets gelyktydig geparse kan word met die uitvoering van 'n XPC event handler**. Noemenswaardig is dat hoewel `_xpc_connection_set_creds` locking implementeer om teen die gedeeltelike oor-skrywing van die audit token te beskerm, dit nie hierdie beskerming na die hele connection object uitbrei nie. Gevolglik skep dit 'n kwesbaarheid waar die audit token vervang kan word gedurende die interval tussen die parsen van 'n pakket en die uitvoering van sy event handler.

Om hierdie kwesbaarheid te benut, is die volgende opstelling benodig:

- Twee mach services, genoem **`A`** en **`B`**, albei kan 'n verbinding vestig.
- Service **`A`** moet 'n autorisasie-check hê vir 'n spesifieke aksie wat slegs **`B`** kan uitvoer (die gebruiker se toepassing kan nie).
- Service **`A`** moet 'n boodskap stuur wat 'n reply verwag.
- Die gebruiker kan 'n boodskap aan **`B`** stuur waarop dit sal antwoord.

Die exploit-proses behels die volgende stappe:

1. Wag dat service **`A`** 'n boodskap stuur wat 'n reply verwag.
2. In plaas daarvan om direk aan **`A`** te antwoord, word die reply port gekaap en gebruik om 'n boodskap na service **`B`** te stuur.
3. Daarna word 'n boodskap wat die verbode aksie behels gestuur, in die verwagting dat dit gelyktydig met die reply van **`B`** verwerk sal word.

Hieronder is 'n visuele voorstelling van die beskrywe aanvalscenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Ontdekkingsprobleme

- **Moeilikhede om Voorbeelde te Vind**: Om voorbeelde van `xpc_connection_get_audit_token` gebruik te soek was uitdagend, beide staties en dinamies.
- **Metodologie**: Frida is gebruik om die `xpc_connection_get_audit_token` funksie te hook, en oproepe wat nie uit event handlers kom nie te filter. Hierdie metode was egter beperk tot die ge-hookte proses en het aktiewe gebruik vereis.
- **Analise Gereedskap**: Gereedskap soos IDA/Ghidra is gebruik om bereikbare mach services te ondersoek, maar die proses was tydrowend en verward deur oproepe wat die dyld shared cache betrek.
- **Skrip-Beperkings**: Pogings om die analise te skrip vir oproepe na `xpc_connection_get_audit_token` vanuit `dispatch_async` blocks is belemmer deur kompleksiteite in die parsen van blocks en interaksies met die dyld shared cache.

## Die regstelling <a href="#the-fix" id="the-fix"></a>

- **Gerapporteerde Probleme**: 'n Rapport is aan Apple ingedien wat die algemene en spesifieke probleme in `smd` uiteensit.
- **Apple se Antwoord**: Apple het die probleem in `smd` aangespreek deur `xpc_connection_get_audit_token` te vervang met `xpc_dictionary_get_audit_token`.
- **Aard van die Regstelling**: Die funksie `xpc_dictionary_get_audit_token` word as veilig beskou omdat dit die audit token direk uit die mach message haal wat aan die ontvangde XPC-boodskap gekoppel is. Dit is egter nie deel van die publieke API nie, soortgelyk aan `xpc_connection_get_audit_token`.
- **Afwesigheid van 'n Wyer Regstelling**: Dit is onduidelik waarom Apple nie 'n meer omvattende regstelling geïmplementeer het nie, soos om boodskappe te verwerp wat nie met die gestoor audit token van die verbinding in lyn is nie. Die moontlikheid dat legitimiete audit token veranderings in sekere scenario's kan voorkom (bv. gebruik van `setuid`) mag 'n faktor wees.
- **Huidige Status**: Die kwessie bestaan voort in iOS 17 en macOS 14, wat dit moeilik maak vir diegene wat dit wil identifiseer en verstaan.

## Vind kwesbare kodepaaie in die praktyk (2024–2025)

Wanneer jy XPC-dienste oudit vir hierdie soort foutklas, fokus op autorisasie wat uitgevoer word buite die boodskap se event handler of gelyktydig met reply-verwerking.

Statiese triage wenke:
- Soek vir oproepe na `xpc_connection_get_audit_token` wat bereikbaar is vanaf blocks wat geplaas is via `dispatch_async`/`dispatch_after` of ander worker queues wat buite die boodskap handler loop.
- Kyk vir autorisasie-helpers wat per-connection en per-boodskap toestand meng (bv. haal PID van `xpc_connection_get_pid` maar audit token van `xpc_connection_get_audit_token`).
- In NSXPC-kode, verifieer dat kontroles gedoen word in `-listener:shouldAcceptNewConnection:` of, vir per-boodskap kontroles, dat die implementering 'n per-boodskap audit token gebruik (bv. die boodskap se dictionary via `xpc_dictionary_get_audit_token` in laervlak kode).

Dinamiese triage wenke:
- Hook `xpc_connection_get_audit_token` en merk invokasies waarvan die user stack nie die event-delivery pad insluit nie (bv. `_xpc_connection_mach_event`). Voorbeeld Frida hook:
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
Aantekeninge:
- Op macOS kan die instrumentering van beskermde/Apple binaries vereis dat SIP gedeaktiveer is of 'n ontwikkelingsomgewing; verkies om jou eie builds of userland services te toets.
- Vir reply-forwarding races (Variant 2), moniteer gelyktydige parsing van reply packets deur die timings van `xpc_connection_send_message_with_reply` te fuzz teenoor normale requests en kontroleer of die effektiewe audit token wat tydens authorization gebruik word beïnvloed kan word.

## Exploitation primitives you will likely need

- Multi-sender setup (Variant 1): create connections to A and B; duplicate the send right of A’s client port and use it as B’s client port so that B’s replies are delivered to A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): vang die send-once right uit A se hangende versoek (reply port), en stuur dan 'n vervaardigde boodskap na B met daardie reply port sodat B se reply by A aankom terwyl jou privileged request ontleed word.

Hierdie vereis laevlak mach message crafting vir die XPC bootstrap en boodskapformate; kyk na die mach/XPC primer-bladsye in hierdie afdeling vir die presiese pakketlayouts en flags.

## Nuttige gereedskap

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) kan help om verbindings te enumereer en verkeer waar te neem om multi-sender opstellings en timing te valideer. Voorbeeld: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose on `xpc_connection_send_message*` and `xpc_connection_get_audit_token` om call sites en stacks te log gedurende black-box testing.

## References

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
