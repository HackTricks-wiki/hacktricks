# macOS xpc_connection_get_audit_token Aanval

{{#include ../../../../../../banners/hacktricks-training.md}}

**Vir meer inligting kyk na die oorspronklike pos:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Dit is 'n samevatting:

## Mach Messages Basiese Inligting

As jy nie weet wat Mach Messages is nie, begin deur hierdie blad te bekyk:


{{#ref}}
../../
{{#endref}}

Vir nou, onthou dat ([definisie van hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages word gestuur oor 'n _mach port_, wat 'n kanaal ingebou in die mach kernel is wat 'n enkele ontvanger en meerdere senders ondersteun. Meerdere prosesse kan boodskappe na 'n mach port stuur, maar op enige oomblik kan slegs 'n enkele proses daaruit lees. Net soos file descriptors en sockets, word mach ports deur die kernel toegewys en bestuur en sien prosesse slegs 'n integer wat hulle kan gebruik om die kernel aan te dui watter van hul mach ports hulle wil gebruik.

## XPC Connection

As jy nie weet hoe 'n XPC-verbinding gestig word nie, kyk:


{{#ref}}
../
{{#endref}}

## Samevatting van die Kwetsbaarheid

Wat belangrik is om te weet, is dat die XPC-abstraksie 'n een-tot-een verbinding is, maar dit bou bo-op 'n tegnologie wat meerdere senders kan hê, dus:

- mach ports het 'n enkele ontvanger en meerdere senders.
- 'n XPC connection se audit token is die audit token wat gekopieer is vanaf die mees onlangs ontvangde boodskap.
- Kry van die audit token van 'n XPC-verbinding is kritiek vir baie security checks.

Alhoewel dit aanvanklik kommerwekkend klink, is daar scenario's waar dit geen probleem veroorsaak nie ([van hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens word dikwels gebruik vir 'n authorization check om te besluit of 'n verbinding aanvaar moet word. Aangesien dit plaasvind met behulp van 'n boodskap na die service port, is daar **nog geen verbinding gevestig nie**. Meer boodskappe op hierdie port sal bloot as addisionele verbindingsversoeke hanteer word. Dus is enige kontrole voor die aanvaarding van 'n verbinding nie kwesbaar nie (dit beteken ook dat binne `-listener:shouldAcceptNewConnection:` die audit token veilig is). Ons soek dus XPC-verbindinge wat spesifieke aksies verifieer.
- XPC event handlers word sinchronies hanteer. Dit beteken dat die event handler vir een boodskap voltooi moet wees voordat dit vir die volgende aangeroep word, selfs op concurrent dispatch queues. Dus binne 'n XPC event handler kan die audit token nie deur ander normale (nie-reply!) boodskappe oorskryf word nie.

Twee verskillende metodes waardeur dit uitgebuit kan word:

1. Variant 1:
- Die **exploit** maak verbinding met service **A** en service **B**.
- Service **B** kan 'n **privileged functionality** in service A aanroep wat die gebruiker nie kan nie.
- Service **A** roep **`xpc_connection_get_audit_token`** terwyl dit _**nie**_ binne die event handler vir 'n verbinding in 'n **`dispatch_async`** is.
- Dus kan 'n **ander** boodskap die Audit Token **oorskryf** omdat dit asynchroon buite die event handler gedispatch word.
- Die exploit gee aan **service B die SEND right na service A**.
- Dus sal svc **B** eintlik die **messages** na service **A** stuur.
- Die **exploit** probeer die **privileged action** aanroep. In 'n wedlooptoestand (Race Condition) kontroleer svc **A** die authorization van die aksie terwyl **svc B die Audit token oorskryf**, wat die exploit toegang gee om die privileged action te voer.
2. Variant 2:
- Service **B** kan 'n **privileged functionality** in service A aanroep wat die gebruiker nie kan nie.
- Die exploit skakel met **service A**, wat aan die exploit 'n boodskap stuur en 'n antwoord in 'n spesifieke reply port verwag.
- Die exploit stuur aan **service B** 'n boodskap en gee daardie reply port deur.
- Wanneer service **B** antwoord, stuur dit die boodskap na service A, **terwyl** die **exploit** 'n ander boodskap na service A stuur wat probeer om 'n privileged functionality te bereik en hoop dat die antwoord van service B die Audit token op die perfekte oomblik oorskryf (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Twee mach services **`A`** en **`B`** waarby ons albei kan aansluit (gebaseer op die sandbox profiel en die authorization checks voor die aanvaarding van die verbinding).
- _**A**_ moet 'n **authorization check** hê vir 'n spesifieke aksie wat **`B`** kan slaag (maar ons app nie).
- Byvoorbeeld, as B sekere **entitlements** het of as root loop, mag dit vir hom moontlik wees om A te vra om 'n privileged action uit te voer.
- Vir hierdie authorization check verkry **`A`** die audit token asynchroon, byvoorbeeld deur `xpc_connection_get_audit_token` vanaf `dispatch_async` aan te roep.

> [!CAUTION]
> In hierdie geval kan 'n aanvaller 'n **Race Condition** veroorsaak deur 'n **exploit** te laat wat **A vra om 'n aksie uit te voer** verskeie kere terwyl **B boodskappe na `A` stuur**. Wanneer die wedloop suksesvol is, sal die **audit token** van **B** in geheue gekopieer word **terwyl** die versoek van ons **exploit** deur A hanteer word, wat dit toegang gee tot die privileged aksie wat slegs B kon versoek.

Dit het gebeur met **`A`** as `smd` en **`B`** as `diagnosticd`. Die funksie [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) kan gebruik word om 'n nuwe privileged helper tool te installeer (as **root**). As 'n proses wat as root loop `smd` kontak, sal daar geen ander kontroles uitgevoer word nie.

Daarom is die service **B** `diagnosticd` omdat dit as **root** loop en gebruik kan word om 'n proses te monitor; sodra monitoring begin het, sal dit **meerdere boodskappe per sekonde** stuur.

Om die aanval uit te voer:

1. Inisieer 'n **verbinding** na die service met die naam `smd` met behulp van die standaard XPC-protokol.
2. Vorm 'n sekondêre **verbinding** na `diagnosticd`. Anders as die normale prosedure, in plaas daarvan om twee nuwe mach ports te skep en te stuur, word die client port send right vervang met 'n duplikaat van die **send right** wat met die `smd`-verbinding geassosieer is.
3. As gevolg hiervan kan XPC-boodskappe na `diagnosticd` gedispatch word, maar antwoorde van `diagnosticd` word herlei na `smd`. Vir `smd` lyk dit asof die boodskappe van beide die gebruiker en `diagnosticd` vanaf dieselfde verbinding kom.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Die volgende stap behels om `diagnosticd` te instrueer om die monitoring van 'n gekose proses te begin (byvoorbeeld die gebruiker se eie proses). Tegelyk word 'n vloed van roetine 1004 boodskappe na `smd` gestuur. Die doel hier is om 'n tool met verhoogde voorregte te installeer.
5. Hierdie aksie veroorsaak 'n wedlooptoestand binne die `handle_bless` funksie. Die tydsberekening is kritiek: die `xpc_connection_get_pid` oproep moet die PID van die gebruiker se proses teruggee (aangesien die privileged tool in die gebruiker se app-bundel is). Die `xpc_connection_get_audit_token` oproep, veral binne die `connection_is_authorized` subroutine, moet egter na die audit token van `diagnosticd` verwys.

## Variant 2: reply forwarding

In 'n XPC-omgewing, alhoewel event handlers nie gelyktydig uitgevoer word nie, het reply-boodskappe 'n unieke gedrag. Spesifiek bestaan daar twee onderskeibare metodes om boodskappe te stuur wat 'n antwoord verwag:

1. **`xpc_connection_send_message_with_reply`**: Hier word die XPC-boodskap ontvang en op 'n aangewese queue verwerk.
2. **`xpc_connection_send_message_with_reply_sync`**: In teenstelling word in hierdie metode die XPC-boodskap ontvang en op die huidige dispatch queue verwerk.

Hierdie onderskeid is belangrik omdat dit die moontlikheid skep dat **reply packets gelyktydig met die uitvoering van 'n XPC event handler gepars kan word**. Terwyl `_xpc_connection_set_creds` wel locking implementeer om teen die gedeeltelike oorskrywing van die audit token te beskerm, strek hierdie beskerming nie oor die hele connection object nie. Gevolglik skep dit 'n kwesbaarheid waar die audit token vervang kan word gedurende die interval tussen die parsing van 'n pakket en die uitvoering van sy event handler.

Om hierdie kwesbaarheid uit te buit, word die volgende opstelling vereis:

- Twee mach services, genoem **`A`** en **`B`**, wat albei 'n verbinding kan vestig.
- Service **`A`** moet 'n authorization check hê vir 'n spesifieke aksie wat slegs **`B`** kan uitvoer (die gebruiker se toepassing nie).
- Service **`A`** moet 'n boodskap stuur wat 'n reply verwag.
- Die gebruiker kan 'n boodskap aan **`B`** stuur waarop dit sal antwoord.

Die uitbuitingsproses behels die volgende stappe:

1. Wag totdat service **`A`** 'n boodskap stuur wat 'n reply verwag.
2. In plaas daarvan om direk aan **`A`** te antwoord, word die reply port gekaap en gebruik om 'n boodskap aan service **`B`** te stuur.
3. Daarna word 'n boodskap wat die verbode aksie behels gestuur, met die verwagting dat dit gelyktydig met die antwoord van **`B`** verwerk sal word.

Hieronder is 'n visuele voorstelling van die beskryfde aanvalscenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Ontdekkingsprobleme

- **Moeilik om voorbeelde te vind**: Om voorbeelde van `xpc_connection_get_audit_token` gebruik te soek was uitdagend, sowel staties as dinamies.
- **Metodologie**: Frida is gebruik om `xpc_connection_get_audit_token` te hook en oproepe te filter wat nie uit event handlers kom nie. Hierdie metode was egter beperk tot die ge-hookte proses en het aktiewe gebruik vereis.
- **Analise-instrumente**: IDA/Ghidra is gebruik om bereikbare mach services te ondersoek, maar die proses was tydrowend en ingewikkeld weens oproepe wat die dyld shared cache betrek.
- **Skripsiebeperkings**: Pogings om die analise te skrip vir oproepe na `xpc_connection_get_audit_token` vanaf `dispatch_async` blocks is bemoeilik deur die kompleksiteite in die parsen van blocks en interaksies met die dyld shared cache.

## Die herstel <a href="#the-fix" id="the-fix"></a>

- **Gerapporteerde probleme**: 'n Verslag is by Apple ingedien wat die algemene en spesifieke probleme binne `smd` beskryf.
- **Apple se reaksie**: Apple het die probleem in `smd` aangespreek deur `xpc_connection_get_audit_token` te vervang met `xpc_dictionary_get_audit_token`.
- **Aard van die herstel**: Die funksie `xpc_dictionary_get_audit_token` word as veiliger beskou aangesien dit die audit token direk uit die mach message haal wat by die ontvangde XPC-boodskap behoort. Dit is egter nie deel van die publieke API nie, net soos `xpc_connection_get_audit_token`.
- **Afwesigheid van 'n breër herstel**: Dit is onduidelik waarom Apple nie 'n meer omvattende herstel geïmplementeer het nie, byvoorbeeld deur boodskappe wat nie met die gestoor audit token van die verbinding belyn nie te verwerp. Die moontlikheid dat legitime veranderinge aan die audit token in sekere scenario's (bv. met `setuid`) kan voorkom, mag 'n faktor wees.
- **Huidige status**: Die probleem bestaan steeds in iOS 17 en macOS 14 en bly 'n uitdaging vir diegene wat dit wil identifiseer en verstaan.

## Vind kwesbare kodepaaie in praktyk (2024–2025)

Wanneer jy XPC-dienste keur vir hierdie klas foute, fokus op authorizations wat buite die boodskap se event handler gedoen word of gelyktydig met reply verwerking.

Statiese triage wenke:
- Soek vir oproepe na `xpc_connection_get_audit_token` wat bereikbaar is vanaf blocks wat via `dispatch_async`/`dispatch_after` of ander worker queues gekoppel is wat buite die boodskap handler loop.
- Kyk vir authorization helpers wat per-connection en per-message toestand meng (bv. haal PID op met `xpc_connection_get_pid` maar die audit token met `xpc_connection_get_audit_token`).
- In NSXPC-kode, verifieer dat kontroles in `-listener:shouldAcceptNewConnection:` gedoen word of, vir per-bericht kontroles, dat die implementering 'n per-bericht audit token gebruik (bv. die boodskap se dictionary via `xpc_dictionary_get_audit_token` in laer vlak kode).

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
- Vir reply-forwarding races (Variant 2), hou die gelyktydige ontleding van reply-pakkies dop deur die timings van `xpc_connection_send_message_with_reply` teenoor normale requests te fuzz en te kontroleer of die effektiewe audit token wat tydens autorisasie gebruik word, beïnvloed kan word.

## Exploitation primitives you will likely need

- Multi-sender setup (Variant 1): skep koneksies na A en B; dupliseer die send right van A’s client port en gebruik dit as B’s client port sodat B’s replies by A afgelewer word.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): vang die send-once right van A se hangende versoek (reply port), en stuur dan 'n vervaardigde boodskap na B deur daardie reply port sodat B se antwoord op A beland terwyl jou bevoorregte versoek ontleed word.

Hierdie vereis lae-vlak mach message opstel vir die XPC bootstrap en boodskapformate; hersien die mach/XPC primer-bladsye in hierdie afdeling vir die presiese pakketuitleg en flags.

## Nuttige gereedskap

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) kan help om verbindings te enumereer en verkeer waar te neem om multi-sender-opstellings en timing te valideer. Voorbeeld: `gxpc -p <PID> --whitelist <service-name>`.
- Klassieke dyld interposing for libxpc: doen interpose op `xpc_connection_send_message*` en `xpc_connection_get_audit_token` om oproepplekke en stacks te log tydens black-box toetsing.



## References

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
