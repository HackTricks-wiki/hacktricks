# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi angalia chapisho la awali:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Huu ni muhtasari:

## Mach Messages Basic Info

Ikiwa hujui Mach Messages ni nini, anza kwa kuangalia ukurasa huu:


{{#ref}}
../../
{{#endref}}

Kwa sasa kumbuka kwamba ([definition kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages hutumwa kupitia _mach port_, ambayo ni channel ya mawasiliano ya **mpokeaji mmoja, watumaji wengi** iliyojengwa ndani ya mach kernel. **Processes nyingi zinaweza kutuma messages** kwenye mach port, lakini wakati wowote **process moja tu inaweza kuisoma**. Kama file descriptors na sockets, mach ports hutengwa na kusimamiwa na kernel, na processes huona integer pekee ambayo zinaweza kutumia kuionyesha kernel ni mach port ipi kati ya zao zinataka kutumia.

## XPC Connection

Ikiwa hujui XPC connection huanzishwaje, angalia:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Jambo muhimu kwako kujua ni kwamba **XPC’s abstraction ni connection ya moja-kwa-moja**, lakini imejengwa juu ya technology ambayo **inaweza kuwa na watumaji wengi, kwa hiyo:**

- Mach ports ni mpokeaji mmoja, **watumaji wengi**.
- Audit token ya XPC connection ni audit token **iliyonakiliwa kutoka kwenye message iliyopokelewa hivi karibuni zaidi**.
- Kupata **audit token** ya XPC connection ni muhimu kwa **security checks** nyingi.<sup>[[1]](#references)</sup>

Ingawa hali iliyo hapo juu inaonekana kuahidi, kuna baadhi ya scenarios ambapo haitasababisha matatizo ([kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens hutumiwa mara nyingi kufanya authorization check ya kuamua kama connection ikubaliwe. Kwa kuwa hili hufanywa kwa kutumia message kwenye service port, **hakuna connection iliyoanzishwa bado**. Messages zaidi kwenye port hii zitashughulikiwa tu kama connection requests za ziada. Kwa hiyo **checks zinazofanywa kabla ya kukubali connection hazina vulnerability** (hii pia inamaanisha kwamba ndani ya `-listener:shouldAcceptNewConnection:` audit token iko salama). Kwa hiyo **tunatafuta XPC connections zinazothibitisha actions maalum**.
- XPC event handlers hushughulikiwa synchronously. Hii inamaanisha kwamba event handler ya message moja lazima ikamilike kabla ya kuitwa kwa message inayofuata, hata kwenye concurrent dispatch queues. Kwa hiyo ndani ya **XPC event handler audit token haiwezi kuandikwa upya** na messages nyingine za kawaida (zisizo za reply!).<sup>[[1]](#references)</sup>

Kuna methods mbili tofauti ambazo hii inaweza kuwa exploitable:

1. Variant1:
- **Exploit** **ina-connect** kwenye service **A** na service **B**
- Service **B** inaweza kuita **privileged functionality** katika service A ambayo user hawezi kuita
- Service **A** inaita **`xpc_connection_get_audit_token`** ikiwa _**haiko**_ ndani ya **event handler** ya connection katika **`dispatch_async`**.
- Kwa hiyo message **tofauti** inaweza **kuandika upya Audit Token** kwa sababu inadispatchiwa asynchronously nje ya event handler.
- Exploit inapitisha kwa **service B** SEND right ya service A.
- Kwa hiyo svc **B** ndiyo itakuwa **inatuma** **messages** kwenda service **A**.
- **Exploit** inajaribu **kuita privileged action.** Katika RC svc **A** **ina-check** authorization ya **action** hii wakati **svc B imeandika upya Audit token** (ikiipa exploit access ya kuita privileged action).
2. Variant 2:
- Service **B** inaweza kuita **privileged functionality** katika service A ambayo user hawezi kuita
- Exploit ina-connect na **service A**, ambayo **inaitumia exploit message** inayotarajia response kwenye **replay** **port** maalum.
- Exploit inatuma service B message inayopitisha **reply port** hiyo.
- Service **B** inapojibu, inat**uma message kwenda service A**, **wakati** **exploit** inatuma **message tofauti kwenda service A** ikijaribu **kufikia privileged functionality** na kutarajia kwamba reply kutoka service B itaandika upya Audit token kwa wakati unaofaa (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Mach services mbili **`A`** na **`B`** ambazo tunaweza ku-connect zote mbili (kulingana na sandbox profile na authorization checks zinazofanywa kabla ya kukubali connection).
- _**A**_ lazima iwe na **authorization check** ya action maalum ambayo **`B`** inaweza kupitisha (lakini app yetu haiwezi).
- Kwa mfano, ikiwa B ina **entitlements** fulani au ina-run kama **root**, inaweza kumruhusu kumuomba A ifanye privileged action.
- Kwa authorization check hii, **`A`** hupata audit token asynchronously, kwa mfano kwa kuita `xpc_connection_get_audit_token` kutoka `dispatch_async`.

> [!CAUTION]
> Katika hali hii attacker anaweza ku-trigger **Race Condition**, na kutengeneza **exploit** inayomuomba A ifanye action mara kadhaa huku **B ikituma messages kwenda `A`**. RC **inapofanikiwa**, **audit token** ya **B** itanakiliwa kwenye memory **wakati request ya exploit** inashughulikiwa na A, na kuipa access ya privileged action ambayo B pekee ingeweza kuomba.

Hili lilitokea kwa **`A`** ikiwa `smd` na **`B`** ikiwa `diagnosticd`. Function [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) kutoka smb inaweza kutumika kusakinisha privileged helper tool mpya (ikiwa **root**). Ikiwa **process inayo-run kama root inawasiliana na** **`smd`**, hakuna checks nyingine zitakazofanywa.

Kwa hiyo, service **B** ni **`diagnosticd`** kwa sababu ina-run kama **root** na inaweza kutumika **kumonitor** process; hivyo monitoring inapoanza, **itatuma messages nyingi kwa sekunde.**

Kufanya attack:

1. Anzisha **connection** kwenye service inayoitwa `smd` kwa kutumia standard XPC protocol.
2. Tengeneza **connection** ya pili kwenda `diagnosticd`. Kinyume na utaratibu wa kawaida, badala ya kuunda na kutuma mach ports mbili mpya, client port send right inabadilishwa na duplicate ya **send right** inayohusishwa na `smd` connection.
3. Kwa sababu hiyo, XPC messages zinaweza kudispatchiwa kwenda `diagnosticd`, lakini responses kutoka `diagnosticd` zinaelekezwa upya kwenda `smd`. Kwa `smd`, inaonekana kana kwamba messages kutoka kwa user na `diagnosticd` zinatoka kwenye connection ileile.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Hatua inayofuata inahusisha kuagiza `diagnosticd` ianze monitoring ya process iliyochaguliwa (huenda ikawa ya user mwenyewe). Wakati huo huo, flood ya messages za kawaida za 1004 inatumwa kwenda `smd`. Lengo ni kusakinisha tool yenye elevated privileges.
5. Action hii ina-trigger race condition ndani ya function ya `handle_bless`. Timing ni muhimu: function call ya `xpc_connection_get_pid` lazima irudishe PID ya process ya user (kwa kuwa privileged tool iko kwenye app bundle ya user). Hata hivyo, function ya `xpc_connection_get_audit_token`, hasa ndani ya subroutine ya `connection_is_authorized`, lazima irejee audit token inayomilikiwa na `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

Katika mazingira ya XPC (Cross-Process Communication), ingawa event handlers hazitekelezwi concurrently, handling ya reply messages ina tabia ya kipekee. Hasa, kuna methods mbili tofauti za kutuma messages zinazotarajia reply:

1. **`xpc_connection_send_message_with_reply`**: Hapa, XPC message inapokelewa na kuchakatwa kwenye queue iliyoteuliwa.
2. **`xpc_connection_send_message_with_reply_sync`**: Kinyume chake, katika method hii, XPC message inapokelewa na kuchakatwa kwenye dispatch queue ya sasa.

Tofauti hii ni muhimu kwa sababu inaruhusu uwezekano wa **reply packets kuchanganuliwa concurrently huku XPC event handler ikiendelea kutekelezwa**. Ingawa `_xpc_connection_set_creds` hutumia locking kulinda dhidi ya overwrite ya sehemu ya audit token, ulinzi huu hauhusishi connection object nzima. Kwa hiyo, hii hutengeneza vulnerability ambapo audit token inaweza kubadilishwa katika muda kati ya packet kuchanganuliwa na event handler yake kutekelezwa.

Ili ku-exploit vulnerability hii, setup ifuatayo inahitajika:

- Mach services mbili, zinazoitwa **`A`** na **`B`**, ambazo zote zinaweza kuanzisha connection.
- Service **`A`** inapaswa kuwa na authorization check ya action maalum ambayo **`B`** pekee inaweza kutekeleza (application ya user haiwezi).
- Service **`A`** inapaswa kutuma message inayotarajia reply.
- User anaweza kutuma message kwa **`B`** ambayo itajibu.

Mchakato wa exploitation unahusisha hatua zifuatazo:

1. Subiri service **`A`** itume message inayotarajia reply.
2. Badala ya kujibu moja kwa moja kwa **`A`**, reply port inatekwa na kutumiwa kutuma message kwa service **`B`**.
3. Baadaye, message inayohusisha forbidden action inadispatchiwa, huku ikitarajiwa kuchakatwa concurrently na reply kutoka **`B`**.<sup>[[1]](#references)</sup>

Chini ni uwakilishi wa picha wa attack scenario iliyoelezwa:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Difficulties in Locating Instances**: Kutafuta instances za matumizi ya `xpc_connection_get_audit_token` kulikuwa kugumu, kwa njia ya static na dynamic.
- **Methodology**: Frida ilitumika ku-hook function ya `xpc_connection_get_audit_token`, ikifilter calls ambazo hazikutoka kwenye event handlers. Hata hivyo, method hii ilikuwa na mipaka kwenye process iliyohookiwa na ilihitaji usage amilifu.
- **Analysis Tooling**: Tools kama IDA/Ghidra zilitumika kuchunguza reachable mach services, lakini mchakato ulikuwa wa muda mrefu, na ulitatizwa na calls zilizohusisha dyld shared cache.
- **Scripting Limitations**: Majaribio ya kuscript analysis ya calls kwenda `xpc_connection_get_audit_token` kutoka kwenye `dispatch_async` blocks yalizuiwa na ugumu wa kuchanganua blocks na mwingiliano na dyld shared cache.<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Report iliwasilishwa kwa Apple ikieleza issues za jumla na maalum zilizopatikana ndani ya `smd`.
- **Apple's Response**: Apple ilishughulikia issue katika `smd` kwa kubadilisha `xpc_connection_get_audit_token` na `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: Function ya `xpc_dictionary_get_audit_token` inachukuliwa kuwa secure kwa sababu inapata audit token moja kwa moja kutoka kwenye mach message inayohusishwa na XPC message iliyopokelewa. Hata hivyo, si sehemu ya public API, sawa na `xpc_connection_get_audit_token`.
- **Absence of a Broader Fix**: Bado haijulikani kwa nini Apple haikutekeleza fix pana zaidi, kama vile kutupa messages ambazo haziambatani na audit token iliyohifadhiwa ya connection. Uwezekano wa audit token kubadilika kihalali katika baadhi ya scenarios (kwa mfano, matumizi ya `setuid`) unaweza kuwa sababu.
- **Current Status**: Issue bado ipo katika iOS 17 na macOS 14, na hivyo kuwa changamoto kwa wanaotaka kuitambua na kuielewa.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

Unapofanya auditing ya XPC services kwa bug class hii, zingatia authorization inayofanywa nje ya message’s event handler au kwa wakati mmoja na reply processing.

Static triage hints:
- Tafuta calls za `xpc_connection_get_audit_token` zinazofikiwa kutoka kwenye blocks zilizowekwa kwenye queue kupitia `dispatch_async`/`dispatch_after` au worker queues nyingine zinazo-run nje ya message handler.
- Tafuta authorization helpers zinazochanganya per-connection na per-message state (kwa mfano, kupata PID kutoka `xpc_connection_get_pid` lakini audit token kutoka `xpc_connection_get_audit_token`).
- Katika NSXPC code, thibitisha kwamba checks zinafanywa katika `-listener:shouldAcceptNewConnection:` au, kwa per-message checks, kwamba implementation inatumia per-message audit token (kwa mfano, dictionary ya message kupitia `xpc_dictionary_get_audit_token` katika lower-level code).

Dynamic triage tips:
- Hook `xpc_connection_get_audit_token` na uweke alama kwenye invocations ambazo user stack yake haina event-delivery path (kwa mfano, `_xpc_connection_mach_event`). Mfano wa Frida hook:
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
Maelezo:
- Kwenye macOS, ku-instrument protected/Apple binaries kunaweza kuhitaji SIP izimwe au kutumia development environment; pendelea kujaribu builds zako mwenyewe au userland services.
- Kwa reply-forwarding races (Variant 2), fuatilia uchanganuzi wa pamoja wa reply packets kwa kufuzz timing za `xpc_connection_send_message_with_reply` dhidi ya requests za kawaida, na uangalie ikiwa audit token inayotumika wakati wa authorization inaweza kuathiriwa.

## Exploitation primitives utakazohitaji

- Multi-sender setup (Variant 1): tengeneza connections kwenda A na B; duplicate send right ya client port ya A na uitumie kama client port ya B ili replies za B ziwasilishwe kwa A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): kamata send-once right kutoka kwenye pending request ya A (reply port), kisha tuma crafted message kwa B ukitumia reply port hiyo ili jibu la B liwasili kwa A wakati privileged request yako ikichanganuliwa.

Haya yanahitaji uundaji wa kiwango cha chini wa mach message kwa bootstrap ya XPC na message formats; pitia kurasa za mach/XPC primer katika sehemu hii kwa miundo kamili ya packet na flags.

## Zana muhimu

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) inaweza kusaidia kuhesabu connections na kuchunguza traffic ili kuthibitisha setups za multi-sender na timing. Mfano: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing kwa libxpc: fanya interpose kwenye `xpc_connection_send_message*` na `xpc_connection_get_audit_token` ili kurekodi call sites na stacks wakati wa black-box testing.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
