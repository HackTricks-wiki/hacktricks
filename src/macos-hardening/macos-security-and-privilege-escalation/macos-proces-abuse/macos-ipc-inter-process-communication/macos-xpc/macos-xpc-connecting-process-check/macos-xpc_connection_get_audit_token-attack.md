# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi angalia chapisho la awali:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Huu ni muhtasari:<sup>[[1]](#references)</sup>

## Mach Messages Basic Info

Ikiwa hujui Mach Messages ni nini, anza kwa kuangalia ukurasa huu:


{{#ref}}
../../
{{#endref}}

Kwa sasa kumbuka kwamba ([definition kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Mach messages hutumwa kupitia _mach port_, ambayo ni channel ya mawasiliano ya **single receiver, multiple sender** iliyojengwa ndani ya mach kernel. **Processes nyingi zinaweza kutuma messages** kwenye mach port, lakini wakati wowote **process moja tu inaweza kusoma kutoka humo**. Kama file descriptors na sockets, mach ports hutengwa na kusimamiwa na kernel, na processes huona integer pekee ambayo zinaweza kutumia kuonyesha kwa kernel ni mach ports zipi zinataka kutumia.

## XPC Connection

Ikiwa hujui jinsi XPC connection inavyoanzishwa, angalia:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Jambo muhimu kwako kujua ni kwamba **XPC’s abstraction ni one-to-one connection**, lakini imejengwa juu ya technology ambayo **inaweza kuwa na senders wengi, hivyo:**

- Mach ports ni single receiver, **multiple sender**.
- Audit token ya XPC connection ni audit token **iliyokopiwa kutoka kwenye message iliyopokelewa hivi karibuni zaidi**.
- Kupata **audit token** ya XPC connection ni muhimu kwa **security checks** nyingi.<sup>[[1]](#references)</sup>

Ingawa hali iliyo hapo juu inaonekana yenye matumaini, kuna scenarios ambazo haitasababisha matatizo ([kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Audit tokens hutumiwa mara nyingi kwa authorization check ya kuamua kama connection ikubalike. Kwa kuwa hili hufanyika kwa kutumia message kwenye service port, **connection bado haijaanzishwa**. Messages zaidi kwenye port hii zitashughulikiwa tu kama connection requests za ziada. Kwa hiyo, **checks zinazofanywa kabla ya kukubali connection haziko vulnerable** (hii pia inamaanisha kwamba ndani ya `-listener:shouldAcceptNewConnection:` audit token ni salama). Kwa hiyo **tunatafuta XPC connections zinazothibitisha actions maalum**.
- XPC event handlers hushughulikiwa synchronously. Hii inamaanisha kwamba event handler ya message moja lazima ikamilike kabla ya kuitwa kwa message inayofuata, hata kwenye concurrent dispatch queues. Kwa hiyo ndani ya **XPC event handler audit token haiwezi kuandikwa upya** na messages nyingine za kawaida (zisizo za reply!).<sup>[[1]](#references)</sup>

Kuna methods mbili tofauti ambazo hii inaweza kuwa exploitable:

1. Variant1:
- **Exploit** **ina-connect** kwenye service **A** na service **B**
- Service **B** inaweza kuita **privileged functionality** kwenye service A ambayo user hawezi kuita
- Service **A** inaita **`xpc_connection_get_audit_token`** ikiwa _**haiko**_ ndani ya **event handler** ya connection katika **`dispatch_async`**.
- Kwa hiyo, message **tofauti** inaweza **kuoverwrite Audit Token** kwa sababu inadispatchiwa asynchronously nje ya event handler.
- Exploit inampa **service B** **SEND right ya service A**.
- Kwa hiyo svc **B** itakuwa inatuma **messages** kwenda kwa service **A**.
- **Exploit** inajaribu **kuita privileged action.** Katika RC svc **A** **ina-check** authorization ya **action** hii wakati **svc B imeoverwrite Audit token** (ikiipa exploit access ya kuita privileged action).
2. Variant 2:
- Service **B** inaweza kuita **privileged functionality** kwenye service A ambayo user hawezi kuita
- Exploit ina-connect na **service A**, ambayo **inaitumia exploit message inayotarajia response** kwenye **replay** **port** maalum.
- Exploit inatuma service **B** message inayopitisha **reply port** hiyo.
- Service **B inapojibu**, inatuma message kwenda service A, **wakati** **exploit** inatuma **message tofauti kwenda service A** ikijaribu **kufikia privileged functionality**, huku ikitarajia kwamba reply kutoka service B ita-overwrite Audit token kwa wakati sahihi (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Mach services mbili **`A`** na **`B`** ambazo tunaweza ku-connect zote mbili (kulingana na sandbox profile na authorization checks zinazofanywa kabla ya kukubali connection).
- _**A**_ lazima iwe na **authorization check** ya action maalum ambayo **B** inaweza kupita (lakini app yetu haiwezi).
- Kwa mfano, ikiwa B ina **entitlements** fulani au ina-run kama **root**, inaweza kumruhusu kuomba A ifanye privileged action.
- Kwa authorization check hii, **A** inapata audit token asynchronously, kwa mfano kwa kuita `xpc_connection_get_audit_token` kutoka `dispatch_async`.

> [!CAUTION]
> Katika hali hii attacker anaweza kuchochea **Race Condition**, na kutengeneza **exploit** inayomwomba A ifanye action mara kadhaa huku ikifanya **B itume messages kwa `A`**. RC inapofanikiwa, **audit token** ya **B** itanakiliwa kwenye memory **wakati ombi la exploit yetu linashughulikiwa** na A, na kuipa access ya privileged action ambayo B pekee ingeweza kuomba.

Hili lilitokea kwa **`A`** ikiwa `smd` na **`B`** ikiwa `diagnosticd`. Function [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) kutoka smb inaweza kutumiwa kusakinisha privileged helper toot mpya (kama **root**). Ikiwa **process inayo-run kama root ina-contact** **smd**, hakuna checks nyingine zitakazofanywa.

Kwa hiyo, service **B** ni **`diagnosticd`** kwa sababu ina-run kama **root** na inaweza kutumiwa **kufuatilia** process; hivyo monitoring inapoanza, **itatuma messages nyingi kwa sekunde.**

Ili kufanya attack:

1. Anzisha **connection** kwenda service inayoitwa `smd` kwa kutumia standard XPC protocol.
2. Tengeneza **connection** ya pili kwenda `diagnosticd`. Kinyume na utaratibu wa kawaida, badala ya kutengeneza na kutuma mach ports mbili mpya, client port send right inabadilishwa na duplicate ya **send right** inayohusishwa na `smd` connection.
3. Kwa sababu hiyo, XPC messages zinaweza ku-dispatchiwa kwenda `diagnosticd`, lakini responses kutoka `diagnosticd` zinarudishwa kwenda `smd`. Kwa `smd`, inaonekana kana kwamba messages kutoka kwa user na `diagnosticd` zinatoka kwenye connection ileile.

![Picha inayoonyesha mchakato wa exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Hatua inayofuata inahusisha kuielekeza `diagnosticd` ianze monitoring ya process iliyochaguliwa (huenda ikawa ya user mwenyewe). Wakati huohuo, flood ya routine 1004 messages inatumwa kwa `smd`. Lengo hapa ni kusakinisha tool yenye elevated privileges.
5. Action hii inachochea race condition ndani ya function ya `handle_bless`. Timing ni muhimu: function call ya `xpc_connection_get_pid` lazima irudishe PID ya process ya user (kwa sababu privileged tool iko kwenye app bundle ya user). Hata hivyo, function ya `xpc_connection_get_audit_token`, hasa ndani ya subroutine ya `connection_is_authorized`, lazima irejee audit token ya `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

Katika mazingira ya XPC (Cross-Process Communication), ingawa event handlers hazitekelezwi concurrently, handling ya reply messages ina behavior ya kipekee. Hasa, kuna methods mbili tofauti za kutuma messages zinazotarajia reply:

1. **`xpc_connection_send_message_with_reply`**: Hapa, XPC message inapokelewa na kuchakatwa kwenye queue iliyoteuliwa.
2. **`xpc_connection_send_message_with_reply_sync`**: Kinyume chake, katika method hii, XPC message inapokelewa na kuchakatwa kwenye dispatch queue ya sasa.

Tofauti hii ni muhimu kwa sababu inaruhusu uwezekano wa **reply packets kuchanganuliwa concurrently na utekelezaji wa XPC event handler**. Ingawa `_xpc_connection_set_creds` inatumia locking kulinda dhidi ya partial overwrite ya audit token, ulinzi huo hauhusishi connection object nzima. Kwa hiyo, hii hutengeneza vulnerability ambapo audit token inaweza kubadilishwa katika muda kati ya packet kuchanganuliwa na event handler yake kutekelezwa.

Ili ku-exploit vulnerability hii, setup ifuatayo inahitajika:

- Mach services mbili, zinazorejelewa kama **`A`** na **`B`**, ambazo zote zinaweza kuanzisha connection.
- Service **`A`** inapaswa kuwa na authorization check ya action maalum ambayo **`B`** pekee inaweza kufanya (application ya user haiwezi).
- Service **`A`** inapaswa kutuma message inayotarajia reply.
- User anaweza kutuma message kwa **`B`** ambayo itajibu.

Mchakato wa exploitation unahusisha hatua zifuatazo:

1. Subiri service **`A`** itume message inayotarajia reply.
2. Badala ya kujibu moja kwa moja kwa **`A`**, reply port inahijackiwa na kutumiwa kutuma message kwa service **`B`**.
3. Baadaye, message inayohusisha forbidden action inadispatchiwa, huku ikitarajiwa kwamba itachakatwa concurrently na reply kutoka **`B`**.<sup>[[1]](#references)</sup>

Hapa chini kuna representation ya kuona ya attack scenario iliyoelezwa:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Difficulties in Locating Instances**: Kutafuta instances za matumizi ya `xpc_connection_get_audit_token` kulikuwa kugumu, kwa static na dynamic analysis.
- **Methodology**: Frida ilitumika ku-hook function ya `xpc_connection_get_audit_token`, na kuchuja calls ambazo hazikutoka kwenye event handlers. Hata hivyo, method hii ilikuwa na kikomo kwa process iliyokuwa hooked na ilihitaji matumizi ya active.
- **Analysis Tooling**: Tools kama IDA/Ghidra zilitumika kuchunguza reachable mach services, lakini process ilikuwa ya muda mrefu na ilichanganywa zaidi na calls zilizohusisha dyld shared cache.
- **Scripting Limitations**: Majaribio ya kuscript analysis ya calls kwenda `xpc_connection_get_audit_token` kutoka kwenye `dispatch_async` blocks yalikwamishwa na ugumu wa kuchanganua blocks na interactions na dyld shared cache.<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Report iliwasilishwa kwa Apple ikieleza issues za jumla na maalum zilizopatikana ndani ya `smd`.
- **Apple's Response**: Apple ilirekebisha issue katika `smd` kwa kubadilisha `xpc_connection_get_audit_token` na `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: Function ya `xpc_dictionary_get_audit_token` inachukuliwa kuwa salama kwa sababu inapata audit token moja kwa moja kutoka kwenye mach message inayohusishwa na XPC message iliyopokelewa. Hata hivyo, si sehemu ya public API, sawa na `xpc_connection_get_audit_token`.
- **Absence of a Broader Fix**: Bado haijulikani kwa nini Apple haikutekeleza fix pana zaidi, kama vile kutupa messages ambazo haziendani na audit token iliyohifadhiwa ya connection. Uwezekano wa audit token kubadilika kihalali katika scenarios fulani (kwa mfano, matumizi ya `setuid`) huenda ukawa sababu.
- **Current Status**: Issue bado ipo katika iOS 17 na macOS 14, jambo linalowaletea changamoto wanaotaka kuitambua na kuielewa.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

Wakati wa ku-audit XPC services kwa bug class hii, zingatia authorization inayofanywa nje ya message’s event handler au concurrently na reply processing.

Static triage hints:
- Tafuta calls za `xpc_connection_get_audit_token` zinazofikiwa kutoka kwenye blocks zilizowekwa kwenye queue kupitia `dispatch_async`/`dispatch_after` au worker queues nyingine zinazo-run nje ya message handler.
- Tafuta authorization helpers zinazochanganya per-connection na per-message state (kwa mfano, kupata PID kutoka `xpc_connection_get_pid` lakini audit token kutoka `xpc_connection_get_audit_token`).
- Katika NSXPC code, thibitisha kwamba checks zinafanywa kwenye `-listener:shouldAcceptNewConnection:` au, kwa per-message checks, kwamba implementation inatumia per-message audit token (kwa mfano, dictionary ya message kupitia `xpc_dictionary_get_audit_token` katika lower-level code).

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
Notes:
- Kwenye macOS, ku-instrument protected/Apple binaries kunaweza kuhitaji SIP izimwe au development environment; pendelea ku-test builds zako mwenyewe au userland services.
- Kwa reply-forwarding races (Variant 2), fuatilia parsing ya reply packets kwa wakati mmoja kwa kufuzz timings za `xpc_connection_send_message_with_reply` dhidi ya requests za kawaida na uangalie ikiwa effective audit token inayotumika wakati wa authorization inaweza kuathiriwa.

## Exploitation primitives utakazohitaji

- Multi-sender setup (Variant 1): tengeneza connections kwa A na B; duplicate send right ya client port ya A na uitumie kama client port ya B ili replies za B zipelekwe kwa A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): capture the send-once right kutoka kwenye ombi linalosubiri la A (reply port), kisha tuma crafted message kwa B ukitumia reply port hiyo ili jibu la B liwasili kwa A wakati privileged request yako inachanganuliwa.

Hizi zinahitaji uundaji wa kiwango cha chini wa mach messages kwa bootstrap ya XPC na message formats; pitia kurasa za mach/XPC primer katika sehemu hii kwa packet layouts na flags sahihi.

## Zana muhimu

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) inaweza kusaidia kuorodhesha connections na kuchunguza traffic ili kuthibitisha mipangilio ya multi-sender na timing. Mfano: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing kwa libxpc: interpose kwenye `xpc_connection_send_message*` na `xpc_connection_get_audit_token` ili kurekodi call sites na stacks wakati wa black-box testing.



## Marejeo

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
