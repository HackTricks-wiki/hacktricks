# Attack ya macOS xpc_connection_get_audit_token

{{#include ../../../../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi angalia post ya awali:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Huu ni muhtasari:

## Taarifa za Msingi za Mach Messages

Ikiwa hujui Mach Messages ni nini, anza kwa kuangalia ukurasa huu:


{{#ref}}
../../
{{#endref}}

Kwa sasa kumbuka kwamba ([definition kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages hutumwa kupitia _mach port_, ambayo ni channel ya mawasiliano ya **single receiver, multiple sender** iliyojengwa ndani ya mach kernel. **Processes nyingi zinaweza kutuma messages** kwenye mach port, lakini wakati wowote **process moja tu inaweza kuzisoma**. Kama file descriptors na sockets, mach ports hutengwa na kusimamiwa na kernel, na processes huona integer pekee ambayo wanaweza kutumia kuonyesha kwa kernel ni mach port ipi wanayotaka kutumia.

## XPC Connection

Ikiwa hujui jinsi XPC connection inavyoanzishwa, angalia:


{{#ref}}
../
{{#endref}}

## Muhtasari wa Vuln

Jambo muhimu kwako kujua ni kwamba **abstraction ya XPC ni one-to-one connection**, lakini imejengwa juu ya technology ambayo **inaweza kuwa na senders wengi, kwa hiyo:**

- Mach ports ni single receiver, **multiple sender**.
- Audit token ya XPC connection ni audit token **iliyonakiliwa kutoka kwenye message iliyopokelewa hivi karibuni zaidi**.
- Kupata **audit token** ya XPC connection ni muhimu kwa **security checks** nyingi.<sup>[1]</sup>

Ingawa hali iliyotajwa hapo awali inaonekana kuahidi, kuna scenarios fulani ambapo haitasababisha matatizo ([kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens hutumiwa mara nyingi kwa authorization check ya kuamua kama connection ikubaliwe. Kwa kuwa hii hufanyika kwa kutumia message kwenye service port, **hakuna connection iliyoanzishwa bado**. Messages zaidi kwenye port hii zitashughulikiwa tu kama connection requests za ziada. Kwa hiyo, **checks kabla ya kukubali connection haziko vulnerable** (hii pia inamaanisha kuwa ndani ya `-listener:shouldAcceptNewConnection:` audit token iko salama). Kwa hiyo **tunatafuta XPC connections zinazothibitisha actions maalum**.
- XPC event handlers hushughulikiwa synchronously. Hii inamaanisha kwamba event handler ya message moja lazima ikamilike kabla ya kuitisha kwa message inayofuata, hata kwenye concurrent dispatch queues. Kwa hiyo ndani ya **XPC event handler audit token haiwezi kuandikwa upya** na messages nyingine za kawaida (zisizo za reply!).<sup>[1]</sup>

Kuna methods mbili tofauti ambazo hii inaweza kuwa exploitable:

1. Variant1:
- **Exploit** **ina-connect** kwenye service **A** na service **B**
- Service **B** inaweza kuita **privileged functionality** kwenye service A ambayo user hawezi kuita
- Service **A** inaita **`xpc_connection_get_audit_token`** ikiwa _**haipo**_ ndani ya **event handler** kwa connection iliyo kwenye **`dispatch_async`**.
- Kwa hiyo message **tofauti** inaweza **kuandika upya Audit Token** kwa sababu inadispatchiwa asynchronously nje ya event handler.
- **Exploit** inapitisha kwa **service B** SEND right ya service A.
- Kwa hiyo svc **B** itakuwa **ikituma** **messages** kwa service **A**.
- **Exploit** inajaribu **kuita privileged action.** Katika RC svc **A** **ina-check** authorization ya **action** hii wakati **svc B imeandika upya Audit token** (ikiipa exploit access ya kuita privileged action).
2. Variant 2:
- Service **B** inaweza kuita **privileged functionality** kwenye service A ambayo user hawezi kuita
- Exploit ina-connect na **service A** ambayo **inaitumia** exploit **message inayotarajia response** kwenye **replay** **port** maalum.
- Exploit inatuma service B message inayopitisha **reply port** hiyo.
- Service **B** inapojibu, **inatuma message kwa service A**, wakati **exploit** inatuma **message tofauti kwa service A** ikijaribu **kufikia privileged functionality** na kutarajia kwamba reply kutoka service B itaandika upya Audit token kwa wakati unaofaa (Race Condition).

## Variant 1: kuita xpc_connection_get_audit_token nje ya event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Mach services mbili **`A`** na **`B`** ambazo tunaweza ku-connect zote mbili (kulingana na sandbox profile na authorization checks kabla ya kukubali connection).
- _**A**_ lazima iwe na **authorization check** kwa action maalum ambayo **`B`** inaweza kupita (lakini app yetu haiwezi).
- Kwa mfano, ikiwa B ina **entitlements** fulani au ina-run kama **root**, inaweza kumruhusu kuomba A ifanye privileged action.
- Kwa authorization check hii, **A** inapata audit token asynchronously, kwa mfano kwa kuita xpc_connection_get_audit_token kutoka `dispatch_async`.

> [!CAUTION]
> Katika hali hii attacker anaweza kuchochea **Race Condition** kwa kutengeneza **exploit** ambayo inaiomba A ifanye action mara kadhaa huku **B ikituma messages kwa `A`**. RC inapofanikiwa, **audit token** ya **B** itanakiliwa kwenye memory wakati request ya **exploit** yetu inashughulikiwa na A, na kuipa access ya privileged action ambayo B pekee ingeweza kuomba.

Hili lilitokea kwa **`A`** ikiwa `smd` na **`B`** ikiwa `diagnosticd`. Function [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) kutoka smb inaweza kutumika kusakinisha privileged helper tool mpya (ikiwa **root**). Ikiwa **process inayo-run kama root inawasiliana na** **smd**, hakuna checks nyingine zitakazofanywa.

Kwa hiyo, service **B** ni **`diagnosticd`** kwa sababu ina-run kama **root** na inaweza kutumika **kumonitor** process; hivyo monitoring inapoanza, **itatuma messages nyingi kwa sekunde.**

Kufanya attack:

1. Anzisha **connection** kwa service inayoitwa `smd` kwa kutumia standard XPC protocol.
2. Unda **connection** ya pili kwa `diagnosticd`. Kinyume na procedure ya kawaida, badala ya kuunda na kutuma mach ports mbili mpya, client port send right inabadilishwa na duplicate ya **send right** inayohusishwa na `smd` connection.
3. Kwa sababu hiyo, XPC messages zinaweza ku-dispatchiwa kwa `diagnosticd`, lakini responses kutoka `diagnosticd` zinaelekezwa upya kwenda `smd`. Kwa `smd`, inaonekana kana kwamba messages kutoka kwa user na `diagnosticd` zinatoka kwenye connection ileile.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Hatua inayofuata inahusisha kuielekeza `diagnosticd` ianze monitoring ya process iliyochaguliwa (huenda ikawa ya user mwenyewe). Wakati huo huo, flood ya messages za kawaida za 1004 inatumwa kwa `smd`. Lengo ni kusakinisha tool yenye elevated privileges.
5. Action hii inachochea race condition ndani ya function ya `handle_bless`. Timing ni muhimu: function call ya `xpc_connection_get_pid` lazima irudishe PID ya process ya user (kwa sababu privileged tool iko kwenye user’s app bundle). Hata hivyo, function ya `xpc_connection_get_audit_token`, hasa ndani ya subroutine ya `connection_is_authorized`, lazima irejee audit token ya `diagnosticd`.<sup>[1]</sup>

## Variant 2: reply forwarding

Katika mazingira ya XPC (Cross-Process Communication), ingawa event handlers hazitekelezwi concurrently, handling ya reply messages ina tabia ya kipekee. Hasa, kuna methods mbili tofauti za kutuma messages zinazotarajia reply:

1. **`xpc_connection_send_message_with_reply`**: Hapa, XPC message inapokelewa na kushughulikiwa kwenye queue iliyoteuliwa.
2. **`xpc_connection_send_message_with_reply_sync`**: Kinyume chake, katika method hii, XPC message inapokelewa na kushughulikiwa kwenye dispatch queue ya sasa.

Tofauti hii ni muhimu kwa sababu inaruhusu uwezekano wa **reply packets ku-parsed concurrently wakati XPC event handler inaendelea kutekelezwa**. Ikumbukwe kwamba ingawa `_xpc_connection_set_creds` inatumia locking kulinda dhidi ya partial overwrite ya audit token, ulinzi huo haujumuishi connection object nzima. Kwa hiyo, hii hutengeneza vulnerability ambapo audit token inaweza kubadilishwa katika muda kati ya packet ku-parsed na event handler yake kutekelezwa.

Ili kutumia vulnerability hii, setup ifuatayo inahitajika:

- Mach services mbili, zinazoitwa **`A`** na **`B`**, ambazo zote zinaweza kuanzisha connection.
- Service **`A`** inapaswa kuwa na authorization check kwa action maalum ambayo **`B`** pekee inaweza kufanya (application ya user haiwezi).
- Service **`A`** inapaswa kutuma message inayotarajia reply.
- User anaweza kutuma message kwa **`B`** ambayo itajibu.

Mchakato wa exploitation una hatua zifuatazo:

1. Subiri service **`A`** itume message inayotarajia reply.
2. Badala ya kujibu moja kwa moja kwa **`A`**, reply port inatekwa na kutumiwa kutuma message kwa service **`B`**.
3. Baadaye, message inayohusisha forbidden action inadispatchiwa, huku ikitarajiwa kwamba itashughulikiwa concurrently na reply kutoka **`B`**.<sup>[1]</sup>

Hapa chini kuna uwakilishi wa kuona wa attack scenario iliyoelezwa:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Matatizo ya Discovery

- **Ugumu wa Kupata Instances**: Kutafuta instances za matumizi ya `xpc_connection_get_audit_token` kulikuwa kugumu, statically na dynamically.
- **Methodology**: Frida ilitumika ku-hook function ya `xpc_connection_get_audit_token`, ikifilter calls ambazo hazikutoka kwenye event handlers. Hata hivyo, method hii ilikuwa na mipaka kwenye process iliyohookiwa na ilihitaji matumizi yake ya active.
- **Analysis Tooling**: Tools kama IDA/Ghidra zilitumika kuchunguza mach services zinazoweza kufikiwa, lakini process hiyo ilichukua muda na ilikuwa ngumu kutokana na calls zilizohusisha dyld shared cache.
- **Scripting Limitations**: Majaribio ya kuscript analysis kwa calls za `xpc_connection_get_audit_token` kutoka kwenye `dispatch_async` blocks yalikwamishwa na ugumu wa ku-parse blocks na interactions na dyld shared cache.<sup>[1]</sup>

## Fix <a href="#the-fix" id="the-fix"></a>

- **Issues Zilizeripotiwa**: Report iliwasilishwa kwa Apple ikieleza issues za jumla na maalum zilizopatikana ndani ya `smd`.
- **Jibu la Apple**: Apple ilishughulikia issue katika `smd` kwa kubadilisha `xpc_connection_get_audit_token` na `xpc_dictionary_get_audit_token`.<sup>[1][2]</sup>
- **Aina ya Fix**: Function ya `xpc_dictionary_get_audit_token` inachukuliwa kuwa secure kwa sababu inapata audit token moja kwa moja kutoka kwenye mach message inayohusishwa na XPC message iliyopokelewa. Hata hivyo, si sehemu ya public API, sawa na `xpc_connection_get_audit_token`.
- **Kutokuwepo kwa Fix pana zaidi**: Haijulikani kwa nini Apple haikutekeleza fix ya kina zaidi, kama kutupa messages ambazo haziendani na audit token iliyohifadhiwa ya connection. Uwezekano wa audit token kubadilika kihalali katika scenarios fulani (kwa mfano, matumizi ya `setuid`) huenda ukawa sababu.
- **Hali ya Sasa**: Issue bado ipo kwenye iOS 17 na macOS 14, ikiwa changamoto kwa wanaotaka kuitambua na kuielewa.<sup>[1]</sup>

## Kupata vulnerable code paths kwa vitendo (2024–2025)

Unapofanya auditing ya XPC services kwa bug class hii, lenga authorization inayofanywa nje ya message’s event handler au kwa wakati mmoja na reply processing.

Vidokezo vya static triage:
- Tafuta calls za `xpc_connection_get_audit_token` zinazofikiwa kutoka blocks zilizowekwa kwenye queue kupitia `dispatch_async`/`dispatch_after` au worker queues nyingine zinazo-run nje ya message handler.
- Tafuta authorization helpers zinazochanganya per-connection na per-message state (kwa mfano, kupata PID kutoka `xpc_connection_get_pid` lakini audit token kutoka `xpc_connection_get_audit_token`).
- Katika NSXPC code, thibitisha kwamba checks zinafanywa kwenye `-listener:shouldAcceptNewConnection:` au, kwa per-message checks, kwamba implementation inatumia per-message audit token (kwa mfano, dictionary ya message kupitia `xpc_dictionary_get_audit_token` kwenye lower-level code).

Vidokezo vya dynamic triage:
- Hook `xpc_connection_get_audit_token` na uflag invocations ambazo user stack yake haina event-delivery path (kwa mfano, `_xpc_connection_mach_event`). Mfano wa Frida hook:
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
- Kwenye macOS, ku-instrument protected/Apple binaries kunaweza kuhitaji SIP izimwe au kutumia development environment; pendelea kujaribu builds zako mwenyewe au userland services.
- Kwa reply-forwarding races (Variant 2), fuatilia uchanganuzi wa wakati mmoja wa reply packets kwa kufuzz timings za `xpc_connection_send_message_with_reply` dhidi ya requests za kawaida na uangalie ikiwa effective audit token inayotumika wakati wa authorization inaweza kuathiriwa.

## Exploitation primitives ambazo huenda utahitaji

- Multi-sender setup (Variant 1): tengeneza connections kwa A na B; duplicate send right ya client port ya A na uitumie kama client port ya B ili replies za B ziwasilishwe kwa A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): capture the send-once right kutoka kwa pending request ya A (reply port), kisha utume crafted message kwa B ukitumia reply port hiyo ili reply ya B ifike kwa A wakati privileged request yako inachanganuliwa.

Hizi zinahitaji low-level mach message crafting kwa ajili ya XPC bootstrap na message formats; pitia mach/XPC primer pages katika section hii kwa packet layouts na flags kamili.

## Useful tooling

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) inaweza kusaidia kuorodhesha connections na kuchunguza traffic ili kuthibitisha multi-sender setups na timing. Mfano: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing kwa libxpc: fanya interpose kwenye `xpc_connection_send_message*` na `xpc_connection_get_audit_token` ili kurekodi call sites na stacks wakati wa black-box testing.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
