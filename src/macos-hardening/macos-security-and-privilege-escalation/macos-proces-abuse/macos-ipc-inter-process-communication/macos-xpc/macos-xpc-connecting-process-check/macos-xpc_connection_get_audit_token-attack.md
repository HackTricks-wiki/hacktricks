# macOS xpc_connection_get_audit_token Shambulio

{{#include ../../../../../../banners/hacktricks-training.md}}

**Kwa taarifa zaidi angalia chapisho la awali:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Huu ni muhtasari:

## Mach Messages Maelezo Msingi

Ikiwa haufahamu Mach Messages anza kuangalia ukurasa huu:


{{#ref}}
../../
{{#endref}}

Kwa sasa kumbuka kwamba ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages hutumwa kupitia _mach port_, ambayo ni njia ya mawasiliano ya **mpokeaji mmoja, watumaji wengi** iliyojengwa ndani ya kernel ya mach. **Mchakato nyingi zinaweza kutuma ujumbe** kwa mach port, lakini wakati wowote **ni mchakato mmoja tu unaweza kusoma kutoka kwake**. Kama file descriptors na sockets, mach ports zinatengwa na kusimamiwa na kernel na michakato inaona tu nambari ya integer, ambayo wanaweza kuitumia kuelekeza kernel ni mach port gani yao wanataka kutumia.

## XPC Connection

Ikiwa haufahamu jinsi XPC connection inavyowekwa angalia:


{{#ref}}
../
{{#endref}}

## Muhtasari wa Udhaifu

Jambo la kuvutia kujua ni kwamba **XPC’s abstraction ni muunganisho wa mmoja-kwa-mmoja**, lakini imejengwa juu ya teknolojia ambayo **inaweza kuwa na watumaji wengi, kwa hivyo:**

- Mach ports ni mpokeaji mmoja, **watumaji wengi**.
- Audit token ya muunganisho wa XPC ni audit token **iliyokopwa kutoka kwenye ujumbe uliopokelewa hivi karibuni**.
- Kupata **audit token** ya muunganisho wa XPC ni muhimu kwa **manyakati ya usalama** mengi.

Ingawa hali hapo juu inaonekana kuleta changamoto, kuna matukio ambapo hili halita kusababisha matatizo ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens mara nyingi hutumika kwa ukaguzi wa ruhusa kuamua kama kukubali muunganisho. Hii inapofanywa kwa kutumia ujumbe kwenye service port, kwa hivyo **hakuna muunganisho ulioanzishwa bado**. Ujumbe zaidi kwenye port hii utaonyeshwa tu kama maombi ya muunganisho ya ziada. Kwa hivyo, **ukaguzi wowote kabla ya kukubali muunganisho hauwezekani kuathiriwa** (hii pia ina maana kwamba ndani ya `-listener:shouldAcceptNewConnection:` audit token iko salama). Kwa hivyo tunatafuta **XPC connections ambazo zinathibitisha vitendo maalum**.
- Event handlers za XPC zinashughulikiwa kwa sinkroni. Hii inamaanisha kuwa event handler kwa ujumbe mmoja lazima ikamilike kabla ya kuitumia kwa ujumbe mwingine, hata kwenye dispatch queues zinazofanya kazi kwa wakati mmoja. Kwa hivyo ndani ya **XPC event handler** audit token haiwezi kuandikishwa upya na ujumbe wengine wa kawaida (si-reply!).

Mbili njia tofauti ambapo hili linaweza kutumika:

1. Variant1:
- **Exploit** inaunganishwa kwenye service **A** na service **B**
- Service **B** inaweza kuomba **kazi yenye ruhusa za juu** ndani ya service A ambayo mtumiaji hawezi
- Service **A** inaita **`xpc_connection_get_audit_token`** wakati haiko ndani ya **event handler** kwa muunganisho katika **`dispatch_async`**.
- Hivyo ujumbe mwingine unaweza **kuandika upya Audit Token** kwa sababu unashughulikiwa kwa asynchronous nje ya event handler.
- Exploit inampa **service B SEND right kwenda service A**.
- Kwa hivyo svc **B** kweli itakuwa ikituma **ujumbe** kwa service **A**.
- **Exploit** inajaribu **kuomba** kitendo cha ruhusa. Ndani ya RC svc **A** **inachunguza** uthibitisho wa kitendo hicho wakati **svc B imeandika upya Audit token** (ikitoa exploit uwezo wa kuita kitendo cha ruhusa).
2. Variant 2:
- Service **B** inaweza kuomba **kazi yenye ruhusa za juu** ndani ya service A ambayo mtumiaji hawezi
- Exploit inaunganishwa na **service A** ambayo inamtumia exploit **ujumbe ukitarajiwa jibu** kwenye **reply port** maalum.
- Exploit inamtumia **service B** ujumbe ukipitisha **reply port** hiyo.
- Wakati service **B** inareply, inatuma ujumbe kwa **service A**, **wakati** exploit inamtumia ujumbe tofauti kwa **service A** ikijaribu kufikia kazi ya ruhusa na kutegemea kuwa reply kutoka service B itaandika upya Audit token kwa wakati kamili (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Huduma mbili za mach **`A`** na **`B`** ambazo zote mbili tunaweza kuunganishwa (kulingana na sandbox profile na ukaguzi wa ruhusa kabla ya kukubali muunganisho).
- _**A**_ lazima iwe na **ukaguzi wa ruhusa** kwa kitendo maalum ambacho **`B`** kinaweza kupitisha (lakini app yetu haiwezi).
- Kwa mfano, kama B ina baadhi ya **entitlements** au inaendesha kama **root**, inaweza kumruhusu kumwomba A anifanye kitendo cha ruhusa.
- Kwa ajili ya ukaguzi huu wa ruhusa, **`A`** hupata audit token kwa asynchronous, kwa mfano kwa kuita `xpc_connection_get_audit_token` kutoka **`dispatch_async`**.

> [!CAUTION]
> Katika kesi hii mshambulizi anaweza kuanzisha **Race Condition** kufanya **exploit** ambayo **inaomba A kufanya kitendo** mara kadhaa wakati ikifanya **B itume ujumbe kwa `A`**. Wakati RC inafanikiwa, **audit token** ya **B** itakopwa katika kumbukumbu **wakati** ombi la **exploit** linashughulikiwa na A, ikimpa **ufikiaji wa kitendo cha ruhusa ambacho B pekee angeweza kuomba**.

Hili lilitokea na **`A`** kama `smd` na **`B`** kama `diagnosticd`. Kazi [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) kutoka smb inaweza kutumika kusakinisha helper tool mpya yenye ruhusa (kama **root**). Ikiwa mchakato unaoendesha kama root unawasiliana na **smd**, hakuna ukaguzi mwingine utafanywa.

Kwa hivyo, service **B** ni **`diagnosticd`** kwa sababu inaendesha kama **root** na inaweza kutumiwa **kumonitor** mchakato, hivyo mara uchunguzi unaanza, itatuma **ujumbe nyingi kwa sekunde**.

Ili kutekeleza shambulio:

1. Anzisha **muunganisho** na service inayoitwa `smd` ukitumia standard XPC protocol.
2. Tengeneza **muunganisho wa pili** kwa `diagnosticd`. Tofauti na taratibu za kawaida, badala ya kuunda na kutuma mach ports mbili mpya, send right ya client port inabadilishwa na duplicate ya **send right** inayohusiana na muunganisho wa `smd`.
3. Kama matokeo, XPC messages zinaweza kusafirishwa kwenda `diagnosticd`, lakini majibu kutoka `diagnosticd` yatarudishwa kwa `smd`. Kwa `smd`, inaonekana kama ujumbe kutoka kwa mtumiaji na `diagnosticd` vinatoka kwenye muunganisho mmoja huo huo.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Hatua inayofuata ni kumwambia `diagnosticd` kuanza ku-monitor mchakato ulioteuliwa (pengine mchakato wa mtumiaji mwenyewe). Kwa wakati huo huo, mkarifishaji wa ujumbe wa kawaida 1004 unatumwa kwa `smd`. Madhumuni hapa ni kusakinisha tool yenye ruhusa za juu.
5. Hii inasababisha race condition ndani ya function `handle_bless`. Muda ni muhimu: simu ya `xpc_connection_get_pid` lazima irudishe PID ya mchakato wa mtumiaji (kwa sababu tool yenye ruhusa iko ndani ya app bundle ya mtumiaji). Hata hivyo, simu ya `xpc_connection_get_audit_token`, hasa ndani ya subroutine `connection_is_authorized`, lazima ianze kurejelea audit token inayomilikiwa na `diagnosticd`.

## Variant 2: reply forwarding

Katika mazingira ya XPC (Cross-Process Communication), ingawa event handlers hazitekelezwi kwa wakati mmoja, utunzaji wa ujumbe za reply una tabia ya kipekee. Hasa, kuna njia mbili tofauti za kutuma ujumbe zinazotarajia reply:

1. **`xpc_connection_send_message_with_reply`**: Hapa, ujumbe wa XPC unapokelewa na kushughulikiwa kwenye queue iliyoteuliwa.
2. **`xpc_connection_send_message_with_reply_sync`**: Kinyume chake, katika njia hii, ujumbe wa XPC unapokelewa na kushughulikiwa kwenye current dispatch queue.

Tofauti hii ni muhimu kwa sababu inaruhusu uwezekano wa **reply packets kusomwa kwa wakati mmoja na utekelezaji wa XPC event handler**. Kwa kuzingatia hilo, wakati `_xpc_connection_set_creds` hufanya locking ili kulinda dhidi ya kuandikishwa sehemu kwa audit token, haileti ulinzi huu kwa object nzima ya connection. Kwa hivyo, hili linaunda udhaifu ambapo audit token inaweza kubadilishwa katika kipindi kati ya kusomwa kwa packet na utekelezaji wa event handler yake.

Ili kutumia udhaifu huu, setup ifuatayo inahitajika:

- Huduma mbili za mach, zinazoitwa **`A`** na **`B`**, zote ambazo zinaweza kuanzisha muunganisho.
- Service **`A`** inapaswa kuwa na ukaguzi wa ruhusa kwa kitendo maalum ambacho ni `B` tu kinaweza kufanya (app ya mtumiaji haiwezi).
- Service **`A`** inapaswa kutuma ujumbe unaotarajia reply.
- Mtumiaji anaweza kutuma ujumbe kwa **`B`** ambao itareply.

Mchakato wa kutekeleza shambulio unajumuisha hatua zifuatazo:

1. Subiri service **`A`** itume ujumbe unaotarajia reply.
2. Badala ya kujibu moja kwa moja kwa **`A`**, reply port inachukuliwa (hijacked) na kutumiwa kutuma ujumbe kwa service **`B`**.
3. Baadaye, ujumbe unaohusisha kitendo kilichozuiliwa unatumwa, kwa matumaini kwamba utakashughulikiwa kwa wakati mmoja na reply kutoka **`B`**.

Hapo chini kuna uwakilishi wa kuona wa tukio la shambulio lililoelezwa:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Ugumu wa Kupata Matukio**: Kutafuta matumizi ya `xpc_connection_get_audit_token` kulikuwa ngumu, kimetumika statically na dynamically.
- **Methodology**: Frida ilitumika ku-hook function `xpc_connection_get_audit_token`, ikichuja simu zisizoanzia kutoka kwa event handlers. Hata hivyo, mbinu hii ilikuwa na kikomo kwa mchakato ulihookiwa tu na ilihitaji matumizi ya moja kwa moja.
- **Tooling ya Uchambuzi**: Zana kama IDA/Ghidra zilitumika kwa kuchambua mach services zinazoonekana, lakini mchakato ulikuwa mrefu, na kuongezeka kwa ugumu kutokana na simu zinazohusisha dyld shared cache.
- **Matingatingo ya Scripting**: Majaribio ya kuandika script kwa ajili ya uchambuzi wa simu za `xpc_connection_get_audit_token` kutoka ndani ya blocks za `dispatch_async` yalishindwa kutokana na ugumu wa kuchambua blocks na mwingiliano na dyld shared cache.

## The fix <a href="#the-fix" id="the-fix"></a>

- **Masuala yaliyoripotiwa**: Ripoti ilitumwa kwa Apple ikielezea masuala ya jumla na maalum yaliyopatikana ndani ya `smd`.
- **Jibu la Apple**: Apple ilitatua suala hilo ndani ya `smd` kwa kubadilisha `xpc_connection_get_audit_token` na `xpc_dictionary_get_audit_token`.
- **Asili ya Fix**: Kazi ya `xpc_dictionary_get_audit_token` inachukuliwa kuwa salama kwa sababu inapata audit token moja kwa moja kutoka kwa mach message inayohusiana na ujumbe wa XPC uliopokelewa. Hata hivyo, sio sehemu ya public API, kama `xpc_connection_get_audit_token`.
- **Ukosefu wa Fix pana**: Haijaeleweka kwa nini Apple haikutekeleza suluhisho pana zaidi, kama kukataa ujumbe usioendana na audit token iliyohifadhiwa ya muunganisho. Inawezekana kwamba mabadiliko halali ya audit token yanaweza kutokea katika baadhi ya hali (mfano, matumizi ya `setuid`) ambayo inaweza kuwa sababu.
- **Hali ya Sasa**: Tatizo linaendelea kuwepo kwenye iOS 17 na macOS 14, likiwa changamoto kwa wale wanaotafuta kulitambua na kulielewa.

## Finding vulnerable code paths in practice (2024–2025)

Wakati wa kuauditi XPC services kwa daraja hili la mdudu, zingatia ukaguzi wa ruhusa unaofanywa nje ya event handler ya ujumbe au sambamba na usindikaji wa reply.

Wito wa triage static:
- Tafuta simu za `xpc_connection_get_audit_token` zinazoweza kufikiwa kutoka kwa blocks zilizo queud kupitia `dispatch_async`/`dispatch_after` au worker queues nyingine zinazofanya kazi nje ya message handler.
- Tazama helpers za uthibitisho zinazochanganya hali za per-connection na per-message (mfano, kupata PID kutoka `xpc_connection_get_pid` lakini audit token kutoka `xpc_connection_get_audit_token`).
- Katika NSXPC code, hakikisha ukaguzi unafanywa katika `-listener:shouldAcceptNewConnection:` au, kwa ukaguzi wa per-message, utekelezaji unatumia audit token ya kila ujumbe (mfano, kamusi ya ujumbe kupitia `xpc_dictionary_get_audit_token` katika code ya chini ya kiwango).

Vidokezo vya triage dynamic:
- Hook `xpc_connection_get_audit_token` na angaza miito ambazo user stack haitoi njia ya utoaji wa event (mfano, `_xpc_connection_mach_event`). Example Frida hook:
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
Vidokezo:
- Kwenye macOS, instrumenting protected/Apple binaries inaweza kuhitaji SIP kuzimwa au development environment; inashauriwa kujaribu builds zako mwenyewe au userland services.
- Kwa reply-forwarding races (Variant 2), fuatilia concurrent parsing ya reply packets kwa fuzzing timings za `xpc_connection_send_message_with_reply` dhidi ya normal requests, na angalia kama the effective audit token inayotumiwa wakati wa authorization inaweza kuathiriwa.

## Exploitation primitives utakazohitaji

- Multi-sender setup (Variant 1): tengeneza connections kwa A na B; duplicate the send right ya client port ya A na uitumie kama client port ya B ili replies za B ziwasilishwe kwa A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): kamata the send-once right kutoka kwenye ombi linalosubiri la A (reply port), kisha tuma ujumbe uliotengenezwa kwa B ukitumia reply port hiyo ili jibu la B lifike kwa A wakati ombi lako lenye ruhusa linapochambuliwa.

Hizi zinahitaji uundaji wa ujumbe za mach kwenye ngazi ya chini kwa ajili ya XPC bootstrap na muundo wa ujumbe; angalia kurasa za mwongozo mach/XPC katika sehemu hii kwa mpangilio halisi wa packet na flags.

## Useful tooling

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) can help enumerate connections and observe traffic to validate multi-sender setups and timing. Example: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose on `xpc_connection_send_message*` and `xpc_connection_get_audit_token` to log call sites and stacks during black-box testing.



## References

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
