# macOS xpc_connection_get_audit_token Shambulio

{{#include ../../../../../../banners/hacktricks-training.md}}

**Kwa taarifa zaidi angalia chapisho la awali:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Hii ni muhtasari:

## Mach Messages Taarifa za Msingi

If you don't know what Mach Messages are start checking this page:


{{#ref}}
../../
{{#endref}}

Kwa sasa kumbuka kwamba ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages zinatumwa kupitia _mach port_, ambayo ni **channel ya mawasiliano yenye mpokeaji mmoja, watumaji wengi** iliyojengwa ndani ya mach kernel. **Mchakato mbalimbali yanaweza kutuma ujumbe** kwa mach port, lakini wakati wowote **mchakato mmoja tu anaweza kusoma kutoka kwake**. Kama vile file descriptors na sockets, mach ports zinatengwa na kusimamiwa na kernel na michakato inaona tu namba ya integer, ambayo wanaweza kuitumia kuonyesha kwa kernel ni mach ports gani yao wanataka kutumia.

## XPC Connection

If you don't know how a XPC connection is established check:


{{#ref}}
../
{{#endref}}

## Muhtasari wa Udhaifu

Jambo la kukupendeza kujua ni kwamba **XPC’s abstraction ni muunganisho wa one-to-one**, lakini inatengenezwa juu ya teknolojia ambayo **inaweza kuwa na watumaji wengi, kwa hivyo:**

- Mach ports ni mpokeaji mmoja, **watumaji wengi**.
- Audit token ya muunganisho wa XPC ni audit token iliyo **kopiwa kutoka kwa ujumbe uliopokelewa mara ya mwisho**.
- Kupata **audit token** ya muunganisho wa XPC ni muhimu kwa **ukaguzi wa usalama** mwingi.

Ingawa hali hapo juu inaonekana kuwa hatari, kuna matukio ambapo hii haitasababisha matatizo ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens mara nyingi hutumiwa kwa ukaguzi wa idhini kuamua kama kukubali muunganisho. Kwa kuwa hii hufanyika kwa kutumia ujumbe kwa service port, **hakuna muunganisho ulioanzishwa bado**. Ujumbe zaidi kwenye port hii utashughulikiwa kama maombi ya muunganisho ya ziada. Kwa hivyo, **ukaguzi kabla ya kukubali muunganisho hauwezi kuathiriwa** (hii pia inamaanisha kwamba ndani ya `-listener:shouldAcceptNewConnection:` audit token iko salama). Kwa hiyo tunatafuta muunganisho za XPC ambazo zinathibitisha vitendo maalum baada ya kuanzishwa.
- Handlers za matukio ya XPC zinashughulikiwa kwa sinkronous. Hii inamaanisha kuwa handler ya tukio kwa ujumbe mmoja lazima ikamilike kabla ya kuitwa kwa ujumbe mwingine, hata kwenye dispatch queues zinazofanya kazi kwa concurrently. Kwa hivyo ndani ya **XPC event handler audit token haiwezi kuandikwa upya** na ujumbe mwingine wa kawaida (si-reply!).

Mbinu mbili tofauti ambazo hii inaweza kutumika kuteketeza:

1. Variant1:
- **Exploit** inajenga **muunganisho** kwa service **A** na service **B**
- Service **B** inaweza kuitisha **kazi yenye ruhusa za juu** katika service A ambayo mtumiaji hawezi
- Service **A** inaita **`xpc_connection_get_audit_token`** wakati haiko ndani ya **event handler** kwa muunganisho katika **`dispatch_async`**.
- Kwa hivyo ujumbe **mwingine** unaweza **kuandika upya Audit Token** kwa sababu unashughulikiwa kwa asynchronous nje ya event handler.
- Exploit inamkabidhi **service B haki ya SEND kwa service A**.
- Hivyo svc **B** ataleta kwa kweli **kutuma** **uju mbe** kwa service **A**.
- **Exploit** inajaribu **kuita** kitendo chenye ruhusa. Katika RC svc **A** **inaangalia** uthibitisho wa kitendo hiki wakati **svc B aliandika upya Audit token** (ikimpa exploit uwezo wa kuita kitendo chenye ruhusa).

2. Variant 2:
- Service **B** inaweza kuitisha **kazi yenye ruhusa za juu** katika service A ambayo mtumiaji hawezi
- Exploit inajenga muunganisho na **service A** ambayo inamtumia exploit **ujumbe unaotarajia jibu** kwenye **reply port** maalum.
- Exploit inamtumia **service B** ujumbe ukimkabidhi **reply port** huo.
- Wakati service **B** inareply, inatuma ujumbe kwa service A, **wakati** exploit inamtumia ujumbe mwingine kwa service A ikijaribu kufikia kazi yenye ruhusa na kutegemea kuwa reply kutoka kwa service B itaandika upya Audit token kwa wakati muafaka (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Skenario:

- Huduma mbili za mach **`A`** na **`B`** ambazo zote tunaweza kuunganisha (kutegemea sandbox profile na ukaguzi wa idhini kabla ya kukubali muunganisho).
- _**A**_ lazima iwe na **ukaguzi wa idhini** kwa kitendo maalum ambacho **`B`** kinaweza kupitisha (lakini app yetu haiwezi).
- Kwa mfano, kama B ina baadhi ya **entitlements** au inaendesha kama **root**, inaweza kumruhusu kuomba A kufanya kitendo chenye ruhusa.
- Kwa ajili ya ukaguzi huu, **`A`** hupata audit token kwa asynchronous, kwa mfano kwa kuita `xpc_connection_get_audit_token` kutoka **`dispatch_async`**.

> [!CAUTION]
> Katika kesi hii mshambuliaji anaweza kusababisha **Race Condition** kwa kufanya **exploit** inayomuomba A kufanya kitendo mara kadhaa huku akifanya **B atume ujumbe kwa `A`**. Wakati RC inafanikisha, **audit token** ya **B** itakopiwa katika kumbukumbu **wakati** ombi la **exploit** linashughulikiwa na A, ikimpa **ufikiaji wa kitendo chenye ruhusa ambacho kwa kawaida B tu ingeweza kuomba**.

Hili lilitokea na **`A`** ikiwa `smd` na **`B`** ikiwa `diagnosticd`. Kazi [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) kutoka smb inaweza kutumika kusanidi helper tool mpya yenye ruhusa za juu (kama **root**). Ikiwa **mchakato unaoendesha kama root unawasiliana** na **smd**, hakuna ukaguzi mwingine utakaoendeshwa.

Kwa hiyo, service **B** ni **`diagnosticd`** kwa sababu inaendesha kama **root** na inaweza kutumika **kufuatilia (monitor)** mchakato, hivyo mara monitoring inaanza, itatuma **ujumbe nyingi kwa sekunde.**

Ili kutekeleza shambulio:

1. Anzisha **muunganisho** kwenye service iliyoitwa `smd` ukitumia protocol ya kawaida ya XPC.
2. Tengeneza muunganisho wa pili kwa `diagnosticd`. Kinyume na taratibu za kawaida, badala ya kuunda na kutuma mach ports mbili mpya, client port send right inabadilishwa na duplicate ya **send right** inayohusiana na muunganisho wa `smd`.
3. Matokeo yake, ujumbe za XPC zinaweza kutumwa kwa `diagnosticd`, lakini majibu kutoka `diagnosticd` yarejeshwe kwa `smd`. Kwa `smd`, inaonekana kama ujumbe kutoka kwa mtumiaji na `diagnosticd` yanatoka kwenye muunganisho huo huo.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Hatua inayofuata ni kumuagiza `diagnosticd` kuanza kufuatilia mchakato ulioteuliwa (inawezekana app ya mtumiaji mwenyewe). Wakati huo huo, msongamano wa ujumbe wa kawaida wa 1004 unatumwa kwa `smd`. Lengo hapa ni kusanidi tool yenye privileju.
5. Hili linasababisha race condition ndani ya function `handle_bless`. Muda ni muhimu: mwito wa `xpc_connection_get_pid` lazima urejeshe PID ya mchakato wa mtumiaji (kwa kuwa tool yenye privileju iko katika bundle ya app ya mtumiaji). Hata hivyo, `xpc_connection_get_audit_token`, hasa ndani ya subroutine `connection_is_authorized`, lazima itumie audit token ya `diagnosticd`.

## Variant 2: reply forwarding

Katika mazingira ya XPC (Cross-Process Communication), ingawa event handlers hazifanyi kazi kwa concurrently, utambuzi wa ujumbe wa reply una tabia ya kipekee. Hasa, kuna njia mbili tofauti za kutuma ujumbe zinazotarajiwa jibu:

1. **`xpc_connection_send_message_with_reply`**: Hapa, ujumbe wa XPC unapiwa na kushughulikiwa kwenye queue iliyoteuliwa.
2. **`xpc_connection_send_message_with_reply_sync`**: Kinyume, katika njia hii, ujumbe wa XPC unapokelewa na kushughulikiwa kwenye current dispatch queue.

Tofauti hii ni muhimu kwa sababu inaruhusu uwezekano wa **reply packets kutumika kwa concurrently na utekelezaji wa XPC event handler**. Kwa suala hili, wakati `_xpc_connection_set_creds` inatekeleza locking ili kuzuia overwrite ya sehemu ya audit token, haifunikii kabisa object ya connection. Kwa hivyo, hili linafanya udhaifu ambapo audit token inaweza kubadilishwa ndani ya kipindi kati ya kusoma packet na utekelezaji wa event handler yake.

Ili kutumia udhaifu huu, setup ifuatayo inahitajika:

- Huduma mbili za mach, zinazoitwa **`A`** na **`B`**, zote zinaweza kuanzisha muunganisho.
- Service **`A`** inapaswa kujumuisha ukaguzi wa idhini kwa kitendo maalum ambacho ni tu **`B`** inaweza kufanya (app ya mtumiaji haiwezi).
- Service **`A`** inapaswa kutuma ujumbe unaotarajia jibu.
- Mtumiaji anaweza kutuma ujumbe kwa **`B`** ambalo B litareply.

Mchakato wa exploitation unahusisha hatua zifuatazo:

1. Subiri service **`A`** itume ujumbe unaotarajia jibu.
2. Badala ya kureply moja kwa moja kwa **`A`**, reply port inachukuliwa na kutumiwa kutuma ujumbe kwa service **`B`**.
3. Baadaye, ujumbe unaohusisha kitendo kilichoruhusiwa kutumwa, ukitarajia kushughulikiwa kwa concurrently na reply kutoka kwa **`B`**.

Hapa chini kuna uwakilishi wa kuona wa skenario ya shambulio iliyotajwa:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Matatizo ya Kugundua

- **Ugumu wa Kupata Matukio**: Kutafuta matumizi ya `xpc_connection_get_audit_token` kilikuwa changamoto, kimetumika kwa static na dynamic.
- **Mbinu**: Frida ilitumika ku-hook `xpc_connection_get_audit_token`, ikichuja ant calls ambazo hazikuanzia kutoka kwa event handlers. Hata hivyo, njia hii ilikuwa na kikomo kwa process iliyohookiwa na ilihitaji matumizi ya active.
- **Vifaa vya Uchambuzi**: Zana kama IDA/Ghidra zilitumika kuchunguza mach services zinazoweza kufikiwa, lakini ilikuwa inachukua muda, iliyo changamoto kwa miito inayohusisha dyld shared cache.
- **Mikato ya Scripting**: Jaribio la kuandika script ya uchambuzi kwa miito ya `xpc_connection_get_audit_token` kutoka kwa blocks zilizoorodheshwa via `dispatch_async` lilishindwa kwa sababu za ugumu katika parsing blocks na mwingiliano na dyld shared cache.

## The fix <a href="#the-fix" id="the-fix"></a>

- **Ripoti Zilizotumwa**: Ripoti ilitumwa kwa Apple ikielezea matatizo ya jumla na maalum yaliyopatikana ndani ya `smd`.
- **Jibu la Apple**: Apple ilitatua suala hilo ndani ya `smd` kwa kubadilisha `xpc_connection_get_audit_token` na `xpc_dictionary_get_audit_token`.
- **Asili ya Fix**: Kazi ya `xpc_dictionary_get_audit_token` inachukuliwa kuwa salama kwa kuwa inapata audit token moja kwa moja kutoka kwa mach message inayohusishwa na ujumbe wa XPC uliopokelewa. Hata hivyo, si sehemu ya public API, kama `xpc_connection_get_audit_token`.
- **Kutokuwepo kwa Fix pana zaidi**: Haijulikani kwanini Apple haikuweka fix ya kina zaidi, kama vile kupondwa kwa ujumbe usiowiana na audit token iliyohifadhiwa ya connection. Inawezekana kuna matukio halali ya mabadiliko ya audit token (mfano, matumizi ya `setuid`) ambayo inaweza kuwa sababu.
- **Hali ya Sasa**: Tatizo linaendelea kwenye iOS 17 na macOS 14, likiwa changamoto kwa wale wanaotaka kuibua na kuelewa.

## Kupata njia za code zilizo hatarishi katika vitendo (2024–2025)

Wakati ukaguzi wa XPC services kwa daraja hili la bug, zingatia idhini zinazofanywa nje ya event handler ya ujumbe au kwa concurrently na usindikaji wa reply.

Wito la triage ya static:
- Tafuta miito ya `xpc_connection_get_audit_token` inayofikiwa kutoka blocks zilizoorodheshwa kupitia `dispatch_async`/`dispatch_after` au queues nyingine za worker zinazofanya kazi nje ya message handler.
- Angalia helpers za idhini zinazochanganya state kwa muunganisho mzima na kwa ujumbe binafsi (mfano, pata PID kutoka `xpc_connection_get_pid` lakini audit token kutoka `xpc_connection_get_audit_token`).
- Katika code ya NSXPC, hakikisha kuwa ukaguzi unafanywa katika `-listener:shouldAcceptNewConnection:` au, kwa ukaguzi wa kila ujumbe, utekelezaji unatumia audit token ya kila ujumbe (mfano, kamusi ya ujumbe kupitia `xpc_dictionary_get_audit_token` katika code ya lower-level).

Vidokezo vya triage ya dynamic:
- Hook `xpc_connection_get_audit_token` na tambua miito ambazo user stack yake haina njia ya event-delivery (mfano, `_xpc_connection_mach_event`). Mfano wa Frida hook:
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
- Kwenye macOS, instrumenting protected/Apple binaries inaweza kuhitaji SIP iwe imezimwa au mazingira ya maendeleo; pendekeza kujaribu builds zako mwenyewe au userland services.
- Kwa reply-forwarding races (Variant 2), angalia parsing sambamba ya reply packets kwa fuzzing timings ya `xpc_connection_send_message_with_reply` dhidi ya requests za kawaida na uhakiki kama effective audit token inayotumika wakati wa authorization inaweza kuathiriwa.

## Exploitation primitives unazoweza kuhitaji

- Multi-sender setup (Variant 1): tengeneza connections kwa A na B; duplicate the send right ya A’s client port na uitumie kama client port ya B ili replies za B ziwasilishwe kwa A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): chukua haki ya send-once kutoka kwa ombi linalosubiri la A (reply port), kisha tuma ujumbe uliotengenezwa kwa B ukitumia reply port hiyo ili jibu la B lifikiswe kwa A wakati ombi lako lenye ruhusa linapochambuliwa.

Hizi zinahitaji utengenezaji wa ujumbe wa mach wa kiwango cha chini kwa ajili ya XPC bootstrap na muundo wa ujumbe; pitia ukurasa wa mwongozo wa mach/XPC katika sehemu hii kwa mpangilio sahihi wa vifurushi na bendera.

## Vifaa muhimu

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) inaweza kusaidia kuorodhesha connections na kuangalia traffic ili kuthibitisha setups za multi-sender na timing. Mfano: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose on `xpc_connection_send_message*` and `xpc_connection_get_audit_token` ili kurekodi call sites na stacks wakati wa black-box testing.



## Marejeleo

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
