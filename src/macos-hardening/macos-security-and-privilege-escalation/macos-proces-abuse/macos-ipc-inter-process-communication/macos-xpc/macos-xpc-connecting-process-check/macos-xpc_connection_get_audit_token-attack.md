# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi angalia chapisho asilia:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Hii ni muhtasari:

## Mach Messages Basic Info

Ikiwa hujui Mach Messages ni nini anza kuangalia ukurasa huu:


{{#ref}}
../../
{{#endref}}

Kwa sasa kumbuka kwamba ([mwelekeo kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages hutumwa kupitia _mach port_, ambayo ni **channel ya mawasiliano ya mpokeaji mmoja, watumaji wengi** iliyojengwa ndani ya kernel ya mach. **Mchakato wengi wanaweza kutuma ujumbe** kwa mach port, lakini wakati wowote **mchakato mmoja tu unaweza kusoma kutoka kwake**. Kama vile file descriptors na sockets, mach ports zinagawiwa na kusimamiwa na kernel na michakato yanaona tu nambari, ambayo wanaweza kuitumia kuonyesha kwa kernel ni mach ports gani wanataka kutumia.

## XPC Connection

Ikiwa hujui jinsi XPC connection inavyoundwa angalia:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Kile ambacho ni muhimu kwako kujua ni kwamba **abstraction ya XPC ni muunganisho mmoja kwa mmoja**, lakini inategemea teknolojia ambayo **inaweza kuwa na watumaji wengi, hivyo:**

- Mach ports ni mpokeaji mmoja, **watumaji wengi**.
- Token ya ukaguzi ya XPC connection ni token ya ukaguzi ya **iliyokopwa kutoka kwa ujumbe uliopokelewa hivi karibuni**.
- Kupata **token ya ukaguzi** ya XPC connection ni muhimu kwa **ukaguzi wa usalama** wengi.

Ingawa hali ya awali inaonekana kuwa na matumaini kuna baadhi ya hali ambapo hii haitasababisha matatizo ([kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Token za ukaguzi mara nyingi hutumiwa kwa ukaguzi wa idhini ili kuamua ikiwa kubali muunganisho. Kadri hii inavyotokea kwa kutumia ujumbe kwa huduma port, **hakuna muunganisho ulioanzishwa bado**. Ujumbe zaidi kwenye port hii utaendeshwa kama maombi ya muunganisho ya ziada. Hivyo, **ukaguzi wowote kabla ya kukubali muunganisho hauko hatarini** (hii pia inamaanisha kwamba ndani ya `-listener:shouldAcceptNewConnection:` token ya ukaguzi iko salama). Kwa hivyo, **tunatafuta XPC connections ambazo zinathibitisha vitendo maalum**.
- XPC event handlers zinashughulikiwa kwa ushirikiano. Hii inamaanisha kwamba mpangilio wa tukio kwa ujumbe mmoja lazima ukamilishwe kabla ya kuitwa kwa ujumbe unaofuata, hata kwenye queues za dispatch zinazoshirikiana. Hivyo ndani ya **XPC event handler token ya ukaguzi haiwezi kuandikwa upya** na ujumbe mwingine wa kawaida (usijibu!).

Mbinu mbili tofauti ambazo hii inaweza kuwa hatarini:

1. Variant1:
- **Exploit** **inaungana** na huduma **A** na huduma **B**
- Huduma **B** inaweza kuita **kazi yenye mamlaka** katika huduma A ambayo mtumiaji hawezi
- Huduma **A** inaita **`xpc_connection_get_audit_token`** wakati _**siyo**_ ndani ya **event handler** kwa muunganisho katika **`dispatch_async`**.
- Hivyo ujumbe **mwingine** unaweza **kuandika upya Audit Token** kwa sababu unatumwa kwa ushirikiano nje ya event handler.
- The exploit inapeleka kwa **huduma B haki ya SEND kwa huduma A**.
- Hivyo svc **B** itakuwa kwa kweli **ikipeleka** **ujumbe** kwa huduma **A**.
- The **exploit** inajaribu **kuita** **kitendo chenye mamlaka.** Katika RC svc **A** **inaangalia** idhini ya **kitendo** hiki wakati **svc B iliandika upya token ya ukaguzi** (ikiipa exploit ufikiaji wa kuita kitendo chenye mamlaka).
2. Variant 2:
- Huduma **B** inaweza kuita **kazi yenye mamlaka** katika huduma A ambayo mtumiaji hawezi
- Exploit inaungana na **huduma A** ambayo **inatuma** exploit ujumbe **ukitarajia jibu** katika **port** maalum ya **replay**.
- Exploit inatuma **huduma** B ujumbe ikipitia **port hiyo ya jibu**.
- Wakati huduma **B inajibu**, inatuma ujumbe kwa huduma A, **wakati** **exploit** inatuma ujumbe tofauti kwa huduma A ikijaribu **kufikia kazi yenye mamlaka** na ikitarajia kwamba jibu kutoka huduma B litaandika upya token ya ukaguzi kwa wakati mzuri (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Hali:

- Huduma mbili za mach **`A`** na **`B`** ambazo tunaweza kuungana nazo zote (kulingana na profaili ya sandbox na ukaguzi wa idhini kabla ya kukubali muunganisho).
- _**A**_ lazima iwe na **ukaguzi wa idhini** kwa kitendo maalum ambacho **`B`** inaweza kupitisha (lakini programu yetu haiwezi).
- Kwa mfano, ikiwa B ina **entitlements** fulani au inafanya kazi kama **root**, inaweza kumruhusu kuomba A kufanya kitendo chenye mamlaka.
- Kwa ajili ya ukaguzi huu wa idhini, **`A`** inapata token ya ukaguzi kwa ushirikiano, kwa mfano kwa kuita `xpc_connection_get_audit_token` kutoka **`dispatch_async`**.

> [!CAUTION]
> Katika kesi hii mshambuliaji anaweza kuanzisha **Race Condition** akifanya **exploit** ambayo **inaomba A kufanya kitendo** mara kadhaa huku ikifanya **B itume ujumbe kwa `A`**. Wakati RC inafanikiwa, **token ya ukaguzi** ya **B** itakopwa kwenye kumbukumbu **wakati** ombi la **exploit** yetu linashughulikiwa na A, ikitoa **ufikiaji wa kitendo chenye mamlaka ambacho ni B pekee angeweza kuomba**.

Hii ilitokea na **`A`** kama `smd` na **`B`** kama `diagnosticd`. Kazi [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) kutoka smb inaweza kutumika kufunga zana mpya ya msaada yenye mamlaka (kama **root**). Ikiwa **mchakato unaofanya kazi kama root unawasiliana** na **smd**, hakuna ukaguzi mwingine utakaofanywa.

Kwa hivyo, huduma **B** ni **`diagnosticd`** kwa sababu inafanya kazi kama **root** na inaweza kutumika **kuangalia** mchakato, hivyo mara tu ufuatiliaji umeanzishwa, itatuma **ujumbe mwingi kwa sekunde**.

Ili kutekeleza shambulio:

1. Anzisha **muunganisho** na huduma iliyopewa jina `smd` kwa kutumia protokali ya kawaida ya XPC.
2. Unda **muunganisho** wa pili na `diagnosticd`. Kinyume na utaratibu wa kawaida, badala ya kuunda na kutuma mach ports mawili mapya, haki ya port ya mteja inabadilishwa na nakala ya **haki ya kutuma** inayohusishwa na muunganisho wa `smd`.
3. Kama matokeo, ujumbe wa XPC unaweza kutumwa kwa `diagnosticd`, lakini majibu kutoka `diagnosticd` yanarudishwa kwa `smd`. Kwa `smd`, inaonekana kana kwamba ujumbe kutoka kwa mtumiaji na `diagnosticd` unatoka kwenye muunganisho mmoja.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Hatua inayofuata inahusisha kuagiza `diagnosticd` kuanzisha ufuatiliaji wa mchakato uliochaguliwa (labda wa mtumiaji mwenyewe). Kwa wakati mmoja, mafuriko ya ujumbe wa kawaida wa 1004 yanatumwa kwa `smd`. Lengo hapa ni kufunga zana yenye mamlaka.
5. Kitendo hiki kinachochea hali ya mbio ndani ya kazi ya `handle_bless`. Wakati ni muhimu: wito wa kazi ya `xpc_connection_get_pid` lazima urudishe PID ya mchakato wa mtumiaji (kama zana yenye mamlaka iko kwenye kifurushi cha programu ya mtumiaji). Hata hivyo, kazi ya `xpc_connection_get_audit_token`, hasa ndani ya subroutine ya `connection_is_authorized`, lazima irejelee token ya ukaguzi inayomilikiwa na `diagnosticd`.

## Variant 2: reply forwarding

Katika mazingira ya XPC (Mawasiliano Kati ya Michakato), ingawa event handlers hazitekelezwi kwa wakati mmoja, usindikaji wa ujumbe wa jibu una tabia ya kipekee. Kwa haswa, kuna mbinu mbili tofauti za kutuma ujumbe zinazotarajia jibu:

1. **`xpc_connection_send_message_with_reply`**: Hapa, ujumbe wa XPC unapokelewa na kushughulikiwa kwenye queue iliyotengwa.
2. **`xpc_connection_send_message_with_reply_sync`**: Kinyume chake, katika mbinu hii, ujumbe wa XPC unapokelewa na kushughulikiwa kwenye queue ya sasa ya dispatch.

Tofauti hii ni muhimu kwa sababu inaruhusu uwezekano wa **pakiti za jibu kuchambuliwa kwa wakati mmoja na utekelezaji wa XPC event handler**. Kwa kuzingatia, wakati `_xpc_connection_set_creds` inatekeleza kufunga ili kulinda dhidi ya kuandika upya kwa sehemu ya token ya ukaguzi, haipanui ulinzi huu kwa kitu chote cha muunganisho. Kwa hivyo, hii inaunda hatari ambapo token ya ukaguzi inaweza kubadilishwa wakati wa kipindi kati ya uchambuzi wa pakiti na utekelezaji wa event handler yake.

Ili kutumia hatari hii, mipangilio ifuatayo inahitajika:

- Huduma mbili za mach, zinazoitwa **`A`** na **`B`**, ambazo zote zinaweza kuanzisha muunganisho.
- Huduma **`A`** inapaswa kujumuisha ukaguzi wa idhini kwa kitendo maalum ambacho ni **`B`** pekee inaweza kutekeleza (programu ya mtumiaji haiwezi).
- Huduma **`A`** inapaswa kutuma ujumbe unaotarajia jibu.
- Mtumiaji anaweza kutuma ujumbe kwa **`B`** ambao itajibu.

Mchakato wa kutumia unajumuisha hatua zifuatazo:

1. Subiri huduma **`A`** itume ujumbe unaotarajia jibu.
2. Badala ya kujibu moja kwa moja kwa **`A`**, port ya jibu inatekwa na kutumika kutuma ujumbe kwa huduma **`B`**.
3. Kisha, ujumbe unaohusisha kitendo kisichoruhusiwa unatumwa, ukiwa na matarajio kwamba utashughulikiwa kwa wakati mmoja na jibu kutoka **`B`**.

Hapa kuna picha ya kuwakilisha hali ya shambulio iliyoelezwa:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Changamoto katika Kutafuta Mifano**: Kutafuta mifano ya matumizi ya `xpc_connection_get_audit_token` ilikuwa ngumu, kwa njia zote za statically na dynamically.
- **Mbinu**: Frida ilitumika kuunganisha kazi ya `xpc_connection_get_audit_token`, ikichuja wito ambao haukutoka kwenye event handlers. Hata hivyo, mbinu hii ilikuwa na mipaka kwa mchakato uliounganishwa na ilihitaji matumizi ya moja kwa moja.
- **Zana za Uchambuzi**: Zana kama IDA/Ghidra zilitumika kuchunguza huduma za mach zinazoweza kufikiwa, lakini mchakato ulikuwa wa kuchukua muda, ukichochewa na wito unaohusisha cache ya pamoja ya dyld.
- **Mipaka ya Scripting**: Jaribio la kuandika script ya uchambuzi wa wito kwa `xpc_connection_get_audit_token` kutoka kwa blocks za `dispatch_async` lilikwamishwa na changamoto katika uchambuzi wa blocks na mwingiliano na cache ya pamoja ya dyld.

## The fix <a href="#the-fix" id="the-fix"></a>

- **Masuala Yaliyoripotiwa**: Ripoti ilitumwa kwa Apple ikielezea masuala ya jumla na maalum yaliyopatikana ndani ya `smd`.
- **Majibu ya Apple**: Apple ilishughulikia suala hilo katika `smd` kwa kubadilisha `xpc_connection_get_audit_token` na `xpc_dictionary_get_audit_token`.
- **Aina ya Marekebisho**: Kazi ya `xpc_dictionary_get_audit_token` inachukuliwa kuwa salama kwani inapata token ya ukaguzi moja kwa moja kutoka kwa ujumbe wa mach unaohusishwa na ujumbe wa XPC uliopokelewa. Hata hivyo, si sehemu ya API ya umma, kama `xpc_connection_get_audit_token`.
- **Ukosefu wa Marekebisho Mapana**: Bado haijulikani kwa nini Apple haikuanzisha marekebisho ya kina zaidi, kama vile kutupa ujumbe ambao hauendani na token ya ukaguzi iliyohifadhiwa ya muunganisho. Uwezekano wa mabadiliko halali ya token ya ukaguzi katika hali fulani (kwa mfano, matumizi ya `setuid`) huenda ni sababu.
- **Hali ya Sasa**: Tatizo linaendelea kuwepo katika iOS 17 na macOS 14, likiwa changamoto kwa wale wanaotafuta kubaini na kuelewa.

{{#include ../../../../../../banners/hacktricks-training.md}}
