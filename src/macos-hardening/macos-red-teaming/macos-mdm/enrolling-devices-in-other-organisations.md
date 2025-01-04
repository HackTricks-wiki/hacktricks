# Kujiandikisha Vifaa katika Mashirika Mengine

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Kama [**ilivyosemwa awali**](#what-is-mdm-mobile-device-management)**,** ili kujaribu kujiandikisha kifaa katika shirika **ni nambari ya Serial pekee inayohitajika**. Mara kifaa kinapojiandikisha, mashirika kadhaa yataweka data nyeti kwenye kifaa kipya: vyeti, programu, nywila za WiFi, mipangilio ya VPN [na kadhalika](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Hivyo, hii inaweza kuwa njia hatari kwa washambuliaji ikiwa mchakato wa kujiandikisha haujalindwa ipasavyo.

**Ifuatayo ni muhtasari wa utafiti [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Angalia kwa maelezo zaidi ya kiufundi!**

## Muhtasari wa Uchambuzi wa Binaries za DEP na MDM

Utafiti huu unachunguza binaries zinazohusiana na Programu ya Kujiandikisha Vifaa (DEP) na Usimamizi wa Vifaa vya Mkononi (MDM) kwenye macOS. Vipengele muhimu ni:

- **`mdmclient`**: Inawasiliana na seva za MDM na kuanzisha ukaguzi wa DEP kwenye toleo la macOS kabla ya 10.13.4.
- **`profiles`**: Inasimamia Profaili za Mipangilio, na kuanzisha ukaguzi wa DEP kwenye toleo la macOS 10.13.4 na baadaye.
- **`cloudconfigurationd`**: Inasimamia mawasiliano ya API ya DEP na inapata profaili za Kujiandikisha Vifaa.

Ukaguzi wa DEP unatumia kazi za `CPFetchActivationRecord` na `CPGetActivationRecord` kutoka kwa mfumo wa faragha wa Profaili za Mipangilio ili kupata Rekodi ya Uanzishaji, huku `CPFetchActivationRecord` ikishirikiana na `cloudconfigurationd` kupitia XPC.

## Uhandisi wa Kurudi wa Protokali ya Tesla na Mpango wa Absinthe

Ukaguzi wa DEP unahusisha `cloudconfigurationd` kutuma payload ya JSON iliyosainiwa na iliyosimbwa kwa _iprofiles.apple.com/macProfile_. Payload hiyo inajumuisha nambari ya serial ya kifaa na hatua "RequestProfileConfiguration". Mpango wa usimbaji unaotumika unajulikana kwa ndani kama "Absinthe". Kufichua mpango huu ni ngumu na kunahusisha hatua nyingi, ambazo zilisababisha kuchunguza njia mbadala za kuingiza nambari za serial zisizo za kawaida katika ombi la Rekodi ya Uanzishaji.

## Kuingilia Maombi ya DEP

Jaribio la kukamata na kubadilisha maombi ya DEP kwa _iprofiles.apple.com_ kwa kutumia zana kama Charles Proxy lilikwamishwa na usimbaji wa payload na hatua za usalama za SSL/TLS. Hata hivyo, kuwezesha usanidi wa `MCCloudConfigAcceptAnyHTTPSCertificate` kunaruhusu kupita uthibitisho wa cheti cha seva, ingawa asili ya payload iliyosimbwa bado inazuia kubadilisha nambari ya serial bila funguo ya kufichua.

## Kuandaa Binaries za Mfumo Zinazoshirikiana na DEP

Kuandaa binaries za mfumo kama `cloudconfigurationd` kunahitaji kuzima Ulinzi wa Uadilifu wa Mfumo (SIP) kwenye macOS. Ikiwa SIP imezimwa, zana kama LLDB zinaweza kutumika kuunganishwa na michakato ya mfumo na labda kubadilisha nambari ya serial inayotumika katika mawasiliano ya API ya DEP. Njia hii inpreferiwa kwani inakwepa changamoto za haki na saini ya msimbo.

**Kutatua Uhandisi wa Binaries:**
Kubadilisha payload ya ombi la DEP kabla ya uwasilishaji wa JSON katika `cloudconfigurationd` ilionekana kuwa na ufanisi. Mchakato huo ulijumuisha:

1. Kuunganisha LLDB na `cloudconfigurationd`.
2. Kutafuta mahali ambapo nambari ya serial ya mfumo inapatikana.
3. Kuingiza nambari ya serial isiyo ya kawaida kwenye kumbukumbu kabla ya payload kusimbwa na kutumwa.

Njia hii iliruhusu kupata profaili kamili za DEP kwa nambari za serial zisizo za kawaida, ikionyesha udhaifu wa uwezekano.

### Kuandaa Uhandisi kwa Kutumia Python

Mchakato wa kutekeleza ulifanywa kuwa wa kiotomatiki kwa kutumia Python na API ya LLDB, na kufanya iwezekane kuingiza nambari za serial zisizo za kawaida kwa njia ya programu na kupata profaili zinazolingana za DEP.

### Athari Zinazoweza Kutokana na Udhaifu wa DEP na MDM

Utafiti huo ulionyesha wasiwasi mkubwa wa usalama:

1. **Ufunuo wa Taarifa**: Kwa kutoa nambari ya serial iliyosajiliwa na DEP, taarifa nyeti za shirika zilizomo katika profaili ya DEP zinaweza kupatikana.

{{#include ../../../banners/hacktricks-training.md}}
