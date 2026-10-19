# Kudunga Ishara kwenye Kiungo cha Mbele cha VSAT

{{#include ../../banners/hacktricks-training.md}}

Terminali ya VSAT kwa kawaida huchukulia downlink ya setilaiti yake kuwa trafiki kutoka kwenye kitovu cha opereta. Katika mfumo wa DVB-RCS, kiungo hicho cha mbele kinaweza kubeba pakiti za IP za mtumiaji pamoja na ujumbe wa udhibiti wa modem. Ikiwa kipokezi hakithibitishi uhalisi wa ujumbe kabla ya kuuchakata, ishara inayodungwa ndani ya eneo hilo inaweza kuvuka mpaka wa uaminifu kati ya redio na control plane. Matokeo yaliyoonyeshwa ni **udungaji wa downlink kwenye terminali**, si uplink kwenda kwenye setilaiti wala kunasa downlink bila kuingilia. Matokeo yanayowezekana hutegemea utekelezaji wa itifaki na uthibitishaji wa ujumbe wa modem, si DVB-RCS pekee.<sup>[[1]](#references)[[2]](#references)</sup>

## Fanya majaribio katika maabara iliyozuiwa RF

Tumia terminali unayomiliki, firmware yake, na SDR iliyounganishwa kwenye ingizo la kipokezi cha modem kupitia kipunguza mawimbi kinachofaa, au tumia usanidi uliofungwa dhidi ya RF. Usisambaze mawimbi kwenye chaneli ya setilaiti inayotumika. Kwanza rekodi carrier ya kuanzia iliyosanidiwa kwenye terminali, kiwango cha alama, na kitambulisho cha idadi ya watumiaji; hivi husaidia kupata kiungo cha mbele.<sup>[[1]](#references)[[3]](#references)</sup> Mlolongo wa upatikanaji wa DVB-RCS hutumia Network Information Table (NIT) kupata RCS Map Table (RMT), kisha Program Association Table (PAT) na Program Map Table (PMT) ili kupata mitiririko ya ishara ya kiungo cha mbele. Terminali inaweza kubadilisha masafa kupitia carriers nyingi za transport stream kabla ya kufikia mtiririko wa data.<sup>[[3]](#references)</sup>

1. Decode au unda upya transport stream ya kuanzia ya lengo, kisha kagua NIT, RMT, service IDs, packet IDs (PIDs), na ushughulikiaji wa marejeleo ya saa. Linganisha kiwango sanifu na parser na logi za lengo; mpangilio au descriptors maalum za mtengenezaji zinaweza kuzuia mtiririko unaokubalika vinginevyo usipokelewe.
2. Katika kisambazaji cha maabara, funga probe salama ya UDP kama `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` na uitume kupitia SDR sink hadi kwenye njia ya kipokezi iliyotengwa. Hakikisha Program Clock Reference (PCR) ya transport stream inalingana na kiwango cha baiti, la sivyo modem inaweza kupoteza usawazishaji kabla ya kuchakata probe.
3. Thibitisha **demodulator lock** na kupokelewa kwa probe kwenye endpoint ya ndani unayoimiliki. Lock pekee huthibitisha tu kwamba physical layer imekubali waveform. Kisha hakiki kama *signalling* ya usimamizi au masasisho isiyothibitishwa uhalisi inaonekana, bila kusakinisha image au kubadilisha usanidi wa huduma.

Kisa kilichochapishwa cha MDM2200 kilitumia moduli ya chanzo ya GNU Radio kwa DVB-RCS/MPE/MPEG-TS na `gr-dtv` kwa modulation ya DVB-S2. Modem yake ilihitaji maelezo maalum ya uanzishaji wa lengo: SDT kabla ya PAT/PMT, RCS content descriptor yenye table ID `0x3E`, na baiti ya faragha ya RMT `0x01` kwa hali yake ya GSE/4CPM. Usidhani thamani hizo zitafanya kazi kwenye terminali nyingine.<sup>[[1]](#references)</sup> Watafiti pia waliona kwamba pakiti za multicast MPE zilifika kwenye modemu zilizokuwa zikizipokea katika usanidi wao, kwa hiyo kulenga hakukuishia kwenye anwani ya MAC ya unicast inayojulikana.<sup>[[1]](#references)</sup> Uchambuzi tofauti uligundua kuwa *signalling* ya udhibiti na masasisho ya programu haikulindwa kwenye mfumo uliochunguzwa, lakini ugunduzi huo lazima uthibitishwe kwa kila utekelezaji.<sup>[[2]](#references)</sup>

Tunnel ya IPsec au VPN ya trafiki ya mtumiaji haithibitishi uhalisi wa *signalling* ya awali ya DVB-RCS au parser ya masasisho ya modem yenyewe. Kwa tathmini iliyoidhinishwa, tofautisha ulinzi wa kriptografia wa **IP ya mtumiaji**, **udhibiti wa kiungo cha mbele**, na trafiki ya **matengenezo/urejeshaji**, badala ya kuchukulia tunnel salama ya mtumiaji kama uthibitisho kwamba udungaji wa mawimbi ya redio umezuiwa.<sup>[[1]](#references)[[2]](#references)</sup>

Kwa ukaguzi wa awali wa I/Q, tazama [uchanganuzi wa ishara za redio](../hardware-hacking/radio.md). Kwa ukaguzi wa firmware na parser upande wa board, tazama [uchanganuzi wa firmware](../firmware-analysis/). Rudi kwenye [muhtasari wa Radio Hacking](./) kwa violesura vingine.

## References

- [1] [Bisping et al. - Mashambulizi ya Kudunga Ishara Zisizotumia Waya dhidi ya Modemu za Setilaiti za VSAT (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: Kufichua Matatizo ya Kimsingi ya Usalama katika Mbinu za Sasa za Mifumo ya VSAT (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - Chaneli ya mwingiliano ya DVB kwa mifumo ya usambazaji wa setilaiti](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
