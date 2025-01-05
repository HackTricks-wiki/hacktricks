# BloodHound & Other AD Enum Tools

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) ni kutoka Sysinternal Suite:

> Mtazamaji na mhariri wa juu wa Active Directory (AD). Unaweza kutumia AD Explorer kuvinjari hifadhidata ya AD kwa urahisi, kufafanua maeneo unayopenda, kuangalia mali za vitu, na sifa bila kufungua masanduku ya mazungumzo, kuhariri ruhusa, kuangalia muundo wa kitu, na kutekeleza utafutaji wa kisasa ambao unaweza kuokoa na kurudi kutekeleza.

### Snapshots

AD Explorer inaweza kuunda snapshots za AD ili uweze kuangalia mtandaoni.\
Inaweza kutumika kugundua vulns mtandaoni, au kulinganisha hali tofauti za DB ya AD kwa muda.

Utahitaji jina la mtumiaji, nenosiri, na mwelekeo wa kuungana (mtumiaji yeyote wa AD anahitajika).

Ili kuchukua snapshot ya AD, nenda kwenye `File` --> `Create Snapshot` na ingiza jina la snapshot.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) ni chombo ambacho kinatoa na kuunganisha vitu mbalimbali kutoka katika mazingira ya AD. Taarifa zinaweza kuwasilishwa katika **ripoti** ya Microsoft Excel **iliyoundwa kwa njia maalum** ambayo inajumuisha muonekano wa muhtasari na vipimo ili kuwezesha uchambuzi na kutoa picha kamili ya hali ya sasa ya mazingira ya AD ya lengo.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound ni programu ya wavuti ya Javascript ya ukurasa mmoja, iliyojengwa juu ya [Linkurious](http://linkurio.us/), iliyokusanywa na [Electron](http://electron.atom.io/), ikiwa na hifadhidata ya [Neo4j](https://neo4j.com/) inayopatiwa na mkusanyiko wa data wa C#.

BloodHound inatumia nadharia ya grafu kufichua uhusiano wa siri na mara nyingi usiokusudiwa ndani ya mazingira ya Active Directory au Azure. Washambuliaji wanaweza kutumia BloodHound kutambua kwa urahisi njia za shambulio zenye ugumu mkubwa ambazo vinginevyo zingekuwa ngumu kutambua haraka. Walinzi wanaweza kutumia BloodHound kutambua na kuondoa njia hizo za shambulio. Timu za buluu na nyekundu zinaweza kutumia BloodHound kupata uelewa mzuri zaidi wa uhusiano wa mamlaka katika mazingira ya Active Directory au Azure.

Hivyo, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound) ni chombo cha ajabu ambacho kinaweza kuhesabu kikoa kiotomatiki, kuhifadhi taarifa zote, kutafuta njia zinazowezekana za kupandisha mamlaka na kuonyesha taarifa zote kwa kutumia grafu.

Booldhound inajumuisha sehemu 2 kuu: **ingestors** na **programu ya uonyeshaji**.

**Ingestors** zinatumika ku **hesabu kikoa na kutoa taarifa zote** katika muundo ambao programu ya uonyeshaji itaelewa.

**Programu ya uonyeshaji inatumia neo4j** kuonyesha jinsi taarifa zote zinavyohusiana na kuonyesha njia tofauti za kupandisha mamlaka katika kikoa.

### Installation

Baada ya kuundwa kwa BloodHound CE, mradi mzima ulisasishwa ili urahisi wa matumizi na Docker. Njia rahisi ya kuanza ni kutumia usanidi wa Docker Compose ulioandaliwa mapema.

1. Sakinisha Docker Compose. Hii inapaswa kujumuishwa na usakinishaji wa [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Endesha:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Pata nenosiri lililotengenezwa kwa bahati katika matokeo ya terminal ya Docker Compose.  
4. Katika kivinjari, tembelea http://localhost:8080/ui/login. Ingia kwa jina la mtumiaji admin na nenosiri lililotengenezwa kwa bahati kutoka kwa kumbukumbu.

Baada ya hii, utahitaji kubadilisha nenosiri lililotengenezwa kwa bahati na utakuwa na kiolesura kipya kilichokamilika, ambacho unaweza kupakua ingestors moja kwa moja.

### SharpHound

Wana chaguzi kadhaa lakini ikiwa unataka kuendesha SharpHound kutoka PC iliyojiunga na eneo, ukitumia mtumiaji wako wa sasa na kutoa taarifa zote unaweza kufanya:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Unaweza kusoma zaidi kuhusu **CollectionMethod** na kikao cha loop [hapa](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Ikiwa unataka kutekeleza SharpHound kwa kutumia akidi tofauti unaweza kuunda kikao cha CMD netonly na kuendesha SharpHound kutoka hapo:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Jifunze zaidi kuhusu Bloodhound katika ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) ni chombo cha kutafuta **vulnerabilities** katika Active Directory zinazohusiana na **Group Policy**. \
Unahitaji **kuendesha group3r** kutoka kwa mwenyeji ndani ya eneo ukitumia **mtumiaji yeyote wa eneo**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **inafanya tathmini ya usalama wa mazingira ya AD** na inatoa **ripoti** nzuri yenye grafu.

Ili kuikimbia, unaweza kutekeleza binary `PingCastle.exe` na itaanzisha **sehemu ya maingiliano** ikionyesha menyu ya chaguzi. Chaguo la msingi kutumia ni **`healthcheck`** ambalo litaanzisha **muonekano** wa **kanda**, na kutafuta **mipangilio isiyo sahihi** na **udhaifu**.

{{#include ../../banners/hacktricks-training.md}}
