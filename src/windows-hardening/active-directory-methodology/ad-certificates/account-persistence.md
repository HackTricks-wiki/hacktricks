# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari mdogo wa sura za kudumu za mashine kutoka kwa utafiti mzuri wa [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## **Kuelewa Wizi wa Akreditivu za Watumiaji Wanaofanya Kazi kwa kutumia Vyeti – PERSIST1**

Katika hali ambapo cheti kinachoruhusu uthibitisho wa kikoa kinaweza kuombwa na mtumiaji, mshambuliaji ana fursa ya **kuomba** na **kuchukua** cheti hiki ili **kuhifadhi kudumu** kwenye mtandao. Kwa kawaida, kiolezo cha `User` katika Active Directory kinaruhusu maombi kama haya, ingawa wakati mwingine kinaweza kuzuiliwa.

Kwa kutumia zana inayoitwa [**Certify**](https://github.com/GhostPack/Certify), mtu anaweza kutafuta vyeti halali vinavyowezesha ufikiaji wa kudumu:
```bash
Certify.exe find /clientauth
```
Inasisitizwa kwamba nguvu ya cheti iko katika uwezo wake wa **kujiuthibitisha kama mtumiaji** anayemilikiwa, bila kujali mabadiliko yoyote ya nenosiri, mradi cheti kimebaki **halali**.

Vyeti vinaweza kuombwa kupitia kiolesura cha picha kwa kutumia `certmgr.msc` au kupitia mstari wa amri na `certreq.exe`. Pamoja na **Certify**, mchakato wa kuomba cheti umewekwa rahisi kama ifuatavyo:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Baada ya ombi kufanikiwa, cheti pamoja na funguo yake ya faragha kinatengenezwa katika muundo wa `.pem`. Ili kubadilisha hii kuwa faili ya `.pfx`, ambayo inaweza kutumika kwenye mifumo ya Windows, amri ifuatayo inatumika:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Faili la `.pfx` linaweza kupakiwa kwenye mfumo wa lengo na kutumika na chombo kinachoitwa [**Rubeus**](https://github.com/GhostPack/Rubeus) kuomba Tiketi ya Kutoa Tiketi (TGT) kwa mtumiaji, ikipanua ufikiaji wa mshambuliaji kwa muda mrefu kama cheti ni **halali** (kawaida mwaka mmoja):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Kikumbusho muhimu kinashirikiwa kuhusu jinsi mbinu hii, ikichanganywa na njia nyingine iliyoelezwa katika sehemu ya **THEFT5**, inamruhusu mshambuliaji kupata kwa kudumu **NTLM hash** ya akaunti bila kuingiliana na Local Security Authority Subsystem Service (LSASS), na kutoka katika muktadha usio na kiwango cha juu, ikitoa njia ya siri ya wizi wa akidi za muda mrefu.

## **K kupata Uthibitisho wa Mashine kwa kutumia Vyeti - PERSIST2**

Njia nyingine inahusisha kujiandikisha akaunti ya mashine ya mfumo ulioathirika kwa ajili ya cheti, ikitumia kigezo cha `Machine` cha kawaida ambacho kinaruhusu vitendo kama hivyo. Ikiwa mshambuliaji atapata mamlaka ya juu kwenye mfumo, wanaweza kutumia akaunti ya **SYSTEM** kuomba vyeti, wakitoa aina ya **persistence**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Hii ufikiaji inamwezesha mshambuliaji kuthibitisha kwa **Kerberos** kama akaunti ya mashine na kutumia **S4U2Self** kupata tiketi za huduma za Kerberos kwa huduma yoyote kwenye mwenyeji, kwa ufanisi ikimpa mshambuliaji ufikiaji wa kudumu kwa mashine.

## **Kupanua Uthibitisho Kupitia Upya Leseni - PERSIST3**

Njia ya mwisho iliyozungumziwa inahusisha kutumia **uhalali** na **muda wa upya** wa mifano ya leseni. Kwa **kuhuisha** leseni kabla ya kuisha, mshambuliaji anaweza kudumisha uthibitisho kwa Active Directory bila haja ya usajili wa tiketi za ziada, ambazo zinaweza kuacha alama kwenye seva ya Mamlaka ya Leseni (CA).

Njia hii inaruhusu njia ya **uthibitisho wa muda mrefu**, ikipunguza hatari ya kugunduliwa kupitia mwingiliano mdogo na seva ya CA na kuepuka uzalishaji wa vitu ambavyo vinaweza kuwajulisha wasimamizi kuhusu uvamizi.

{{#include ../../../banners/hacktricks-training.md}}
