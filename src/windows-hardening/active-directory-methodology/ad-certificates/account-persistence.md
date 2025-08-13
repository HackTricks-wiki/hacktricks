# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari mdogo wa sura za kudumu za mashine kutoka utafiti mzuri wa [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## **Kuelewa Wizi wa Akreditivu za Watumiaji Wanaofanya Kazi kwa kutumia Vyeti – PERSIST1**

Katika hali ambapo cheti kinachoruhusu uthibitishaji wa kikoa kinaweza kuombwa na mtumiaji, mshambuliaji ana fursa ya **kuomba** na **kuchukua** cheti hiki ili **kuhifadhi kudumu** kwenye mtandao. Kwa kawaida, kiolezo cha `User` katika Active Directory kinaruhusu maombi kama haya, ingawa wakati mwingine kinaweza kuzuiliwa.

Kwa kutumia zana inayoitwa [**Certify**](https://github.com/GhostPack/Certify), mtu anaweza kutafuta vyeti halali vinavyowezesha ufikiaji wa kudumu:
```bash
Certify.exe find /clientauth
```
Inasisitizwa kwamba nguvu ya cheti iko katika uwezo wake wa **kujiuthibitisha kama mtumiaji** anayehusiana nacho, bila kujali mabadiliko yoyote ya nenosiri, mradi tu cheti kikiwa **halali**.

Vyeti vinaweza kuombwa kupitia kiolesura cha picha kwa kutumia `certmgr.msc` au kupitia mstari wa amri na `certreq.exe`. Pamoja na **Certify**, mchakato wa kuomba cheti umewekwa rahisi kama ifuatavyo:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Baada ya ombi kufanikiwa, cheti pamoja na funguo yake ya faragha inaundwa katika muundo wa `.pem`. Ili kubadilisha hii kuwa faili ya `.pfx`, ambayo inaweza kutumika kwenye mifumo ya Windows, amri ifuatayo inatumika:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Faili la `.pfx` linaweza kupakiwa kwenye mfumo wa lengo na kutumika na chombo kinachoitwa [**Rubeus**](https://github.com/GhostPack/Rubeus) kuomba Tiketi ya Kutoa Tiketi (TGT) kwa mtumiaji, ikipanua ufikiaji wa mshambuliaji kwa muda mrefu kama cheti ni **halali** (kawaida mwaka mmoja):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Kikumbusho muhimu kinashirikiwa kuhusu jinsi mbinu hii, ikichanganywa na njia nyingine iliyoelezwa katika sehemu ya **THEFT5**, inamruhusu mshambuliaji kupata kwa kudumu **NTLM hash** ya akaunti bila kuingiliana na Local Security Authority Subsystem Service (LSASS), na kutoka katika muktadha usio na kiwango cha juu, ikitoa njia ya siri ya wizi wa akidi za muda mrefu.

## **K kupata Uthibitisho wa Mashine kwa kutumia Vyeti - PERSIST2**

Njia nyingine inahusisha kujiandikisha kwa akaunti ya mashine ya mfumo ulioathirika kwa ajili ya cheti, ikitumia kigezo cha `Machine` cha kawaida ambacho kinaruhusu vitendo kama hivyo. Ikiwa mshambuliaji atapata mamlaka ya juu kwenye mfumo, wanaweza kutumia akaunti ya **SYSTEM** kuomba vyeti, wakitoa aina ya **persistence**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Hii ufikiaji inamuwezesha mshambuliaji kuthibitisha kwenye **Kerberos** kama akaunti ya mashine na kutumia **S4U2Self** kupata tiketi za huduma za Kerberos kwa huduma yoyote kwenye mwenyeji, kwa ufanisi ikimpa mshambuliaji ufikiaji wa kudumu kwenye mashine.

## **Kupanua Uthibitisho Kupitia Urenewal wa Cheti - PERSIST3**

Njia ya mwisho iliyozungumziwa inahusisha kutumia **validity** na **renewal periods** za mifano ya vyeti. Kwa **kurenew** cheti kabla ya kuisha, mshambuliaji anaweza kudumisha uthibitisho kwa Active Directory bila haja ya kujiandikisha tiketi za ziada, ambazo zinaweza kuacha alama kwenye seva ya Mamlaka ya Cheti (CA).

### Urenewal wa Cheti na Certify 2.0

Kuanza na **Certify 2.0** mchakato wa urenewal umejikita kikamilifu kupitia amri mpya ya `request-renew`. Iwapo kuna cheti kilichotolewa awali (katika muundo wa **base-64 PKCS#12**) mshambuliaji anaweza kuki renew bila kuingiliana na mmiliki wa awali – bora kwa uthibitisho wa kimya, wa muda mrefu:
```powershell
Certify.exe request-renew --ca SERVER\\CA-NAME \
--cert-pfx MIACAQMwgAYJKoZIhvcNAQcBoIAkgA...   # original PFX
```
Amri itarudisha PFX mpya ambayo ni halali kwa kipindi kingine cha maisha kamili, ikikuruhusu kuendelea kuthibitisha hata baada ya cheti cha kwanza kuisha au kufutwa.

## Marejeo

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}
