# AD CS Rekening Volharding

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n klein opsomming van die masjien volharding hoofstukke van die wonderlike navorsing van [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## **Begrip van Aktiewe Gebruiker Kredensiaal Diefstal met Sertifikate – PERSIST1**

In 'n scenario waar 'n sertifikaat wat domeinverifikasie toelaat deur 'n gebruiker aangevra kan word, het 'n aanvaller die geleentheid om hierdie sertifikaat te **aanspreek** en **steel** om **volharding** op 'n netwerk te **onderhou**. Standaard laat die `User` sjabloon in Active Directory sulke versoeke toe, alhoewel dit soms gedeaktiveer kan wees.

Deur 'n hulpmiddel genaamd [**Certify**](https://github.com/GhostPack/Certify) te gebruik, kan 'n mens soek na geldige sertifikate wat volhoubare toegang moontlik maak:
```bash
Certify.exe find /clientauth
```
Dit word beklemtoon dat 'n sertifikaat se krag lê in sy vermoë om **as die gebruiker** waarvoor dit behoort te **authentiseer**, ongeag enige wagwoordveranderings, solank die sertifikaat **geld** bly.

Sertifikate kan aangevra word deur 'n grafiese koppelvlak met `certmgr.msc` of deur die opdraglyn met `certreq.exe`. Met **Certify** word die proses om 'n sertifikaat aan te vra vereenvoudig soos volg:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Na 'n suksesvolle versoek word 'n sertifikaat saam met sy privaat sleutel in `.pem` formaat gegenereer. Om dit in 'n `.pfx` lêer te omskakel, wat op Windows-stelsels gebruik kan word, word die volgende opdrag gebruik:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Die `.pfx` lêer kan dan na 'n teikenstelsel opgelaai word en gebruik word met 'n hulpmiddel genaamd [**Rubeus**](https://github.com/GhostPack/Rubeus) om 'n Ticket Granting Ticket (TGT) vir die gebruiker aan te vra, wat die aanvaller se toegang verleng solank die sertifikaat **geld** (tipies een jaar):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
'n Belangrike waarskuwing word gedeel oor hoe hierdie tegniek, gekombineer met 'n ander metode wat in die **THEFT5** afdeling uiteengesit word, 'n aanvaller in staat stel om volhoubaar 'n rekening se **NTLM hash** te verkry sonder om met die Local Security Authority Subsystem Service (LSASS) te interaksie, en vanuit 'n nie-verhoogde konteks, wat 'n meer stil metode vir langtermyn geloofsbriefdiefstal bied.

## **Masjien Volhoubaarheid Verkry met Sertifikate - PERSIST2**

'n Ander metode behels die inskrywing van 'n gecompromitteerde stelsel se masjienrekening vir 'n sertifikaat, wat die standaard `Machine` sjabloon gebruik wat sulke aksies toelaat. As 'n aanvaller verhoogde voorregte op 'n stelsel verkry, kan hulle die **SYSTEM** rekening gebruik om sertifikate aan te vra, wat 'n vorm van **volhoubaarheid** bied:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Hierdie toegang stel die aanvaller in staat om te autentiseer by **Kerberos** as die masjienrekening en **S4U2Self** te gebruik om Kerberos-dienskaartjies vir enige diens op die gasheer te verkry, wat effektief die aanvaller volgehoue toegang tot die masjien bied.

## **Uitbreiding van Volgehoue Toegang Deur Sertifikaat Vernuwing - PERSIST3**

Die finale metode wat bespreek word, behels die benutting van die **geldigheid** en **vernuwingperiodes** van sertifikaat sjablone. Deur 'n sertifikaat voor sy vervaldatum te **vernuwe**, kan 'n aanvaller die autentisering na Active Directory handhaaf sonder die behoefte aan addisionele kaartjie inskrywings, wat spore op die Sertifikaat Owerheid (CA) bediener kan agterlaat.

Hierdie benadering stel 'n **verlengde volgehoue toegang** metode in, wat die risiko van opsporing minimaliseer deur minder interaksies met die CA bediener en die generering van artefakte te vermy wat administrateurs op die indringing kan waarsku.

{{#include ../../../banners/hacktricks-training.md}}
