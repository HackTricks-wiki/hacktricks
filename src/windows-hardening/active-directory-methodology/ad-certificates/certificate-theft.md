# AD CS Sertifikaat Diefstal

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n klein opsomming van die Diefstal hoofstukke van die wonderlike navorsing van [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Wat kan ek met 'n sertifikaat doen

Voordat ons kyk hoe om die sertifikate te steel, het jy hier 'n paar inligting oor hoe om te vind waarvoor die sertifikaat nuttig is:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Eksportering van Sertifikate met die Crypto APIs – DIEFSTAL1

In 'n **interaktiewe lessenaar sessie** kan 'n gebruiker of masjien sertifikaat, saam met die private sleutel, maklik onttrek word, veral as die **private sleutel uitvoerbaar** is. Dit kan bereik word deur na die sertifikaat in `certmgr.msc` te navigeer, regsklik daarop te klik, en `All Tasks → Export` te kies om 'n wagwoord-beskermde .pfx-lêer te genereer.

Vir 'n **programmatiese benadering** is gereedskap soos die PowerShell `ExportPfxCertificate` cmdlet of projekte soos [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) beskikbaar. Hierdie gebruik die **Microsoft CryptoAPI** (CAPI) of die Cryptography API: Next Generation (CNG) om met die sertifikaatwinkel te kommunikeer. Hierdie APIs bied 'n reeks kriptografiese dienste, insluitend dié wat nodig is vir sertifikaatberging en -verifikasie.

As 'n private sleutel egter as nie-uitvoerbaar gestel is, sal beide CAPI en CNG normaalweg die onttrekking van sulke sertifikate blokkeer. Om hierdie beperking te omseil, kan gereedskap soos **Mimikatz** gebruik word. Mimikatz bied `crypto::capi` en `crypto::cng` opdragte om die onderskeie APIs te patch, wat die uitvoer van private sleutels moontlik maak. Spesifiek patch `crypto::capi` die CAPI binne die huidige proses, terwyl `crypto::cng` die geheue van **lsass.exe** teiken vir patching.

## Diefstal van Gebruiker Sertifikate via DPAPI – DIEFSTAL2

Meer inligting oor DPAPI in:

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

In Windows word **sertifikaat private sleutels deur DPAPI beskerm**. Dit is belangrik om te erken dat die **berging plekke vir gebruiker en masjien private sleutels** verskillend is, en die lêerstrukture verskil afhangende van die kriptografiese API wat deur die bedryfstelsel gebruik word. **SharpDPAPI** is 'n gereedskap wat hierdie verskille outomaties kan navigeer wanneer dit die DPAPI blobs ontsleutel.

**Gebruiker sertifikate** is hoofsaaklik in die register onder `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` gehuisves, maar sommige kan ook in die gids `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` gevind word. Die ooreenstemmende **private sleutels** vir hierdie sertifikate word tipies gestoor in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` vir **CAPI** sleutels en `%APPDATA%\Microsoft\Crypto\Keys\` vir **CNG** sleutels.

Om 'n **sertifikaat en sy geassosieerde private sleutel** te **onttrek**, behels die proses:

1. **Kies die teiken sertifikaat** uit die gebruiker se winkel en verkry sy sleutel winkel naam.
2. **Vind die vereiste DPAPI masterkey** om die ooreenstemmende private sleutel te ontsleutel.
3. **Ontsleutel die private sleutel** deur die platte teks DPAPI masterkey te gebruik.

Vir **die verkryging van die platte teks DPAPI masterkey** kan die volgende benaderings gebruik word:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Om die ontsleuteling van masterkey-lêers en private sleutel-lêers te stroomlyn, bewys die `certificates` opdrag van [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) nuttig te wees. Dit aanvaar `/pvk`, `/mkfile`, `/password`, of `{GUID}:KEY` as argumente om die private sleutels en gekoppelde sertifikate te ontsleutel, en genereer vervolgens 'n `.pem` lêer.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Masjien Sertifikaat Diefstal via DPAPI – THEFT3

Masjien sertifikate wat deur Windows in die registrasie gestoor word by `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` en die geassosieerde private sleutels geleë in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (vir CAPI) en `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (vir CNG) word geënkripteer met die masjien se DPAPI meester sleutels. Hierdie sleutels kan nie met die domein se DPAPI rugsteun sleutel ontkrip word nie; eerder is die **DPAPI_SYSTEM LSA geheim**, wat slegs deur die SYSTEM gebruiker toegang kan verkry, nodig.

Handmatige ontkripping kan bereik word deur die `lsadump::secrets` opdrag in **Mimikatz** uit te voer om die DPAPI_SYSTEM LSA geheim te onttrek, en daarna hierdie sleutel te gebruik om die masjien meester sleutels te ontkrip. Alternatiewelik kan Mimikatz se `crypto::certificates /export /systemstore:LOCAL_MACHINE` opdrag gebruik word na die patching van CAPI/CNG soos voorheen beskryf.

**SharpDPAPI** bied 'n meer geoutomatiseerde benadering met sy sertifikate opdrag. Wanneer die `/machine` vlag met verhoogde toestemmings gebruik word, eskaleer dit na SYSTEM, dump die DPAPI_SYSTEM LSA geheim, gebruik dit om die masjien DPAPI meester sleutels te ontkrip, en gebruik dan hierdie platte sleutels as 'n soek tabel om enige masjien sertifikaat private sleutels te ontkrip.

## Vind Sertifikaat Lêers – THEFT4

Sertifikate word soms direk binne die lêerstelsel gevind, soos in lêer deel of die Downloads gids. Die mees algemeen teëgekomende tipes sertifikaat lêers wat op Windows omgewings teikens is, is `.pfx` en `.p12` lêers. Alhoewel minder gereeld, verskyn lêers met uitbreidings `.pkcs12` en `.pem` ook. Addisionele noemenswaardige sertifikaat-verwante lêer uitbreidings sluit in:

- `.key` vir private sleutels,
- `.crt`/`.cer` vir sertifikate slegs,
- `.csr` vir Sertifikaat Ondertekening Versoeke, wat nie sertifikate of private sleutels bevat nie,
- `.jks`/`.keystore`/`.keys` vir Java Keystores, wat sertifikate saam met private sleutels kan hou wat deur Java toepassings gebruik word.

Hierdie lêers kan gesoek word met PowerShell of die opdragprompt deur te kyk na die genoemde uitbreidings.

In gevalle waar 'n PKCS#12 sertifikaat lêer gevind word en dit deur 'n wagwoord beskerm word, is die onttrekking van 'n hash moontlik deur die gebruik van `pfx2john.py`, beskikbaar by [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Daarna kan JohnTheRipper gebruik word om te probeer om die wagwoord te kraak.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Kredensiaal Diefstal via PKINIT – THEFT5

Die gegewe inhoud verduidelik 'n metode vir NTLM kredensiaal diefstal via PKINIT, spesifiek deur die diefstal metode wat as THEFT5 geëtiketteer is. Hier is 'n herverklaring in passiewe stem, met die inhoud geanonimiseer en saamgevat waar toepaslik:

Om NTLM-outeentifikasie [MS-NLMP] te ondersteun vir toepassings wat nie Kerberos-outeentifikasie fasiliteer nie, is die KDC ontwerp om die gebruiker se NTLM eenrigting funksie (OWF) binne die privilege-attribuut sertifikaat (PAC) terug te gee, spesifiek in die `PAC_CREDENTIAL_INFO` buffer, wanneer PKCA gebruik word. Gevolglik, indien 'n rekening outentifiseer en 'n Ticket-Granting Ticket (TGT) via PKINIT verkry, word 'n meganisme inherent voorsien wat die huidige gasheer in staat stel om die NTLM-hash uit die TGT te onttrek om ouer outentifikasie protokolle te ondersteun. Hierdie proses behels die ontsleuteling van die `PAC_CREDENTIAL_DATA` struktuur, wat essensieel 'n NDR-geserialiseerde voorstelling van die NTLM-plaktekst is.

Die nut **Kekeo**, toeganklik by [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), word genoem as in staat om 'n TGT te versoek wat hierdie spesifieke data bevat, en so die onttrekking van die gebruiker se NTLM te fasiliteer. Die opdrag wat vir hierdie doel gebruik word, is soos volg:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Daarbenewens word opgemerk dat Kekeo slimkaart-beskermde sertifikate kan verwerk, mits die pin herwin kan word, met verwysing na [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Dieselfde vermoë word aangedui as ondersteun deur **Rubeus**, beskikbaar by [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Hierdie verduideliking sluit die proses en gereedskap in wat betrokke is by NTLM geloofsbriewe diefstal via PKINIT, met fokus op die herwinning van NTLM hashes deur TGT verkry deur PKINIT, en die nutsmiddels wat hierdie proses fasiliteer.

{{#include ../../../banners/hacktricks-training.md}}
