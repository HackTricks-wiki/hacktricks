# AD CS-sertifikaatdiefstal

{{#include ../../../banners/hacktricks-training.md}}

**Dit is ’n kort opsomming van die Diefstal-hoofstukke van die uitstekende navorsing uit [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## Wat kan ek met ’n sertifikaat doen?

Voordat jy kyk hoe om die sertifikate te steel, is hier inligting oor hoe om vas te stel waarvoor die sertifikaat bruikbaar is:
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Sertifikate uitvoer met behulp van die Crypto APIs – THEFT1

In ’n **interaktiewe lessenaarsessie** kan ’n gebruiker- of masji admite? sertifikaat, saam met die private sleutel, maklik onttrek word, veral indien die **private sleutel uitvoerbaar** is. Dit kan gedoen word deur na die sertifikaat in `certmgr.msc` te navigeer, daarop te regsklik en `All Tasks → Export` te kies om ’n wagwoordbeskermde .pfx-lêer te genereer.<sup>[[1]](#references)</sup>

Vir ’n **programmatiese benadering** is nutsmiddels soos die PowerShell-`ExportPfxCertificate` cmdlet of projekte soos [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) beskikbaar. Hierdie gebruik die **Microsoft CryptoAPI** (CAPI) of die Cryptography API: Next Generation (CNG) om met die sertifikaatstore te kommunikeer. Hierdie APIs verskaf ’n reeks kriptografiese dienste, insluitend dié wat vir sertifikaatberging en authentication nodig is.

Indien ’n private sleutel egter as nie-uitvoerbaar ingestel is, sal beide CAPI en CNG normaalweg die onttrekking van sulke sertifikate blokkeer. Om hierdie beperking te omseil, kan nutsmiddels soos **Mimikatz** gebruik word. Mimikatz bied die `crypto::capi`- en `crypto::cng`-commands om die onderskeie APIs te patch, wat die uitvoer van private sleutels moontlik maak. Spesifiek patch `crypto::capi` die CAPI binne die huidige proses, terwyl `crypto::cng` die geheue van **lsass.exe** teiken om dit te patch.

## Diefstal van gebruikersertifikate via DPAPI – THEFT2

Meer inligting oor DPAPI in:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

In Windows word **private sertifikaatsleutels deur DPAPI beskerm**. Dit is belangrik om te besef dat die **bergingsliggings vir gebruiker- en masjienprivate sleutels** verskil, en dat die lêerstrukture wissel na gelang van die kriptografiese API wat deur die bedryfstelsel gebruik word. **SharpDPAPI** is ’n tool wat hierdie verskille outomaties kan hanteer wanneer die DPAPI-blobs gedekripteer word.<sup>[[1]](#references)</sup>

**Gebruikersertifikate** word hoofsaaklik in die register onder `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` gehuisves, maar sommige kan ook in die gids `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` gevind word. Die ooreenstemmende **private sleutels** vir hierdie sertifikate word gewoonlik in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` vir **CAPI**-sleutels en `%APPDATA%\Microsoft\Crypto\Keys\` vir **CNG**-sleutels gestoor.

Om ’n **sertifikaat en die geassosieerde private sleutel te onttrek**, behels die proses:

1. **Kies die teikens sertifikaat** uit die gebruiker se store en haal die naam van sy sleutelstore op.
2. **Vind die vereiste DPAPI-masterkey** om die ooreenstemmende private sleutel te dekripteer.
3. **Dekripteer die private sleutel** deur die plaintext DPAPI-masterkey te gebruik.

Vir die **verkryging van die plaintext DPAPI-masterkey** kan die volgende benaderings gebruik word:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Om die dekripsie van masterkey-lêers en private sleutel-lêers te stroomlyn, is die `certificates`-opdrag van [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) nuttig. Dit aanvaar `/pvk`, `/mkfile`, `/password` of `{GUID}:KEY` as argumente om die private sleutels en gekoppelde sertifikate te dekripteer, waarna dit ’n `.pem`-lêer genereer.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Diefstal van masjiensertifikate via DPAPI – THEFT3

Masjiens sertifikate wat deur Windows in die register by `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` gestoor word, en die geassosieerde private sleutels wat in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (vir CAPI) en `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (vir CNG) geleë is, word met die masjien se DPAPI-hoofsleutels geënkripteer. Hierdie sleutels kan nie met die domein se DPAPI-rugsteunsleutel gedekripteer word nie; die **DPAPI_SYSTEM LSA secret**, waartoe slegs die SYSTEM-gebruiker toegang het, word eerder vereis.<sup>[[1]](#references)</sup>

Handmatige dekripsie kan bereik word deur die `lsadump::secrets`-opdrag in **Mimikatz** uit te voer om die DPAPI_SYSTEM LSA secret te onttrek, en vervolgens hierdie sleutel te gebruik om die masjien-hoofsleutels te dekрипteer. Alternatiewelik kan Mimikatz se `crypto::certificates /export /systemstore:LOCAL_MACHINE`-opdrag gebruik word nadat CAPI/CNG gelap is soos voorheen beskryf.

**SharpDPAPI** bied ’n meer geoutomatiseerde benadering met sy certificates-opdrag. Wanneer die `/machine`-vlag met verhoogde toestemmings gebruik word, eskaleer dit na SYSTEM, dump dit die DPAPI_SYSTEM LSA secret, gebruik dit dit om die masjien se DPAPI-hoofsleutels te dekрипteer, en gebruik dit dan hierdie plaintext-sleutels as ’n opsoektabel om enige private sleutels van masjiens sertifikate te dekрипteer.

## Vind van sertifikaatlêers – THEFT4

Sertifikate word soms direk binne die lêerstelsel gevind, soos in lêerdelings of die Downloads-lêergids. Die sertifikaatlêertipes wat die algemeenste binne Windows-omgewings geteiken word, is `.pfx`- en `.p12`-lêers. Alhoewel dit minder gereeld voorkom, verskyn lêers met die uitbreidings `.pkcs12` en `.pem` ook. Verdere noemenswaardige sertifikaatverwante lêeruitbreidings sluit in:<sup>[[1]](#references)</sup>

- `.key` vir private sleutels,
- `.crt`/`.cer` slegs vir sertifikate,
- `.csr` vir Certificate Signing Requests, wat nie sertifikate of private sleutels bevat nie,
- `.jks`/`.keystore`/`.keys` vir Java Keystores, wat sertifikate tesame met private sleutels kan bevat wat deur Java-toepassings gebruik word.

Hierdie lêers kan met PowerShell of die command prompt opgespoor word deur na die genoemde uitbreidings te soek.

In gevalle waar ’n PKCS#12-sertifikaatlêer gevind word en dit deur ’n wagwoord beskerm word, is die onttrekking van ’n hash moontlik deur `pfx2john.py` te gebruik, wat by [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) beskikbaar is. Vervolgens kan JohnTheRipper gebruik word om te probeer om die wagwoord te crack.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5 (UnPAC the hash)

Die gegewe inhoud verduidelik ’n metode vir NTLM credential theft via PKINIT, spesifiek deur die theft-metode genaamd THEFT5. Hier volg ’n herverduideliking in die passiewe vorm, met die inhoud geanonimiseer en waar toepaslik opgesom:<sup>[[1]](#references)</sup>

Om NTLM-authentication `MS-NLMP` te ondersteun vir toepassings wat nie Kerberos-authentication fasiliteer nie, is die KDC ontwerp om die gebruiker se NTLM one-way function (OWF) binne die privilege attribute certificate (PAC) terug te stuur, spesifiek in die `PAC_CREDENTIAL_INFO`-buffer, wanneer PKCA gebruik word. Gevolglik word daar, wanneer ’n account authenticate en ’n Ticket-Granting Ticket (TGT) via PKINIT bekom, inherent ’n meganisme voorsien waarmee die huidige host die NTLM hash uit die TGT kan onttrek om legacy authentication protocols te handhaaf. Hierdie proses behels die decryption van die `PAC_CREDENTIAL_DATA`-struktuur, wat in wese ’n NDR-geserialiseerde voorstelling van die NTLM plaintext is.

Die utility **Kekeo**, beskikbaar by [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), word genoem as ’n utility wat ’n TGT met hierdie spesifieke data kan aanvra, waardeur die gebruiker se NTLM verkry kan word. Die command wat hiervoor gebruik word, is soos volg:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** kan ook hierdie inligting met die opsie **`asktgt [...] /getcredentials`** verkry.

Daar word ook aangedui dat Kekeo smartcard-beskermde sertifikate kan verwerk, mits die pin verkry kan word, met verwysing na [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Daar word aangedui dat dieselfde vermoë deur **Rubeus** ondersteun word, beskikbaar by [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Hierdie verduideliking omvat die proses en nutsprogramme wat betrokke is by NTLM credential theft via PKINIT, met die fokus op die verkryging van NTLM-hashes deur middel van ’n TGT wat met PKINIT verkry is, asook die nutsprogramme wat hierdie proses fasiliteer.

## Verwysings

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
