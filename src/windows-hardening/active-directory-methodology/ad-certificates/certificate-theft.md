# AD CS Certificate Theft

{{#include ../../../banners/hacktricks-training.md}}

**Huu ni muhtasari mfupi wa sura za Theft kutoka kwenye utafiti bora wa [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## Ninaweza kufanya nini kwa certificate

Kabla ya kuangalia jinsi ya kuiba certificates, hapa kuna maelezo kuhusu jinsi ya kubaini certificate inavyoweza kuwa muhimu:
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
## Kuhamisha Certificates kwa Kutumia Crypto APIs – THEFT1

Katika **interactive desktop session**, kutoa certificate ya user au machine, pamoja na private key, kunaweza kufanywa kwa urahisi, hasa ikiwa **private key inaweza ku-exportiwa**. Hili linaweza kufanywa kwa kwenda kwenye certificate katika `certmgr.msc`, kubofya kulia, kisha kuchagua `All Tasks → Export` ili kutengeneza faili la .pfx linalolindwa kwa password.<sup>[[1]](#references)</sup>

Kwa **programmatic approach**, tools kama PowerShell `ExportPfxCertificate` cmdlet au projects kama [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) zinapatikana. Hizi hutumia **Microsoft CryptoAPI** (CAPI) au Cryptography API: Next Generation (CNG) kuingiliana na certificate store. APIs hizi hutoa huduma mbalimbali za cryptographic, zikiwemo zinazohitajika kwa certificate storage na authentication.

Hata hivyo, ikiwa private key imewekwa kuwa non-exportable, CAPI na CNG kwa kawaida zitazuia extraction ya certificates hizo. Ili kukwepa kizuizi hiki, tools kama **Mimikatz** zinaweza kutumika. Mimikatz hutoa commands za `crypto::capi` na `crypto::cng` za kupatch APIs husika, hivyo kuruhusu exportation ya private keys. Hasa, `crypto::capi` hupatch CAPI ndani ya process ya sasa, huku `crypto::cng` ikilenga memory ya **lsass.exe** kwa ajili ya patching.

## Wizi wa User Certificate kupitia DPAPI – THEFT2

Maelezo zaidi kuhusu DPAPI katika:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Katika Windows, **certificate private keys zinalindwa na DPAPI**. Ni muhimu kutambua kwamba **storage locations za user na machine private keys** ni tofauti, na file structures hutofautiana kulingana na cryptographic API inayotumiwa na operating system. **SharpDPAPI** ni tool inayoweza kutambua tofauti hizi kiotomatiki wakati wa ku-decrypt DPAPI blobs.<sup>[[1]](#references)</sup>

**User certificates** kwa kiasi kikubwa huhifadhiwa kwenye registry chini ya `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, lakini baadhi pia zinaweza kupatikana katika directory `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. **Private keys** zinazohusiana na certificates hizi kwa kawaida huhifadhiwa katika `%APPDATA%\Microsoft\Crypto\RSA\User SID\` kwa keys za **CAPI**, na `%APPDATA%\Microsoft\Crypto\Keys\` kwa keys za **CNG**.

Ili **kutoa certificate na private key yake inayohusiana**, mchakato unahusisha:

1. **Kuchagua certificate lengwa** kutoka kwenye store ya user na kupata jina la key store yake.
2. **Kutafuta DPAPI masterkey inayohitajika** ili ku-decrypt private key husika.
3. **Ku-decrypt private key** kwa kutumia DPAPI masterkey iliyo katika plaintext.

Kwa **kupata DPAPI masterkey iliyo katika plaintext**, approaches zifuatazo zinaweza kutumika:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Ili kurahisisha decryption ya faili za masterkey na faili za private key, command ya `certificates` kutoka [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) ni muhimu. Inakubali `/pvk`, `/mkfile`, `/password`, au `{GUID}:KEY` kama arguments za ku-decrypt private keys na certificates zinazohusiana, kisha hutengeneza faili la `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Wizi wa Vyeti vya Mashine kupitia DPAPI – THEFT3

Vyeti vya mashine vinavyohifadhiwa na Windows kwenye registry katika `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` pamoja na funguo zake za faragha zinazopatikana katika `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (kwa CAPI) na `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (kwa CNG) husimbwa kwa kutumia master keys za DPAPI za mashine. Funguo hizi haziwezi kufumbuliwa kwa kutumia domain’s DPAPI backup key; badala yake, **DPAPI_SYSTEM LSA secret**, ambayo inaweza kufikiwa na mtumiaji wa SYSTEM pekee, inahitajika.<sup>[[1]](#references)</sup>

Decryption ya mwongozo inaweza kufanywa kwa kutekeleza amri ya `lsadump::secrets` katika **Mimikatz** ili kutoa DPAPI_SYSTEM LSA secret, kisha kutumia ufunguo huu kufumbua machine masterkeys. Vinginevyo, amri ya `crypto::certificates /export /systemstore:LOCAL_MACHINE` ya Mimikatz inaweza kutumiwa baada ya kupatch CAPI/CNG kama ilivyoelezwa awali.

**SharpDPAPI** hutoa mbinu iliyo automated zaidi kupitia amri yake ya certificates. Flag ya `/machine` inapotumiwa kwa elevated permissions, hupandisha privileges hadi SYSTEM, hutoa DPAPI_SYSTEM LSA secret, huitumia kufumbua machine DPAPI masterkeys, kisha hutumia funguo hizi za plaintext kama lookup table kufumbua private keys za vyeti vyovyote vya mashine.

## Kutafuta Certificate Files – THEFT4

Vyeti wakati mwingine hupatikana moja kwa moja ndani ya filesystem, kama vile kwenye file shares au Downloads folder. Aina za certificate files zinazopatikana mara nyingi na kulengwa katika Windows environments ni files za `.pfx` na `.p12`. Ingawa hupatikana kwa nadra zaidi, files zenye extensions za `.pkcs12` na `.pem` pia huonekana. Extensions nyingine muhimu zinazohusiana na certificates ni pamoja na:<sup>[[1]](#references)</sup>

- `.key` kwa private keys,
- `.crt`/`.cer` kwa certificates pekee,
- `.csr` kwa Certificate Signing Requests, ambazo hazina certificates wala private keys,
- `.jks`/`.keystore`/`.keys` kwa Java Keystores, ambazo zinaweza kuhifadhi certificates pamoja na private keys zinazotumiwa na Java applications.

Files hizi zinaweza kutafutwa kwa kutumia PowerShell au command prompt kwa kutafuta extensions zilizotajwa.

Katika hali ambapo PKCS#12 certificate file inapatikana na imelindwa kwa password, inawezekana kutoa hash kwa kutumia `pfx2john.py`, inayopatikana kwenye [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Baadaye, JohnTheRipper inaweza kutumiwa kujaribu kukrack password.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Wizi wa Credential za NTLM kupitia PKINIT – THEFT5 (UnPAC the hash)

Maudhui yaliyotolewa yanaeleza mbinu ya wizi wa credential za NTLM kupitia PKINIT, hasa kupitia mbinu ya wizi iliyopewa jina la THEFT5. Hapa inaelezwa upya kwa mtindo wa passive voice, huku maudhui yakifupishwa na kutotajwa utambulisho inapofaa:<sup>[[1]](#references)</sup>

Ili kusaidia authentication ya NTLM `MS-NLMP` kwa applications ambazo haziwezeshi authentication ya Kerberos, KDC imeundwa kurejesha one-way function (OWF) ya NTLM ya mtumiaji ndani ya privilege attribute certificate (PAC), hasa katika buffer ya `PAC_CREDENTIAL_INFO`, PKCA inapotumika. Kwa hiyo, account inapo-authenticate na kupata Ticket-Granting Ticket (TGT) kupitia PKINIT, utaratibu wa asili huwepo unaowezesha host ya sasa kutoa NTLM hash kutoka kwenye TGT ili kuendeleza legacy authentication protocols. Mchakato huu unahusisha kusimbua muundo wa `PAC_CREDENTIAL_DATA`, ambao kimsingi ni uwakilishi wa NTLM plaintext ulioserializwa kwa NDR.

Utility **Kekeo**, inayopatikana kwenye [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), inatajwa kuwa na uwezo wa kuomba TGT iliyo na data hii maalum, hivyo kuwezesha kurejeshwa kwa NTLM ya mtumiaji. Command inayotumika kwa madhumuni haya ni kama ifuatavyo:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** inaweza pia kupata taarifa hii kwa kutumia chaguo **`asktgt [...] /getcredentials`**.

Zaidi ya hayo, imebainishwa kuwa Kekeo inaweza kuchakata vyeti vinavyolindwa na smartcard, iwapo PIN inaweza kupatikana, kama inavyoelezwa katika [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Uwezo huo huo unaonyeshwa kuwa unaungwa mkono na **Rubeus**, unaopatikana katika [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Maelezo haya yanafafanua mchakato na zana zinazohusika katika NTLM credential theft kupitia PKINIT, yakilenga upatikanaji wa NTLM hashes kupitia TGT inayopatikana kwa kutumia PKINIT, pamoja na zana zinazowezesha mchakato huu.

## Marejeo

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
