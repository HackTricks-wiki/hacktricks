# AD CS Certificate Theft

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari mdogo wa sura za Wizi za utafiti mzuri kutoka [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Nini naweza kufanya na cheti

Kabla ya kuangalia jinsi ya kuiba vyeti, hapa kuna taarifa kuhusu jinsi ya kupata matumizi ya cheti:
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
## Exporting Certificates Using the Crypto APIs – THEFT1

Katika **kipindi cha desktop cha mwingiliano**, kutoa cheti cha mtumiaji au mashine, pamoja na funguo binafsi, inaweza kufanywa kwa urahisi, hasa ikiwa **funguo binafsi inaweza kusafirishwa**. Hii inaweza kufanywa kwa kuingia kwenye cheti katika `certmgr.msc`, kubonyeza kulia juu yake, na kuchagua `All Tasks → Export` ili kuunda faili ya .pfx iliyo na nenosiri.

Kwa **mbinu ya programu**, zana kama vile PowerShell `ExportPfxCertificate` cmdlet au miradi kama [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) zinapatikana. Hizi hutumia **Microsoft CryptoAPI** (CAPI) au Cryptography API: Next Generation (CNG) kuingiliana na duka la vyeti. APIs hizi zinatoa anuwai ya huduma za kificho, ikiwa ni pamoja na zile zinazohitajika kwa ajili ya uhifadhi wa vyeti na uthibitishaji.

Hata hivyo, ikiwa funguo binafsi imewekwa kama isiyoweza kusafirishwa, CAPI na CNG kawaida zitazuia utoaji wa vyeti kama hivyo. Ili kupita kizuizi hiki, zana kama **Mimikatz** zinaweza kutumika. Mimikatz inatoa amri za `crypto::capi` na `crypto::cng` kubadilisha APIs husika, kuruhusu usafirishaji wa funguo binafsi. Kwa hakika, `crypto::capi` inabadilisha CAPI ndani ya mchakato wa sasa, wakati `crypto::cng` inalenga kumbukumbu ya **lsass.exe** kwa ajili ya kubadilisha.

## User Certificate Theft via DPAPI – THEFT2

Maelezo zaidi kuhusu DPAPI katika:

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Katika Windows, **funguo binafsi za cheti zinahifadhiwa na DPAPI**. Ni muhimu kutambua kwamba **mahali pa uhifadhi kwa funguo binafsi za mtumiaji na mashine** ni tofauti, na muundo wa faili hutofautiana kulingana na API ya kificho inayotumiwa na mfumo wa uendeshaji. **SharpDPAPI** ni zana ambayo inaweza kuzunguka tofauti hizi kiotomatiki wakati wa kufungua DPAPI blobs.

**Vyeti vya mtumiaji** kwa kawaida vinahifadhiwa katika rejista chini ya `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, lakini baadhi vinaweza pia kupatikana katika directory `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Funguo binafsi zinazohusiana na vyeti hivi kwa kawaida huhifadhiwa katika `%APPDATA%\Microsoft\Crypto\RSA\User SID\` kwa funguo za **CAPI** na `%APPDATA%\Microsoft\Crypto\Keys\` kwa funguo za **CNG**.

Ili **kutoa cheti na funguo binafsi zinazohusiana**, mchakato unajumuisha:

1. **Kuchagua cheti lengwa** kutoka duka la mtumiaji na kupata jina la duka la funguo zake.
2. **Kutafuta DPAPI masterkey inayohitajika** ili kufungua funguo binafsi inayohusiana.
3. **Kufungua funguo binafsi** kwa kutumia DPAPI masterkey ya maandiko.

Kwa **kupata DPAPI masterkey ya maandiko**, mbinu zifuatazo zinaweza kutumika:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Ili kurahisisha ufichuzi wa faili za masterkey na faili za funguo binafsi, amri ya `certificates` kutoka [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) inathibitisha kuwa na manufaa. Inakubali `/pvk`, `/mkfile`, `/password`, au `{GUID}:KEY` kama hoja za kufichua funguo binafsi na vyeti vilivyohusishwa, kisha inazalisha faili ya `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Wizi wa Cheti cha Mashine kupitia DPAPI – THEFT3

Cheti za mashine zinahifadhiwa na Windows katika rejista kwenye `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` na funguo za faragha zinazohusiana ziko katika `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (kwa CAPI) na `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (kwa CNG) zimefungwa kwa kutumia funguo za DPAPI za mashine. Funguo hizi hazinaweza kufunguliwa kwa funguo za akiba za DPAPI za kanda; badala yake, **DPAPI_SYSTEM LSA siri**, ambayo ni lazima itumike na mtumiaji wa SYSTEM, inahitajika.

Funguo za kufungua zinaweza kupatikana kwa kutekeleza amri `lsadump::secrets` katika **Mimikatz** ili kutoa siri ya DPAPI_SYSTEM LSA, na kisha kutumia funguo hii kufungua funguo za master za mashine. Vinginevyo, amri ya Mimikatz `crypto::certificates /export /systemstore:LOCAL_MACHINE` inaweza kutumika baada ya kurekebisha CAPI/CNG kama ilivyoelezwa hapo awali.

**SharpDPAPI** inatoa njia ya kiotomatiki zaidi kwa amri zake za vyeti. Wakati bendera ya `/machine` inapotumika na ruhusa za juu, inainua hadi SYSTEM, inatoa siri ya DPAPI_SYSTEM LSA, inaitumia kufungua funguo za master za DPAPI za mashine, na kisha inatumia funguo hizi za maandiko kama jedwali la kutafuta kufungua funguo zozote za faragha za cheti cha mashine.

## Kutafuta Faili za Vyeti – THEFT4

Vyeti mara nyingine hupatikana moja kwa moja ndani ya mfumo wa faili, kama vile katika sehemu za faili au folda ya Downloads. Aina za kawaida za faili za vyeti zinazolengwa kwa mazingira ya Windows ni faili za `.pfx` na `.p12`. Ingawa si mara nyingi, faili zenye viambatisho `.pkcs12` na `.pem` pia huonekana. Viambatisho vingine vya faili vinavyohusiana na vyeti ni pamoja na:

- `.key` kwa funguo za faragha,
- `.crt`/`.cer` kwa vyeti pekee,
- `.csr` kwa Maombi ya Kusaini Vyeti, ambavyo havina vyeti au funguo za faragha,
- `.jks`/`.keystore`/`.keys` kwa Java Keystores, ambazo zinaweza kuwa na vyeti pamoja na funguo za faragha zinazotumiwa na programu za Java.

Faili hizi zinaweza kutafutwa kwa kutumia PowerShell au amri ya prompt kwa kutafuta viambatisho vilivyotajwa.

Katika hali ambapo faili ya cheti ya PKCS#12 inapatikana na inalindwa na nenosiri, utoaji wa hash unaweza kufanywa kwa kutumia `pfx2john.py`, inayopatikana kwenye [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Kisha, JohnTheRipper inaweza kutumika kujaribu kuvunja nenosiri.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

Maudhui yaliyotolewa yanaelezea mbinu ya wizi wa akreditivu za NTLM kupitia PKINIT, hasa kupitia mbinu ya wizi iliyopewa jina THEFT5. Hapa kuna ufafanuzi wa upya kwa sauti ya passiv, huku maudhui yakiwa yamefichwa na kufupishwa inapohitajika:

Ili kusaidia uthibitishaji wa NTLM [MS-NLMP] kwa programu ambazo hazifanyii kazi uthibitishaji wa Kerberos, KDC imeundwa kurudisha kazi ya moja kwa moja ya NTLM (OWF) ya mtumiaji ndani ya cheti cha sifa (PAC), hasa katika buffer ya `PAC_CREDENTIAL_INFO`, wakati PKCA inatumika. Kwa hivyo, iwapo akaunti itathibitishwa na kupata Tiketi ya Kutoa Tiketi (TGT) kupitia PKINIT, mekanismu inapatikana ambayo inaruhusu mwenyeji wa sasa kutoa hash ya NTLM kutoka kwa TGT ili kudumisha itifaki za uthibitishaji za zamani. Mchakato huu unajumuisha ufichuzi wa muundo wa `PAC_CREDENTIAL_DATA`, ambao kimsingi ni picha ya NDR iliyosimbwa ya NTLM plaintext.

Kifaa **Kekeo**, kinachopatikana kwenye [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), kinatajwa kuwa na uwezo wa kuomba TGT inayojumuisha data hii maalum, hivyo kurahisisha upatikanaji wa NTLM wa mtumiaji. Amri inayotumika kwa ajili ya kusudi hili ni kama ifuatavyo:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Zaidi ya hayo, inabainishwa kuwa Kekeo inaweza kushughulikia vyeti vilivyolindwa na kadi za smartcard, ikiwa pin inaweza kupatikana, huku ikirejelea [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Uwezo huo huo unaripotiwa kuungwa mkono na **Rubeus**, inayopatikana katika [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Maelezo haya yanajumuisha mchakato na zana zinazohusika katika wizi wa akreditivu za NTLM kupitia PKINIT, zikilenga katika kupata hash za NTLM kupitia TGT iliyopatikana kwa kutumia PKINIT, na matumizi yanayosaidia mchakato huu.

{{#include ../../../banners/hacktricks-training.md}}
