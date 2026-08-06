# Krađa AD CS sertifikata

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je kratak sažetak poglavlja o krađi iz odličnog istraživanja sa adrese [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## Šta mogu da uradim sa sertifikatom

Pre nego što proverimo kako da ukrademo sertifikate, evo nekoliko informacija o tome kako da utvrdite za šta je sertifikat koristan:
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
## Izvoz sertifikata pomoću Crypto APIs – THEFT1

U **interaktivnoj desktop sesiji**, izdvajanje korisničkog ili mašinskog sertifikata zajedno sa privatnim ključem može se jednostavno obaviti, naročito ako je **privatni ključ moguće izvesti**. To se može postići pronalaženjem sertifikata u `certmgr.msc`, klikom desnim tasterom miša na njega i izborom opcije `All Tasks → Export`, čime se generiše .pfx datoteka zaštićena lozinkom.<sup>[[1]](#references)</sup>

Za **programski pristup**, dostupni su alati kao što su PowerShell `ExportPfxCertificate` cmdlet ili projekti poput [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer). Oni koriste **Microsoft CryptoAPI** (CAPI) ili Cryptography API: Next Generation (CNG) za interakciju sa skladištem sertifikata. Ovi API-ji pružaju niz kriptografskih usluga, uključujući one potrebne za skladištenje sertifikata i autentifikaciju.

Međutim, ako je privatni ključ podešen kao takav da se ne može izvesti, CAPI i CNG će uobičajeno blokirati izdvajanje takvih sertifikata. Za zaobilaženje ovog ograničenja mogu se koristiti alati kao što je **Mimikatz**. Mimikatz pruža komande `crypto::capi` i `crypto::cng` za patchovanje odgovarajućih API-ja, čime se omogućava izvoz privatnih ključeva. Konkretno, `crypto::capi` patchuje CAPI unutar trenutnog procesa, dok `crypto::cng` cilja memoriju procesa **lsass.exe** radi patchovanja.

## Krađa korisničkih sertifikata putem DPAPI – THEFT2

Više informacija o DPAPI-ju:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

U Windowsu, **privatni ključevi sertifikata zaštićeni su pomoću DPAPI-ja**. Važno je razumeti da su **lokacije skladištenja privatnih ključeva korisnika i mašina** različite, a strukture datoteka se razlikuju u zavisnosti od kriptografskog API-ja koji operativni sistem koristi. **SharpDPAPI** je alat koji može automatski da obradi ove razlike prilikom dešifrovanja DPAPI blobova.<sup>[[1]](#references)</sup>

**Korisnički sertifikati** se uglavnom čuvaju u registru, pod ključem `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, ali se neki mogu pronaći i u direktorijumu `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Odgovarajući **privatni ključevi** za ove sertifikate obično se čuvaju u `%APPDATA%\Microsoft\Crypto\RSA\User SID\` za **CAPI** ključeve i u `%APPDATA%\Microsoft\Crypto\Keys\` za **CNG** ključeve.

Za **izdvajanje sertifikata i njegovog povezanog privatnog ključa**, postupak obuhvata:

1. **Izbor ciljnog sertifikata** iz korisničkog skladišta i preuzimanje naziva njegovog skladišta ključeva.
2. **Pronalaženje potrebnog DPAPI masterkey-a** za dešifrovanje odgovarajućeg privatnog ključa.
3. **Dešifrovanje privatnog ključa** korišćenjem plaintext DPAPI masterkey-a.

Za **dobijanje plaintext DPAPI masterkey-a**, mogu se koristiti sledeći pristupi:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Radi pojednostavljenja dešifrovanja masterkey fajlova i fajlova privatnih ključeva, komanda `certificates` iz [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) može biti veoma korisna. Prihvata `/pvk`, `/mkfile`, `/password` ili `{GUID}:KEY` kao argumente za dešifrovanje privatnih ključeva i povezanih sertifikata, nakon čega generiše `.pem` fajl.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Krađa sertifikata računara putem DPAPI-ja – THEFT3

Sertifikati računara koje Windows čuva u registru na lokaciji `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` i pridruženi privatni ključevi koji se nalaze u `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (za CAPI) i `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (za CNG) šifrovani su pomoću DPAPI master ključeva računara. Ovi ključevi ne mogu se dešifrovati pomoću DPAPI backup ključa domena; umesto toga, potreban je **DPAPI_SYSTEM LSA secret**, kojem može pristupiti samo SYSTEM korisnik.<sup>[[1]](#references)</sup>

Ručno dešifrovanje može se izvršiti pokretanjem komande `lsadump::secrets` u alatu **Mimikatz**, kako bi se izvukao DPAPI_SYSTEM LSA secret, a zatim korišćenjem ovog ključa za dešifrovanje master ključeva računara. Alternativno, Mimikatz komanda `crypto::certificates /export /systemstore:LOCAL_MACHINE` može se koristiti nakon patchovanja CAPI/CNG-a, kao što je prethodno opisano.

**SharpDPAPI** nudi automatizovaniji pristup pomoću svoje certificates komande. Kada se `/machine` flag koristi sa povišenim privilegijama, alat eskalira na SYSTEM, dump-uje DPAPI_SYSTEM LSA secret, koristi ga za dešifrovanje DPAPI master ključeva računara, a zatim koristi ove ključeve u plaintext obliku kao tabelu za pretragu radi dešifrovanja privatnih ključeva sertifikata računara.

## Pronalaženje datoteka sertifikata – THEFT4

Sertifikati se ponekad mogu pronaći direktno u filesystemu, na primer u file share-ovima ili folderu Downloads. Najčešći tipovi datoteka sertifikata namenjeni Windows okruženjima su `.pfx` i `.p12` datoteke. Ređe se pojavljuju i datoteke sa ekstenzijama `.pkcs12` i `.pem`. Dodatne značajne ekstenzije povezane sa sertifikatima obuhvataju:<sup>[[1]](#references)</sup>

- `.key` za privatne ključeve,
- `.crt`/`.cer` samo za sertifikate,
- `.csr` za Certificate Signing Requests, koji ne sadrže sertifikate ni privatne ključeve,
- `.jks`/`.keystore`/`.keys` za Java Keystores, koji mogu sadržati sertifikate zajedno sa privatnim ključevima koje koriste Java aplikacije.

Ove datoteke mogu se pretražiti pomoću PowerShell-a ili command prompt-a, traženjem navedenih ekstenzija.

U slučajevima kada se pronađe PKCS#12 datoteka sertifikata zaštićena lozinkom, hash se može izvući pomoću alata `pfx2john.py`, dostupnog na [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Nakon toga, JohnTheRipper može se koristiti za pokušaj crackovanja lozinke.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5 (UnPAC the hash)

Navedeni sadržaj objašnjava metod krađe NTLM credentials putem PKINIT-a, konkretno kroz metod krađe označen kao THEFT5. Ovde je sadržaj ponovo objašnjen u pasivnom obliku, uz anonimizaciju i sažimanje sadržaja gde je to primenljivo:<sup>[[1]](#references)</sup>

Da bi se podržala NTLM authentication `MS-NLMP` za aplikacije koje ne omogućavaju Kerberos authentication, KDC je dizajniran tako da vrati korisničku NTLM one-way function (OWF) unutar privilege attribute certificate (PAC)-a, konkretno u `PAC_CREDENTIAL_INFO` buffer-u, kada se koristi PKCA. Prema tome, ako se account authenticate-uje i obezbedi Ticket-Granting Ticket (TGT) putem PKINIT-a, implicitno je obezbeđen mehanizam koji omogućava trenutnom host-u da izvuče NTLM hash iz TGT-a radi održavanja legacy authentication protokola. Ovaj proces obuhvata decryption `PAC_CREDENTIAL_DATA` structure-a, koji u suštini predstavlja NDR serialized prikaz NTLM plaintext-a.

Utility **Kekeo**, dostupan na [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), navodi se kao alat koji može da zatraži TGT koji sadrži ove podatke, čime se omogućava preuzimanje korisničkog NTLM-a. Komanda koja se koristi u tu svrhu je sledeća:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** takođe može da preuzme ove informacije pomoću opcije **`asktgt [...] /getcredentials`**.

Pored toga, navodi se da Kekeo može da obrađuje sertifikate zaštićene smartcard-om, pod uslovom da je PIN moguće preuzeti, uz upućivanje na [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Navodi se da istu mogućnost podržava i **Rubeus**, dostupan na [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Ovo objašnjenje obuhvata proces i alate koji se koriste za krađu NTLM akreditiva putem PKINIT-a, sa fokusom na preuzimanje NTLM hash vrednosti kroz TGT dobijen pomoću PKINIT-a, kao i na uslužne alate koji olakšavaju ovaj proces.

## Reference

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
