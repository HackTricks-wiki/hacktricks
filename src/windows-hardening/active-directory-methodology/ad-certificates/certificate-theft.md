# Kradzież certyfikatów AD CS

{{#include ../../../banners/hacktricks-training.md}}

**To krótkie podsumowanie rozdziałów dotyczących kradzieży z doskonałego opracowania dostępnego pod adresem [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## Do czego mogę użyć certyfikatu

Zanim sprawdzimy, jak ukraść certyfikaty, znajdziesz tutaj informacje o tym, do czego można wykorzystać dany certyfikat:
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
## Eksportowanie certyfikatów za pomocą Crypto APIs – THEFT1

W **interaktywnej sesji pulpitu** wyodrębnienie certyfikatu użytkownika lub komputera wraz z kluczem prywatnym jest łatwe, szczególnie jeśli **klucz prywatny można eksportować**. Można to zrobić, przechodząc do certyfikatu w `certmgr.msc`, klikając go prawym przyciskiem myszy i wybierając `All Tasks → Export`, aby wygenerować chroniony hasłem plik .pfx.<sup>[[1]](#references)</sup>

W przypadku **podejścia programistycznego** można użyć narzędzi takich jak cmdlet PowerShell `ExportPfxCertificate` lub projektów takich jak [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer). Wykorzystują one **Microsoft CryptoAPI** (CAPI) lub Cryptography API: Next Generation (CNG) do interakcji z magazynem certyfikatów. Te API udostępniają szereg usług kryptograficznych, w tym usługi wymagane do przechowywania certyfikatów i uwierzytelniania.

Jeśli jednak klucz prywatny jest ustawiony jako nieeksportowalny, zarówno CAPI, jak i CNG zazwyczaj blokują wyodrębnianie takich certyfikatów. Aby obejść to ograniczenie, można użyć narzędzi takich jak **Mimikatz**. Mimikatz udostępnia polecenia `crypto::capi` i `crypto::cng`, które patchują odpowiednie API, umożliwiając eksport kluczy prywatnych. W szczególności `crypto::capi` patchuje CAPI w bieżącym procesie, natomiast `crypto::cng` celuje w pamięć **lsass.exe**, aby ją spatchować.

## Kradzież certyfikatu użytkownika za pomocą DPAPI – THEFT2

Więcej informacji o DPAPI:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

W systemie Windows **klucze prywatne certyfikatów są chronione przez DPAPI**. Należy pamiętać, że **lokalizacje przechowywania kluczy prywatnych użytkownika i komputera** są różne, a struktury plików różnią się w zależności od API kryptograficznego używanego przez system operacyjny. **SharpDPAPI** to narzędzie, które może automatycznie uwzględniać te różnice podczas odszyfrowywania obiektów blob DPAPI.<sup>[[1]](#references)</sup>

**Certyfikaty użytkownika** są przechowywane głównie w rejestrze pod adresem `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, ale niektóre z nich można również znaleźć w katalogu `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Odpowiadające im **klucze prywatne** są zazwyczaj przechowywane w `%APPDATA%\Microsoft\Crypto\RSA\User SID\` dla kluczy **CAPI** oraz w `%APPDATA%\Microsoft\Crypto\Keys\` dla kluczy **CNG**.

Aby **wyodrębnić certyfikat wraz z powiązanym kluczem prywatnym**, należy:

1. **Wybrać docelowy certyfikat** z magazynu użytkownika i pobrać nazwę jego magazynu kluczy.
2. **Zlokalizować wymagany klucz główny DPAPI**, aby odszyfrować odpowiadający mu klucz prywatny.
3. **Odszyfrować klucz prywatny** za pomocą klucza głównego DPAPI w postaci jawnego tekstu.

Aby **uzyskać klucz główny DPAPI w postaci jawnego tekstu**, można zastosować następujące podejścia:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Aby usprawnić deszyfrowanie plików masterkey i plików kluczy prywatnych, przydatna okazuje się komenda `certificates` z [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI). Przyjmuje ona argumenty `/pvk`, `/mkfile`, `/password` lub `{GUID}:KEY` w celu odszyfrowania kluczy prywatnych i powiązanych certyfikatów, a następnie generuje plik `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Kradzież certyfikatów maszynowych za pomocą DPAPI – THEFT3

Certyfikaty maszynowe przechowywane przez Windows w rejestrze `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` oraz powiązane klucze prywatne znajdujące się w `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (dla CAPI) i `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (dla CNG) są szyfrowane za pomocą głównych kluczy DPAPI maszyny. Kluczy tych nie można odszyfrować za pomocą klucza kopii zapasowej DPAPI domeny; wymagany jest natomiast **sekret DPAPI_SYSTEM LSA**, do którego dostęp ma wyłącznie użytkownik SYSTEM.<sup>[[1]](#references)</sup>

Ręczne odszyfrowanie można przeprowadzić, wykonując w **Mimikatz** polecenie `lsadump::secrets` w celu wyodrębnienia sekretu DPAPI_SYSTEM LSA, a następnie używając tego klucza do odszyfrowania głównych kluczy maszyny. Alternatywnie, po spatchowaniu CAPI/CNG w sposób opisany wcześniej można użyć polecenia Mimikatz `crypto::certificates /export /systemstore:LOCAL_MACHINE`.

**SharpDPAPI** oferuje bardziej zautomatyzowane podejście za pomocą polecenia certificates. Po użyciu flagi `/machine` z podwyższonymi uprawnieniami narzędzie eskaluje uprawnienia do SYSTEM, zrzuca sekret DPAPI_SYSTEM LSA, używa go do odszyfrowania głównych kluczy DPAPI maszyny, a następnie wykorzystuje te klucze w postaci jawnego tekstu jako tabelę wyszukiwania do odszyfrowania dowolnych prywatnych kluczy certyfikatów maszynowych.

## Wyszukiwanie plików certyfikatów – THEFT4

Certyfikaty można czasami znaleźć bezpośrednio w systemie plików, na przykład w udziałach plikowych lub folderze Downloads. Najczęściej spotykane typy plików certyfikatów przeznaczonych dla środowisk Windows to pliki `.pfx` i `.p12`. Rzadziej występują także pliki z rozszerzeniami `.pkcs12` i `.pem`. Inne istotne rozszerzenia plików związanych z certyfikatami obejmują:<sup>[[1]](#references)</sup>

- `.key` dla kluczy prywatnych,
- `.crt`/`.cer` wyłącznie dla certyfikatów,
- `.csr` dla żądań podpisania certyfikatu (Certificate Signing Requests), które nie zawierają certyfikatów ani kluczy prywatnych,
- `.jks`/`.keystore`/`.keys` dla Java Keystores, które mogą zawierać certyfikaty wraz z kluczami prywatnymi używanymi przez aplikacje Java.

Pliki te można wyszukiwać za pomocą PowerShell lub wiersza polecenia, szukając wymienionych rozszerzeń.

Jeśli znaleziony plik certyfikatu PKCS#12 jest chroniony hasłem, możliwe jest wyodrębnienie hasha za pomocą `pfx2john.py`, dostępnego na stronie [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Następnie można użyć JohnTheRipper do próby złamania hasła.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Kradzież poświadczeń NTLM przez PKINIT – THEFT5 (UnPAC the hash)

Przedstawiona treść wyjaśnia metodę kradzieży poświadczeń NTLM przez PKINIT, a konkretnie metodę kradzieży oznaczoną jako THEFT5. Poniżej przedstawiono jej ponowne wyjaśnienie w stronie biernej, z anonimizacją i podsumowaniem treści tam, gdzie ma to zastosowanie:<sup>[[1]](#references)</sup>

Aby obsługiwać uwierzytelnianie NTLM `MS-NLMP` w przypadku aplikacji, które nie obsługują uwierzytelniania Kerberos, KDC został zaprojektowany tak, aby zwracać jednokierunkową funkcję (OWF) NTLM użytkownika w ramach certyfikatu atrybutów uprawnień (PAC), konkretnie w buforze `PAC_CREDENTIAL_INFO`, gdy używany jest PKCA. W rezultacie, jeśli konto uwierzytelni się i uzyska Ticket-Granting Ticket (TGT) za pośrednictwem PKINIT, zapewniony zostaje mechanizm umożliwiający bieżącemu hostowi wyodrębnienie hasha NTLM z TGT w celu obsługi starszych protokołów uwierzytelniania. Proces ten obejmuje odszyfrowanie struktury `PAC_CREDENTIAL_DATA`, która jest zasadniczo serializowaną za pomocą NDR reprezentacją danych uwierzytelniających NTLM w postaci jawnej.

Wspomniano, że narzędzie **Kekeo**, dostępne pod adresem [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), może zażądać TGT zawierającego te konkretne dane, umożliwiając tym samym odzyskanie NTLM użytkownika. Użyte w tym celu polecenie jest następujące:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** może również uzyskać te informacje za pomocą opcji **`asktgt [...] /getcredentials`**.

Dodatkowo wskazano, że Kekeo może przetwarzać certyfikaty chronione przez smartcard, pod warunkiem że można odzyskać kod PIN. W tym kontekście odwołano się do [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Wskazano również, że tę samą funkcję obsługuje **Rubeus**, dostępny pod adresem [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

To wyjaśnienie przedstawia proces i narzędzia związane z kradzieżą poświadczeń NTLM za pośrednictwem PKINIT, koncentrując się na odzyskiwaniu hashy NTLM za pomocą TGT uzyskanego przez PKINIT oraz na narzędziach ułatwiających ten proces.

## Referencje

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
