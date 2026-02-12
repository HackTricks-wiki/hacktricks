# AD CS — utrzymanie w domenie

{{#include ../../../banners/hacktricks-training.md}}

**To jest podsumowanie technik utrzymania w domenie opisanych w [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf). Sprawdź tam szczegóły.**

## Fałszowanie certyfikatów przy użyciu skradzionych certyfikatów CA (Golden Certificate) - DPERSIST1

Jak rozpoznać, że certyfikat jest certyfikatem CA?

Można stwierdzić, że certyfikat jest certyfikatem CA, jeśli spełnionych jest kilka warunków:

- Certyfikat jest przechowywany na serwerze CA, a jego klucz prywatny zabezpieczony za pomocą DPAPI maszyny lub sprzętowo, np. TPM/HSM, jeśli system operacyjny to obsługuje.
- Pola Issuer i Subject certyfikatu odpowiadają rozróżnialnej nazwie (distinguished name) CA.
- W certyfikatach CA występuje wyłącznie rozszerzenie "CA Version".
- Certyfikat nie zawiera pól Extended Key Usage (EKU).

Aby wydobyć klucz prywatny tego certyfikatu, obsługowaną metodą jest użycie narzędzia `certsrv.msc` na serwerze CA za pomocą wbudowanego GUI. Niemniej jednak ten certyfikat nie różni się od innych przechowywanych w systemie; dlatego do ekstrakcji można zastosować metody takie jak [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Certyfikat i klucz prywatny można również uzyskać za pomocą Certipy używając następującego polecenia:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Po zdobyciu certyfikatu CA i jego klucza prywatnego w formacie `.pfx`, narzędzia takie jak [ForgeCert](https://github.com/GhostPack/ForgeCert) mogą być użyte do wygenerowania ważnych certyfikatów:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> Użytkownik będący celem fałszowania certyfikatu musi być aktywny i zdolny do uwierzytelnienia w Active Directory, aby proces się powiódł. Fałszowanie certyfikatu dla specjalnych kont, takich jak krbtgt, jest nieskuteczne.

Ten sfałszowany certyfikat będzie **ważny** do określonej daty zakończenia oraz tak długo, jak ważny jest certyfikat root CA (zwykle od 5 do **10+ lat**). Jest on również ważny dla **maszyn**, więc w połączeniu z **S4U2Self** atakujący może **maintain persistence on any domain machine** tak długo, jak ważny jest certyfikat CA.\
Ponadto **certyfikaty wygenerowane** tą metodą **nie mogą być odwołane**, ponieważ CA o nich nie wie.

### Działanie pod Strong Certificate Mapping Enforcement (2025+)

Od 11 lutego 2025 (po wdrożeniu KB5014754) kontrolery domeny domyślnie stosują **Full Enforcement** dla mapowań certyfikatów. W praktyce oznacza to, że Twoje sfałszowane certyfikaty muszą albo:

- Zawierać silne powiązanie z docelowym kontem (na przykład rozszerzenie bezpieczeństwa SID), lub
- Być sparowane z silnym, eksplicytnym mapowaniem w atrybucie `altSecurityIdentities` obiektu docelowego.

Niezawodnym podejściem do persistence jest wygenerowanie sfałszowanego certyfikatu powiązanego z ukradzionym Enterprise CA, a następnie dodanie silnego, eksplicytnego mapowania do principala ofiary:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Uwagi
- Jeśli potrafisz stworzyć sfałszowane certyfikaty, które zawierają rozszerzenie SID, będą one mapowane automatycznie nawet przy Full Enforcement. W przeciwnym razie preferuj jawne, silne mapowania. Zobacz [account-persistence](account-persistence.md) aby dowiedzieć się więcej o jawnych mapowaniach.
- Unieważnianie nie pomaga obrońcom: sfałszowane certyfikaty nie są znane w bazie danych CA i w związku z tym nie można ich unieważnić.

#### Full-Enforcement compatible forging (SID-aware)

Zaktualizowane narzędzia pozwalają osadzić SID bezpośrednio, dzięki czemu golden certificates pozostają użyteczne nawet gdy DCs odrzucają weak mappings:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Wstawiając SID unikasz potrzeby modyfikowania `altSecurityIdentities`, które mogą być monitorowane, a jednocześnie spełniasz rygorystyczne kontrole mapowania.

## Ufanie fałszywym certyfikatom CA - DPERSIST2

Obiekt `NTAuthCertificates` jest przeznaczony do przechowywania jednego lub więcej **certyfikatów CA** w atrybucie `cacertificate`, którego używa Active Directory (AD). Proces weryfikacji wykonywany przez **domain controller** polega na sprawdzeniu obiektu `NTAuthCertificates` pod kątem wpisu pasującego do **CA określonego** w polu Issuer uwierzytelniającego **certyfikatu**. Uwierzytelnianie jest kontynuowane, jeśli znaleziono dopasowanie.

Samopodpisany certyfikat CA może zostać dodany do obiektu `NTAuthCertificates` przez atakującego, o ile ma on kontrolę nad tym obiektem AD. Zwykle tylko członkowie grupy **Enterprise Admin**, wraz z **Domain Admins** lub **Administrators** w **forest root’s domain**, mają uprawnienia do modyfikacji tego obiektu. Mogą oni edytować obiekt `NTAuthCertificates` używając `certutil.exe` poleceniem `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, lub korzystając z [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Dodatkowe przydatne polecenia dla tej techniki:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Ta możliwość jest szczególnie istotna w połączeniu z wcześniej opisanym sposobem wykorzystującym ForgeCert do dynamicznego generowania certyfikatów.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Złośliwa błędna konfiguracja - DPERSIST3

Możliwości uzyskania **persistence** poprzez modyfikacje deskryptorów zabezpieczeń komponentów **AD CS** są liczne. Modyfikacje opisane w sekcji "[Domain Escalation](domain-escalation.md)" mogą zostać złośliwie wprowadzone przez atakującego z podwyższonymi uprawnieniami. Obejmuje to dodanie „praw kontrolnych” (np. WriteOwner/WriteDACL/etc.) do wrażliwych komponentów, takich jak:

- Obiekt **CA server’s AD computer**
- **CA server’s RPC/DCOM server**
- Każdy **descendant AD object or container** w **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na przykład Certificate Templates container, Certification Authorities container, obiekt NTAuthCertificates itd.)
- **AD groups delegated rights to control AD CS** domyślnie lub przez organizację (takie jak wbudowana grupa Cert Publishers i któregokolwiek z jej członków)

Przykład złośliwej implementacji obejmowałby atakującego, który ma **elevated permissions** w domenie, dodającego uprawnienie **`WriteOwner`** do domyślnego szablonu certyfikatów **`User`**, gdzie atakujący jest principalem tego prawa. Aby to wykorzystać, atakujący najpierw zmieniłby właściciela szablonu **`User`** na siebie. Następnie na szablonie zostałby ustawiony **`mspki-certificate-name-flag`** na **1**, aby włączyć **`ENROLLEE_SUPPLIES_SUBJECT`**, co pozwala użytkownikowi podać Subject Alternative Name w żądaniu. W konsekwencji atakujący mógłby **enroll** używając tego **template**, wybierając jako nazwę alternatywną nazwę **domain administrator**, i użyć pozyskanego certyfikatu do uwierzytelnienia jako DA.

Praktyczne ustawienia, które atakujący mogą wprowadzić dla długoterminowego persistence w domenie (zob. {{#ref}}domain-escalation.md{{#endref}} po szczegóły i wykrywanie):

- Flagi polityki CA pozwalające na SAN od wnioskodawców (np. włączenie `EDITF_ATTRIBUTESUBJECTALTNAME2`). To utrzymuje ścieżki podobne do ESC1 wykorzystywalne.
- DACL szablonu lub ustawienia umożliwiające wydawanie z możliwością uwierzytelniania (np. dodanie EKU Client Authentication, włączenie `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolowanie obiektu `NTAuthCertificates` lub kontenerów CA, aby stale ponownie wprowadzać rogue issuers, jeśli obrońcy spróbują posprzątać.

> [!TIP]
> In hardened environments after KB5014754, pairing these misconfigurations with explicit strong mappings (`altSecurityIdentities`) ensures your issued or forged certificates remain usable even when DCs enforce strong mapping.

### Certificate renewal abuse (ESC14) for persistence

Jeśli przejmiesz authentication-capable certificate (lub Enrollment Agent), możesz go **renew** w nieskończoność, dopóki wydający template pozostaje opublikowany, a twój CA nadal ufa łańcuchowi wydawcy. Odnowienie zachowuje oryginalne powiązania tożsamości, ale wydłuża ważność, utrudniając usunięcie, chyba że szablon zostanie naprawiony lub CA zostanie ponownie opublikowane.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Jeśli kontrolery domeny są w trybie **Full Enforcement**, dodaj `-sid <victim SID>` (lub użyj szablonu, który nadal zawiera rozszerzenie bezpieczeństwa SID), aby odnowiony certyfikat końcowy nadal był silnie mapowany bez modyfikowania `altSecurityIdentities`. Atakujący z uprawnieniami administratora CA mogą także dostosować `policy\RenewalValidityPeriodUnits`, aby wydłużyć okres ważności odnowionych certyfikatów przed wystawieniem sobie certyfikatu.

## References

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
