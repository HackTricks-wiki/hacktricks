# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**To jest podsumowanie technik utrzymywania domeny przedstawionych w [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Sprawdź to, aby uzyskać więcej szczegółów.

## Fałszowanie certyfikatów za pomocą skradzionych certyfikatów CA - DPERSIST1

Jak można stwierdzić, że certyfikat jest certyfikatem CA?

Można ustalić, że certyfikat jest certyfikatem CA, jeśli spełnione są następujące warunki:

- Certyfikat jest przechowywany na serwerze CA, a jego klucz prywatny jest zabezpieczony przez DPAPI maszyny lub przez sprzęt, taki jak TPM/HSM, jeśli system operacyjny to wspiera.
- Pola Issuer i Subject certyfikatu odpowiadają wyróżnionej nazwie CA.
- W certyfikatach CA obecne jest rozszerzenie "CA Version" wyłącznie.
- Certyfikat nie zawiera pól Extended Key Usage (EKU).

Aby wyodrębnić klucz prywatny tego certyfikatu, narzędzie `certsrv.msc` na serwerze CA jest wspieraną metodą za pośrednictwem wbudowanego GUI. Niemniej jednak, ten certyfikat nie różni się od innych przechowywanych w systemie; dlatego można zastosować metody takie jak [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) do jego wyodrębnienia.

Certyfikat i klucz prywatny można również uzyskać za pomocą Certipy, używając następującego polecenia:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Po zdobyciu certyfikatu CA i jego klucza prywatnego w formacie `.pfx`, można wykorzystać narzędzia takie jak [ForgeCert](https://github.com/GhostPack/ForgeCert) do generowania ważnych certyfikatów:
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
> Użytkownik, który jest celem fałszowania certyfikatu, musi być aktywny i zdolny do uwierzytelnienia w Active Directory, aby proces zakończył się sukcesem. Fałszowanie certyfikatu dla specjalnych kont, takich jak krbtgt, jest nieskuteczne.

Ten fałszywy certyfikat będzie **ważny** do daty końcowej określonej i **tak długo, jak certyfikat CA jest ważny** (zwykle od 5 do **10+ lat**). Jest również ważny dla **maszyn**, więc w połączeniu z **S4U2Self**, atakujący może **utrzymać trwałość na dowolnej maszynie w domenie** tak długo, jak certyfikat CA jest ważny.\
Ponadto, **certyfikaty generowane** tą metodą **nie mogą być unieważnione**, ponieważ CA nie jest ich świadoma.

## Zaufanie do fałszywych certyfikatów CA - DPERSIST2

Obiekt `NTAuthCertificates` jest zdefiniowany jako zawierający jeden lub więcej **certyfikatów CA** w swoim atrybucie `cacertificate`, z którego korzysta Active Directory (AD). Proces weryfikacji przez **kontroler domeny** polega na sprawdzeniu obiektu `NTAuthCertificates` pod kątem wpisu odpowiadającego **CA określonemu** w polu Wydawca autoryzującego **certyfikatu**. Uwierzytelnianie postępuje, jeśli znaleziono dopasowanie.

Certyfikat CA podpisany samodzielnie może być dodany do obiektu `NTAuthCertificates` przez atakującego, pod warunkiem, że ma kontrolę nad tym obiektem AD. Zwykle tylko członkowie grupy **Enterprise Admin**, wraz z **Domain Admins** lub **Administratorami** w **domenie głównej lasu**, mają uprawnienia do modyfikacji tego obiektu. Mogą edytować obiekt `NTAuthCertificates` za pomocą `certutil.exe` z poleceniem `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, lub korzystając z [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Ta zdolność jest szczególnie istotna, gdy jest używana w połączeniu z wcześniej opisanym sposobem wykorzystania ForgeCert do dynamicznego generowania certyfikatów.

## Złośliwa niewłaściwa konfiguracja - DPERSIST3

Możliwości **trwałości** poprzez **modyfikacje deskryptora zabezpieczeń komponentów AD CS** są liczne. Modyfikacje opisane w sekcji "[Domain Escalation](domain-escalation.md)" mogą być złośliwie wdrażane przez atakującego z podwyższonym dostępem. Obejmuje to dodanie "praw kontrolnych" (np. WriteOwner/WriteDACL/etc.) do wrażliwych komponentów, takich jak:

- Obiekt komputera AD **serwera CA**
- **Serwer RPC/DCOM serwera CA**
- Dowolny **obiekt lub kontener AD potomny** w **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na przykład kontener szablonów certyfikatów, kontener autorytetów certyfikacji, obiekt NTAuthCertificates itd.)
- **Grupy AD, którym przyznano prawa do kontrolowania AD CS** domyślnie lub przez organizację (takie jak wbudowana grupa Cert Publishers i wszyscy jej członkowie)

Przykład złośliwej implementacji obejmowałby atakującego, który ma **podwyższone uprawnienia** w domenie, dodającego uprawnienie **`WriteOwner`** do domyślnego szablonu certyfikatu **`User`**, przy czym atakujący byłby głównym uprawnionym do tego prawa. Aby to wykorzystać, atakujący najpierw zmieniłby własność szablonu **`User`** na siebie. Następnie, **`mspki-certificate-name-flag`** zostałby ustawiony na **1** w szablonie, aby włączyć **`ENROLLEE_SUPPLIES_SUBJECT`**, co pozwala użytkownikowi dostarczyć nazwę alternatywną w żądaniu. Następnie atakujący mógłby **zarejestrować** się, korzystając z **szablonu**, wybierając nazwę **administrator domeny** jako nazwę alternatywną, i wykorzystać uzyskany certyfikat do uwierzytelnienia jako DA.

{{#include ../../../banners/hacktricks-training.md}}
