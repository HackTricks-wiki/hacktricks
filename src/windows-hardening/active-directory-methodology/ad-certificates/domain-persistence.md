# AD CS — trwałość w domenie

{{#include ../../../banners/hacktricks-training.md}}

**To podsumowanie technik utrzymywania trwałości w domenie opisanych w [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Więcej szczegółów znajdziesz w tym dokumencie.<sup>[[5]](#references)</sup>

## Fałszowanie certyfikatów przy użyciu skradzionych certyfikatów CA (Golden Certificate) - DPERSIST1

Jak rozpoznać, że certyfikat jest certyfikatem CA?

Można stwierdzić, że certyfikat jest certyfikatem CA, jeśli spełnia kilka warunków:<sup>[[5]](#references)</sup>

- Certyfikat jest przechowywany na serwerze CA, a jego klucz prywatny jest zabezpieczony przez DPAPI komputera lub przez sprzęt, taki jak TPM/HSM, jeśli obsługuje go system operacyjny.
- Pola Issuer i Subject certyfikatu są zgodne z nazwą wyróżniającą CA.
- Rozszerzenie „CA Version” występuje wyłącznie w certyfikatach CA.
- Certyfikat nie zawiera pól Extended Key Usage (EKU).

Do wyodrębnienia klucza prywatnego tego certyfikatu obsługiwaną metodą jest użycie narzędzia `certsrv.msc` na serwerze CA za pośrednictwem wbudowanego GUI. Certyfikat ten nie różni się jednak od innych certyfikatów przechowywanych w systemie, dlatego do jego wyodrębnienia można zastosować metody takie jak [technika THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Certyfikat i klucz prywatny można również uzyskać za pomocą Certipy, używając następującego polecenia:<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Po uzyskaniu certyfikatu CA i jego klucza prywatnego w formacie `.pfx` można użyć narzędzi takich jak [ForgeCert](https://github.com/GhostPack/ForgeCert), aby wygenerować prawidłowe certyfikaty:

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
> Użytkownik, dla którego fałszowany jest certyfikat, musi być aktywny i móc uwierzytelniać się w Active Directory, aby proces zakończył się powodzeniem. Fałszowanie certyfikatu dla kont specjalnych, takich jak krbtgt, jest nieskuteczne.

Ten sfałszowany certyfikat będzie **ważny** do określonej daty końcowej i tak **długo, jak ważny jest certyfikat głównego urzędu certyfikacji** (zwykle od 5 do **ponad 10 lat**). Jest również ważny dla **komputerów**, więc w połączeniu z **S4U2Self** atakujący może **utrzymać persistence na dowolnym komputerze w domenie** tak długo, jak ważny jest certyfikat CA.\
Co więcej, **certyfikatów wygenerowanych** tą metodą **nie można unieważnić**, ponieważ CA nie wie o ich istnieniu.

### Działanie przy włączonym Strong Certificate Mapping Enforcement (2025+)

Od 11 lutego 2025 r. (po wdrożeniu KB5014754) kontrolery domeny domyślnie stosują **Full Enforcement** w przypadku mapowania certyfikatów. W praktyce oznacza to, że sfałszowane certyfikaty muszą:

- Zawierać silne powiązanie z kontem docelowym (na przykład rozszerzenie zabezpieczeń SID) lub
- Być połączone z silnym, jawnym mapowaniem w atrybucie `altSecurityIdentities` obiektu docelowego.<sup>[[1]](#references)</sup>

Niezawodne podejście do utrzymania persistence polega na wystawieniu sfałszowanego certyfikatu, którego łańcuch prowadzi do skradzionego Enterprise CA, a następnie dodaniu silnego, jawnego mapowania do podmiotu będącego celem:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Notatki
- Jeśli możesz utworzyć sfałszowane certyfikaty zawierające rozszerzenie zabezpieczeń SID, będą one mapowane niejawnie nawet przy włączonym trybie Full Enforcement. W przeciwnym razie preferuj jawne silne mapowania. Więcej informacji o jawnych mapowaniach znajdziesz w [account-persistence](account-persistence.md).
- Unieważnianie nie pomaga tu obrońcom: sfałszowane certyfikaty są nieznane bazie danych CA, więc nie można ich unieważnić.

#### Tworzenie sfałszowanych certyfikatów zgodnych z Full Enforcement (uwzględniających SID)

Zaktualizowane narzędzia pozwalają osadzić SID bezpośrednio w certyfikacie, dzięki czemu golden certificates pozostają użyteczne nawet wtedy, gdy kontrolery domeny odrzucają słabe mapowania:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

Osadzając SID, unikasz konieczności modyfikowania `altSecurityIdentities`, które może być monitorowane, a jednocześnie spełniasz wymagania dotyczące silnego mapowania.

## Zaufanie do fałszywych certyfikatów CA - DPERSIST2

Obiekt `NTAuthCertificates` jest zdefiniowany jako zawierający co najmniej jeden **certyfikat CA** w swoim atrybucie `cacertificate`, z którego korzysta Active Directory (AD). Proces weryfikacji przeprowadzany przez **kontroler domeny** obejmuje sprawdzenie obiektu `NTAuthCertificates` pod kątem wpisu pasującego do **CA wskazanego** w polu Issuer uwierzytelniającego **certyfikatu**. Uwierzytelnianie jest kontynuowane, jeśli zostanie znalezione dopasowanie.<sup>[[5]](#references)</sup>

Atakujący może dodać samopodpisany certyfikat CA do obiektu `NTAuthCertificates`, jeśli ma nad nim kontrolę. Zwykle uprawnienie do modyfikowania tego obiektu mają tylko członkowie grupy **Enterprise Admin**, a także grup **Domain Admins** lub **Administrators** w **domenie głównego lasu**. Mogą oni edytować obiekt `NTAuthCertificates` za pomocą `certutil.exe`, używając polecenia `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, lub korzystając z [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Dodatkowe przydatne polecenia związane z tą techniką:

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

Ta możliwość jest szczególnie istotna w połączeniu z wcześniej opisaną metodą wykorzystującą ForgeCert do dynamicznego generowania certyfikatów.

> Kwestie mapowania po 2025 r.: umieszczenie rogue CA w NTAuth ustanawia zaufanie wyłącznie do wystawiającego CA. Aby używać certyfikatów końcowych do logowania, gdy kontrolery domeny działają w trybie **Full Enforcement**, certyfikat końcowy musi zawierać rozszerzenie zabezpieczeń SID albo obiekt docelowy musi mieć silne, jawne mapowanie (na przykład Issuer+Serial w `altSecurityIdentities`). Zobacz {{#ref}}account-persistence.md{{#endref}}.

## Złośliwa błędna konfiguracja - DPERSIST3

Możliwości utrzymania **persistence** przez **modyfikację deskryptorów zabezpieczeń** składników AD CS są liczne. Modyfikacje opisane w sekcji „[Domain Escalation](domain-escalation.md)” mogą zostać złośliwie wprowadzone przez atakującego z podwyższonymi uprawnieniami. Obejmuje to dodanie „uprawnień do kontrolowania” (np. WriteOwner/WriteDACL/itp.) do wrażliwych składników, takich jak:<sup>[[5]](#references)</sup>

- Obiekt **komputera AD serwera CA**
- **Serwer RPC/DCOM serwera CA**
- Dowolny **podrzędny obiekt lub kontener AD** w **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na przykład kontener Certificate Templates, kontener Certification Authorities, obiekt NTAuthCertificates itp.)
- **Grupy AD, którym organizacja jawnie delegowała uprawnienia do kontrolowania CA lub szablonów**. Wbudowana grupa Cert Publishers ma uprawnienia do publikowania certyfikatów w obiektach użytkowników w AD; samo członkostwo w tej grupie nie nadaje uprawnień do kontrolowania CA lub szablonów ani uprawnień do rejestracji. Osobno sprawdź odpowiednie uprawnienia CA i szablonów. Zobacz [Microsoft's description of Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) oraz [certificate template permissions](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Przykładem złośliwego wdrożenia byłoby dodanie przez atakującego, który ma **podwyższone uprawnienia** w domenie, uprawnienia **`WriteOwner`** do domyślnego szablonu certyfikatu **`User`**, przy czym atakujący byłby podmiotem, któremu nadano to uprawnienie. Aby to wykorzystać, atakujący najpierw zmieniłby właściciela szablonu **`User`** na siebie. Następnie ustawiłby **`mspki-certificate-name-flag`** na **1** w szablonie, aby włączyć **`ENROLLEE_SUPPLIES_SUBJECT`** i umożliwić użytkownikowi podanie w żądaniu alternatywnej nazwy podmiotu (Subject Alternative Name). Atakujący mógłby potem **zarejestrować się** przy użyciu **szablonu**, wybierając jako nazwę alternatywną nazwę **administratora domeny**, a następnie użyć uzyskanego certyfikatu do uwierzytelnienia się jako DA.

Praktyczne ustawienia, które atakujący mogą zmienić, aby utrzymać persistence w domenie przez długi czas (pełne omówienie i sposoby wykrywania znajdziesz w {{#ref}}domain-escalation.md{{#endref}}):

- Flagi zasad CA umożliwiające pobieranie SAN z żądań (np. włączenie `EDITF_ATTRIBUTESUBJECTALTNAME2`). Pozwala to nadal wykorzystywać ścieżki podobne do ESC1.
- DACL lub ustawienia szablonu umożliwiające wystawianie certyfikatów nadających się do uwierzytelniania (np. dodanie EKU Client Authentication, włączenie `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolowanie obiektu `NTAuthCertificates` lub kontenerów CA, aby stale ponownie wprowadzać rogue issuers, jeśli obrońcy spróbują je usunąć.

> [!TIP]
> W utwardzonych środowiskach po zastosowaniu KB5014754 połączenie tych błędnych konfiguracji z jawnymi, silnymi mapowaniami (`altSecurityIdentities`) zapewnia, że wystawione lub sfałszowane certyfikaty pozostaną użyteczne nawet wtedy, gdy kontrolery domeny będą wymuszać silne mapowanie.

### Nadużycie odnawiania certyfikatów (ESC14) w celu utrzymania persistence

Jeśli przejmiesz certyfikat umożliwiający uwierzytelnianie (lub certyfikat Enrollment Agent), możesz go **odnawiać bezterminowo**, dopóki szablon wystawiający pozostaje opublikowany, a CA nadal ufa łańcuchowi wystawcy. Odnowienie zachowuje pierwotne powiązania tożsamości, ale przedłuża ważność certyfikatu, przez co usunięcie zagrożenia jest trudne, chyba że szablon zostanie naprawiony lub CA ponownie opublikowane.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Jeśli kontrolery domeny działają w trybie **Full Enforcement**, dodaj `-sid <victim SID>` (lub użyj szablonu, który nadal zawiera rozszerzenie zabezpieczeń SID), aby odnowiony certyfikat końcowy nadal był silnie mapowany bez modyfikowania `altSecurityIdentities`. Atakujący z uprawnieniami administratora CA mogą też zmienić `policy\RenewalValidityPeriodUnits`, aby wydłużyć okres ważności odnawianych certyfikatów, zanim wystawią sobie certyfikat.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Zmiany dotyczące uwierzytelniania opartego na certyfikatach na kontrolerach domeny Windows (harmonogram wymuszania i silne mapowania)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Dokumentacja poleceń oraz użycie forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (zintegrowane forge z obsługą SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Omówienie nadużyć związanych z odnawianiem ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Nadużywanie Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
