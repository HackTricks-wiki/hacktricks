# Certyfikaty AD

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

### Składniki certyfikatu

- **Podmiot (Subject)** certyfikatu wskazuje jego właściciela.
- **Klucz publiczny (Public Key)** jest powiązany z kluczem prywatnym, aby połączyć certyfikat z jego prawowitym właścicielem.
- **Okres ważności (Validity Period)**, określony datami **NotBefore** i **NotAfter**, wyznacza czas obowiązywania certyfikatu.
- Unikatowy **numer seryjny (Serial Number)** nadany przez urząd certyfikacji (CA) identyfikuje każdy certyfikat.
- **Wystawca (Issuer)** to urząd certyfikacji, który wystawił certyfikat.
- **SubjectAlternativeName** umożliwia przypisanie dodatkowych nazw do podmiotu, zwiększając elastyczność jego identyfikacji.
- **Ograniczenia podstawowe (Basic Constraints)** określają, czy certyfikat jest przeznaczony dla urzędu certyfikacji, czy podmiotu końcowego, oraz definiują ograniczenia jego użycia.
- **Rozszerzone zastosowania klucza (Extended Key Usages, EKUs)** określają konkretne przeznaczenie certyfikatu, np. podpisywanie kodu lub szyfrowanie poczty e-mail, za pomocą identyfikatorów obiektów (OID).
- **Algorytm podpisu (Signature Algorithm)** określa metodę podpisywania certyfikatu.
- **Podpis (Signature)**, utworzony przy użyciu klucza prywatnego wystawcy, gwarantuje autentyczność certyfikatu.<sup>[[4]](#references)</sup>

### Szczególne uwagi

- **Alternatywne nazwy podmiotu (SANs)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co jest istotne w przypadku serwerów obsługujących wiele domen. Bezpieczne procesy wystawiania certyfikatów są kluczowe, aby uniknąć ryzyka podszywania się przez atakujących, którzy manipulują specyfikacją SAN.<sup>[[4]](#references)</sup>

### Urzędy certyfikacji (CA) w Active Directory (AD)

AD CS rozpoznaje certyfikaty CA w lesie AD za pomocą specjalnych kontenerów, z których każdy pełni odrębną funkcję:<sup>[[4]](#references)</sup>

- Kontener **Certification Authorities** przechowuje zaufane certyfikaty głównych CA.
- Kontener **Enrolment Services** zawiera informacje o korporacyjnych CA i ich szablonach certyfikatów.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA upoważnionych do uwierzytelniania w AD.
- Kontener **AIA (Authority Information Access)** ułatwia weryfikację łańcucha certyfikatów za pomocą certyfikatów pośrednich i certyfikatów CA powiązanych relacją cross-certification.

### Uzyskiwanie certyfikatu: przepływ żądania certyfikatu przez klienta

1. Proces żądania rozpoczyna się od wyszukania przez klientów korporacyjnego CA.
2. Po wygenerowaniu pary kluczy publicznego i prywatnego tworzony jest CSR zawierający klucz publiczny i inne informacje.
3. CA weryfikuje CSR względem dostępnych szablonów certyfikatów i wystawia certyfikat zgodnie z uprawnieniami danego szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.<sup>[[4]](#references)</sup>

### Szablony certyfikatów

Definiowane w AD szablony określają ustawienia i uprawnienia dotyczące wystawiania certyfikatów, w tym dozwolone EKU oraz uprawnienia do rejestracji i modyfikacji. Są kluczowe dla zarządzania dostępem do usług certyfikatów.<sup>[[4]](#references)</sup>

**Wersja schematu szablonu ma znaczenie.** Starsze szablony **v1** (na przykład wbudowany szablon **WebServer**) nie mają kilku współczesnych mechanizmów wymuszania zasad. Badania nad **ESC15/EKUwu** wykazały, że w przypadku **szablonów v1** osoba składająca żądanie może umieścić w CSR wartości **Application Policies/EKUs**, które mają **pierwszeństwo przed** EKU skonfigurowanymi w szablonie. Umożliwia to uzyskanie certyfikatów do uwierzytelniania klienta, agenta rejestracji lub podpisywania kodu przy samych uprawnieniach do rejestracji. Należy preferować **szablony v2/v3**, usuwać lub zastępować domyślne szablony v1 oraz ściśle ograniczać EKU do zamierzonego zastosowania.<sup>[[1]](#references)</sup>

## Rejestracja certyfikatu

Proces rejestracji certyfikatu rozpoczyna administrator, który **tworzy szablon certyfikatu**. Następnie **publikuje** go korporacyjny urząd certyfikacji (CA). Dzięki temu szablon jest dostępny dla klientów, którzy mogą zarejestrować certyfikat. Aby to zrobić, nazwę szablonu dodaje się do pola `certificatetemplates` obiektu Active Directory.<sup>[[4]](#references)</sup>

Aby klient mógł zażądać certyfikatu, musi otrzymać **uprawnienia do rejestracji**. Uprawnienia te są określane przez deskryptory zabezpieczeń przypisane do szablonu certyfikatu i samego korporacyjnego CA. Żądanie zostanie zrealizowane tylko wtedy, gdy uprawnienia zostaną przyznane w obu miejscach.

### Uprawnienia do rejestracji szablonu

Uprawnienia te określa się za pomocą wpisów kontroli dostępu (ACE), które definiują m.in.:

- Uprawnienia **Certificate-Enrollment** i **Certificate-AutoEnrollment**, z których każde ma przypisany konkretny GUID.
- **ExtendedRights**, które zezwala na wszystkie uprawnienia rozszerzone.
- **FullControl/GenericAll**, które zapewnia pełną kontrolę nad szablonem.

### Uprawnienia do rejestracji w korporacyjnym CA

Uprawnienia CA są określone w jego deskryptorze zabezpieczeń, dostępnym w konsoli zarządzania Certificate Authority. Niektóre ustawienia umożliwiają nawet zdalny dostęp użytkownikom o niskich uprawnieniach, co może stanowić zagrożenie dla bezpieczeństwa.

### Dodatkowe mechanizmy kontroli wystawiania

Mogą obowiązywać dodatkowe mechanizmy kontroli, takie jak:

- **Zatwierdzenie przez menedżera**: żądania pozostają w stanie oczekiwania do czasu zatwierdzenia przez menedżera certyfikatów.
- **Agenci rejestracji i autoryzowane podpisy**: określają wymaganą liczbę podpisów CSR oraz wymagane identyfikatory OID zasad aplikacji.

### Metody żądania certyfikatów

Certyfikaty można uzyskać za pomocą:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), korzystając z interfejsów DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), przez nazwane potoki lub TCP/IP.
3. **Interfejsu webowego rejestracji certyfikatów**, po zainstalowaniu roli Certificate Authority Web Enrollment.
4. **Usługi rejestracji certyfikatów** (CES) wraz z usługą Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dla urządzeń sieciowych, z użyciem Simple Certificate Enrollment Protocol (SCEP).

Użytkownicy Windows mogą również żądać certyfikatów za pomocą interfejsu graficznego (`certmgr.msc` lub `certlm.msc`) albo narzędzi wiersza poleceń (`certreq.exe` lub polecenia PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Uwierzytelnianie certyfikatem

Active Directory (AD) obsługuje uwierzytelnianie certyfikatem, wykorzystując głównie protokoły **Kerberos** i **Secure Channel (Schannel)**.

### Proces uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos żądanie użytkownika o Ticket Granting Ticket (TGT) jest podpisywane przy użyciu **klucza prywatnego** certyfikatu użytkownika. Żądanie to przechodzi kilka weryfikacji wykonywanych przez kontroler domeny, w tym weryfikację **ważności**, **ścieżki** i **statusu unieważnienia** certyfikatu. Weryfikacje obejmują także sprawdzenie, czy certyfikat pochodzi z zaufanego źródła, oraz potwierdzenie obecności wystawcy w **magazynie certyfikatów NTAUTH**. Pomyślne przejście weryfikacji skutkuje wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD znajduje się pod adresem:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

ma kluczowe znaczenie dla ustanawiania zaufania na potrzeby uwierzytelniania certyfikatami.<sup>[[4]](#references)</sup>

Od wdrożenia **KB5014754** współczesne uwierzytelnianie Kerberos certyfikatami dotyczy głównie **siły mapowania**, a nie tylko EKU.<sup>[[2]](#references)</sup> W utwardzonych lasach:

- Certyfikat zawierający wyłącznie **UPN/DNS SAN** może już nie wystarczać do logowania.
- KDC preferuje **silne powiązanie**, zwykle **rozszerzenie SID security** (`1.3.6.1.4.1.311.25.2`) lub silne jawne mapowanie w `altSecurityIdentities`.
- Jeśli certyfikat nie ma silnego mapowania, kontrolery domeny rejestrują **Kdcsvc Event ID 39/41** w trybie zgodności i odmawiają uwierzytelnienia w trybie wymuszania.
- W mieszanych ścieżkach ataku **ESC9/ESC16** mają znaczenie, ponieważ usuwają rozszerzenie SID z wydawanych certyfikatów; operatorzy polegają wtedy na jawnych mapowaniach lub formatach SID w SAN URL, jeśli dana ścieżka ataku je obsługuje.

### Uwierzytelnianie Secure Channel (Schannel)

Schannel umożliwia nawiązywanie bezpiecznych połączeń TLS/SSL. Podczas uzgadniania połączenia klient przedstawia certyfikat, który — jeśli zostanie pomyślnie zweryfikowany — autoryzuje dostęp. Mapowanie certyfikatu na konto AD może obejmować funkcję Kerberos **S4U2Self** lub **Subject Alternative Name (SAN)** certyfikatu, a także inne metody.<sup>[[4]](#references)</sup>

Schannel jest również praktycznym rozwiązaniem awaryjnym, gdy **PKINIT** jest niedostępny. Na przykład jeśli kontroler domeny nie ma odpowiedniego certyfikatu **Smart Card Logon**, narzędzia `certipy auth`/PKINIT mogą nie uzyskać TGT, ale ten sam certyfikat nadal może być użyteczny do uwierzytelniania i wykonywania operacji LDAP przez **LDAPS** lub **LDAP StartTLS**.

### Enumeracja usług certyfikatów AD

Usługi certyfikatów AD można enumerować za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CA)** i ich konfiguracjach. Dostęp do tych informacji ma każdy uwierzytelniony użytkownik domeny, bez specjalnych uprawnień. Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** służą do enumeracji i oceny podatności w środowiskach AD CS.

Polecenia służące do korzystania z tych narzędzi obejmują:

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

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Najnowsze luki i aktualizacje zabezpieczeń (2022-2025)

| Rok | ID / nazwa | Wpływ | Najważniejsze wnioski |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – „Certifried” / ESC6 | *Eskalacja uprawnień* przez podszywanie się pod certyfikaty kont komputerów podczas PKINIT. | Poprawka jest zawarta w aktualizacjach zabezpieczeń z **10 maja 2022 r.** Kontrole audytu i silnego mapowania wprowadzono za pośrednictwem **KB5014754**; środowiska powinny już działać w trybie *Full Enforcement*. |
| 2023 | **CVE-2023-35350 / 35351** | *Zdalne wykonanie kodu* w rolach AD CS Web Enrollment (certsrv) i CES. | Publiczne PoC są ograniczone, ale podatne składniki IIS często są dostępne z sieci wewnętrznej. Zainstaluj poprawkę z **lipcowego Patch Tuesday 2023**. |
| 2024 | **CVE-2024-49019** – „EKUwu” / ESC15 | W przypadku **szablonów v1** żądający z prawami rejestracji może umieścić **Application Policies/EKU** w żądaniu CSR, które mają pierwszeństwo przed EKU szablonu, uzyskując certyfikaty do uwierzytelniania klienta, agenta rejestracji lub podpisywania kodu. | Poprawka dostępna od **12 listopada 2024 r.** Zastąp lub wycofaj szablony v1 (np. domyślny WebServer), ogranicz EKU do wymaganych zastosowań i ogranicz prawa rejestracji. |

### Harmonogram wzmacniania zabezpieczeń Microsoft (KB5014754)

Microsoft wprowadził wdrożenie w trzech fazach (Compatibility → Audit → Enforcement), aby odejść od słabych, niejawnych mapowań w uwierzytelnianiu certyfikatami Kerberos. Od **11 lutego 2025 r.** kontrolery domeny automatycznie przełączają się na **Full Enforcement**, jeśli wartość rejestru `StrongCertificateBindingEnforcement` nie jest ustawiona. Microsoft później zaktualizował harmonogram, tak aby powrót do trybu zgodności pozostał możliwy do aktualizacji zabezpieczeń z **9 września 2025 r.**<sup>[[2]](#references)</sup> Administratorzy powinni:

1. Zainstalować poprawki na wszystkich kontrolerach domeny i serwerach AD CS (z maja 2022 r. lub nowsze).
2. Monitorować zdarzenia Event ID 39/41 pod kątem słabych mapowań w fazie *Audit*.
3. Ponownie wystawić certyfikaty do uwierzytelniania klienta z nowym **rozszerzeniem SID** lub skonfigurować silne mapowania ręczne, zanim wymuszanie zablokuje słabe mapowania.

### Uwagi operatora dotyczące wzmocnionych lasów

- W środowiskach z 2025 r. i nowszych **samo ESC1/ESC6 to już nie cała historia**. Jeśli żądasz certyfikatu dla innego podmiotu, zwykle potrzebujesz też artefaktu silnego mapowania, takiego jak rozszerzenie SID lub jawne mapowanie.
- **ESC15 (EKUwu)** jest przydatne głównie w niezałatanych środowiskach, ponieważ pozwala zmienić nieszkodliwe szablony **v1**, takie jak **WebServer**, w certyfikaty obsługujące uwierzytelnianie lub rolę agenta rejestracji przez wstrzyknięcie **Application Policies**. Kerberos PKINIT nadal weryfikuje EKU, ale **LDAP Schannel** uwzględnia również Application Policies, przez co nadużycia oparte na LDAP pozostają możliwe.<sup>[[1]](#references)</sup>
- **ESC16** to ustawienie obejmujące cały urząd certyfikacji: jeśli urząd globalnie wyłączy rozszerzenie zabezpieczeń SID, zachowanie mapowania każdego wystawionego certyfikatu będzie słabsze, chyba że łańcuch ataku wstawi SID w innym obsługiwanym formacie.
- **Uprawnienia ESC7 są odrębne:** nadanie CA uprawnienia `ManageCA` może pozwolić na zmianę ustawień, takich jak `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), podczas gdy `ManageCertificates` reguluje zatwierdzanie żądań. Jawne Deny dla uprawnień zarządzającego certyfikatami może zablokować tę ścieżkę zatwierdzania, nawet jeśli przyznano również Allow; przed łączeniem ustawień i szablonów sprawdź efektywną listę ACL urzędu certyfikacji. Zobacz [ocenę listy ACL urzędu certyfikacji firmy Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Ulepszenia wykrywania i wzmacniania zabezpieczeń

* **Czujnik AD CS w Defender for Identity (2023-2024)** udostępnia teraz oceny stanu zabezpieczeń dla ESC1-ESC8/ESC11 i generuje alerty w czasie rzeczywistym, takie jak *„Wystawienie certyfikatu kontrolera domeny dla podmiotu, który nie jest kontrolerem domeny”* (ESC8) i *„Zapobieganie rejestracji certyfikatów z dowolnymi Application Policies”* (ESC15). Aby korzystać z tych wykryć, wdroż czujniki na wszystkich serwerach AD CS.<sup>[[3]](#references)</sup>
* Wyłącz opcję **„Supply in the request”** na wszystkich szablonach lub ściśle ogranicz jej użycie; preferuj jawnie zdefiniowane wartości SAN/EKU.
* Usuń z szablonów **Any Purpose** lub **No EKU**, chyba że są bezwzględnie wymagane (ogranicza to scenariusze ESC2).
* Wymagaj **zatwierdzenia przez kierownika** lub dedykowanych procesów Enrollment Agent dla wrażliwych szablonów (np. WebServer / CodeSigning).
* Ogranicz dostęp do web enrollment (`certsrv`) i punktów końcowych CES/NDES do zaufanych sieci lub wymagaj uwierzytelniania certyfikatem klienta.
* Wymuś szyfrowanie rejestracji RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), aby ograniczyć ESC11 (przekaźnik RPC). Ta flaga jest **domyślnie włączona**, ale często wyłącza się ją dla starszych klientów, co ponownie otwiera ryzyko ataku relay.
* Zabezpiecz punkty końcowe rejestracji oparte na **IIS** (CES/Certsrv): w miarę możliwości wyłącz NTLM lub wymagaj HTTPS + Extended Protection, aby blokować ataki relay ESC8.

Oceń ESC11 na hoście, na którym działa urząd certyfikacji; może to być serwer członkowski domeny, a nie kontroler domeny. Odczytaj aktywne `InterfaceFlags` urzędu certyfikacji w `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; wartość nieczytelna lub brakująca oznacza nieznany wynik, a nie dowód, że szyfrowanie RPC jest wyłączone. Brak ustawionego bitu `IF_ENFORCEENCRYPTICERTREQUEST` wskazuje konfigurację wymagającą dalszej analizy, ale nadal potrzebny jest dostępny punkt końcowy rejestracji RPC, poświadczenia, których użycie można wymusić, oraz użyteczny szablon certyfikatu. W przypadku ESC8 samo wyzwanie HTTP NTLM nie wystarcza: potwierdź, że działa punkt końcowy rejestracji.

---

## References

- [1] [EKUwu: nie tylko kolejny przypadek AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: zmiany w uwierzytelnianiu opartym na certyfikatach na kontrolerach domeny Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Oceny stanu zabezpieczeń certyfikatów - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: nadużywanie Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
