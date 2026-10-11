# Certyfikaty AD

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

### Składniki certyfikatu

- **Podmiot** certyfikatu określa jego właściciela.
- **Klucz publiczny** jest powiązany z kluczem prywatnym, aby przypisać certyfikat jego prawowitemu właścicielowi.
- **Okres ważności**, określony datami **NotBefore** i **NotAfter**, wyznacza czas obowiązywania certyfikatu.
- Unikatowy **numer seryjny**, nadawany przez urząd certyfikacji (CA), identyfikuje każdy certyfikat.
- **Wystawca** oznacza CA, który wystawił certyfikat.
- **SubjectAlternativeName** umożliwia przypisanie podmiotowi dodatkowych nazw, zwiększając elastyczność identyfikacji.
- **Ograniczenia podstawowe** określają, czy certyfikat jest przeznaczony dla CA, czy dla jednostki końcowej, i definiują ograniczenia dotyczące jego użycia.
- **Rozszerzone zastosowania klucza (EKU)** określają konkretne cele certyfikatu, takie jak podpisywanie kodu lub szyfrowanie poczty e-mail, za pomocą identyfikatorów obiektów (OID).
- **Algorytm podpisu** określa metodę podpisywania certyfikatu.
- **Podpis**, utworzony przy użyciu klucza prywatnego wystawcy, gwarantuje autentyczność certyfikatu.<sup>[[4]](#references)</sup>

### Szczególne kwestie

- **Alternatywne nazwy podmiotu (SAN)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co ma kluczowe znaczenie w przypadku serwerów obsługujących wiele domen. Bezpieczne procedury wystawiania certyfikatów są niezbędne, aby uniknąć ryzyka podszywania się przez atakujących, którzy manipulują specyfikacją SAN.<sup>[[4]](#references)</sup>

### Urzędy certyfikacji (CA) w Active Directory (AD)

AD CS rozpoznaje certyfikaty CA w lesie AD za pośrednictwem wyznaczonych kontenerów, z których każdy pełni odrębną funkcję:<sup>[[4]](#references)</sup>

- Kontener **Certification Authorities** przechowuje zaufane certyfikaty głównych CA.
- Kontener **Enrolment Services** zawiera informacje o korporacyjnych CA i ich szablonach certyfikatów.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA autoryzowane do uwierzytelniania w AD.
- Kontener **AIA (Authority Information Access)** ułatwia weryfikację łańcucha certyfikatów przy użyciu certyfikatów pośrednich i certyfikatów krzyżowych CA.

### Uzyskiwanie certyfikatu: przepływ żądania certyfikatu klienta

1. Proces żądania rozpoczyna się od wyszukania przez klienta korporacyjnego CA.
2. Po wygenerowaniu pary kluczy publicznego i prywatnego tworzony jest CSR zawierający klucz publiczny i inne informacje.
3. CA sprawdza CSR względem dostępnych szablonów certyfikatów i wystawia certyfikat zgodnie z uprawnieniami określonymi w szablonie.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.<sup>[[4]](#references)</sup>

### Szablony certyfikatów

Szablony te są definiowane w AD i określają ustawienia oraz uprawnienia dotyczące wystawiania certyfikatów, w tym dozwolone EKU oraz uprawnienia do rejestracji lub modyfikacji. Mają kluczowe znaczenie dla zarządzania dostępem do usług certyfikatów.<sup>[[4]](#references)</sup>

**Wersja schematu szablonu ma znaczenie.** Starsze szablony **v1** (na przykład wbudowany szablon **WebServer**) nie obsługują kilku nowoczesnych mechanizmów egzekwowania zasad. Badania nad **ESC15/EKUwu** wykazały, że w przypadku szablonów **v1** żądający może umieścić w CSR **Application Policies/EKU**, które mają **pierwszeństwo przed** skonfigurowanymi w szablonie EKU. Umożliwia to uzyskanie certyfikatów client-auth, enrollment agent lub do podpisywania kodu przy posiadaniu jedynie uprawnień do rejestracji. Preferuj szablony **v2/v3**, usuń lub zastąp domyślne szablony v1 i ściśle ogranicz EKU do zamierzonego zastosowania.<sup>[[1]](#references)</sup>

## Rejestracja certyfikatów

Proces rejestracji certyfikatów rozpoczyna administrator, który **tworzy szablon certyfikatu**, a następnie **publikuje** go w korporacyjnym urzędzie certyfikacji (CA). Dzięki temu szablon jest dostępny dla klientów, którzy mogą złożyć wniosek o certyfikat. Aby go opublikować, należy dodać nazwę szablonu do pola `certificatetemplates` obiektu Active Directory.<sup>[[4]](#references)</sup>

Aby klient mógł złożyć wniosek o certyfikat, musi otrzymać **uprawnienia do rejestracji**. Uprawnienia te są określone przez deskryptory zabezpieczeń szablonu certyfikatu oraz samego korporacyjnego CA. Aby wniosek został pomyślnie złożony, uprawnienia muszą zostać przyznane w obu miejscach.

### Uprawnienia do rejestracji szablonu

Uprawnienia te są określane za pomocą wpisów kontroli dostępu (ACE), które wskazują między innymi takie uprawnienia jak:

- Uprawnienia **Certificate-Enrollment** i **Certificate-AutoEnrollment**, powiązane z określonymi identyfikatorami GUID.
- **ExtendedRights**, które przyznaje wszystkie uprawnienia rozszerzone.
- **FullControl/GenericAll**, które zapewnia pełną kontrolę nad szablonem.

### Uprawnienia do rejestracji w korporacyjnym CA

Uprawnienia CA są określone w jego deskryptorze zabezpieczeń, dostępnym z poziomu konsoli zarządzania Certificate Authority. Niektóre ustawienia umożliwiają nawet użytkownikom o niskich uprawnieniach dostęp zdalny, co może stanowić zagrożenie dla bezpieczeństwa.

### Dodatkowe mechanizmy kontroli wystawiania

Mogą obowiązywać dodatkowe mechanizmy kontroli, takie jak:

- **Zatwierdzenie przez menedżera**: Umieszcza wnioski w stanie oczekiwania na zatwierdzenie przez menedżera certyfikatów.
- **Agenci rejestracji i autoryzowane podpisy**: Określają liczbę wymaganych podpisów w CSR oraz wymagane OID zasad aplikacji.

### Metody składania wniosków o certyfikaty

Certyfikaty można uzyskać za pomocą:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), korzystającego z interfejsów DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), korzystającego z nazwanych potoków lub TCP/IP.
3. **Interfejsu internetowego rejestracji certyfikatów**, po zainstalowaniu roli Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES) w połączeniu z usługą Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dla urządzeń sieciowych, korzystającej z Simple Certificate Enrollment Protocol (SCEP).

Użytkownicy Windows mogą również składać wnioski o certyfikaty za pośrednictwem interfejsu graficznego (`certmgr.msc` lub `certlm.msc`) albo narzędzi wiersza poleceń (`certreq.exe` lub polecenia PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Uwierzytelnianie za pomocą certyfikatów

Active Directory (AD) obsługuje uwierzytelnianie za pomocą certyfikatów, wykorzystując głównie protokoły **Kerberos** i **Secure Channel (Schannel)**.

### Proces uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos żądanie użytkownika o Ticket Granting Ticket (TGT) jest podpisywane **kluczem prywatnym** certyfikatu użytkownika. Kontroler domeny przeprowadza kilka walidacji tego żądania, w tym sprawdza **ważność**, **ścieżkę** i **status unieważnienia** certyfikatu. Walidacje obejmują również sprawdzenie, czy certyfikat pochodzi z zaufanego źródła, oraz potwierdzenie obecności wystawcy w **magazynie certyfikatów NTAUTH**. Pomyślne przejście walidacji skutkuje wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD znajduje się pod adresem:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

ma kluczowe znaczenie dla ustanawiania zaufania na potrzeby uwierzytelniania certyfikatami.<sup>[[4]](#references)</sup>

Od czasu wdrożenia **KB5014754** nowoczesne uwierzytelnianie Kerberos certyfikatami zależy głównie od **siły mapowania**, a nie tylko od EKU.<sup>[[2]](#references)</sup> W zahartowanych lasach:

- Certyfikat zawierający tylko **SAN UPN/DNS** może już nie wystarczyć do logowania.
- KDC preferuje **silne powiązanie**, zazwyczaj **rozszerzenie zabezpieczeń SID** (`1.3.6.1.4.1.311.25.2`) lub silne jawne mapowanie w `altSecurityIdentities`.
- Jeśli certyfikat nie ma silnego mapowania, kontrolery domeny rejestrują **Kdcsvc Event ID 39/41** w trybie zgodności i odmawiają uwierzytelnienia w trybie wymuszania.
- W mieszanych ścieżkach ataku **ESC9/ESC16** mają znaczenie, ponieważ usuwają rozszerzenie SID z wystawianych certyfikatów; operatorzy polegają wtedy na jawnych mapowaniach lub formatach SID w adresie URL SAN, jeśli dana ścieżka ataku je obsługuje.

### Uwierzytelnianie Secure Channel (Schannel)

Schannel umożliwia nawiązywanie bezpiecznych połączeń TLS/SSL. Podczas uzgadniania połączenia klient przedstawia certyfikat, który — jeśli zostanie pomyślnie zweryfikowany — uprawnia do dostępu. Mapowanie certyfikatu na konto AD może obejmować funkcję Kerberos **S4U2Self** lub **Subject Alternative Name (SAN)** certyfikatu, a także inne metody.<sup>[[4]](#references)</sup>

Schannel jest też praktycznym rozwiązaniem zapasowym, gdy **PKINIT** jest niedostępny. Na przykład jeśli kontroler domeny nie ma odpowiedniego certyfikatu **Smart Card Logon**, narzędzie `certipy auth` lub inne narzędzie PKINIT może nie uzyskać TGT, ale ten sam certyfikat nadal może działać w uwierzytelnianiu i operacjach LDAP za pośrednictwem **LDAPS** lub **LDAP StartTLS**.

### Enumeracja AD Certificate Services

Usługi certyfikatów AD można enumerować za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CA)** i ich konfiguracjach. Dostęp do tych informacji ma każdy użytkownik uwierzytelniony w domenie, bez specjalnych uprawnień. Do enumeracji i oceny podatności w środowiskach AD CS służą narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)**.

Polecenia użycia tych narzędzi obejmują:

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

## Ostatnie podatności i aktualizacje zabezpieczeń (2022-2025)

| Rok | ID / nazwa | Wpływ | Najważniejsze wnioski |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – „Certifried” / ESC6 | *Privilege escalation* przez spoofing certyfikatów kont komputerów podczas PKINIT. | Poprawka jest zawarta w aktualizacjach zabezpieczeń z **10 maja 2022 r.** Mechanizmy audytu i silnego mapowania wprowadzono za pośrednictwem **KB5014754**; środowiska powinny być teraz w trybie *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* w rolach AD CS Web Enrollment (certsrv) i CES. | Publiczne PoC są ograniczone, ale podatne komponenty IIS są często dostępne wewnętrznie. Zainstaluj poprawkę z **lipcowego** Patch Tuesday 2023.  |
| 2024 | **CVE-2024-49019** – „EKUwu” / ESC15 | W przypadku **szablonów v1** zgłaszający mający prawa do rejestracji może umieścić **Application Policies/EKU** w CSR; mają one pierwszeństwo przed EKU szablonu, co pozwala uzyskać certyfikaty do uwierzytelniania klienta, agenta rejestracji lub podpisywania kodu. | Poprawka jest dostępna od **12 listopada 2024 r.** Zastąp lub wycofaj szablony v1 (np. domyślny WebServer), ogranicz EKU do zamierzonego zastosowania i ogranicz prawa do rejestracji. |

### Oś czasu wzmacniania zabezpieczeń Microsoft (KB5014754)

Microsoft wprowadził wdrożenie w trzech fazach (Compatibility → Audit → Enforcement), aby odejść od słabego, niejawnego mapowania w uwierzytelnianiu certyfikatami Kerberos. Od **11 lutego 2025 r.** kontrolery domeny automatycznie przełączają się na **Full Enforcement**, jeśli wartość rejestru `StrongCertificateBindingEnforcement` nie jest ustawiona. Microsoft później zaktualizował harmonogram, tak aby powrót do trybu zgodności pozostał możliwy do aktualizacji zabezpieczeń z **9 września 2025 r.**<sup>[[2]](#references)</sup> Administratorzy powinni:

1. Zainstalować poprawki na wszystkich kontrolerach domeny i serwerach AD CS (z maja 2022 r. lub nowsze).
2. Monitorować zdarzenia Event ID 39/41 pod kątem słabego mapowania w fazie *Audit*.
3. Ponownie wystawić certyfikaty do uwierzytelniania klienta z nowym rozszerzeniem **SID** albo skonfigurować silne mapowanie ręczne, zanim wymuszanie zablokuje słabe mapowanie.

### Wskazówki dla operatorów zabezpieczonych lasów

- W środowiskach z 2025 r. i nowszych **samo ESC1/ESC6 to już nie cała historia**. Jeśli żądasz certyfikatu dla innego podmiotu, zwykle potrzebujesz też artefaktu silnego mapowania, takiego jak rozszerzenie SID lub jawne mapowanie.
- **ESC15 (EKUwu)** jest przydatne głównie w niezałatanych środowiskach, ponieważ zmienia nieszkodliwe szablony **v1**, takie jak **WebServer**, w certyfikaty umożliwiające uwierzytelnianie lub działanie jako agent rejestracji przez wstrzyknięcie **Application Policies**. Kerberos PKINIT nadal sprawdza EKU, ale **LDAP Schannel** uwzględnia również Application Policies, dzięki czemu nadużycia oparte na LDAP pozostają możliwe.<sup>[[1]](#references)</sup>
- **ESC16** to ustawienie obejmujące cały CA: jeśli CA globalnie wyłączy rozszerzenie zabezpieczeń SID, każdy wystawiony certyfikat będzie podlegał słabszemu mapowaniu, chyba że łańcuch ataku wstawi SID w innym obsługiwanym formacie.
- **Uprawnienia ESC7 są odrębne:** nadanie CA uprawnienia `ManageCA` może umożliwić zmianę ustawień, takich jak `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), a `ManageCertificates` kontroluje zatwierdzanie żądań. Jawne Deny dotyczące uprawnień menedżera certyfikatów może zablokować tę ścieżkę zatwierdzania, nawet jeśli ustawiono również Allow; przed łączeniem ustawień i szablonów sprawdź efektywną listę ACL CA. Zobacz [ocenę listy ACL CA firmy Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Udoskonalenia wykrywania i wzmacniania zabezpieczeń

* **Czujnik AD CS w Defender for Identity (2023-2024)** udostępnia teraz oceny stanu zabezpieczeń dla ESC1-ESC8/ESC11 i generuje alerty w czasie rzeczywistym, takie jak *„Wystawienie certyfikatu kontrolera domeny dla podmiotu niebędącego kontrolerem domeny”* (ESC8) i *„Zapobieganie rejestracji certyfikatu z dowolnymi Application Policies”* (ESC15). Aby skorzystać z tych mechanizmów wykrywania, wdroż czujniki na wszystkich serwerach AD CS.<sup>[[3]](#references)</sup>
* Wyłącz opcję **„Supply in the request”** we wszystkich szablonach albo ściśle ogranicz jej użycie; preferuj jawnie zdefiniowane wartości SAN/EKU.
* Usuń **Any Purpose** lub **No EKU** z szablonów, chyba że są absolutnie niezbędne (ogranicza to scenariusze ESC2).
* Wymagaj **zatwierdzenia przez menedżera** lub dedykowanych procesów Enrollment Agent dla wrażliwych szablonów (np. WebServer / CodeSigning).
* Ogranicz dostęp do web enrollment (`certsrv`) oraz punktów końcowych CES/NDES do zaufanych sieci albo zabezpiecz je uwierzytelnianiem za pomocą certyfikatu klienta.
* Wymuś szyfrowanie rejestracji RPC (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), aby ograniczyć ESC11 (RPC relay). Flaga jest **domyślnie włączona**, ale często wyłącza się ją z myślą o starszych klientach, co ponownie otwiera ryzyko relay.
* Zabezpiecz punkty końcowe rejestracji oparte na **IIS** (CES/Certsrv): tam, gdzie to możliwe, wyłącz NTLM albo wymagaj HTTPS i Extended Protection, aby blokować ataki ESC8 relay.

Oceń ESC11 na hoście, na którym działa CA; może to być serwer członkowski domeny, a nie kontroler domeny. Odczytaj `InterfaceFlags` aktywnego CA z `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; nieczytelna lub brakująca wartość oznacza nieznany wynik, a nie dowód na wyłączenie szyfrowania RPC. Wyzerowany bit `IF_ENFORCEENCRYPTICERTREQUEST` wskazuje na możliwy problem z konfiguracją, ale do jego wykorzystania nadal potrzebne są osiągalny punkt końcowy rejestracji RPC, poświadczenia, których użycie można wymusić, oraz użyteczny szablon certyfikatu. W przypadku ESC8 samo wyzwanie HTTP NTLM nie wystarczy: potwierdź istnienie działającego punktu końcowego rejestracji.

---

## References

- [1] [EKUwu: Nie tylko kolejny AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Zmiany w uwierzytelnianiu opartym na certyfikatach na kontrolerach domeny Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Oceny stanu zabezpieczeń certyfikatów - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Nadużywanie Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
