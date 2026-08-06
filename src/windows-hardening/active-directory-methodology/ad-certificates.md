# Certyfikaty AD

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

### Elementy certyfikatu

- **Subject** certyfikatu określa jego właściciela.
- **Public Key** jest powiązany z kluczem prywatnym, aby połączyć certyfikat z jego prawowitym właścicielem.
- **Validity Period**, określany przez daty **NotBefore** i **NotAfter**, wyznacza okres ważności certyfikatu.
- Unikalny **Serial Number**, nadawany przez Certificate Authority (CA), identyfikuje każdy certyfikat.
- **Issuer** wskazuje CA, które wystawiło certyfikat.
- **SubjectAlternativeName** pozwala określić dodatkowe nazwy podmiotu, zwiększając elastyczność identyfikacji.
- **Basic Constraints** określają, czy certyfikat jest przeznaczony dla CA, czy dla jednostki końcowej, oraz definiują ograniczenia jego użycia.
- **Extended Key Usages (EKUs)** określają konkretne zastosowania certyfikatu, takie jak podpisywanie kodu lub szyfrowanie wiadomości e-mail, za pomocą Object Identifiers (OIDs).
- **Signature Algorithm** określa metodę podpisywania certyfikatu.
- **Signature**, utworzony za pomocą klucza prywatnego wystawcy, gwarantuje autentyczność certyfikatu.<sup>[[4]](#references)</sup>

### Szczególne kwestie

- **Subject Alternative Names (SANs)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co ma kluczowe znaczenie w przypadku serwerów obsługujących wiele domen. Bezpieczne procesy wystawiania są niezbędne, aby uniknąć ryzyka impersonacji przez attackerów manipulujących specyfikacją SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) w Active Directory (AD)

AD CS rozpoznaje certyfikaty CA w lesie AD za pośrednictwem wyznaczonych kontenerów, z których każdy pełni unikalną rolę:<sup>[[4]](#references)</sup>

- Kontener **Certification Authorities** przechowuje zaufane certyfikaty głównych CA.
- Kontener **Enrolment Services** zawiera informacje o Enterprise CAs i ich certificate templates.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA autoryzowane do uwierzytelniania w AD.
- Kontener **AIA (Authority Information Access)** ułatwia walidację łańcucha certyfikatów za pomocą certyfikatów pośrednich i cross CA.

### Pozyskiwanie certyfikatu: przepływ żądania certyfikatu klienta

1. Proces żądania rozpoczyna się od znalezienia przez klientów Enterprise CA.
2. Po wygenerowaniu pary klucza publicznego i prywatnego tworzony jest CSR zawierający klucz publiczny oraz inne informacje.
3. CA porównuje CSR z dostępnymi certificate templates i wystawia certyfikat zgodnie z uprawnieniami określonymi w template.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.<sup>[[4]](#references)</sup>

### Certificate Templates

Zdefiniowane w AD templates określają ustawienia i uprawnienia związane z wystawianiem certyfikatów, w tym dozwolone EKUs oraz uprawnienia do enrollment lub modyfikacji, które mają kluczowe znaczenie dla zarządzania dostępem do usług certyfikatów.<sup>[[4]](#references)</sup>

**Wersja schematu template ma znaczenie.** Starsze templates **v1** (na przykład wbudowany template **WebServer**) nie zawierają kilku nowoczesnych mechanizmów egzekwowania zasad. Badania **ESC15/EKUwu** wykazały, że w przypadku **v1 templates** requester może osadzić w CSR **Application Policies/EKUs**, które mają **pierwszeństwo przed** EKUs skonfigurowanymi w template, umożliwiając uzyskanie certyfikatów client-auth, enrollment agent lub code-signing przy samych uprawnieniach enrollment. Preferuj templates **v2/v3**, usuwaj lub zastępuj domyślne templates v1 i ściśle ograniczaj EKUs do zamierzonego zastosowania.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Proces enrollment certyfikatów rozpoczyna administrator, który **tworzy certificate template**, a następnie **publikuje** go za pomocą Enterprise Certificate Authority (CA). Dzięki temu template staje się dostępny do enrollment przez klientów. Odbywa się to przez dodanie nazwy template do pola `certificatetemplates` obiektu Active Directory.<sup>[[4]](#references)</sup>

Aby klient mógł zażądać certyfikatu, należy przyznać **uprawnienia enrollment**. Uprawnienia te są definiowane przez deskryptory bezpieczeństwa certificate template oraz samego Enterprise CA. Aby żądanie zakończyło się powodzeniem, uprawnienia muszą zostać przyznane w obu miejscach.

### Uprawnienia enrollment template

Uprawnienia te są określane za pomocą Access Control Entries (ACEs), które definiują między innymi następujące uprawnienia:

- Uprawnienia **Certificate-Enrollment** i **Certificate-AutoEnrollment**, z których każde jest powiązane z określonymi GUID-ami.
- **ExtendedRights**, umożliwiające korzystanie ze wszystkich uprawnień rozszerzonych.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad template.

### Uprawnienia enrollment Enterprise CA

Uprawnienia CA są określone w jego deskryptorze bezpieczeństwa, dostępnym za pośrednictwem konsoli zarządzania Certificate Authority. Niektóre ustawienia umożliwiają nawet użytkownikom o niskich uprawnieniach zdalny dostęp, co może stanowić zagrożenie bezpieczeństwa.

### Dodatkowe mechanizmy kontroli wystawiania

Mogą obowiązywać dodatkowe mechanizmy kontroli, takie jak:

- **Manager Approval**: umieszcza żądania w stanie oczekiwania do czasu zatwierdzenia przez certificate manager.
- **Enrolment Agents and Authorized Signatures**: określają liczbę wymaganych podpisów w CSR oraz niezbędne Application Policy OIDs.

### Metody żądania certyfikatów

Certyfikaty można uzyskiwać za pomocą:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), z użyciem interfejsów DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), za pośrednictwem named pipes lub TCP/IP.
3. **web interface enrollment certyfikatów**, po zainstalowaniu roli Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), w połączeniu z usługą Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dla urządzeń sieciowych, z użyciem Simple Certificate Enrollment Protocol (SCEP).

Użytkownicy Windows mogą również żądać certyfikatów za pomocą GUI (`certmgr.msc` lub `certlm.msc`) albo narzędzi wiersza poleceń (`certreq.exe` lub polecenia PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uwierzytelnianie za pomocą certyfikatu

Active Directory (AD) obsługuje uwierzytelnianie za pomocą certyfikatów, wykorzystując przede wszystkim protokoły **Kerberos** oraz **Secure Channel (Schannel)**.

### Proces uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos żądanie użytkownika dotyczące Ticket Granting Ticket (TGT) jest podpisywane przy użyciu **klucza prywatnego** certyfikatu użytkownika. Żądanie to przechodzi kilka etapów walidacji przez kontroler domeny, obejmujących **ważność**, **ścieżkę** oraz **status unieważnienia** certyfikatu. Walidacja obejmuje również sprawdzenie, czy certyfikat pochodzi z zaufanego źródła, oraz potwierdzenie obecności wystawcy w **magazynie certyfikatów NTAUTH**. Pomyślne zakończenie walidacji skutkuje wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD, znajdujący się pod adresem:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ma kluczowe znaczenie dla ustanawiania zaufania na potrzeby uwierzytelniania za pomocą certyfikatu.<sup>[[4]](#references)</sup>

Od czasu wdrożenia **KB5014754** nowoczesne uwierzytelnianie Kerberos za pomocą certyfikatów dotyczy przede wszystkim **siły mapowania**, a nie tylko EKU.<sup>[[2]](#references)</sup> W zahartowanych lasach:

- Certyfikat zawierający wyłącznie **UPN/DNS SAN** może już nie wystarczać do logowania.
- KDC preferuje **silne powiązanie**, zazwyczaj rozszerzenie bezpieczeństwa **SID** (`1.3.6.1.4.1.311.25.2`) lub silne jawne mapowanie w `altSecurityIdentities`.
- Jeśli certyfikat nie ma silnego mapowania, kontrolery domeny rejestrują zdarzenia **Kdcsvc Event ID 39/41** w trybie zgodności i odmawiają uwierzytelnienia w trybie wymuszania.
- W mieszanych ścieżkach ataku znaczenie mają **ESC9/ESC16**, ponieważ usuwają rozszerzenie SID z wydawanych certyfikatów; operatorzy polegają wtedy na jawnych mapowaniach lub formatach SID SAN URL, jeśli dana ścieżka ataku je obsługuje.

### Uwierzytelnianie Secure Channel (Schannel)

Schannel umożliwia bezpieczne połączenia TLS/SSL, podczas których klient przedstawia certyfikat, który — jeśli zostanie pomyślnie zweryfikowany — autoryzuje dostęp. Mapowanie certyfikatu na konto AD może wykorzystywać funkcję **S4U2Self** Kerberosa lub **Subject Alternative Name (SAN)** certyfikatu, a także inne metody.<sup>[[4]](#references)</sup>

Schannel jest również praktycznym rozwiązaniem awaryjnym, gdy **PKINIT** jest niedostępny. Na przykład jeśli kontroler domeny nie ma odpowiedniego certyfikatu **Smart Card Logon**, narzędzia `certipy auth`/PKINIT mogą nie uzyskać TGT, ale ten sam certyfikat może nadal działać przeciwko **LDAPS** lub **LDAP StartTLS** do uwierzytelniania i wykonywania operacji LDAP.

### Enumeracja AD Certificate Services

Usługi certyfikatów AD można enumerować za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CA)** i ich konfiguracji. Jest to dostępne dla każdego użytkownika uwierzytelnionego w domenie, bez specjalnych uprawnień. Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** służą do enumeracji i oceny podatności w środowiskach AD CS.

Polecenia używane z tymi narzędziami obejmują:
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

## Najnowsze podatności i aktualizacje zabezpieczeń (2022-2025)

| Rok | ID / Nazwa | Wpływ | Najważniejsze informacje |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – „Certifried” / ESC6 | *Eskalacja uprawnień* poprzez spoofing certyfikatów kont komputerów podczas PKINIT. | Poprawka została uwzględniona w aktualizacjach zabezpieczeń z **10 maja 2022 r.** Mechanizmy audytowania i strong-mapping zostały wprowadzone przez **KB5014754**; środowiska powinny obecnie działać w trybie *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Zdalne wykonanie kodu* w rolach AD CS Web Enrollment (certsrv) i CES. | Publiczne PoC są ograniczone, ale podatne komponenty IIS są często dostępne wewnętrznie. Podatność została załatana w ramach Patch Tuesday w **lipcu 2023 r.**  |
| 2024 | **CVE-2024-49019** – „EKUwu” / ESC15 | W przypadku **v1 templates** wnioskodawca posiadający uprawnienia enrollment może osadzić **Application Policies/EKUs** w CSR. Mają one pierwszeństwo przed EKU z szablonu, umożliwiając utworzenie certyfikatów client-auth, enrollment agent lub code-signing. | Załatane od **12 listopada 2024 r.** Należy zastąpić lub wycofać v1 templates (np. domyślny WebServer), ograniczyć EKU do zamierzonego zastosowania i ograniczyć uprawnienia enrollment. |

### Oś czasu hardeningu Microsoft (KB5014754)

Microsoft wprowadził wdrożenie w trzech fazach (Compatibility → Audit → Enforcement), aby odejść w uwierzytelnianiu certyfikatami Kerberos od słabych implicit mappings. Od **11 lutego 2025 r.** kontrolery domeny automatycznie przełączają się do trybu **Full Enforcement**, jeśli wartość rejestru `StrongCertificateBindingEnforcement` nie jest ustawiona. Microsoft później zaktualizował harmonogram, dzięki czemu powrót do trybu compatibility pozostaje możliwy do aktualizacji zabezpieczeń z **9 września 2025 r.**<sup>[[2]](#references)</sup> Administratorzy powinni:

1. Zainstalować poprawki na wszystkich kontrolerach domeny i serwerach AD CS (z maja 2022 r. lub nowsze).
2. Monitorować zdarzenia o ID 39/41 pod kątem weak mappings podczas fazy *Audit*.
3. Ponownie wystawić certyfikaty client-auth z nowym rozszerzeniem **SID** lub skonfigurować strong manual mappings przed włączeniem wymuszania, które zablokuje weak mappings.

### Uwagi operatora dotyczące hardened forests

- **ESC1/ESC6 alone is no longer the whole story** w środowiskach 2025+. Jeśli żądasz certyfikatu dla innego principal, zwykle potrzebujesz również strong mapping artifact, takiego jak rozszerzenie SID lub jawne mapowanie.
- **ESC15 (EKUwu)** jest najbardziej wartościowe w niezałatanych środowiskach, ponieważ zmienia nieszkodliwe **v1 templates**, takie jak **WebServer**, w certyfikaty obsługujące uwierzytelnianie lub enrollment agent, poprzez wstrzyknięcie **Application Policies**. Kerberos PKINIT nadal sprawdza EKU, ale **LDAP Schannel** respektuje również Application Policies, dzięki czemu abuse oparty na LDAP pozostaje istotny.<sup>[[1]](#references)</sup>
- **ESC16** to ustawienie dotyczące całego CA: jeśli CA globalnie wyłączy rozszerzenie zabezpieczeń SID, każdy wystawiony certyfikat będzie korzystał ze słabszego mapowania, chyba że attack chain wstrzyknie SID w innym obsługiwanym formacie.

---

## Udoskonalenia detekcji i hardeningu

* **Defender for Identity AD CS sensor (2023-2024)** udostępnia obecnie oceny stanu zabezpieczeń dla ESC1-ESC8/ESC11 i generuje alerty w czasie rzeczywistym, takie jak *„Domain-controller certificate issuance for a non-DC”* (ESC8) oraz *„Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Aby korzystać z tych detekcji, należy wdrożyć sensory na wszystkich serwerach AD CS.<sup>[[3]](#references)</sup>
* Wyłącz lub ściśle ogranicz opcję **„Supply in the request”** we wszystkich szablonach; preferuj jawnie zdefiniowane wartości SAN/EKU.
* Usuń **Any Purpose** lub **No EKU** z szablonów, chyba że są absolutnie wymagane (ogranicza scenariusze ESC2).
* Wymagaj **manager approval** lub używaj dedykowanych procesów Enrollment Agent dla wrażliwych szablonów (np. WebServer / CodeSigning).
* Ogranicz web enrollment (`certsrv`) oraz endpointy CES/NDES do zaufanych sieci lub umieść je za uwierzytelnianiem z użyciem certyfikatów klienta.
* Wymuś szyfrowanie RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), aby ograniczyć ESC11 (RPC relay). Flaga jest **domyślnie włączona**, ale często wyłącza się ją dla starszych klientów, co ponownie otwiera ryzyko relay.
* Zabezpiecz endpointy enrollment oparte na **IIS** (CES/Certsrv): tam, gdzie to możliwe, wyłącz NTLM lub wymagaj HTTPS + Extended Protection, aby blokować relay ESC8.

---

## References

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
