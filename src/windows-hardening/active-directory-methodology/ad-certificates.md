# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

### Składniki Certificate

- **Subject** certificate oznacza jego właściciela.
- **Public Key** jest sparowany z prywatnie przechowywanym kluczem, aby powiązać certificate z jego prawowitym właścicielem.
- **Validity Period**, zdefiniowany przez daty **NotBefore** i **NotAfter**, określa okres ważności certificate.
- Unikalny **Serial Number**, nadawany przez Certificate Authority (CA), identyfikuje każdy certificate.
- **Issuer** odnosi się do CA, która wydała certificate.
- **SubjectAlternativeName** umożliwia dodatkowe nazwy dla subject, zwiększając elastyczność identyfikacji.
- **Basic Constraints** określa, czy certificate jest dla CA czy dla end entity, oraz definiuje ograniczenia użycia.
- **Extended Key Usages (EKUs)** określają konkretne przeznaczenia certificate, takie jak code signing lub email encryption, za pomocą Object Identifiers (OIDs).
- **Signature Algorithm** określa metodę podpisywania certificate.
- **Signature**, utworzony przy użyciu private key issuer, gwarantuje autentyczność certificate.

### Szczególne Uwagi

- **Subject Alternative Names (SANs)** rozszerzają zastosowanie certificate na wiele tożsamości, co jest kluczowe dla serwerów z wieloma domenami. Bezpieczne procesy wydawania są niezbędne, aby uniknąć ryzyka impersonation przez attackerów manipulujących specyfikacją SAN.

### Certificate Authorities (CAs) w Active Directory (AD)

AD CS rozpoznaje certyfikaty CA w lesie AD poprzez określone kontenery, z których każdy pełni unikalną rolę:

- Kontener **Certification Authorities** przechowuje zaufane root CA certyfikaty.
- Kontener **Enrolment Services** zawiera szczegóły Enterprise CAs i ich certificate templates.
- Obiekt **NTAuthCertificates** obejmuje CA certyfikaty autoryzowane do AD authentication.
- Kontener **AIA (Authority Information Access)** ułatwia walidację chain certificate z pośrednimi i cross CA certyfikatami.

### Pozyskiwanie Certificate: Client Certificate Request Flow

1. Proces request rozpoczyna się od tego, że clients znajdują Enterprise CA.
2. Tworzony jest CSR, zawierający public key i inne szczegóły, po wygenerowaniu pary private-public key.
3. CA ocenia CSR względem dostępnych certificate templates, wydając certificate na podstawie uprawnień szablonu.
4. Po zatwierdzeniu CA podpisuje certificate swoim private key i odsyła je do clienta.

### Certificate Templates

Zdefiniowane w AD, te templates opisują settings i permissions do wydawania certyfikatów, w tym dozwolone EKUs oraz prawa enrollment lub modyfikacji, co ma kluczowe znaczenie dla zarządzania dostępem do usług certificate.

**Wersja schema template ma znaczenie.** Legacy **v1** templates (na przykład wbudowany template **WebServer**) nie mają kilku nowoczesnych mechanizmów enforcement. Badania **ESC15/EKUwu** pokazały, że na **v1 templates** requester może osadzić w CSR **Application Policies/EKUs**, które są **preferowane nad** skonfigurowanymi w template EKUs, umożliwiając client-auth, enrollment agent lub code-signing certyfikaty przy samych prawach enrollment. Preferuj **v2/v3 templates**, usuń lub zastąp domyślne v1, i ściśle zawęź EKUs do zamierzonego celu.

## Certificate Enrollment

Proces enrollment dla certyfikatów jest inicjowany przez administratora, który **tworzy certificate template**, a następnie jest on **publikowany** przez Enterprise Certificate Authority (CA). Sprawia to, że template staje się dostępny do client enrollment, co osiąga się przez dodanie nazwy template do pola `certificatetemplates` obiektu Active Directory.

Aby client mógł zażądać certificate, muszą zostać przyznane **enrollment rights**. Te prawa są zdefiniowane przez security descriptors na certificate template oraz samej Enterprise CA. Uprawnienia muszą zostać przyznane w obu lokalizacjach, aby request zakończył się powodzeniem.

### Template Enrollment Rights

Te prawa są określane przez Access Control Entries (ACEs), opisujące uprawnienia takie jak:

- prawa **Certificate-Enrollment** i **Certificate-AutoEnrollment**, każde powiązane z określonymi GUID.
- **ExtendedRights**, pozwalające na wszystkie rozszerzone uprawnienia.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad template.

### Enterprise CA Enrollment Rights

Prawa CA są opisane w jego security descriptor, dostępnym przez konsolę zarządzania Certificate Authority. Niektóre ustawienia nawet pozwalają użytkownikom z niskimi uprawnieniami na zdalny dostęp, co może stanowić problem bezpieczeństwa.

### Dodatkowe Kontrole Wydawania

Mogą obowiązywać pewne kontrole, takie jak:

- **Manager Approval**: Umieszcza requesty w stanie oczekującym na zatwierdzenie przez certificate managera.
- **Enrolment Agents and Authorized Signatures**: Określają liczbę wymaganych podpisów na CSR oraz niezbędne Application Policy OIDs.

### Metody Requestowania Certificate

Certificates mogą być requestowane poprzez:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), z użyciem interfejsów DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), przez named pipes lub TCP/IP.
3. **certificate enrollment web interface**, z zainstalowaną rolą Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), w połączeniu z usługą Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dla urządzeń sieciowych, z użyciem Simple Certificate Enrollment Protocol (SCEP).

Użytkownicy Windows mogą również requestować certificates przez GUI (`certmgr.msc` lub `certlm.msc`) albo narzędzia command-line (`certreq.exe` lub polecenie PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uwierzytelnianie certyfikatem

Active Directory (AD) obsługuje uwierzytelnianie certyfikatem, głównie wykorzystując protokoły **Kerberos** oraz **Secure Channel (Schannel)**.

### Proces uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos, żądanie użytkownika o Ticket Granting Ticket (TGT) jest podpisywane przy użyciu **private key** certyfikatu użytkownika. To żądanie przechodzi kilka walidacji przez domain controller, w tym sprawdzenie **validity**, **path** i **revocation status** certyfikatu. Walidacje obejmują także weryfikację, czy certyfikat pochodzi z zaufanego źródła, oraz potwierdzenie obecności wystawcy w **NTAUTH certificate store**. Pomyślne walidacje skutkują wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD, znajdujący się pod:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ma kluczowe znaczenie dla ustanawiania zaufania dla certificate authentication.

Od wdrożenia **KB5014754** nowoczesne Kerberos certificate auth opiera się głównie na **mapping strength**, a nie tylko na EKUs. W wzmocnionych forestach:

- Certyfikat zawierający jedynie **UPN/DNS SAN** może już nie wystarczyć do logon.
- KDC preferuje **strong binding**, zwykle **SID security extension** (`1.3.6.1.4.1.311.25.2`) albo silne jawne mapowanie w `altSecurityIdentities`.
- Jeśli cert nie ma silnego mapowania, DCs zapisują **Kdcsvc Event ID 39/41** w compatibility mode i odmawiają auth w enforcement mode.
- W mieszanych ścieżkach ataku **ESC9/ESC16** mają znaczenie, ponieważ usuwają SID extension z wydanych certs; operatorzy polegają wtedy na jawnych mapowaniach albo formatach SAN URL SID tam, gdzie ścieżka ataku je obsługuje.

### Secure Channel (Schannel) Authentication

Schannel umożliwia bezpieczne połączenia TLS/SSL, gdzie podczas handshake klient przedstawia certyfikat, który — jeśli zostanie poprawnie zweryfikowany — autoryzuje dostęp. Mapowanie certyfikatu na konto AD może obejmować funkcję Kerberos **S4U2Self** albo **Subject Alternative Name (SAN)** certyfikatu, między innymi.

Schannel jest też praktycznym fallbackiem, gdy **PKINIT** jest niedostępny. Na przykład jeśli domain controller nie ma odpowiedniego certyfikatu **Smart Card Logon**, narzędzia `certipy auth`/PKINIT mogą nie uzyskać TGT, ale ten sam certyfikat może nadal działać przeciwko **LDAPS** albo **LDAP StartTLS** do authentication i operacji LDAP.

### AD Certificate Services Enumeration

Usługi certyfikatów AD można enumerować przez zapytania LDAP, uzyskując informacje o **Enterprise Certificate Authorities (CAs)** i ich konfiguracjach. Jest to dostępne dla każdego użytkownika uwierzytelnionego w domain bez specjalnych uprawnień. Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** są używane do enumeracji i oceny podatności w środowiskach AD CS.

Polecenia do używania tych narzędzi obejmują:
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

## Ostatnie luki i aktualizacje bezpieczeństwa (2022-2025)

| Rok | ID / Nazwa | Wpływ | Najważniejsze wnioski |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* przez spoofing certyfikatów kont maszyn podczas PKINIT. | Patch jest uwzględniony w aktualizacjach bezpieczeństwa z **10 maja 2022**. Audyt i kontrolki strong-mapping zostały wprowadzone przez **KB5014754**; środowiska powinny teraz działać w trybie *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* w rolach AD CS Web Enrollment (certsrv) i CES. | Publiczne PoC są ograniczone, ale podatne komponenty IIS często są wystawione wewnętrznie. Patch od **lipcowego 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Na szablonach **v1**, żądający z prawami enrollment może osadzić **Application Policies/EKUs** w CSR, które mają priorytet nad EKU szablonu, tworząc certyfikaty do client-auth, enrollment agent lub code-signing. | Załatane od **12 listopada 2024**. Zastąp lub wycofaj szablony v1 (np. domyślny WebServer), ogranicz EKU do zamierzonego użycia i ogranicz prawa enrollment. |

### Harmonogram hardeningu Microsoft (KB5014754)

Microsoft wprowadził wdrożenie w trzech fazach (Compatibility → Audit → Enforcement), aby przenieść uwierzytelnianie Kerberos oparte na certyfikatach z dala od słabych, domyślnych mapowań. Od **11 lutego 2025** kontrolery domeny automatycznie przełączają się na **Full Enforcement**, jeśli wartość rejestru `StrongCertificateBindingEnforcement` nie jest ustawiona. Microsoft później zaktualizował harmonogram, tak aby powrót do trybu compatibility pozostawał możliwy do **aktualizacji bezpieczeństwa z 9 września 2025**. Administratorzy powinni:

1. Załatwić wszystkie DCs i serwery AD CS (maj 2022 lub nowsze).
2. Monitorować Event ID 39/41 pod kątem słabych mapowań podczas fazy *Audit*.
3. Ponownie wydać certyfikaty client-auth z nowym rozszerzeniem **SID** albo skonfigurować silne ręczne mapowania, zanim enforcement zablokuje słabe mapowania.

### Uwagi operatorskie dla utwardzonych lasów

- **ESC1/ESC6 samo w sobie nie jest już całą historią** w środowiskach 2025+. Jeśli żądasz certyfikatu dla innej tożsamości, zwykle potrzebujesz też silnego artefaktu mapowania, takiego jak rozszerzenie SID albo jawne mapowanie.
- **ESC15 (EKUwu)** jest głównie przydatne w niezałatanych środowiskach, ponieważ zamienia nieszkodliwe szablony **v1**, takie jak **WebServer**, w certyfikaty zdolne do uwierzytelniania lub działania jako enrollment agent przez wstrzyknięcie **Application Policies**. Kerberos PKINIT nadal analizuje EKU, ale **LDAP Schannel** także honoruje Application Policies, co utrzymuje nadużycia oparte na LDAP jako istotne.
- **ESC16** to przełącznik na poziomie całego CA: jeśli CA globalnie wyłączy rozszerzenie bezpieczeństwa SID, każdy wydany certyfikat wraca do słabszego zachowania mapowania, chyba że łańcuch ataku wstrzyknie SID w innym obsługiwanym formacie.

---

## Ulepszenia wykrywania i hardeningu

* **Defender for Identity AD CS sensor (2023-2024)** teraz pokazuje oceny postawy dla ESC1-ESC8/ESC11 i generuje alerty w czasie rzeczywistym, takie jak *“Domain-controller certificate issuance for a non-DC”* (ESC8) oraz *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Upewnij się, że sensory są wdrożone na wszystkich serwerach AD CS, aby skorzystać z tych wykryć.
* Wyłącz lub ściśle ogranicz opcję **“Supply in the request”** we wszystkich szablonach; preferuj jawnie zdefiniowane wartości SAN/EKU.
* Usuń **Any Purpose** lub **No EKU** z szablonów, chyba że jest to absolutnie wymagane (dotyczy scenariuszy ESC2).
* Wymagaj zatwierdzenia przez managera lub dedykowanych workflow Enrollment Agent dla wrażliwych szablonów (np. WebServer / CodeSigning).
* Ogranicz web enrollment (`certsrv`) oraz punkty końcowe CES/NDES do zaufanych sieci albo umieść je za uwierzytelnianiem certyfikatem klienta.
* Wymuś szyfrowanie RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), aby ograniczyć ESC11 (RPC relay). Flaga jest **włączona domyślnie**, ale często bywa wyłączana dla legacy clients, co ponownie otwiera ryzyko relay.
* Zabezpiecz punkty końcowe enrollment oparte na **IIS** (CES/Certsrv): wyłącz NTLM tam, gdzie to możliwe, albo wymagaj HTTPS + Extended Protection, aby blokować relaye ESC8.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
