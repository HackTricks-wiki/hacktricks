# Certyfikaty AD

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

### Składniki certyfikatu

- **Subject** certyfikatu oznacza jego właściciela.
- **Public Key** jest sparowany z prywatnym kluczem, aby powiązać certyfikat z jego prawowitym właścicielem.
- **Validity Period**, definiowany przez daty **NotBefore** i **NotAfter**, określa okres ważności certyfikatu.
- Unikalny **Serial Number**, nadawany przez Certificate Authority (CA), identyfikuje każdy certyfikat.
- **Issuer** odnosi się do CA, który wydał certyfikat.
- **SubjectAlternativeName** pozwala na dodatkowe nazwy podmiotu, zwiększając elastyczność identyfikacji.
- **Basic Constraints** określają, czy certyfikat jest dla CA czy dla końcowego podmiotu i definiują ograniczenia użycia.
- **Extended Key Usages (EKUs)** określają konkretne przeznaczenia certyfikatu, takie jak code signing czy szyfrowanie e‑maili, przy użyciu Object Identifiers (OIDs).
- **Signature Algorithm** określa metodę podpisywania certyfikatu.
- **Signature**, stworzony przy użyciu prywatnego klucza wystawcy, gwarantuje autentyczność certyfikatu.

### Szczególne uwagi

- **Subject Alternative Names (SANs)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co jest kluczowe dla serwerów obsługujących wiele domen. Bezpieczne procesy wydawania są niezbędne, aby uniknąć ryzyka podszywania się przez atakujących manipulujących specyfikacją SAN.

### Certificate Authorities (CAs) w Active Directory (AD)

AD CS rozpoznaje certyfikaty CA w lesie AD poprzez wyznaczone kontenery, z których każdy pełni inną rolę:

- **Certification Authorities** container przechowuje zaufane certyfikaty root CA.
- **Enrolment Services** container zawiera informacje o Enterprise CAs i ich template'ach certyfikatów.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA uprawnione do uwierzytelniania w AD.
- **AIA (Authority Information Access)** container ułatwia walidację łańcucha certyfikatów przy użyciu certyfikatów pośrednich i cross CA.

### Pozyskiwanie certyfikatu: przepływ żądania klienta

1. Proces żądania zaczyna się, gdy klient znajduje Enterprise CA.
2. Tworzony jest CSR zawierający publiczny klucz i inne dane, po wygenerowaniu pary klucz publiczny–prywatny.
3. CA ocenia CSR w odniesieniu do dostępnych certificate templates i wydaje certyfikat na podstawie uprawnień szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim prywatnym kluczem i zwraca go klientowi.

### Template'y certyfikatów

Zdefiniowane w AD, te template'y określają ustawienia i uprawnienia do wydawania certyfikatów, w tym dozwolone EKU oraz prawa do enrollmentu lub modyfikacji, co jest kluczowe dla zarządzania dostępem do usług certyfikacji.

**Wersja schematu template'a ma znaczenie.** Starsze **v1** template'y (na przykład wbudowany **WebServer** template) nie posiadają wielu nowoczesnych mechanizmów wymuszających. Badania **ESC15/EKUwu** pokazały, że dla **v1 templates** requester może osadzić **Application Policies/EKUs** w CSR, które są **preferowane nad** skonfigurowanymi EKU szablonu, umożliwiając uzyskanie client-auth, enrollment agent lub code-signing certyfikatów mając jedynie prawa enrollmentu. Preferuj **v2/v3 templates**, usuń lub nadpisz domyślne v1 i ściśle ogranicz EKU do zamierzonego celu.

## Enrollment certyfikatu

Proces enrollmentu certyfikatów jest inicjowany przez administratora, który **tworzy certificate template**, który następnie jest **publikowany** przez Enterprise Certificate Authority (CA). To udostępnia template klientom do enrollmentu, co osiąga się przez dodanie nazwy template'a do pola `certificatetemplates` obiektu Active Directory.

Aby klient mógł zażądać certyfikatu, muszą być przydzielone **enrollment rights**. Prawa te są definiowane przez security descriptors na certificate template oraz na samym Enterprise CA. Uprawnienia muszą być przyznane w obu miejscach, aby żądanie zakończyło się powodzeniem.

### Prawa enrollmentu na template'ie

Prawa te są określone przez Access Control Entries (ACE), wyszczególniające uprawnienia takie jak:

- **Certificate-Enrollment** i **Certificate-AutoEnrollment**, każde powiązane z określonymi GUIDami.
- **ExtendedRights**, pozwalające na wszystkie rozszerzone uprawnienia.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad template'em.

### Prawa enrollmentu na Enterprise CA

Prawa CA są wyszczególnione w jej security descriptor, dostępnym poprzez konsolę zarządzania Certificate Authority. Niektóre ustawienia nawet pozwalają użytkownikom o niskich uprawnieniach na zdalny dostęp, co może stanowić problem bezpieczeństwa.

### Dodatkowe kontrole wydawania

Mogą obowiązywać pewne kontrole, takie jak:

- **Manager Approval**: umieszcza żądania w stanie oczekującym do zatwierdzenia przez certificate managera.
- **Enrolment Agents and Authorized Signatures**: określają liczbę wymaganych podpisów na CSR oraz potrzebne Application Policy OIDs.

### Metody żądania certyfikatów

Certyfikaty mogą być żądane przez:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), z użyciem interfejsów DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), przez named pipes lub TCP/IP.
3. interfejs webowy do certificate enrollment, z zainstalowaną rolą Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), w powiązaniu z usługą Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dla urządzeń sieciowych, przy użyciu Simple Certificate Enrollment Protocol (SCEP).

Użytkownicy Windows mogą także żądać certyfikatów przez GUI (`certmgr.msc` lub `certlm.msc`) lub narzędzia wiersza poleceń (`certreq.exe` lub PowerShellowy `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uwierzytelnianie certyfikatami

Active Directory (AD) obsługuje uwierzytelnianie za pomocą certyfikatów, głównie wykorzystując protokoły **Kerberos** i **Secure Channel (Schannel)**.

### Proces uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos żądanie użytkownika o Ticket Granting Ticket (TGT) jest podpisywane przy użyciu **klucza prywatnego** certyfikatu użytkownika. Żądanie to przechodzi przez szereg weryfikacji wykonywanych przez kontroler domeny, w tym sprawdzenie **ważności**, **ścieżki** oraz **statusu unieważnienia** certyfikatu. Weryfikacje obejmują także sprawdzenie, czy certyfikat pochodzi z zaufanego źródła oraz potwierdzenie obecności wystawcy w **magazynie certyfikatów NTAUTH**. Pomyślne weryfikacje skutkują wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD, znajdujący się w:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
jest kluczowy dla ustanawiania zaufania dla uwierzytelniania przy użyciu certyfikatów.

### Uwierzytelnianie Secure Channel (Schannel)

Schannel umożliwia bezpieczne połączenia TLS/SSL, gdzie podczas handshake klient przedstawia certyfikat, który, jeśli zostanie pomyślnie zweryfikowany, autoryzuje dostęp. Powiązanie certyfikatu z kontem AD może obejmować funkcję Kerberos **S4U2Self** lub pole **Subject Alternative Name (SAN)** certyfikatu, między innymi metodami.

### Enumeracja AD Certificate Services

Usługi certyfikatów AD można enumerować za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CAs)** i ich konfiguracjach. Jest to dostępne dla dowolnego użytkownika uwierzytelnionego w domenie bez specjalnych uprawnień. Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** są używane do enumeracji i oceny podatności w środowiskach AD CS.

Polecenia do użycia tych narzędzi obejmują:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Recent Vulnerabilities & Security Updates (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Patch is included in the **May 10 2022** security updates. Auditing & strong-mapping controls were introduced via **KB5014754**; environments should now be in *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Public PoCs are limited, but the vulnerable IIS components are often exposed internally. Patch as of **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Patched as of **November 12, 2024**. Replace or supersede v1 templates (e.g., default WebServer), restrict EKUs to intent, and limit enrollment rights. |

### Microsoft hardening timeline (KB5014754)

Microsoft introduced a three-phase rollout (Compatibility → Audit → Enforcement) to move Kerberos certificate authentication away from weak implicit mappings. As of **February 11 2025**, domain controllers automatically switch to **Full Enforcement** if the `StrongCertificateBindingEnforcement` registry value is not set. Administrators should:

1. Patch all DCs & AD CS servers (May 2022 or later).
2. Monitor Event ID 39/41 for weak mappings during the *Audit* phase.
3. Re-issue client-auth certificates with the new **SID extension** or configure strong manual mappings before February 2025.

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** now surfaces posture assessments for ESC1-ESC8/ESC11 and generates real-time alerts such as *“Domain-controller certificate issuance for a non-DC”* (ESC8) and *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Ensure sensors are deployed to all AD CS servers to benefit from these detections.
* Disable or tightly scope the **“Supply in the request”** option on all templates; prefer explicitly defined SAN/EKU values.
* Remove **Any Purpose** or **No EKU** from templates unless absolutely required (addresses ESC2 scenarios).
* Require **manager approval** or dedicated Enrollment Agent workflows for sensitive templates (e.g., WebServer / CodeSigning).
* Restrict web enrollment (`certsrv`) and CES/NDES endpoints to trusted networks or behind client-certificate authentication.
* Enforce RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) to mitigate ESC11 (RPC relay). The flag is **on by default**, but is often disabled for legacy clients, which re-opens relay risk.
* Secure **IIS-based enrollment endpoints** (CES/Certsrv): disable NTLM where possible or require HTTPS + Extended Protection to block ESC8 relays.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
