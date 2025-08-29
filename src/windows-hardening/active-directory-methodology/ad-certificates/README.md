# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

### Składniki certyfikatu

- **Subject** certyfikatu oznacza jego właściciela.
- **Public Key** jest sparowany z kluczem prywatnym, aby powiązać certyfikat z jego prawowitym właścicielem.
- **Validity Period**, określony przez daty **NotBefore** i **NotAfter**, wyznacza okres ważności certyfikatu.
- Unikalny **Serial Number**, nadawany przez Certificate Authority (CA), identyfikuje każdy certyfikat.
- **Issuer** odnosi się do CA, który wydał certyfikat.
- **SubjectAlternativeName** pozwala na dodatkowe nazwy podmiotu, zwiększając elastyczność identyfikacji.
- **Basic Constraints** określają, czy certyfikat jest dla CA czy dla końcowego podmiotu oraz definiują ograniczenia użycia.
- **Extended Key Usages (EKUs)** określają konkretne przeznaczenia certyfikatu, takie jak podpisywanie kodu czy szyfrowanie poczty, za pomocą Object Identifiers (OIDs).
- **Signature Algorithm** określa metodę podpisania certyfikatu.
- **Signature**, utworzony przy użyciu prywatnego klucza wystawcy, gwarantuje autentyczność certyfikatu.

### Szczególne uwagi

- **Subject Alternative Names (SANs)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co jest kluczowe dla serwerów obsługujących wiele domen. Bezpieczne procesy wydawania są niezbędne, aby uniknąć ryzyka podszywania się przez atakującego manipulującego specyfikacją SAN.

### Certificate Authorities (CAs) w Active Directory (AD)

AD CS rozpoznaje certyfikaty CA w lesie AD poprzez wyznaczone kontenery, z których każdy pełni inną rolę:

- **Certification Authorities** container przechowuje zaufane certyfikaty root CA.
- **Enrolment Services** container zawiera informacje o Enterprise CAs i ich certificate templates.
- Obiekt **NTAuthCertificates** obejmuje certyfikaty CA uprawnione do uwierzytelniania w AD.
- **AIA (Authority Information Access)** container ułatwia weryfikację łańcucha certyfikatów za pomocą certyfikatów pośrednich i cross CA.

### Pozyskiwanie certyfikatów: przepływ żądania klienta

1. Proces rozpoczyna się, gdy klient znajduje Enterprise CA.
2. Tworzony jest CSR, zawierający klucz publiczny i inne szczegóły, po wygenerowaniu pary kluczy publiczny-prywatny.
3. CA ocenia CSR względem dostępnych certificate templates i wydaje certyfikat zgodnie z uprawnieniami szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.

### Certificate Templates

Zdefiniowane w AD, te szablony określają ustawienia i uprawnienia do wydawania certyfikatów, w tym dozwolone EKU oraz prawa do rejestracji lub modyfikacji — kluczowe dla zarządzania dostępem do usług certyfikatowych.

## Certificate Enrollment

Proces rejestracji certyfikatów jest inicjowany przez administratora, który **tworzy certificate template**, a następnie szablon jest **publikowany** przez Enterprise Certificate Authority (CA). To udostępnia szablon do rejestracji przez klientów, co osiąga się przez dodanie nazwy szablonu do pola `certificatetemplates` obiektu Active Directory.

Aby klient mógł zażądać certyfikatu, muszą być przyznane **enrollment rights**. Prawa te definiowane są przez security descriptors na certificate template oraz na samym Enterprise CA. Uprawnienia muszą być nadane w obu miejscach, aby żądanie zakończyło się powodzeniem.

### Prawa do rejestracji szablonu

Prawa te określone są poprzez Access Control Entries (ACE), wyszczególniając uprawnienia takie jak:

- **Certificate-Enrollment** i **Certificate-AutoEnrollment**, każde powiązane z konkretnymi GUID.
- **ExtendedRights**, pozwalające na wszystkie rozszerzone uprawnienia.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad szablonem.

### Prawa do rejestracji na Enterprise CA

Prawa CA są opisane w jego security descriptor, dostępnym przez konsolę zarządzania Certificate Authority. Niektóre ustawienia pozwalają nawet użytkownikom o niskich uprawnieniach na zdalny dostęp, co może stanowić problem bezpieczeństwa.

### Dodatkowe kontrole wydawania

Mogą obowiązywać pewne kontrole, takie jak:

- **Manager Approval**: umieszcza żądania w stanie oczekującym do momentu zatwierdzenia przez managera certyfikatów.
- **Enrolment Agents i Authorized Signatures**: określają liczbę wymaganych podpisów na CSR oraz niezbędne Application Policy OIDs.

### Metody żądania certyfikatów

Certyfikaty można żądać za pomocą:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), używając interfejsów DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), przez named pipes lub TCP/IP.
3. Interfejsu webowego certificate enrollment, z rolą Certificate Authority Web Enrollment zainstalowaną.
4. **Certificate Enrollment Service** (CES), w połączeniu z usługą Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dla urządzeń sieciowych, używając Simple Certificate Enrollment Protocol (SCEP).

Użytkownicy Windows mogą także żądać certyfikatów poprzez GUI (`certmgr.msc` lub `certlm.msc`) lub narzędzia wiersza poleceń (`certreq.exe` lub polecenie PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uwierzytelnianie certyfikatami

Active Directory (AD) obsługuje uwierzytelnianie certyfikatami, głównie wykorzystując protokoły **Kerberos** i **Secure Channel (Schannel)**.

### Proces uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos żądanie użytkownika o Ticket Granting Ticket (TGT) jest podpisywane przy użyciu **klucza prywatnego** certyfikatu użytkownika. Żądanie to jest poddawane kilku weryfikacjom przez kontroler domeny, w tym sprawdzeniu **ważności**, **ścieżki** oraz **stanu unieważnienia** certyfikatu. Weryfikacje obejmują również sprawdzenie, że certyfikat pochodzi z zaufanego źródła oraz potwierdzenie obecności wystawcy w **NTAUTH certificate store**. Pomyślne weryfikacje skutkują wystawieniem TGT. Obiekt **`NTAuthCertificates`** w AD, znajdujący się pod:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
Jest kluczowy dla ustanawiania zaufania przy uwierzytelnianiu za pomocą certyfikatów.

### Uwierzytelnianie Secure Channel (Schannel)

Schannel ułatwia bezpieczne połączenia TLS/SSL, gdzie podczas handshake klient przedstawia certyfikat, który, jeśli zostanie pomyślnie zweryfikowany, uprawnia do dostępu. Mapowanie certyfikatu na konto AD może obejmować funkcję Kerberos **S4U2Self** lub wykorzystanie **Subject Alternative Name (SAN)** certyfikatu, oraz inne metody.

### Enumeracja usług certyfikatów AD

Usługi certyfikatów AD można enumerować za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CAs)** i ich konfiguracjach. Jest to dostępne dla każdego użytkownika uwierzytelnionego w domenie bez specjalnych uprawnień. Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** służą do enumeracji i oceny podatności w środowiskach AD CS.

Polecenia do użycia tych narzędzi obejmują:
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
## Źródła

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
