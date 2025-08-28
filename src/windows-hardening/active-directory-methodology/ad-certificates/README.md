# Certyfikaty AD

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

### Składniki certyfikatu

- The **Subject** of the certificate denotes its owner.
- A **Public Key** is paired with a privately held key to link the certificate to its rightful owner.
- The **Validity Period**, defined by **NotBefore** and **NotAfter** dates, marks the certificate's effective duration.
- A unique **Serial Number**, provided by the Certificate Authority (CA), identifies each certificate.
- The **Issuer** refers to the CA that has issued the certificate.
- **SubjectAlternativeName** allows for additional names for the subject, enhancing identification flexibility.
- **Basic Constraints** identify if the certificate is for a CA or an end entity and define usage restrictions.
- **Extended Key Usages (EKUs)** delineate the certificate's specific purposes, like code signing or email encryption, through Object Identifiers (OIDs).
- The **Signature Algorithm** specifies the method for signing the certificate.
- The **Signature**, created with the issuer's private key, guarantees the certificate's authenticity.

### Szczególne uwagi

- **Subject Alternative Names (SANs)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co jest kluczowe dla serwerów obsługujących wiele domen. Bezpieczne procesy wydawania są niezbędne, aby uniknąć ryzyka podszywania się przez atakujących modyfikujących specyfikację SAN.

### Certificate Authorities (CAs) w Active Directory (AD)

AD CS rozpoznaje certyfikaty CA w lesie AD za pomocą wyznaczonych kontenerów, z których każdy pełni unikalną rolę:

- **Certification Authorities** container przechowuje zaufane certyfikaty root CA.
- **Enrolment Services** container zawiera informacje o Enterprise CAs i ich certificate templates.
- **NTAuthCertificates** object obejmuje certyfikaty CA uprawnione do uwierzytelniania w AD.
- **AIA (Authority Information Access)** container ułatwia walidację łańcucha certyfikatów dzięki certyfikatom pośrednim i cross CA.

### Pozyskiwanie certyfikatu: przebieg żądania klienta

1. Proces żądania zaczyna się od odnalezienia Enterprise CA przez klienta.
2. Tworzony jest CSR, zawierający klucz publiczny i inne dane, po wygenerowaniu pary klucz publiczny–prywatny.
3. CA ocenia CSR względem dostępnych certificate templates i wydaje certyfikat na podstawie uprawnień szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.

### Certificate Templates

Zdefiniowane w AD, te szablony określają ustawienia i uprawnienia do wydawania certyfikatów, w tym dozwolone EKU oraz prawa do enrollment i modyfikacji — kluczowe do zarządzania dostępem do usług certyfikacyjnych.

## Rejestracja certyfikatu

Proces rejestracji certyfikatów jest inicjowany przez administratora, który **tworzy certificate template**, który następnie jest **publikowany** przez Enterprise Certificate Authority (CA). To udostępnia szablon do rejestracji przez klientów, co osiąga się dodając nazwę szablonu do pola `certificatetemplates` obiektu Active Directory.

Aby klient mógł zażądać certyfikatu, muszą być przyznane mu **enrollment rights**. Prawa te są definiowane przez security descriptors na certificate template oraz na samym Enterprise CA. Uprawnienia muszą być nadane w obu miejscach, aby żądanie zakończyło się sukcesem.

### Prawa do rejestracji szablonu

Prawa te są określone przez Access Control Entries (ACE), szczegółowo opisujące uprawnienia takie jak:

- **Certificate-Enrollment** i **Certificate-AutoEnrollment** prawa, każde powiązane z określonymi GUID.
- **ExtendedRights**, pozwalające na wszystkie rozszerzone uprawnienia.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad szablonem.

### Prawa Enterprise CA do rejestracji

Prawa CA są opisane w jego security descriptorze, dostępnym przez konsolę zarządzania Certificate Authority. Niektóre ustawienia mogą nawet umożliwiać zdalny dostęp użytkownikom o niskich uprawnieniach, co może stanowić zagrożenie bezpieczeństwa.

### Dodatkowe kontrole wydawania

Mogą być stosowane pewne kontrole, takie jak:

- **Manager Approval**: umieszcza żądania w stanie oczekującym do momentu zatwierdzenia przez managera certyfikatów.
- **Enrolment Agents and Authorized Signatures**: określają liczbę wymaganych podpisów w CSR oraz niezbędne Application Policy OIDy.

### Metody żądania certyfikatów

Certyfikaty można żądać przez:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), używając interfejsów DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), przez named pipes lub TCP/IP.
3. Interfejs webowy certificate enrollment, z rolą Certificate Authority Web Enrollment zainstalowaną.
4. **Certificate Enrollment Service** (CES), w powiązaniu z Certificate Enrollment Policy (CEP) service.
5. **Network Device Enrollment Service** (NDES) dla urządzeń sieciowych, używając Simple Certificate Enrollment Protocol (SCEP).

Użytkownicy Windows mogą także żądać certyfikatów przez GUI (`certmgr.msc` lub `certlm.msc`) lub narzędzia wiersza poleceń (`certreq.exe` lub polecenie PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uwierzytelnianie za pomocą certyfikatów

Active Directory (AD) obsługuje uwierzytelnianie przy użyciu certyfikatów, głównie z wykorzystaniem protokołów **Kerberos** i **Secure Channel (Schannel)**.

### Proces uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos żądanie użytkownika o Ticket Granting Ticket (TGT) jest podpisywane przy użyciu **klucza prywatnego** certyfikatu użytkownika. To żądanie podlega kilku weryfikacjom wykonywanym przez kontroler domeny, w tym sprawdzeniu **ważności**, **ścieżki** oraz **statusu unieważnienia** certyfikatu. Weryfikacje obejmują także potwierdzenie, że certyfikat pochodzi z zaufanego źródła oraz obecności wystawcy w **magazynie certyfikatów NTAUTH**. Udane weryfikacje skutkują wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD, znajdujący się pod:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
jest kluczowe dla ustanawiania zaufania w uwierzytelnianiu za pomocą certyfikatów.

### Secure Channel (Schannel) Authentication

Schannel umożliwia bezpieczne połączenia TLS/SSL, w których podczas handshake klient przedstawia certyfikat, który — jeśli zostanie pomyślnie zweryfikowany — uprawnia do dostępu. Mapowanie certyfikatu na konto AD może wykorzystywać funkcję Kerberos **S4U2Self** lub **Subject Alternative Name (SAN)** certyfikatu, między innymi metodami.

### AD Certificate Services Enumeration

Usługi certyfikatów AD można wyliczyć za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CAs)** i ich konfiguracjach. Jest to dostępne dla dowolnego użytkownika uwierzytelnionego w domenie bez specjalnych uprawnień. Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** są używane do enumeracji i oceny podatności w środowiskach AD CS.

Przykładowe polecenia użycia tych narzędzi obejmują:
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
