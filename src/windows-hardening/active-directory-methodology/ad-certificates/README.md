# Certyfikaty AD

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

### Składniki certyfikatu

- **Subject** certyfikatu określa jego właściciela.
- **Public Key** jest powiązany z kluczem przechowywanym prywatnie, aby połączyć certyfikat z jego prawowitym właścicielem.
- **Validity Period**, definiowany przez daty **NotBefore** i **NotAfter**, określa okres obowiązywania certyfikatu.
- Unikalny **Serial Number**, nadany przez Certificate Authority (CA), identyfikuje każdy certyfikat.
- **Issuer** oznacza CA, które wydało certyfikat.
- **SubjectAlternativeName** pozwala określić dodatkowe nazwy podmiotu, zwiększając elastyczność identyfikacji.
- **Basic Constraints** określają, czy certyfikat jest przeznaczony dla CA, czy dla jednostki końcowej, oraz definiują ograniczenia jego użycia.
- **Extended Key Usages (EKUs)** określają konkretne zastosowania certyfikatu, takie jak podpisywanie kodu lub szyfrowanie wiadomości e-mail, za pomocą Object Identifiers (OIDs).
- **Signature Algorithm** określa metodę podpisywania certyfikatu.
- **Signature**, utworzony za pomocą klucza prywatnego wystawcy, gwarantuje autentyczność certyfikatu.<sup>[[1]](#references)</sup>

### Uwagi specjalne

- **Subject Alternative Names (SANs)** rozszerzają możliwość zastosowania certyfikatu na wiele tożsamości, co ma kluczowe znaczenie dla serwerów obsługujących wiele domen. Bezpieczne procesy wydawania certyfikatów są niezbędne, aby uniknąć ryzyka podszywania się przez attackerów manipulujących specyfikacją SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) w Active Directory (AD)

AD CS rozpoznaje certyfikaty CA w lesie AD za pośrednictwem wyznaczonych kontenerów, z których każdy pełni określoną funkcję:<sup>[[1]](#references)</sup>

- Kontener **Certification Authorities** przechowuje zaufane certyfikaty głównych CA.
- Kontener **Enrolment Services** zawiera informacje o Enterprise CAs i ich szablonach certyfikatów.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA autoryzowane do uwierzytelniania w AD.
- Kontener **AIA (Authority Information Access)** ułatwia walidację łańcucha certyfikatów za pomocą pośrednich certyfikatów CA oraz certyfikatów cross CA.

### Pozyskiwanie certyfikatu: przepływ żądania certyfikatu klienta

1. Proces żądania rozpoczyna się od znalezienia przez klienta Enterprise CA.
2. Po wygenerowaniu pary kluczy publiczny-prywatny tworzony jest CSR zawierający klucz publiczny i inne informacje.
3. CA ocenia CSR względem dostępnych szablonów certyfikatów i wydaje certyfikat na podstawie uprawnień szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.<sup>[[1]](#references)</sup>

### Szablony certyfikatów

Zdefiniowane w AD szablony określają ustawienia i uprawnienia związane z wydawaniem certyfikatów, w tym dozwolone EKUs oraz prawa do rejestracji lub modyfikacji, co ma kluczowe znaczenie dla zarządzania dostępem do usług certyfikatów.<sup>[[1]](#references)</sup>

## Rejestracja certyfikatu

Proces rejestracji certyfikatów rozpoczyna administrator, który **tworzy szablon certyfikatu**, a następnie zostaje on **opublikowany** przez Enterprise Certificate Authority (CA). Dzięki temu szablon staje się dostępny dla rejestracji klientów. Osiąga się to przez dodanie nazwy szablonu do pola `certificatetemplates` obiektu Active Directory.<sup>[[1]](#references)</sup>

Aby klient mógł zażądać certyfikatu, należy przyznać mu **uprawnienia do rejestracji**. Uprawnienia te są definiowane przez deskryptory zabezpieczeń szablonu certyfikatu oraz samego Enterprise CA. Aby żądanie zakończyło się powodzeniem, uprawnienia muszą zostać przyznane w obu tych miejscach.<sup>[[1]](#references)</sup>

### Uprawnienia do rejestracji w szablonie

Uprawnienia te są określane za pomocą Access Control Entries (ACEs), które definiują między innymi:<sup>[[1]](#references)</sup>

- Uprawnienia **Certificate-Enrollment** i **Certificate-AutoEnrollment**, z których każde jest powiązane z określonymi GUID-ami.
- **ExtendedRights**, umożliwiające korzystanie ze wszystkich uprawnień rozszerzonych.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad szablonem.

### Uprawnienia do rejestracji w Enterprise CA

Uprawnienia CA są określone w jego deskryptorze zabezpieczeń, dostępnym za pośrednictwem konsoli zarządzania Certificate Authority. Niektóre ustawienia umożliwiają nawet użytkownikom o niskich uprawnieniach zdalny dostęp, co może stanowić zagrożenie bezpieczeństwa.<sup>[[1]](#references)</sup>

### Dodatkowe mechanizmy kontroli wydawania

Mogą obowiązywać określone mechanizmy kontroli, takie jak:<sup>[[1]](#references)</sup>

- **Manager Approval**: umieszcza żądania w stanie oczekiwania do czasu zatwierdzenia ich przez certificate managera.
- **Enrolment Agents and Authorized Signatures**: określają liczbę wymaganych podpisów w CSR oraz niezbędne Application Policy OIDs.

### Metody żądania certyfikatów

Certyfikaty można uzyskiwać za pośrednictwem:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), z użyciem interfejsów DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), za pośrednictwem named pipes lub TCP/IP.
3. **certificate enrollment web interface**, po zainstalowaniu roli Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), w połączeniu z usługą Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dla urządzeń sieciowych, z użyciem Simple Certificate Enrollment Protocol (SCEP).

Użytkownicy systemu Windows mogą również żądać certyfikatów za pośrednictwem GUI (`certmgr.msc` lub `certlm.msc`) albo narzędzi wiersza poleceń (`certreq.exe` lub polecenia `Get-Certificate` w PowerShell).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uwierzytelnianie za pomocą certyfikatu

Active Directory (AD) obsługuje uwierzytelnianie za pomocą certyfikatów, wykorzystując głównie protokoły **Kerberos** oraz **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Proces uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos żądanie użytkownika dotyczące Ticket Granting Ticket (TGT) jest podpisywane przy użyciu **klucza prywatnego** certyfikatu użytkownika. Żądanie to przechodzi kilka kontroli wykonywanych przez kontroler domeny, w tym sprawdzenie **ważności**, **ścieżki** oraz statusu **odwołania** certyfikatu. Kontrole obejmują również weryfikację, czy certyfikat pochodzi z zaufanego źródła, oraz potwierdzenie obecności wystawcy w **magazynie certyfikatów NTAUTH**. Pomyślne przejście kontroli skutkuje wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD, znajdujący się pod adresem:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ma kluczowe znaczenie dla ustanawiania zaufania podczas uwierzytelniania certyfikatowego.<sup>[[1]](#references)</sup>

### Uwierzytelnianie za pomocą Secure Channel (Schannel)

Schannel umożliwia bezpieczne połączenia TLS/SSL, podczas których w ramach handshake klient przedstawia certyfikat, który po pomyślnej walidacji autoryzuje dostęp.<sup>[[2]](#references)</sup> Mapowanie certyfikatu na konto AD może obejmować funkcję **S4U2Self** protokołu Kerberos lub pole **Subject Alternative Name (SAN)** certyfikatu, a także inne metody.<sup>[[1]](#references)</sup>

### Enumeracja AD Certificate Services

Usługi certyfikatów AD można enumerować za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CAs)** i ich konfiguracjach. Dostęp do tych informacji ma każdy uwierzytelniony w domenie użytkownik, bez specjalnych uprawnień.<sup>[[1]](#references)</sup> Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** służą do enumeracji i oceny podatności w środowiskach AD CS.<sup>[[3]](#references)</sup>

Polecenia służące do korzystania z tych narzędzi obejmują:
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
## Odnośniki

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Czym jest uwierzytelnianie klienta SSL/TLS i jak działa?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
