# Certyfikaty AD

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

### Składniki certyfikatu

- **Subject** certyfikatu wskazuje jego właściciela.
- **Public Key** jest powiązany z kluczem prywatnym, aby połączyć certyfikat z jego prawowitym właścicielem.
- **Validity Period**, określany przez daty **NotBefore** i **NotAfter**, wyznacza okres ważności certyfikatu.
- Unikalny **Serial Number**, nadany przez Certificate Authority (CA), identyfikuje każdy certyfikat.
- **Issuer** wskazuje CA, które wydało certyfikat.
- **SubjectAlternativeName** umożliwia przypisanie dodatkowych nazw do podmiotu, zwiększając elastyczność identyfikacji.
- **Basic Constraints** określają, czy certyfikat jest przeznaczony dla CA czy dla encji końcowej, oraz definiują ograniczenia jego użycia.
- **Extended Key Usages (EKUs)** określają konkretne zastosowania certyfikatu, takie jak podpisywanie kodu lub szyfrowanie wiadomości e-mail, za pomocą Object Identifiers (OIDs).
- **Signature Algorithm** określa metodę podpisywania certyfikatu.
- **Signature**, utworzony przy użyciu klucza prywatnego wystawcy, gwarantuje autentyczność certyfikatu.<sup>[[1]](#references)</sup>

### Szczególne kwestie

- **Subject Alternative Names (SANs)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co ma kluczowe znaczenie w przypadku serwerów obsługujących wiele domen. Bezpieczne procesy wydawania certyfikatów są niezbędne, aby uniknąć ryzyka podszywania się przez atakujących manipulujących specyfikacją SAN.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) w Active Directory (AD)

AD CS rozpoznaje certyfikaty CA w lesie AD za pośrednictwem wyznaczonych kontenerów, z których każdy pełni unikalną funkcję:<sup>[[1]](#references)</sup>

- Kontener **Certification Authorities** zawiera zaufane certyfikaty głównych CA.
- Kontener **Enrolment Services** zawiera informacje o Enterprise CAs i ich szablonach certyfikatów.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA autoryzowane do uwierzytelniania w AD.
- Kontener **AIA (Authority Information Access)** ułatwia walidację łańcucha certyfikatów za pomocą certyfikatów pośrednich i certyfikatów między CA.

### Pozyskiwanie certyfikatu: przepływ żądania certyfikatu klienta

1. Proces żądania rozpoczyna się od znalezienia przez klientów Enterprise CA.
2. Po wygenerowaniu pary klucza publicznego i prywatnego tworzony jest CSR zawierający klucz publiczny oraz inne informacje.
3. CA ocenia CSR względem dostępnych szablonów certyfikatów i wydaje certyfikat na podstawie uprawnień szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.<sup>[[1]](#references)</sup>

### Szablony certyfikatów

Zdefiniowane w AD szablony określają ustawienia i uprawnienia dotyczące wydawania certyfikatów, w tym dozwolone EKUs oraz prawa do enrollmentu lub modyfikacji, co ma kluczowe znaczenie dla zarządzania dostępem do usług certyfikatów.<sup>[[1]](#references)</sup>

## Enrollment certyfikatów

Proces enrollmentu certyfikatów rozpoczyna administrator, który **tworzy szablon certyfikatu**, a następnie **publikuje** go Enterprise Certificate Authority (CA). Dzięki temu szablon staje się dostępny do enrollmentu przez klientów. Odbywa się to przez dodanie nazwy szablonu do pola `certificatetemplates` obiektu Active Directory.<sup>[[1]](#references)</sup>

Aby klient mógł zażądać certyfikatu, należy przyznać **prawa enrollmentu**. Prawa te są definiowane przez deskryptory zabezpieczeń na szablonie certyfikatu oraz na samym Enterprise CA. Uprawnienia muszą zostać przyznane w obu lokalizacjach, aby żądanie zakończyło się powodzeniem.<sup>[[1]](#references)</sup>

### Prawa enrollmentu szablonu

Prawa te są określane za pomocą Access Control Entries (ACEs), które definiują uprawnienia takie jak:<sup>[[1]](#references)</sup>

- Prawa **Certificate-Enrollment** i **Certificate-AutoEnrollment**, z których każde jest powiązane z określonymi GUID-ami.
- **ExtendedRights**, zezwalające na wszystkie rozszerzone uprawnienia.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad szablonem.

### Prawa enrollmentu Enterprise CA

Uprawnienia CA są określone w jego deskryptorze zabezpieczeń, dostępnym za pośrednictwem konsoli zarządzania Certificate Authority. Niektóre ustawienia umożliwiają nawet użytkownikom o niskich uprawnieniach zdalny dostęp, co może stanowić zagrożenie bezpieczeństwa.<sup>[[1]](#references)</sup>

### Dodatkowe mechanizmy kontroli wydawania

Mogą obowiązywać określone mechanizmy kontroli, takie jak:<sup>[[1]](#references)</sup>

- **Manager Approval**: umieszcza żądania w stanie oczekiwania do momentu zatwierdzenia przez menedżera certyfikatów.
- **Enrolment Agents and Authorized Signatures**: określają liczbę wymaganych podpisów w CSR oraz niezbędne Application Policy OIDs.

### Metody żądania certyfikatów

Certyfikaty można żądać za pośrednictwem:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), z wykorzystaniem interfejsów DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), za pośrednictwem named pipes lub TCP/IP.
3. **certificate enrollment web interface**, po zainstalowaniu roli Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), w połączeniu z usługą Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dla urządzeń sieciowych, z wykorzystaniem Simple Certificate Enrollment Protocol (SCEP).

Użytkownicy Windows mogą również żądać certyfikatów za pomocą GUI (`certmgr.msc` lub `certlm.msc`) albo narzędzi wiersza poleceń (`certreq.exe` lub polecenia PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uwierzytelnianie za pomocą certyfikatu

Active Directory (AD) obsługuje uwierzytelnianie za pomocą certyfikatów, wykorzystując przede wszystkim protokoły **Kerberos** i **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Proces uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos żądanie użytkownika dotyczące Ticket Granting Ticket (TGT) jest podpisywane przy użyciu **klucza prywatnego** certyfikatu użytkownika. Żądanie to przechodzi przez kilka walidacji wykonywanych przez kontroler domeny, w tym sprawdzenie **ważności**, **ścieżki** i statusu **unieważnienia** certyfikatu. Walidacje obejmują również sprawdzenie, czy certyfikat pochodzi z zaufanego źródła, oraz potwierdzenie obecności wystawcy w **magazynie certyfikatów NTAUTH**. Pomyślne przejście walidacji skutkuje wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD, znajdujący się pod adresem:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ma kluczowe znaczenie dla ustanowienia zaufania na potrzeby uwierzytelniania za pomocą certyfikatu.<sup>[[1]](#references)</sup>

### Uwierzytelnianie Secure Channel (Schannel)

Schannel umożliwia bezpieczne połączenia TLS/SSL. Podczas handshake klient przedstawia certyfikat, który — jeśli zostanie pomyślnie zweryfikowany — autoryzuje dostęp.<sup>[[2]](#references)</sup> Mapowanie certyfikatu na konto AD może obejmować funkcję Kerberos **S4U2Self** lub **Subject Alternative Name (SAN)** certyfikatu, a także inne metody.<sup>[[1]](#references)</sup>

### Enumeracja AD Certificate Services

Usługi certyfikatów AD można enumerować za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CA)** oraz ich konfiguracjach. Jest to dostępne dla każdego uwierzytelnionego w domenie użytkownika bez specjalnych uprawnień.<sup>[[1]](#references)</sup> Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** służą do enumeracji i oceny podatności w środowiskach AD CS.<sup>[[3]](#references)</sup>

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
Rubeus może również używać chronionego hasłem certyfikatu PFX do uwierzytelniania PKINIT i żądać TGT. Opcjonalny przełącznik `/getcredentials` żąda biletu usługi U2U i próbuje odzyskać hash NT konta:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certyfikat z drugiej ręki: nadużywanie Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Czym jest uwierzytelnianie klienta SSL/TLS i jak działa?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
