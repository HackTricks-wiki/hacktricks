# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

### Składniki certyfikatu

- **Podmiot** certyfikatu oznacza jego właściciela.
- **Klucz publiczny** jest sparowany z kluczem prywatnym, aby powiązać certyfikat z jego prawowitym właścicielem.
- **Okres ważności**, określony przez daty **NotBefore** i **NotAfter**, oznacza czas obowiązywania certyfikatu.
- Unikalny **Numer seryjny**, dostarczony przez Urząd Certyfikacji (CA), identyfikuje każdy certyfikat.
- **Wydawca** odnosi się do CA, który wydał certyfikat.
- **SubjectAlternativeName** pozwala na dodatkowe nazwy dla podmiotu, zwiększając elastyczność identyfikacji.
- **Podstawowe ograniczenia** identyfikują, czy certyfikat jest dla CA, czy dla podmiotu końcowego, oraz definiują ograniczenia użytkowania.
- **Rozszerzone zastosowania klucza (EKU)** określają konkretne cele certyfikatu, takie jak podpisywanie kodu lub szyfrowanie e-maili, za pomocą identyfikatorów obiektów (OID).
- **Algorytm podpisu** określa metodę podpisywania certyfikatu.
- **Podpis**, stworzony za pomocą klucza prywatnego wydawcy, gwarantuje autentyczność certyfikatu.

### Specjalne uwagi

- **Alternatywne nazwy podmiotu (SAN)** rozszerzają zastosowanie certyfikatu na wiele tożsamości, co jest kluczowe dla serwerów z wieloma domenami. Bezpieczne procesy wydawania są niezbędne, aby uniknąć ryzyka podszywania się przez atakujących manipulujących specyfikacją SAN.

### Urzędy Certyfikacji (CA) w Active Directory (AD)

AD CS uznaje certyfikaty CA w lesie AD poprzez wyznaczone kontenery, z których każdy pełni unikalne role:

- Kontener **Urzędów Certyfikacji** przechowuje zaufane certyfikaty głównych CA.
- Kontener **Usług rejestracji** zawiera szczegóły dotyczące CA przedsiębiorstwa i ich szablonów certyfikatów.
- Obiekt **NTAuthCertificates** zawiera certyfikaty CA autoryzowane do uwierzytelniania AD.
- Kontener **AIA (Dostęp do informacji o autorytecie)** ułatwia walidację łańcucha certyfikatów z certyfikatami pośrednimi i krzyżowymi CA.

### Pozyskiwanie certyfikatu: Proces żądania certyfikatu klienta

1. Proces żądania rozpoczyna się od znalezienia przez klientów CA przedsiębiorstwa.
2. Tworzony jest CSR, zawierający klucz publiczny i inne szczegóły, po wygenerowaniu pary kluczy publiczno-prywatnych.
3. CA ocenia CSR w odniesieniu do dostępnych szablonów certyfikatów, wydając certyfikat na podstawie uprawnień szablonu.
4. Po zatwierdzeniu CA podpisuje certyfikat swoim kluczem prywatnym i zwraca go klientowi.

### Szablony certyfikatów

Zdefiniowane w AD, te szablony określają ustawienia i uprawnienia do wydawania certyfikatów, w tym dozwolone EKU oraz prawa do rejestracji lub modyfikacji, co jest kluczowe dla zarządzania dostępem do usług certyfikacyjnych.

## Rejestracja certyfikatu

Proces rejestracji certyfikatów jest inicjowany przez administratora, który **tworzy szablon certyfikatu**, który następnie jest **publikowany** przez Urząd Certyfikacji (CA) przedsiębiorstwa. Umożliwia to dostępność szablonu do rejestracji przez klientów, co osiąga się poprzez dodanie nazwy szablonu do pola `certificatetemplates` obiektu Active Directory.

Aby klient mógł zażądać certyfikatu, muszą być przyznane **prawa rejestracji**. Prawa te są definiowane przez deskryptory zabezpieczeń na szablonie certyfikatu oraz samym Urzędzie Certyfikacji (CA) przedsiębiorstwa. Uprawnienia muszą być przyznane w obu lokalizacjach, aby żądanie mogło być skuteczne.

### Prawa rejestracji szablonu

Prawa te są określone za pomocą wpisów kontroli dostępu (ACE), szczegółowo opisujących uprawnienia, takie jak:

- Prawa **Certificate-Enrollment** i **Certificate-AutoEnrollment**, z każdym związanym z określonymi GUID.
- **ExtendedRights**, pozwalające na wszystkie rozszerzone uprawnienia.
- **FullControl/GenericAll**, zapewniające pełną kontrolę nad szablonem.

### Prawa rejestracji CA przedsiębiorstwa

Prawa CA są określone w jego deskryptorze zabezpieczeń, dostępnym za pośrednictwem konsoli zarządzania Urzędem Certyfikacji. Niektóre ustawienia pozwalają nawet użytkownikom o niskich uprawnieniach na zdalny dostęp, co może stanowić zagrożenie dla bezpieczeństwa.

### Dodatkowe kontrole wydawania

Mogą obowiązywać pewne kontrole, takie jak:

- **Zatwierdzenie menedżera**: Umieszcza żądania w stanie oczekiwania do zatwierdzenia przez menedżera certyfikatów.
- **Agenci rejestracji i autoryzowane podpisy**: Określają liczbę wymaganych podpisów na CSR oraz niezbędne identyfikatory polityki aplikacji OID.

### Metody żądania certyfikatów

Certyfikaty można żądać za pośrednictwem:

1. **Protokół rejestracji certyfikatów klienta Windows** (MS-WCCE), używając interfejsów DCOM.
2. **Protokół ICertPassage Remote** (MS-ICPR), przez potoki nazwane lub TCP/IP.
3. **Interfejs internetowy rejestracji certyfikatów**, z zainstalowaną rolą Web Enrollment Urzędu Certyfikacji.
4. **Usługa rejestracji certyfikatów** (CES), w połączeniu z usługą polityki rejestracji certyfikatów (CEP).
5. **Usługa rejestracji urządzeń sieciowych** (NDES) dla urządzeń sieciowych, używając prostego protokołu rejestracji certyfikatów (SCEP).

Użytkownicy systemu Windows mogą również żądać certyfikatów za pośrednictwem GUI (`certmgr.msc` lub `certlm.msc`) lub narzędzi wiersza poleceń (`certreq.exe` lub polecenia `Get-Certificate` PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uwierzytelnianie za pomocą certyfikatów

Active Directory (AD) wspiera uwierzytelnianie za pomocą certyfikatów, głównie wykorzystując protokoły **Kerberos** i **Secure Channel (Schannel)**.

### Proces Uwierzytelniania Kerberos

W procesie uwierzytelniania Kerberos, żądanie użytkownika o Ticket Granting Ticket (TGT) jest podpisywane za pomocą **klucza prywatnego** certyfikatu użytkownika. To żądanie przechodzi przez kilka walidacji przez kontroler domeny, w tym **ważność** certyfikatu, **ścieżkę** oraz **status unieważnienia**. Walidacje obejmują również weryfikację, że certyfikat pochodzi z zaufanego źródła oraz potwierdzenie obecności wystawcy w **magazynie certyfikatów NTAUTH**. Pomyślne walidacje skutkują wydaniem TGT. Obiekt **`NTAuthCertificates`** w AD, znajdujący się pod:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
jest kluczowe dla ustanowienia zaufania w przypadku uwierzytelniania certyfikatów.

### Uwierzytelnianie Secure Channel (Schannel)

Schannel ułatwia bezpieczne połączenia TLS/SSL, gdzie podczas handshake klient przedstawia certyfikat, który, jeśli zostanie pomyślnie zweryfikowany, autoryzuje dostęp. Mapowanie certyfikatu do konta AD może obejmować funkcję Kerberos **S4U2Self** lub **Subject Alternative Name (SAN)** certyfikatu, między innymi metody.

### Enumeracja usług certyfikatów AD

Usługi certyfikatów AD mogą być enumerowane za pomocą zapytań LDAP, ujawniając informacje o **Enterprise Certificate Authorities (CAs)** i ich konfiguracjach. Jest to dostępne dla każdego użytkownika uwierzytelnionego w domenie bez specjalnych uprawnień. Narzędzia takie jak **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** są używane do enumeracji i oceny podatności w środowiskach AD CS.

Polecenia do korzystania z tych narzędzi obejmują:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Odniesienia

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{{#include ../../banners/hacktricks-training.md}}
