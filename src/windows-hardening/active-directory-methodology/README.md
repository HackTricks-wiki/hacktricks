# Active Directory Metodologia

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, permettendo agli **amministratori di rete** di creare e gestire efficacemente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettata per scalare, facilitando l'organizzazione di un gran numero di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **alberi** e **foreste**. Un **dominio** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. Gli **alberi** sono gruppi di questi domini collegati da una struttura condivisa, e una **foresta** rappresenta la raccolta di più alberi, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Diritti specifici di **accesso** e **comunicazione** possono essere assegnati a ciascuno di questi livelli.

Concetti chiave all'interno di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Denota entità all'interno della directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Domain** – Funziona come contenitore per gli oggetti della directory, con la capacità per più domini di coesistere all'interno di una **forest**, ciascuno mantenendo la propria raccolta di oggetti.
4. **Tree** – Un raggruppamento di domini che condividono un dominio radice comune.
5. **Forest** – Il livello massimo della struttura organizzativa in Active Directory, composto da diversi alberi con **trust relationships** tra di loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi critici per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi comprendono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, inclusi **autenticazione** e funzionalità di **ricerca**.
2. **Certificate Services** – Sovrintende alla creazione, distribuzione e gestione dei **certificati digitali**.
3. **Lightweight Directory Services** – Supporta applicazioni abilitati alla directory tramite il **protocollo LDAP**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare gli utenti attraverso più applicazioni web in una singola sessione.
5. **Rights Management** – Aiuta a proteggere materiali soggetti a copyright regolando la loro distribuzione e uso non autorizzati.
6. **DNS Service** – Cruciale per la risoluzione dei **nomi di dominio**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Per imparare come **attaccare un AD** è necessario comprendere molto bene il processo di autenticazione **Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Puoi consultare rapidamente [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una visione rapida dei comandi che puoi eseguire per enumerare/sfruttare un AD.

> [!WARNING]
> La comunicazione Kerberos **richiede un nome completamente qualificato (FQDN)** per eseguire azioni. Se provi ad accedere a una macchina tramite l'indirizzo IP, **verrà usato NTLM e non Kerberos**.

## Recon Active Directory (No creds/sessions)

Se hai accesso a un ambiente AD ma non possiedi credenziali/sessioni potresti:

- **Pentest the network:**
- Scansionare la rete, trovare macchine e porte aperte e provare a **sfruttare vulnerabilità** o **estrarre credenziali** da esse (per esempio, [gli printer possono essere target molto interessanti](ad-information-in-printers.md)).
- L'enumerazione del DNS può fornire informazioni sui server chiave nel dominio come web, printer, share, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare più informazioni su come fare questo.
- **Controllare l'accesso null e Guest sui servizi smb** (questo non funzionerà su versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server SMB può essere trovata qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerare Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP può essere trovata qui (presta **speciale attenzione all'accesso anonimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Avvelenare la rete**
- Raccogliere credenziali **spacciandosi per servizi con Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedere agli host **abusando del relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogliere credenziali **esponendo** servizi UPnP falsi con **evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrarre username/nomi da documenti interni, social media, servizi (soprattutto web) all'interno degli ambienti di dominio e anche da quelli pubblicamente disponibili.
- Se trovi i nomi completi dei lavoratori dell'azienda, puoi provare diverse convenzioni di username AD (**read this**)(https://activedirectorypro.com/active-directory-user-naming-convention/). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettere a caso e 3 numeri a caso_ (abc123).
- Strumenti:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Controlla le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesta una **username non valida** il server risponderà usando il codice di errore **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permettendoci di determinare che lo username era invalido. Gli **username validi** restituiranno o il **TGT in un AS-REP** oppure l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che all'utente è richiesta la pre-autenticazione.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controller. Il metodo invoca la funzione `DsrGetDcNameEx2` dopo aver fatto il bind dell'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca può essere trovata [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se trovi uno di questi server nella rete puoi anche eseguire **user enumeration** contro di esso. Ad esempio, puoi usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puoi trovare liste di usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere il **nome delle persone che lavorano in azienda** dalla fase di recon che avresti dovuto eseguire prima. Con nome e cognome puoi usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali usernames validi.

### Knowing one or several usernames

Ok, quindi sai già di avere un username valido ma nessuna password... Prova:

- [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT_REQ_PREAUTH_ puoi **richiedere un AS_REP message** per quell'utente che conterrà alcuni dati criptati con una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): Prova le password più **comuni** con ciascuno degli utenti scoperti, magari qualche utente usa una password debole (tieni presente la password policy!).
- Nota che puoi anche **spray OWA servers** per provare a ottenere accesso alle caselle mail degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti essere in grado di **ottenere** alcuni challenge **hashes** da crackare avvelenando alcuni protocolli della **rete**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare Active Directory avrai **più email e una migliore comprensione della rete**. Potresti riuscire a forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) per ottenere accesso all'ambiente AD.

### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** con l'**account null o guest** potresti **posizionare file** (come un file SCF) che se in qualche modo vengono aperti **scatenano un'autenticazione NTLM verso di te**, così puoi **rubare** il **NTLM challenge** per crackarlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Per questa fase è necessario aver **compromesso le credenziali o una sessione di un account di dominio valido.** Se hai delle credenziali valide o una shell come domain user, **ricorda che le opzioni date prima sono ancora valide per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata dovresti conoscere qual è il **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Aver compromesso un account è un **grande passo per iniziare a compromettere l'intero dominio**, perché potrai avviare la **Active Directory Enumeration:**

Per quanto riguarda [**ASREPRoast**](asreproast.md) ora puoi trovare tutti i possibili utenti vulnerabili, e per quanto riguarda [**Password Spraying**](password-spraying.md) puoi ottenere una **lista di tutti gli usernames** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- Puoi usare il [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell for recon**](../basic-powershell-for-pentesters/index.html) che sarà più stealthy
- Puoi anche [**use powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro strumento eccellente per il recon in Active Directory è [**BloodHound**](bloodhound.md). Non è **molto stealthy** (dipende dai metodi di collection che usi), ma **se non ti interessa** provarlo assolutamente. Trova dove gli utenti possono RDP, trova path verso altri gruppi, ecc.
- **Altri tool automatici di enumerazione AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) poiché potrebbero contenere informazioni interessanti.
- Uno **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** dalla suite **SysInternal**.
- Puoi anche cercare nel database LDAP con **ldapsearch** per cercare credenziali nei campi _userPassword_ & _unixUserPassword_, o anche in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se usi **Linux**, puoi anche enumerare il dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Puoi anche provare strumenti automatici come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

È molto facile ottenere tutti gli usernames di dominio da Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione Enumeration sembra breve, è la parte più importante di tutte. Accedi ai link (principalmente quelli di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e esercitati fino a sentirti a tuo agio. Durante un assessment, questo sarà il momento chiave per trovare la strada verso DA o per decidere che non si può fare nulla.

### Kerberoast

Kerberoasting consiste nell'ottenere **TGS tickets** usati da servizi legati ad account utente e crackare la loro crittografia — che si basa sulle password degli utenti — **offline**.

Maggiori dettagli in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute delle credenziali puoi verificare se hai accesso a qualche **macchina**. A tal fine, puoi usare **CrackMapExec** per tentare connessioni su diversi server con protocolli differenti, in base alle tue scansioni porte.

### Local Privilege Escalation

Se hai compromesso credenziali o una sessione come user di dominio e hai **accesso** con questo utente a **qualunque macchina nel dominio** dovresti cercare di scalare privilegi localmente e cercare credenziali. Questo perché solo con privilegi di amministratore locale potrai **dumpare gli hash di altri utenti** in memoria (LSASS) e localmente (SAM).

C'è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È molto **improbabile** che troverai **tickets** nell'utente corrente che ti diano permessi per accedere a risorse inaspettate, ma puoi comunque verificare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **più email e una migliore comprensione della rete**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Cerca Creds in Computer Shares | SMB Shares

Now that you have some basic credentials you should check if you can **trovare** any **interesting files being shared inside the AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalation di privilegi su Active Directory CON privileged credentials/session

**Per le tecniche seguenti un utente di dominio normale non è sufficiente, serve qualche privilegio/credenziale speciale per eseguire questi attacchi.**

### Hash extraction

Si spera che tu sia riuscito a **compromettere qualche account local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Poi, è il momento di estrarre tutti gli hash dalla memoria e localmente.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Devi usare qualche **tool** che esegua l'**NTLM authentication** usando quell'**hash**, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell'**hash** dentro **LSASS**, così quando verrà effettuata un'**NTLM authentication**, quell'**hash** sarà usato. L'ultima opzione è ciò che fa mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

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

If you have the **hash** or **password** of a **amministratore locale** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è abbastanza **rumoroso** e **LAPS** lo **mitigherebbe**.

### MSSQL Abuse & Trusted Links

Se un utente ha privilegi per **access MSSQL instances**, potrebbe riuscire a usarle per **eseguire comandi** sull'host MSSQL (se in esecuzione come SA), **rubare** l'hash NetNTLM o perfino eseguire un **relay attack**.\
Inoltre, se un'istanza MSSQL è trusted (database link) da una diversa istanza MSSQL, se l'utente ha privilegi sul database trusted potrà **usare la trust relationship per eseguire query anche nell'altra istanza**. Queste trust possono essere concatenate e ad un certo punto l'utente potrebbe trovare un database mal configurato dove può eseguire comandi.\
**I link fra database funzionano anche attraverso forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Le suite di inventory e deployment di terze parti spesso espongono percorsi potenti verso credenziali e code execution. Vedi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se trovi un qualsiasi oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sul computer, sarai in grado di dumpare i TGT dalla memoria di tutti gli utenti che effettuano il login sul computer.\
Quindi, se un **Domain Admin** accede al computer, potrai dumpare il suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie al constrained delegation potresti perfino **compromettere automaticamente un Print Server** (si spera che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se a un utente o computer è permesso fare "Constrained Delegation" sarà in grado di **impersonare qualsiasi utente per accedere ad alcuni servizi su un computer**.\
Poi, se **comprometti l'hash** di questo utente/computer sarai in grado di **impersonare qualsiasi utente** (anche Domain Admins) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto abilita l'ottenimento di code execution con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su oggetti di dominio** che potrebbero permetterti di **muoverti lateralmente** o **escalare privilegi** in seguito.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Scoprire un **Spool service in ascolto** all'interno del dominio può essere **abusato** per **acquisire nuove credenziali** ed **escalare privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacons nei loro processi** per impersonarli.\
Di solito gli utenti accedono al sistema via RDP, quindi qui trovi come effettuare un paio di attacchi sulle sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **local Administrator password** sui computer joined al dominio, assicurando che sia **randomizzata**, unica e frequentemente **cambiata**. Queste password sono memorizzate in Active Directory e l'accesso è controllato tramite ACL a soli utenti autorizzati. Con permessi sufficienti per accedere a queste password, il pivoting verso altri computer diventa possibile.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per escalare privilegi all'interno dell'ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se sono configurati **template vulnerabili** è possibile abusarne per escalare privilegi:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Una volta ottenuti privilegi di **Domain Admin** o ancora meglio **Enterprise Admin**, puoi **dumpare** il **database di dominio**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Alcune delle tecniche discusse prima possono essere usate per persistenza.\
Per esempio potresti:

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

L'**Silver Ticket attack** crea un **legittimo TGS ticket** per un servizio specifico usando l'**NTLM hash** (per esempio, l'**hash dell'account PC**). Questo metodo viene impiegato per **ottenere accesso ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** implica che un attaccante ottenga l'**NTLM hash dell'account krbtgt** in un ambiente Active Directory. Questo account è speciale perché viene usato per firmare tutti i **TGT (Ticket Granting Tickets)**, essenziali per autenticarsi nella rete AD.

Una volta ottenuto questo hash, l'attaccante può creare **TGT** per qualsiasi account desideri (come nel Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Questi sono come i golden tickets ma forgiati in modo da **bypassare i meccanismi comuni di rilevamento dei golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Possedere i certificati di un account o essere in grado di richiederli** è un ottimo modo per persistere nell'account utente (anche se questo cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usare certificati è anche un modo per persistere con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory assicura la sicurezza dei **gruppi privilegiati** (come Domain Admins e Enterprise Admins) applicando una lista standard di **ACL** attraverso questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzione può essere sfruttata; se un attaccante modifica l'ACL di AdminSDHolder per dare pieno accesso a un utente normale, quell'utente ottiene ampi controlli su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi e permettere accessi non voluti a meno che non sia strettamente monitorata.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account **local administrator**. Ottenendo diritti admin su una macchina simile, l'hash del Local Administrator può essere estratto usando **mimikatz**. Successivamente è necessaria una modifica al registro per **abilitare l'uso di questa password**, permettendo l'accesso remoto all'account Local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **concedere** alcune **permessi speciali** a un **utente** su specifici oggetti di dominio che permetteranno all'utente di **escalare privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** sono usati per **memorizzare** i **permessi** che un **oggetto** ha **su** un altro **oggetto**. Se riesci a fare anche solo una **piccola modifica** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover essere membro di un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Alterare **LSASS** in memoria per stabilire una **password universale**, concedendo accesso a tutti gli account di dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare il tuo **SSP** per **catturare** in **clear text** le **credenziali** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** in AD e lo usa per **pushare attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare log riguardo le **modifiche**. Hai bisogno di privilegi DA ed essere nel **root domain**.\
Nota che se usi dati errati, appariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo discusso come escalare privilegi se hai **permessi sufficienti per leggere le password LAPS**. Tuttavia, queste password possono anche essere usate per **mantenere persistenza**.\
Vedi:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera la **Forest** come il confine di sicurezza. Questo implica che **compromettere un singolo dominio potrebbe potenzialmente portare al compromesso dell'intera Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che permette a un utente di un **dominio** di accedere a risorse in un altro **dominio**. Crea essenzialmente un collegamento tra i sistemi di autenticazione dei due domini, permettendo il flusso delle verifiche di autenticazione. Quando i domini impostano una trust, scambiano e conservano specifiche **chiavi** all'interno dei loro **Domain Controller (DC)**, che sono cruciali per l'integrità della trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **dominio trusted**, deve prima richiedere uno speciale ticket noto come **inter-realm TGT** al DC del proprio dominio. Questo TGT è cifrato con una **chiave di trust** condivisa che entrambi i domini hanno concordato. L'utente poi presenta questo TGT al **DC del dominio trusted** per ottenere un ticket di servizio (**TGS**). Dopo la verifica dell'inter-realm TGT da parte del DC del dominio trusted, questo emette un TGS, concedendo all'utente l'accesso al servizio.

**Passi**:

1. Un **client computer** in **Domain 1** inizia il processo usando il suo **NTLM hash** per richiedere un **Ticket Granting Ticket (TGT)** al suo **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato correttamente.
3. Il client poi richiede un **inter-realm TGT** a DC1, necessario per accedere a risorse in **Domain 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 come parte della trust a due vie.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2)** di **Domain 2**.
6. DC2 verifica l'inter-realm TGT utilizzando la trust key condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server in Domain 2 a cui il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è cifrato con l'hash dell'account del server, per ottenere accesso al servizio in Domain 2.

### Different trusts

È importante notare che **una trust può essere a 1 way o a 2 ways**. Nella configurazione a 2 vie, entrambi i domini si fidano l'uno dell'altro, ma nella relazione di trust **one way** uno dei domini sarà il **trusted** e l'altro il **trusting**. In quest'ultimo caso, **potrai accedere solo alle risorse all'interno del dominio trusting dal dominio trusted**.

Se Domain A trusts Domain B, A è il dominio trusting e B è il trusted. Inoltre, in **Domain A** questa sarebbe una **Outbound trust**; e in **Domain B** questa sarebbe una **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Configurazione comune all'interno della stessa forest, dove un child domain ha automaticamente una two-way transitive trust con il parent domain. Questo significa che le richieste di autenticazione possono fluire senza soluzione di continuità tra parent e child.
- **Cross-link Trusts**: Chiamate anche "shortcut trusts", sono stabilite tra child domains per accelerare i processi di referral. In forest complesse, i referral di autenticazione solitamente devono viaggiare fino alla root della forest e poi scendere verso il dominio target. Creando cross-links, il percorso si accorcia, utile soprattutto in ambienti geograficamente distribuiti.
- **External Trusts**: Impostate tra domini diversi e non correlati e sono per natura non-transitive. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), le external trusts sono utili per accedere a risorse in un dominio al di fuori della forest corrente che non è connesso da una forest trust. La sicurezza è rafforzata tramite SID filtering con le external trusts.
- **Tree-root Trusts**: Trust automaticamente stabilite tra il forest root domain e una nuova tree root aggiunta. Non comunemente incontrate, le tree-root trusts sono importanti per aggiungere nuovi domain trees a una forest, permettendo loro di mantenere un nome di dominio unico e assicurando la transitive two-way. Maggiori informazioni nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Questo tipo di trust è una two-way transitive trust tra due forest root domains, applicando anche SID filtering per migliorare le misure di sicurezza.
- **MIT Trusts**: Queste trust sono stabilite con domini Kerberos non-Windows, compatibili con [RFC4120](https://tools.ietf.org/html/rfc4120). Le MIT trusts sono più specializzate e servono per integrazioni con sistemi Kerberos esterni all'ecosistema Windows.

#### Other differences in **trusting relationships**

- Una relazione di trust può anche essere **transitive** (A trust B, B trust C, allora A trust C) o **non-transitive**.
- Una relazione di trust può essere impostata come **bidirectional trust** (entrambi si fidano reciprocamente) oppure come **one-way trust** (solo uno dei due si fida dell'altro).

### Attack Path

1. **Enumerare** le relazioni di trusting
2. Controllare se qualche **security principal** (user/group/computer) ha **accesso** a risorse dell'**altro dominio**, magari tramite voci ACE o facendo parte di gruppi dell'altro dominio. Cercare **relazioni cross-domain** (la trust è stata probabilmente creata per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono **pivotare** attraverso i domini.

Gli attaccanti possono accedere a risorse in un altro dominio tramite tre meccanismi principali:

- **Local Group Membership**: I principal possono essere aggiunti a gruppi locali sulle macchine, come il gruppo "Administrators" su un server, concedendo loro un controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: I principal possono anche essere membri di gruppi all'interno del dominio estero. Tuttavia, l'efficacia di questo metodo dipende dalla natura della trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principal possono essere specificati in una **ACL**, particolarmente come entità in **ACE** all'interno di una **DACL**, fornendo accesso a risorse specifiche. Per chi vuole approfondire la meccanica di ACL, DACL e ACE, il whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare i foreign security principals nel dominio. Questi saranno user/group provenienti da **un dominio/forest esterno**.

Puoi verificare questo con **Bloodhound** o usando powerview:
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
> Puoi determinare quale viene usata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ottenere privilegi Enterprise admin nel dominio child/parent abusando della trust tramite SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendere come il Configuration Naming Context (NC) possa essere sfruttato è cruciale. Il Configuration NC funge da repository centrale per i dati di configurazione in un forest di Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) del forest, e i DC scrivibili mantengono una copia scrivibile del Configuration NC. Per sfruttarlo, è necessario avere **privilegi SYSTEM su un DC**, preferibilmente un child DC.

**Link GPO to root DC site**

Il contenitore Sites del Configuration NC contiene informazioni sui site di tutti i computer membri del dominio nel forest di Active Directory (AD). Operando con privilegi SYSTEM su qualsiasi DC, un attaccante può collegare GPO ai siti del root DC. Questa operazione può compromettere il dominio root manipolando le policy applicate a tali siti.

Per informazioni dettagliate, si può consultare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vettore d'attacco consiste nel prendere di mira gMSA privilegiati all'interno del dominio. La KDS Root key, essenziale per calcolare le password dei gMSA, è memorizzata nel Configuration NC. Con privilegi SYSTEM su qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA nel forest.

Analisi dettagliata e guida passo-passo sono disponibili in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco complementare delegated MSA (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ulteriori ricerche esterne: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attaccante può modificare lo Schema AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Ciò potrebbe portare ad accesso non autorizzato e controllo sugli oggetti AD appena creati.

Ulteriori letture sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 mira al controllo degli oggetti della Public Key Infrastructure (PKI) per creare un certificate template che consenta l'autenticazione come qualsiasi utente all'interno del forest. Poiché gli oggetti PKI risiedono nel Configuration NC, compromettere un child DC scrivibile abilita l'esecuzione di attacchi ESC5.

Ulteriori dettagli sono disponibili in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari senza ADCS, l'attaccante può predisporre i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
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
In questo scenario **il tuo dominio è trusted** da un dominio esterno, concedendoti **permessi indeterminati** su quest'ultimo. Dovrai scoprire **quali principals del tuo dominio hanno quale accesso sul dominio esterno** e poi cercare di sfruttarlo:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio di Foresta Esterno - One-Way (Outbound)
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
In questo scenario **il tuo dominio** sta **affidando** alcuni **privilegi** a un'entità proveniente da **domini diversi**.

Tuttavia, quando un **domain is trusted** dal domain che effettua il trusting, il trusted domain **crea un utente** con un **nome prevedibile** che utilizza come **password la trusted password**. Ciò significa che è possibile **accedere a un utente del dominio che effettua il trusting per entrare nel dominio trusted** per enumerarlo e tentare di scalare ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il trusted domain è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** della domain trust (cosa non molto comune).

Un altro modo per compromettere il trusted domain è aspettare su una macchina dove un **user from the trusted domain can access** per effettuare il login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Inoltre, se la **vittima ha montato il suo hard drive**, dal processo della **RDP session** l'attaccante potrebbe salvare **backdoors** nella **startup folder of the hard drive**. Questa tecnica si chiama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazione dell'abuso dei domain trust

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SIDHistory attraverso forest trusts è mitigato da SID Filtering, che è attivato di default in tutti gli inter-forest trusts. Questo si basa sull'assunto che i trust intra-forest siano sicuri, considerando la forest, piuttosto che il domain, come confine di sicurezza secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID filtering potrebbe interrompere applicazioni e accessi utente, portando alla sua disattivazione occasionale.

### **Selective Authentication:**

- Per gli inter-forest trusts, l'uso di Selective Authentication assicura che gli utenti delle due forest non siano autenticati automaticamente. Invece, sono richieste autorizzazioni esplicite affinché gli utenti possano accedere a domini e server all'interno del domain o della forest che effettua il trusting.
- È importante notare che queste misure non proteggono contro lo sfruttamento del writable Configuration Naming Context (NC) o attacchi sull'account di trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Si raccomanda che i Domain Admins possano effettuare il login solo sui Domain Controllers, evitando il loro utilizzo su altri host.
- **Service Account Privileges**: I servizi non dovrebbero girare con privilegi di Domain Admin (DA) per mantenere la sicurezza.
- **Temporal Privilege Limitation**: Per i task che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementazione di Deception Techniques**

- Implementare deception comporta impostare trappole, come utenti o computer esca, con caratteristiche come password che non scadono o che sono segnati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o l'aggiunta a gruppi ad alto privilegio.
- Un esempio pratico prevede l'uso di strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maggiori informazioni sul deployment di tecniche di deception sono disponibili su [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicatori sospetti includono ObjectSID atipici, logon poco frequenti, date di creazione e basso numero di bad password.
- **General Indicators**: Confrontare gli attributi di potenziali oggetti esca con quelli di oggetti genuini può rivelare incongruenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare tali deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitare l'enumerazione delle sessioni sui Domain Controllers per prevenire il rilevamento da parte di ATA.
- **Ticket Impersonation**: Utilizzare chiavi **aes** per la creazione di ticket aiuta a eludere il rilevamento non degradando a NTLM.
- **DCSync Attacks**: Eseguire da una macchina non Domain Controller per evitare il rilevamento da parte di ATA è consigliato, poiché l'esecuzione diretta da un Domain Controller genererà alert.

## Riferimenti

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
