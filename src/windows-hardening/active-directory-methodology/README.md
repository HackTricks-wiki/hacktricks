# Metodologia di Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, permettendo agli **amministratori di rete** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettata per scalare, facilitando l'organizzazione di un gran numero di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **tree** e **forest**. Un **domain** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. I **tree** sono gruppi di questi domini collegati da una struttura condivisa, e una **forest** rappresenta la collezione di più tree, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Diritti specifici di **accesso** e **comunicazione** possono essere assegnati a ciascuno di questi livelli.

Concetti chiave all'interno di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Indica entità all'interno della directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Domain** – Funziona come contenitore per gli oggetti della directory; possono coesistere più domini all'interno di una **forest**, ciascuno con la propria raccolta di oggetti.
4. **Tree** – Un raggruppamento di domini che condividono un dominio root comune.
5. **Forest** – Il livello più alto della struttura organizzativa in Active Directory, composto da diversi tree con **trust relationships** tra loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi critici per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi includono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, inclusi **authentication** e funzionalità di **search**.
2. **Certificate Services** – Sovraintende la creazione, distribuzione e gestione dei **digital certificates** sicuri.
3. **Lightweight Directory Services** – Supporta applicazioni abilitate alla directory tramite il protocollo **LDAP**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare utenti attraverso più applicazioni web in una singola sessione.
5. **Rights Management** – Aiuta a proteggere materiale coperto da copyright regolando la sua distribuzione e uso non autorizzati.
6. **DNS Service** – Cruciale per la risoluzione dei **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Per imparare come **attaccare un AD** è necessario comprendere molto bene il processo di **autenticazione Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Riepilogo rapido

Puoi consultare [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una vista rapida dei comandi che puoi eseguire per enumerare/sfruttare un AD.

> [!WARNING]
> La comunicazione Kerberos **richiede un full qualifid name (FQDN)** per eseguire azioni. Se provi ad accedere a una macchina tramite l'indirizzo IP, **verrà usato NTLM e non Kerberos**.

## Ricognizione Active Directory (senza credenziali/sessioni)

Se hai accesso a un ambiente AD ma non disponi di credenziali/sessioni puoi:

- **Pentest the network:**
- Scansionare la rete, trovare macchine e porte aperte e cercare di **exploitare vulnerabilità** o **estrarre credenziali** da esse (ad esempio, [printers could be very interesting targets](ad-information-in-printers.md)).
- L'enumerazione del DNS può fornire informazioni su server chiave nel dominio come web, stampanti, condivisioni, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare più informazioni su come farlo.
- **Controlla l'accesso null e Guest sui servizi smb** (questo non funzionerà sulle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server SMB può essere trovata qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerare LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP può essere trovata qui (presta **particolare attenzione all'accesso anonimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Avvelenare la rete**
- Raccogliere credenziali [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedere agli host [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogliere credenziali **esponendo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrarre username/nomi da documenti interni, social media, servizi (soprattutto web) all'interno degli ambienti di dominio e anche da risorse pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti, puoi provare diverse convenzioni per gli username AD ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerazione utenti

- **Anonymous SMB/LDAP enum:** Controlla le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesta una username non valida il server risponderà con il codice di errore Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permettendoci di determinare che lo username era invalido. Gli username **validi** restituiranno o il **TGT in a AS-REP** response o l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che all'utente è richiesta la pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controllers. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo il bind dell'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se trovi uno di questi server nella rete puoi anche eseguire **user enumeration** su di esso. Ad esempio, puoi usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puoi trovare elenchi di username in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e in quest'altro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere i **nome delle persone che lavorano nell'azienda** dalla fase di recon che avresti dovuto eseguire prima. Con nome e cognome puoi usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali username validi.

### Knowing one or several usernames

Ok, quindi sai di avere già uno username valido ma nessuna password... Prova allora:

- [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT_REQ_PREAUTH_ puoi **richiedere un messaggio AS_REP** per quell'utente che conterrà alcuni dati criptati da una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): Proviamo le **password più comuni** con ciascuno degli utenti scoperti, magari qualche utente usa una password debole (keep in mind the password policy!).
- Nota che puoi anche **spray OWA servers** per provare ad ottenere accesso ai server mail degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti essere in grado di **ottenere** alcuni challenge **hash** da crackare avvelenando alcuni protocolli della **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare l'Active Directory avrai **più email e una migliore comprensione della network**. Potresti essere in grado di forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) per ottenere accesso all'ambiente AD.

### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** con l'**utente null o guest** potresti **piazzare file** (come un file SCF) che se in qualche modo vengono aperti innescheranno un'autenticazione NTLM verso di te così potrai **rubare** la **NTLM challenge** per crackarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerazione di Active Directory CON credenziali/sessione

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido.** Se hai credenziali valide o una shell come utente di dominio, **ricorda che le opzioni indicate prima sono ancora valide per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata dovresti sapere qual è il **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Avere compromesso un account è un **grande passo per iniziare a compromettere l'intero dominio**, perché sarai in grado di iniziare la **enumerazione di Active Directory:**

Per quanto riguarda [**ASREPRoast**](asreproast.md) ora puoi trovare ogni possibile utente vulnerabile, e per quanto riguarda [**Password Spraying**](password-spraying.md) puoi ottenere una **lista di tutti gli username** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- Puoi usare il [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell for recon**](../basic-powershell-for-pentesters/index.html) che sarà più stealthier
- Puoi anche [**use powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro strumento fantastico per il recon in Active Directory è [**BloodHound**](bloodhound.md). Non è **molto stealthy** (a seconda dei metodi di raccolta che usi), ma **se non ti interessa** provarlo assolutamente. Trova dove gli utenti possono RDP, trova percorsi verso altri gruppi, ecc.
- **Altri strumenti automatici di enumerazione AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) poiché potrebbero contenere informazioni interessanti.
- Uno **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** dalla suite **SysInternal**.
- Puoi anche cercare nel database LDAP con **ldapsearch** per cercare credenziali nei campi _userPassword_ & _unixUserPassword_, o anche in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se usi **Linux**, puoi anche enumerare il dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Puoi anche provare strumenti automatici come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

È molto facile ottenere tutti gli username del dominio da Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione di Enumerazione sembra breve, è la più importante. Accedi ai link (soprattutto quelli di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e esercitati finché non ti senti a tuo agio. Durante un assessment, questo sarà il momento chiave per trovare la strada verso DA o per decidere che non si può fare nulla.

### Kerberoast

Kerberoasting consiste nell'ottenere **TGS tickets** usati dai servizi legati ad account utente e nel crackare la loro cifratura—che si basa sulle password degli utenti—**offline**.

Maggiori dettagli in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute alcune credenziali potresti verificare se hai accesso a qualche **macchina**. A tal fine, puoi usare **CrackMapExec** per tentare di connetterti a vari server con diversi protocolli, in base alle tue scansioni di porte.

### Local Privilege Escalation

Se hai compromesso credenziali o una sessione come utente di dominio normale e hai **accesso** con questo utente a **qualsiasi macchina nel dominio** dovresti provare a trovare il modo di **escalare i privilegi localmente e saccheggiare credenziali**. Questo perché solo con privilegi di amministratore locale potrai **dumpare gli hash di altri utenti** in memoria (LSASS) e localmente (SAM).

C'è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È molto **improbabile** che tu trovi **tickets** nell'utente corrente che ti diano permessi per accedere a risorse inaspettate, ma potresti controllare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se sei riuscito a enumerare Active Directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Cerca Creds in Computer Shares | SMB Shares

Ora che hai delle credenziali di base dovresti verificare se puoi **trovare** file **interessanti condivisi all'interno dell'AD**. Potresti farlo manualmente ma è un compito molto noioso e ripetitivo (e lo è ancora di più se trovi centinaia di doc da controllare).

[**Segui questo link per scoprire gli strumenti che potresti usare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se puoi **accedere ad altri PC o shares** potresti **posizionare file** (come un SCF file) che se in qualche modo vengono aperti attiveranno un t**rigger an NTLM authentication against you** così potrai **steal** la **NTLM challenge** per crackarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità permetteva a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Per le tecniche seguenti un utente di dominio normale non è sufficiente, hai bisogno di privilegi/credenziali speciali per eseguire questi attacchi.**

### Hash extraction

Si spera tu sia riuscito a **compromettere qualche account local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Poi, è il momento di estrarre tutti gli hash dalla memoria e localmente.\
[**Leggi questa pagina sui diversi modi per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **tool** che esegua l'**autenticazione NTLM usando** quell'**hash**, **oppure** potresti creare un nuovo **sessionlogon** e **iniettare** quell'**hash** dentro il **LSASS**, così quando verrà eseguita qualsiasi **NTLM authentication**, quell'**hash** verrà usato. L'ultima opzione è quello che fa mimikatz.\
[**Leggi questa pagina per più informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **usare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash over NTLM protocol. Pertanto, questo può essere particolarmente **utile in reti dove il protocollo NTLM è disabilitato** e solo **Kerberos è consentito** come protocollo di autenticazione.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli attaccanti **rubano il ticket di autenticazione di un utente** invece della sua password o dei suoi hash. Questo ticket rubato viene poi usato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno della rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se hai l'**hash** o la **password** di un **amministratore locale** dovresti provare a **accedere localmente** ad altri **PC** con quelle credenziali.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### Abuso di MSSQL e Trusted Links

Se un utente ha i privilegi per **accedere alle istanze MSSQL**, potrebbe usare questo accesso per **eseguire comandi** sull'host MSSQL (se in esecuzione come SA), **rubare** l'**hash** NetNTLM o perfino effettuare un **relay attack**.\
Inoltre, se un'istanza MSSQL è trusted (database link) da una diversa istanza MSSQL, se l'utente ha privilegi sul database trusted potrà **usare la relazione di trust per eseguire query anche nell'altra istanza**. Questi trust possono essere concatenati e a un certo punto l'utente potrebbe trovare un database mal configurato dove poter eseguire comandi.\
**I collegamenti tra database funzionano anche attraverso forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso di piattaforme per asset/deployment IT

Suite di inventory e deployment di terze parti spesso espongono percorsi potenti verso credenziali ed esecuzione di codice. Vedi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se trovi un oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sulla macchina, potrai dumpare i TGTs dalla memoria di ogni utente che effettua il login sulla macchina.\
Quindi, se un **Domain Admin effettua il login sulla macchina**, potrai dumpare il suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie al constrained delegation potresti persino **compromettere automaticamente un Print Server** (si spera che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se un utente o computer è autorizzato per la "Constrained Delegation" sarà in grado di **impersonare qualsiasi utente per accedere ad alcuni servizi su una macchina**.\
Poi, se **comprometti l'hash** di questo utente/computer sarai in grado di **impersonare qualsiasi utente** (anche domain admins) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto consente di ottenere l'esecuzione di codice con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su oggetti del dominio** che potrebbero permetterti di **muoverti lateralmente**/**escalare** privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso del servizio Printer Spooler

Scoprire un **servizio Spool in ascolto** all'interno del dominio può essere **abusato** per **acquisire nuove credenziali** e **escalare privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso di sessioni di terze parti

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accedono al sistema via RDP, quindi qui trovi come eseguire un paio di attacchi su sessioni RDP di terzi:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'Administrator locale** sui computer uniti al dominio, garantendo che sia **randomizzata**, unica e frequentemente **cambiata**. Queste password sono memorizzate in Active Directory e l'accesso è controllato tramite ACLs solo agli utenti autorizzati. Con permessi sufficienti per accedere a queste password, diventa possibile pivotare verso altri computer.


{{#ref}}
laps.md
{{#endref}}

### Furto di certificati

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per escalare privilegi all'interno dell'ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso di Certificate Templates

Se sono configurati template vulnerabili è possibile abusarne per escalare privilegi:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation con account ad alto privilegio

### Dumping delle credenziali di dominio

Una volta ottenuti privilegi di **Domain Admin** o, ancora meglio, di **Enterprise Admin**, puoi **dumpare** il **database del dominio**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc come persistenza

Alcune delle tecniche discusse in precedenza possono essere usate per la persistenza.\
Per esempio potresti:

- Rendere gli utenti vulnerabili a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Rendere gli utenti vulnerabili a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Concedere privilegi di [**DCSync**](#dcsync) a un utente

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'attacco **Silver Ticket** crea un **legittimo TGS (Ticket Granting Service) ticket** per un servizio specifico utilizzando l'**hash NTLM** (per esempio, l'**hash dell'account PC**). Questo metodo viene impiegato per **ottenere i privilegi di accesso al servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un attacco **Golden Ticket** coinvolge l'accesso da parte di un attaccante all'**hash NTLM dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Tickets (TGTs)**, essenziali per l'autenticazione nella rete AD.

Una volta ottenuto questo hash, l'attaccante può creare **TGTs** per qualsiasi account desideri (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Questi sono come golden tickets forgiati in modo da **bypassare i meccanismi comuni di rilevamento dei golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avere i certificati di un account o poterli richiedere** è un ottimo modo per mantenere la persistenza nell'account di un utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usare certificati consente anche di persistere con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins e Enterprise Admins) applicando una standard **Access Control List (ACL)** su questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata; se un attaccante modifica l'ACL di AdminSDHolder per dare pieno accesso a un utente normale, quell'utente ottiene un controllo esteso su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro se non monitorata attentamente.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account di **amministratore locale**. Ottenendo diritti admin su una macchina del genere, l'hash dell'Administrator locale può essere estratto usando **mimikatz**. Successivamente è necessaria una modifica al registro per **abilitare l'uso di questa password**, permettendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **concedere** alcune **permessi speciali** a un **utente** su specifici oggetti del dominio che permetteranno all'utente di **escalare privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** sono usati per **memorizzare** le **permissions** che un **oggetto** ha **su** un altro **oggetto**. Se puoi fare una **piccola modifica** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover essere membro di un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **password universale**, concedendo accesso a tutti gli account del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare il tuo **SSP** per **catturare** in **chiaro** le **credenziali** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo usa per **pushare attributi** (SIDHistory, SPNs...) su oggetti specifici **senza** lasciare log riguardanti le **modifiche**. Hai bisogno di privilegi DA e di essere all'interno del **root domain**.\
Nota che se usi dati errati, appariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo discusso di come escalare privilegi se si hanno **permessi sufficienti per leggere le password LAPS**. Tuttavia, queste password possono anche essere usate per **mantenere la persistenza**.\
Vedi:


{{#ref}}
laps.md
{{#endref}}

## Escalation privilegi nella Forest - Domain Trusts

Microsoft considera la **Forest** come il perimetro di sicurezza. Questo implica che **compromettere un singolo dominio potrebbe potenzialmente portare al compromesso dell'intera Forest**.

### Informazioni di base

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che permette a un utente di un **dominio** di accedere a risorse in un altro **dominio**. Crea essenzialmente un collegamento tra i sistemi di autenticazione dei due domini, permettendo il flusso delle verifiche di autenticazione. Quando i domini instaurano un trust, scambiano e conservano specifiche **chiavi** nei loro **Domain Controllers (DCs)**, che sono cruciali per l'integrità del trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **dominio trusted**, deve prima richiedere un ticket speciale noto come **inter-realm TGT** al DC del proprio dominio. Questo TGT è cifrato con una **chiave** condivisa che entrambi i domini hanno concordato. L'utente poi presenta questo TGT al **DC del dominio trusted** per ottenere un ticket di servizio (**TGS**). Dopo la verifica dell'inter-realm TGT da parte del DC del dominio trusted, viene emesso un TGS che concede all'utente l'accesso al servizio.

**Passi**:

1. Un **client computer** in **Domain 1** avvia il processo usando il suo **NTLM hash** per richiedere un **Ticket Granting Ticket (TGT)** al suo **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato con successo.
3. Il client richiede quindi un **inter-realm TGT** a DC1, necessario per accedere alle risorse in **Domain 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 come parte del trust bidirezionale.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2)** di **Domain 2**.
6. DC2 verifica l'inter-realm TGT usando la trust key condivisa e, se valido, rilascia un **Ticket Granting Service (TGS)** per il server in Domain 2 a cui il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è cifrato con l'hash dell'account del server, per ottenere accesso al servizio in Domain 2.

### Diversi trust

È importante notare che **un trust può essere a senso 1 o a senso 2**. Nell'opzione a 2 vie, entrambi i domini si fidano l'uno dell'altro, ma nel trust **a 1 via** una delle parti sarà il **trusted** e l'altra il **trusting** domain. In quest'ultimo caso, **potrai accedere solo alle risorse all'interno del dominio trusting dal dominio trusted**.

Se Domain A si fida di Domain B, A è il dominio trusting e B è il trusted. Inoltre, in **Domain A**, questo sarà un **Outbound trust**; e in **Domain B**, questo sarà un **Inbound trust**.

**Diverse relazioni di trusting**

- **Parent-Child Trusts**: Configurazione comune all'interno della stessa forest, dove un dominio figlio ha automaticamente un trust transitive a due vie con il dominio padre. Ciò permette il flusso di richieste di autenticazione tra padre e figlio.
- **Cross-link Trusts**: Chiamati anche "shortcut trusts", sono stabiliti tra domini figli per accelerare i processi di referral. In forest complesse, i referral di autenticazione tipicamente devono viaggiare fino alla radice della forest e poi scendere nel dominio di destinazione. Creando cross-links, il percorso si accorcia, utile soprattutto in ambienti geograficamente dispersi.
- **External Trusts**: Stabiliti tra domini differenti e non correlati e sono per natura non-transitivi. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), gli external trusts sono utili per accedere a risorse in un dominio al di fuori della forest corrente che non è connesso tramite un forest trust. La sicurezza è rafforzata tramite SID filtering con gli external trusts.
- **Tree-root Trusts**: Questi trust vengono creati automaticamente tra il dominio root della forest e una nuova tree root aggiunta. Anche se non comuni, i tree-root trusts sono importanti per aggiungere nuovi alberi di dominio a una forest, permettendo loro di mantenere un nome di dominio unico e assicurando la transitività bidirezionale. Ulteriori informazioni sono disponibili nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Questo tipo di trust è un trust transitive a due vie tra due forest root domains, applicando anche SID filtering per migliorare le misure di sicurezza.
- **MIT Trusts**: Questi trust sono stabiliti con domini Kerberos non-Windows conformi a [RFC4120](https://tools.ietf.org/html/rfc4120). I MIT trusts sono più specializzati e servono ambienti che richiedono integrazione con sistemi basati su Kerberos al di fuori dell'ecosistema Windows.

#### Altre differenze nelle **relazioni di trusting**

- Una relazione di trust può anche essere **transitiva** (A trust B, B trust C, quindi A trust C) o **non-transitiva**.
- Una relazione di trust può essere impostata come **bidirectional trust** (entrambi si fidano l'uno dell'altro) o come **one-way trust** (solo uno dei due si fida dell'altro).

### Percorso d'attacco

1. **Enumerare** le relazioni di trusting
2. Verificare se qualche **security principal** (utente/gruppo/computer) ha **accesso** a risorse dell'**altro dominio**, magari tramite voci ACE o essendo membro di gruppi dell'altro dominio. Cercare **relazioni cross-domain** (probabilmente il trust è stato creato per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono **pivotare** attraverso i domini.

Gli attaccanti possono accedere a risorse in un altro dominio tramite tre meccanismi principali:

- **Local Group Membership**: I principals possono essere aggiunti a gruppi locali sulle macchine, come il gruppo “Administrators” su un server, concedendo loro controllo significativo sulla macchina.
- **Foreign Domain Group Membership**: I principals possono anche essere membri di gruppi nel dominio straniero. Tuttavia, l'efficacia di questo metodo dipende dalla natura del trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principals possono essere specificati in un'**ACL**, in particolare come entità in **ACE** all'interno di una **DACL**, fornendo accesso a risorse specifiche. Per chi vuole approfondire la meccanica di ACLs, DACLs e ACEs, il whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Trovare utenti/gruppi esterni con permessi

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare i foreign security principals nel dominio. Questi saranno utenti/gruppi provenienti da **un dominio/forest esterno**.

Puoi verificare questo in **Bloodhound** o usando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalation di privilegi Child-to-Parent nella foresta
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
> Puoi verificare quale viene usata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalare a Enterprise admin nel dominio child/parent abusando della trust tramite SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendere come la Configuration Naming Context (NC) può essere sfruttata è fondamentale. La Configuration NC funge da repository centrale per i dati di configurazione attraverso una forest in ambienti Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) all'interno della forest, con i DC scrivibili che mantengono una copia scrivibile della Configuration NC. Per sfruttarla, è necessario avere i privilegi **SYSTEM su un DC**, preferibilmente un child DC.

**Link GPO to root DC site**

Il container Sites della Configuration NC include informazioni sui site di tutti i computer joinati al dominio all'interno della forest AD. Operando con privilegi SYSTEM su qualsiasi DC, un attacker può linkare GPO ai site del root DC. Questa azione può compromettere il dominio root manipolando le policy applicate a questi site.

Per informazioni approfondite, si può esplorare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vettore d'attacco coinvolge il targeting di gMSA privilegiati all'interno del dominio. La KDS Root key, essenziale per calcolare le password delle gMSA, è memorizzata nella Configuration NC. Con privilegi SYSTEM su qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA nella forest.

Analisi dettagliata e guida passo-passo sono disponibili in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco complementare delegato MSA (BadSuccessor – abuso degli attributi di migration):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ulteriore ricerca esterna: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attacker può modificare lo Schema AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Questo potrebbe portare ad accessi non autorizzati e al controllo su oggetti AD creati successivamente.

Ulteriori letture sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 prende di mira il controllo sugli oggetti PKI per creare un certificate template che permette di autenticarsi come qualsiasi utente all'interno della forest. Poiché gli oggetti PKI risiedono nella Configuration NC, compromettere un DC child scrivibile permette l'esecuzione di attacchi ESC5.

Ulteriori dettagli possono essere letti in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari privi di ADCS, l'attacker ha la capacità di impostare i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In questo scenario **il tuo domain è trusted** da un domain esterno che ti concede **permessi non determinati** su di esso. Dovrai trovare **quali principals del tuo domain hanno quale accesso sul domain esterno** e poi cercare di sfruttarlo:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
In questo scenario **your domain** è **trusting** alcuni **privileges** a principal da **different domains**.

Tuttavia, quando un **domain is trusted** dal domain che si fida, il trusted domain **creates a user** con un **predictable name** che usa come **password the trusted password**. Ciò significa che è possibile **access a user from the trusting domain to get inside the trusted one** per enumerarlo e provare a elevare ulteriori privileges:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il trusted domain è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **opposite direction** della domain trust (che non è molto comune).

Un altro modo per compromettere il trusted domain è aspettare su una macchina alla quale un **user from the trusted domain can access** per effettuare il login via **RDP**. Poi, l'attaccante potrebbe iniettare codice nel processo della sessione RDP e **access the origin domain of the victim** da lì.  
Inoltre, se il **victim mounted his hard drive**, dal processo della **RDP session** l'attaccante potrebbe salvare **backdoors** nella **startup folder of the hard drive**. Questa tecnica è chiamata **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazione dell'abuso dei trust di dominio

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SID history across forest trusts è mitigato da SID Filtering, che è attivato di default su tutti gli inter-forest trusts. Questo si basa sull'assunzione che gli intra-forest trusts siano sicuri, considerando la forest, piuttosto che il domain, come confine di sicurezza secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID filtering potrebbe interrompere applicazioni e l'accesso degli utenti, portando alla sua disattivazione occasionale.

### **Selective Authentication:**

- Per gli inter-forest trusts, l'uso di Selective Authentication assicura che gli utenti delle due forest non siano automaticamente autenticati. Invece, sono richieste autorizzazioni esplicite affinché gli utenti possano accedere a domain e server all'interno del trusting domain o della forest.
- È importante notare che queste misure non proteggono contro lo sfruttamento del writable Configuration Naming Context (NC) né contro attacchi al trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Si raccomanda che i Domain Admins siano autorizzati a fare il login solo sui Domain Controllers, evitando il loro utilizzo su altri host.
- **Service Account Privileges**: I servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA) per mantenere la sicurezza.
- **Temporal Privilege Limitation**: Per le attività che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementare deception comporta l'impostazione di trappole, come decoy users o computers, con caratteristiche quali password che non scadono o marcati come Trusted for Delegation. Un approccio dettagliato include la creazione di users con diritti specifici o l'aggiunta agli high privilege groups.
- Un esempio pratico prevede l'uso di strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maggiori dettagli sul deploy di tecniche di deception sono disponibili su [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicatori sospetti includono ObjectSID atipico, logon poco frequenti, date di creazione e basso conteggio di bad password.
- **General Indicators**: Confrontare gli attributi di oggetti potenzialmente decoy con quelli degli oggetti genuini può rivelare incoerenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare nell'identificazione di tali deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
  - **User Enumeration**: Evitare la session enumeration sui Domain Controllers per prevenire il rilevamento da parte di ATA.
  - **Ticket Impersonation**: Utilizzare chiavi **aes** per la creazione dei ticket aiuta a eludere il rilevamento non effettuando il downgrade a NTLM.
  - **DCSync Attacks**: Eseguire da un non-Domain Controller per evitare il rilevamento da parte di ATA è consigliato, poiché l'esecuzione diretta da un Domain Controller genererà alert.

## Riferimenti

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
