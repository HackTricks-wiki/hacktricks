# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, permettendo agli **amministratori di rete** di creare e gestire in modo efficiente **domains**, **users** e **objects** all'interno di una rete. È progettata per scalare, facilitando l'organizzazione di un gran numero di utenti in **groups** e **subgroups** gestibili, controllando i **access rights** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domains**, **trees** e **forests**. Un **domain** comprende una raccolta di oggetti, come **users** o **devices**, che condividono un database comune. I **trees** sono gruppi di questi domains collegati da una struttura condivisa, e una **forest** rappresenta la raccolta di più trees, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Diritti specifici di **access** e **communication** possono essere assegnati a ciascuno di questi livelli.

Concetti chiave all'interno di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli Active Directory objects.
2. **Object** – Indica entità all'interno della directory, inclusi **users**, **groups** o **shared folders**.
3. **Domain** – Funziona come contenitore per gli directory objects, con la possibilità che più domains coesistano all'interno di una **forest**, ognuno mantenendo la propria raccolta di oggetti.
4. **Tree** – Un raggruppamento di domains che condividono un dominio root comune.
5. **Forest** – Il punto più alto della struttura organizzativa in Active Directory, composto da diversi trees con **trust relationships** fra loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi critici per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi comprendono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **users** e **domains**, inclusi **authentication** e funzionalità di **search**.
2. **Certificate Services** – Sovrintende alla creazione, distribuzione e gestione dei **digital certificates** sicuri.
3. **Lightweight Directory Services** – Supporta applicazioni abilitate alla directory tramite il protocollo **LDAP**.
4. **Directory Federation Services** – Fornisce capacità di **single-sign-on** per autenticare utenti su più applicazioni web in una singola sessione.
5. **Rights Management** – Aiuta a proteggere materiale coperto da copyright regolando la sua distribuzione e uso non autorizzati.
6. **DNS Service** – Cruciale per la risoluzione dei **domain names**.

Per una spiegazione più dettagliata controlla: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Leggi questa pagina se non sai ancora come funziona.**](kerberos-authentication.md)

## Cheat Sheet

Puoi dare un'occhiata a [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una visione rapida di quali comandi eseguire per enumerare/sfruttare un AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Se hai accesso a un ambiente AD ma non possiedi credenziali/sessioni, potresti:

- **Pentest the network:**
- Scansionare la rete, trovare macchine e porte aperte e provare a **exploit vulnerabilities** o **extract credentials** da esse (per esempio, [printers could be very interesting targets](ad-information-in-printers.md)).
- L'enumerazione del DNS può fornire informazioni su server chiave nel domain come web, printers, shares, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare più informazioni su come farlo.
- **Check for null and Guest access on smb services** (questo non funzionerà sulle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un SMB server può essere trovata qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP può essere trovata qui (prestare **particolare attenzione all'accesso anonimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Raccogliere credenziali **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedere agli host **abusing the relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogliere credenziali **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrarre usernames/nomi da documenti interni, social media, servizi (soprattutto web) all'interno degli ambienti del domain e anche da quelli pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti dell'azienda, potresti provare diverse convenzioni di AD **username conventions** ([**leggi questo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Strumenti:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Controlla le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesto un **invalid username** il server risponderà utilizzando il **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permettendoci di determinare che lo username era invalido. Gli **valid usernames** provocano o il **TGT in a AS-REP** response o l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che all'utente è richiesta la pre-authentication.
- **No Authentication against MS-NRPC**: Usare auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controllers. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo il binding dell'interfaccia MS-NRPC per verificare se l'user o il computer esistono senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca può essere trovata [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se trovi uno di questi server nella rete, puoi anche eseguire **user enumeration** su di esso. Ad esempio, potresti usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puoi trovare liste di nomi utente in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere i **nomi delle persone che lavorano in azienda** raccolti durante la fase di recon che avresti dovuto eseguire prima. Con nome e cognome puoi usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali username validi.

### Knowing one or several usernames

Ok, quindi sai già di avere uno username valido ma nessuna password... Prova quindi:

- [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT_REQ_PREAUTH_ puoi **richiedere un AS_REP** per quell'utente che conterrà dei dati cifrati da una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): Prova le password più **comuni** con ciascuno degli utenti scoperti; magari qualche utente usa una password debole (tieni presente la policy delle password!).
- Nota che puoi anche eseguire password spraying sui server OWA per cercare di ottenere accesso alle caselle di posta degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti essere in grado di **ottenere** alcuni challenge **hash** da crackare avvelenando alcuni protocolli della **rete**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito ad enumerare Active Directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare attacchi NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) per ottenere accesso all'ambiente AD.

### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** con l'utente **null o guest** potresti **posizionare file** (come un file SCF) che, se in qualche modo vengono aperti, **attiveranno un'autenticazione NTLM verso di te** così da poter **rubare** il **challenge NTLM** per poi crackarlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido.** Se hai credenziali valide o una shell come domain user, **ricorda che le opzioni descritte prima rimangono valide per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata dovresti conoscere il **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Avere compromesso un account è un **passo importante per iniziare a compromettere l'intero dominio**, perché potrai avviare l'**Active Directory Enumeration:**

Riguardo a [**ASREPRoast**](asreproast.md) ora puoi trovare ogni possibile utente vulnerabile, e riguardo a [**Password Spraying**](password-spraying.md) puoi ottenere **la lista di tutti gli username** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- Puoi usare [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell for recon**](../basic-powershell-for-pentesters/index.html) che sarà più stealthy
- Puoi anche [**use powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro ottimo tool per il recon in Active Directory è [**BloodHound**](bloodhound.md). Non è **molto stealthy** (dipende dai metodi di collection che usi), ma **se non ti interessa** questo aspetto dovresti assolutamente provarlo. Trova dove gli utenti possono RDP, scopri percorsi verso altri gruppi, ecc.
- **Altri strumenti automatizzati di enumerazione AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) possono contenere informazioni interessanti.
- Uno **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** della SysInternal Suite.
- Puoi anche cercare nel database LDAP con **ldapsearch** per trovare credenziali nei campi _userPassword_ & _unixUserPassword_, o anche in _Description_. vedi [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se usi **Linux**, puoi anche enumerare il dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Puoi provare anche strumenti automatici come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

È molto facile ottenere tutti gli username del dominio da Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). Su Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione Enumeration sembra breve, è la parte più importante di tutte. Accedi ai link (principalmente quelli di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e esercitati fino a sentirti a tuo agio. Durante un assessment, questo sarà il momento chiave per trovare la strada verso DA o per decidere che non si può fare nulla.

### Kerberoast

Kerberoasting consiste nell'ottenere **TGS tickets** usati da servizi legati ad account utente e nel crackare la loro cifratura — basata sulle password utente — **offline**.

Maggiori dettagli in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute delle credenziali puoi verificare se hai accesso a qualche **macchina**. A tal fine puoi usare **CrackMapExec** per tentare connessioni su più server con differenti protocolli, in base alla tua scansione delle porte.

### Local Privilege Escalation

Se hai compromesso credenziali o una sessione come domain user e hai **accesso** con quell'utente a **qualunque macchina nel dominio** dovresti provare a trovare un modo per **escalare i privilegi localmente e recuperare credenziali**. Solo con privilegi di amministratore locale potrai **dumpare gli hash di altri utenti** in memoria (LSASS) e localmente (SAM).

C'è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È molto **improbabile** che troverai **ticket** nell'utente corrente che ti concedano il permesso di accedere a risorse inaspettate, ma puoi controllare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se sei riuscito a enumerare Active Directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Cerca Creds nelle condivisioni dei computer | SMB Shares

Ora che hai alcune credenziali di base dovresti verificare se puoi **trovare** file **interessanti condivisi all'interno della AD**. Potresti farlo manualmente ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti da controllare).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** potresti **posizionare file** (come un file SCF) che se in qualche modo vengono aperti **triggereranno un'autenticazione NTLM verso di te** così potrai **rubare** la **NTLM challenge** per crackerarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità permetteva a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalation dei privilegi su Active Directory CON credenziali/sessione privilegiata

**Per le tecniche seguenti un normale utente di dominio non è sufficiente, servono privilegi/credenziali speciali per eseguire questi attacchi.**

### Hash extraction

Sperabilmente sei riuscito a **compromettere qualche account di amministratore locale** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluso relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Poi, è il momento di dumpare tutti gli hash dalla memoria e localmente.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **tool** che **esegua** l'**autenticazione NTLM usando** quell'**hash**, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell'**hash** dentro LSASS, così quando viene eseguita qualsiasi **autenticazione NTLM**, quell'**hash verrà usato.** L'ultima opzione è quello che fa mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **usare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash sul protocollo NTLM. Pertanto, questo può essere particolarmente **utile in reti dove il protocollo NTLM è disabilitato** e solo **Kerberos è permesso** come protocollo di autenticazione.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nella tecnica di attacco **Pass The Ticket (PTT)**, gli attaccanti **rubano il ticket di autenticazione di un utente** invece della sua password o dei suoi valori hash. Questo ticket rubato viene poi usato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno della rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se hai l'**hash** o la **password** di un **amministratore locale** dovresti provare a **loginare localmente** su altri **PC** con quelle credenziali.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### MSSQL Abuse & Trusted Links

Se un utente ha privilegi per **accedere a istanze MSSQL**, potrebbe essere in grado di usarle per **eseguire comandi** sull'host MSSQL (se in esecuzione come SA), **rubare** l'NetNTLM **hash** o perfino eseguire un **relay** **attack**.\
Inoltre, se un'istanza MSSQL è trusted (database link) da una diversa istanza MSSQL, se l'utente ha privilegi sul database trusted, potrà **usare la relazione di trust per eseguire query anche nell'altra istanza**. Questi trust possono essere concatenati e a un certo punto l'utente potrebbe trovare un database mal configurato dove può eseguire comandi.\
**I link tra database funzionano anche attraverso forest trust.**


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

Se trovi qualsiasi oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sulla macchina, sarai in grado di dumpare TGTs dalla memoria di ogni utente che si logga sulla macchina.\
Quindi, se un **Domain Admin si logga sulla macchina**, potrai dumpare il suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie a constrained delegation potresti anche **compromettere automaticamente un Print Server** (si spera che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se un utente o computer è autorizzato per la "Constrained Delegation" potrà **impersonare qualsiasi utente per accedere ad alcuni servizi su un computer**.\
Quindi, se **comprometti l'hash** di questo utente/computer sarai in grado di **impersonare qualsiasi utente** (anche domain admins) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto permette di ottenere esecuzione di codice con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su oggetti di dominio** che potrebbero permetterti di **muoverti lateralmente** o **escalare** privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Scoprire un **Spool service in ascolto** all'interno del dominio può essere **abusato** per **acquisire nuove credenziali** e **escalare privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e perfino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accederanno al sistema via RDP, quindi qui trovi come effettuare un paio di attacchi su sessioni RDP di terzi:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'Administrator locale** sui computer joinati al dominio, assicurando che sia **randomizzata**, unica e frequentemente **cambiata**. Queste password sono immagazzinate in Active Directory e l'accesso è controllato tramite ACLs solo agli utenti autorizzati. Con permessi sufficienti per accedere a queste password, diventa possibile pivotare verso altri computer.


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

Una volta ottenuti privilegi di **Domain Admin** o ancor meglio **Enterprise Admin**, puoi **dumpare** il **database di dominio**: _ntds.dit_.

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

L'**Silver Ticket attack** crea un **legittimo Ticket Granting Service (TGS) ticket** per un servizio specifico usando l'**NTLM hash** (per esempio, l'**hash dell'account PC**). Questo metodo viene impiegato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** coinvolge un attaccante che ottiene accesso all'**NTLM hash dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Tickets (TGTs)**, essenziali per l'autenticazione nella rete AD.

Una volta che l'attaccante ottiene questo hash, può creare **TGTs** per qualsiasi account desideri (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Sono come golden tickets forgiati in modo da **bypassare i meccanismi comuni di rilevamento dei golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avere i certificati di un account o essere in grado di richiederli** è un ottimo modo per mantenere persistence nell'account dell'utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usare certificati è anche possibile per persistere con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins e Enterprise Admins) applicando una ACL standard su questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata: se un attaccante modifica la ACL di AdminSDHolder per dare pieno accesso a un utente normale, quell'utente ottiene un ampio controllo su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro se non monitorata attentamente.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account **administrator locale**. Ottenendo diritti admin su tale macchina, l'hash dell'Administrator locale può essere estratto usando **mimikatz**. Successivamente è necessaria una modifica al registro per **abilitare l'uso di questa password**, permettendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **dare** alcune **permessi speciali** a un **utente** su specifici oggetti di dominio che permetteranno all'utente di **escalare privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** sono usati per **memorizzare** i **permessi** che un **oggetto** ha **su** un altro **oggetto**. Se puoi solo **fare** una **piccola modifica** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza la necessità di essere membro di un gruppo privilegiato.


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
Puoi creare il tuo **SSP** per **catturare** in **clear text** le **credentials** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo usa per **pushare attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare alcun **log** riguardo le **modifiche**. Hai bisogno di privilegi DA e di essere all'interno del **root domain**.\
Nota che se usi dati errati, appariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo discusso come escalare privilegi se si hanno **sufficienti permessi per leggere le password LAPS**. Tuttavia, queste password possono anche essere usate per **mantenere persistence**.\
Vedi:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

È importante notare che **un trust può essere a 1 via o a 2 vie**. Nella configurazione a 2 vie, entrambi i domain si fidano reciprocamente, ma nella relazione di trust **a 1 via** uno dei domain sarà il **trusted** e l'altro il **trusting** domain. In quest'ultimo caso, **potrai accedere solo a risorse all'interno del trusting domain dal trusted**.

Se Domain A trusts Domain B, A è il trusting domain e B è il trusted. Inoltre, in **Domain A**, questo sarebbe un **Outbound trust**; e in **Domain B**, questo sarebbe un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Configurazione comune all'interno della stessa forest, dove un child domain ha automaticamente un trust transitivo a due vie con il suo parent domain. Questo significa che le richieste di autenticazione possono fluire tra parent e child.
- **Cross-link Trusts**: Chiamati anche "shortcut trusts", sono stabiliti tra child domain per velocizzare i processi di referral. In forest complesse, i referral di autenticazione normalmente devono viaggiare fino alla root della forest e poi scendere al domain target. Creando cross-links, il percorso viene abbreviato, utile in ambienti geograficamente distribuiti.
- **External Trusts**: Stabiliti tra domain differenti e non correlati e sono non-transitivi. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), gli external trusts sono utili per accedere a risorse in un domain fuori dalla forest corrente che non è connesso tramite un forest trust. La sicurezza è rafforzata tramite SID filtering con external trusts.
- **Tree-root Trusts**: Questi trust vengono creati automaticamente tra il forest root domain e un nuovo tree root aggiunto. Non sono comuni, ma sono importanti per aggiungere nuovi domain trees a una forest, permettendo loro di mantenere un nome di dominio unico e assicurando transitività a due vie. Maggiori informazioni nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Questo tipo di trust è un trust transitivo a due vie tra due forest root domains, applicando anche SID filtering per migliorare la sicurezza.
- **MIT Trusts**: Questi trust sono stabiliti con domini Kerberos non-Windows compatibili RFC4120. I MIT trusts sono più specializzati e servono per integrazioni con sistemi Kerberos esterni all'ecosistema Windows.

#### Other differences in **trusting relationships**

- Una relazione di trust può anche essere **transitiva** (A trust B, B trust C, allora A trust C) o **non-transitiva**.
- Una relazione di trust può essere impostata come **bidirectional trust** (entrambi si fidano) o come **one-way trust** (solo uno dei due si fida).

### Attack Path

1. **Enumerare** le relazioni di trusting
2. Controllare se qualche **security principal** (user/group/computer) ha **accesso** a risorse dell'**altro domain**, magari tramite voci ACE o appartenendo a gruppi dell'altro domain. Cercare **relazioni attraverso domain** (probabilmente il trust è stato creato per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono **pivotare** tra i domain.

Gli attaccanti possono accedere a risorse in un altro domain attraverso tre meccanismi principali:

- **Local Group Membership**: Principals potrebbero essere aggiunti a gruppi locali sulle macchine, come il gruppo “Administrators” su un server, concedendo loro ampio controllo su quella macchina.
- **Foreign Domain Group Membership**: I principals possono anche essere membri di gruppi all'interno del domain esterno. Tuttavia, l'efficacia di questo metodo dipende dalla natura del trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principals potrebbero essere specificati in una **ACL**, in particolare come entità nelle **ACE** all'interno di una **DACL**, fornendo accesso a risorse specifiche. Per chi vuole approfondire la meccanica di ACLs, DACLs e ACEs, il whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare foreign security principals nel domain. Questi saranno utenti/gruppi da **un domain/forest esterno**.

Puoi verificare questo in **Bloodhound** o usando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent escalation dei privilegi nella forest
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
> Puoi vedere quale viene usata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Ottenere i privilegi di Enterprise Admin nel dominio child/parent abusando della trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Sfruttare la Configuration NC scrivibile

È fondamentale capire come può essere sfruttata la Configuration Naming Context (NC). La Configuration NC funge da repository centrale per i dati di configurazione nell'intera forest in ambienti Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) della forest, e i DC scrivibili mantengono una copia scrivibile della Configuration NC. Per sfruttarla, è necessario avere **privilegi SYSTEM su un DC**, preferibilmente un child DC.

**Collegare una GPO al sito root del DC**

Il contenitore Sites della Configuration NC include informazioni sui siti di tutti i computer uniti al dominio nella forest AD. Operando con privilegi SYSTEM su qualsiasi DC, un attaccante può linkare GPO ai siti del root DC. Questa azione può compromettere il dominio root manipolando le policy applicate a questi siti.

Per informazioni approfondite, si può consultare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromettere qualsiasi gMSA nella forest**

Un vettore d'attacco consiste nel prendere di mira gMSA privilegiati all'interno del dominio. La KDS Root key, essenziale per calcolare le password delle gMSA, è memorizzata nella Configuration NC. Con privilegi SYSTEM su qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password per qualsiasi gMSA nella forest.

Analisi dettagliata e guida passo-passo si trovano in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco MSA delegato complementare (BadSuccessor – abuso degli attributi di migrazione):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ricerca esterna aggiuntiva: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, aspettare la creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attaccante può modificare lo Schema AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Questo può portare ad accessi non autorizzati e al controllo sugli oggetti AD appena creati.

Ulteriori approfondimenti sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 mira al controllo degli oggetti Public Key Infrastructure (PKI) per creare un template di certificato che consente l'autenticazione come qualsiasi utente nella forest. Poiché gli oggetti PKI risiedono nella Configuration NC, compromettere un child DC scrivibile permette di eseguire attacchi ESC5.

Maggiori dettagli sono disponibili in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari privi di ADCS, l'attaccante ha la possibilità di configurare i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Dominio di una forest esterna - One-Way (Inbound) o bidirezionale
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
In questo scenario **your domain is trusted** da un dominio esterno che ti concede **undetermined permissions** su di esso. Dovrai trovare **which principals of your domain have which access over the external domain** e poi cercare di sfruttarlo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio della foresta esterna - One-Way (Outbound)
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
In questo scenario **your domain** sta **trusting** alcuni **privileges** a principal provenienti da **different domains**.

Tuttavia, quando un **domain is trusted** dal dominio che confida, il dominio trusted **creates a user** con un **predictable name** che usa come **password the trusted password**. Questo significa che è possibile **access a user from the trusting domain to get inside the trusted one** per enumerarlo e provare a scalare ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il dominio trusted è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **opposite direction** del domain trust (cosa non molto comune).

Un altro modo per compromettere il dominio trusted è aspettare su una macchina dove un **user from the trusted domain can access** per accedere via **RDP**. Poi l'attaccante potrebbe injectare codice nel processo della **RDP session** e **access the origin domain of the victim** da lì.\
Inoltre, se la **victim mounted his hard drive**, dal processo della **RDP session** l'attaccante potrebbe salvare **backdoors** nella **startup folder of the hard drive**. Questa tecnica si chiama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazioni per l'abuso dei trust di dominio

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SID history attraverso forest trusts è mitigato da SID Filtering, che è attivato di default su tutti gli inter-forest trusts. Questo si basa sull'assunto che gli intra-forest trusts siano sicuri, considerando la forest, piuttosto che il domain, come confine di sicurezza secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID filtering può interrompere applicazioni e accessi utente, portando alla sua disattivazione occasionale.

### **Selective Authentication:**

- Per gli inter-forest trusts, l'uso di Selective Authentication assicura che gli utenti delle due forest non siano autenticati automaticamente. Invece, sono richieste permission esplicite per permettere agli utenti di accedere a domain e server all'interno del trusting domain o della forest.
- È importante notare che queste misure non proteggono contro lo sfruttamento del writable Configuration Naming Context (NC) né contro attacchi sull'account di trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementa primitive LDAP in stile bloodyAD come x64 Beacon Object Files che girano interamente all'interno di un on-host implant (es., Adaptix C2). Gli operatori compilano il pacchetto con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, caricano `ldap.axs`, e poi eseguono `ldap <subcommand>` dal beacon. Tutto il traffico scorre nel contesto di sicurezza del logon corrente su LDAP (389) con signing/sealing o LDAPS (636) con auto certificate trust, quindi non sono richiesti socks proxies o artefatti su disco.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, e `get-groupmembers` risolvono short names/OU paths in full DNs e dumpano gli oggetti corrispondenti.
- `get-object`, `get-attribute`, e `get-domaininfo` estraggono attributi arbitrari (inclusi security descriptors) più i metadati di forest/domain da `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, e `get-rbcd` espongono roasting candidates, delegation settings, e i descriptor di existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direttamente da LDAP.
- `get-acl` e `get-writable --detailed` parsano la DACL per elencare trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), e inheritance, fornendo obiettivi immediati per l'ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permettono all'operatore di predisporre nuovi principal o account macchina ovunque esistano diritti su OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` dirottano direttamente gli obiettivi una volta trovati i diritti di write-property.
- Comandi incentrati su ACL come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync` traducono WriteDACL/WriteOwner su qualsiasi oggetto AD in reset di password, controllo della membership di gruppi o privilegi di replicazione DCSync senza lasciare artefatti PowerShell/ADSI. I corrispettivi `remove-*` ripuliscono gli ACE iniettati.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` rendono immediatamente un utente compromesso Kerberoastable; `add-asreproastable` (toggle UAC) lo marca per AS-REP roasting senza toccare la password.
- Le macro di delega (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, i flag UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di PowerShell remoto o RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inietta SID privilegiati nella SID history di un principal controllato (vedi [SID-History Injection](sid-history-injection.md)), fornendo ereditarietà di accesso stealth completamente via LDAP/LDAPS.
- `move-object` cambia il DN/OU di computer o utenti, permettendo ad un attacker di spostare asset in OU dove esistono già diritti delegati prima di abusare di `set-password`, `add-groupmember` o `add-spn`.
- Comandi di rimozione strettamente mirati (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) permettono un rapido rollback dopo che l'operatore ha raccolto credenziali o persistenza, minimizzando la telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Si raccomanda che i Domain Admins possano effettuare il login solo sui Domain Controller, evitando il loro utilizzo su altri host.
- **Service Account Privileges**: I servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA) per mantenere la sicurezza.
- **Temporal Privilege Limitation**: Per attività che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- L'implementazione della deception comporta l'impostazione di trappole, come utenti o computer decoy, con caratteristiche quali password che non scadono o marcati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o l'aggiunta a gruppi ad alto privilegio.
- Un esempio pratico prevede l'uso di strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maggiori informazioni sul deploy di tecniche di deception si trovano su [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicatori sospetti includono ObjectSID atipico, logon poco frequenti, date di creazione e basso conteggio di bad password.
- **General Indicators**: Confrontare gli attributi di potenziali oggetti decoy con quelli di oggetti genuini può rivelare incongruenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare nell'identificazione di tali deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitare l'enumerazione di sessioni sui Domain Controller per prevenire il rilevamento da parte di ATA.
- **Ticket Impersonation**: Utilizzare chiavi **aes** per la creazione di ticket aiuta a evadere il rilevamento non effettuando il downgrade a NTLM.
- **DCSync Attacks**: Eseguire da un host non-Domain Controller per evitare il rilevamento da parte di ATA è consigliato, poiché l'esecuzione diretta da un Domain Controller genererà allarmi.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
