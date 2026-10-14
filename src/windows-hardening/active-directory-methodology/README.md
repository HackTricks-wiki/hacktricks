# Metodologia di Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Panoramica di base

**Active Directory** è una tecnologia fondamentale che consente agli **amministratori di rete** di creare e gestire in modo efficiente **domini**, **utenti** e **oggetti** all'interno di una rete. È progettata per scalare e permette di organizzare un gran numero di utenti in **gruppi** e **sottogruppi** gestibili, controllando i **diritti di accesso** a vari livelli.

La struttura di **Active Directory** è composta da tre livelli principali: **domini**, **alberi** e **foreste**. Un **dominio** comprende una raccolta di oggetti, come **utenti** o **dispositivi**, che condividono un database comune. Gli **alberi** sono gruppi di questi domini collegati da una struttura condivisa, mentre una **foresta** è l'insieme di più alberi interconnessi tramite **relazioni di trust**, che costituisce il livello più alto della struttura organizzativa. A ciascuno di questi livelli è possibile assegnare specifici **diritti di accesso** e di **comunicazione**.

I concetti chiave di **Active Directory** includono:

1. **Directory** – Contiene tutte le informazioni relative agli oggetti di Active Directory.
2. **Oggetto** – Indica le entità presenti nella directory, inclusi **utenti**, **gruppi** o **cartelle condivise**.
3. **Dominio** – Funge da contenitore per gli oggetti della directory; più domini possono coesistere in una **foresta**, mantenendo ciascuno la propria raccolta di oggetti.
4. **Albero** – Un gruppo di domini che condividono un dominio radice comune.
5. **Foresta** – Il livello più alto della struttura organizzativa di Active Directory, composto da diversi alberi con **relazioni di trust** tra loro.

**Active Directory Domain Services (AD DS)** comprende una serie di servizi fondamentali per la gestione centralizzata e la comunicazione all'interno di una rete. Questi servizi includono:

1. **Domain Services** – Centralizza l'archiviazione dei dati e gestisce le interazioni tra **utenti** e **domini**, incluse le funzionalità di **autenticazione** e **ricerca**.
2. **Certificate Services** – Gestisce la creazione, la distribuzione e la gestione di **certificati digitali** sicuri.
3. **Lightweight Directory Services** – Supporta le applicazioni abilitate per le directory tramite il **protocollo LDAP**.
4. **Directory Federation Services** – Fornisce funzionalità di **single sign-on** per autenticare gli utenti su più applicazioni web in un'unica sessione.
5. **Rights Management** – Contribuisce a proteggere il materiale coperto da copyright regolamentandone la distribuzione e l'uso non autorizzati.
6. **DNS Service** – Fondamentale per la risoluzione dei **nomi di dominio**.

Per una spiegazione più dettagliata, consulta: [**TechTerms - Definizione di Active Directory**](https://techterms.com/definition/active_directory)

### **Autenticazione Kerberos**

Per imparare ad **attaccare un AD**, è necessario **comprendere** molto bene il **processo di autenticazione Kerberos**.\
[**Leggi questa pagina se non sai ancora come funziona.**](kerberos-authentication.md)

## Cheat Sheet

Puoi consultare [https://wadcoms.github.io/](https://wadcoms.github.io) per una rapida panoramica dei comandi da eseguire per enumerare o sfruttare un AD.

> [!WARNING]
> La comunicazione Kerberos **richiede normalmente un fully qualified domain name (FQDN)** affinché il client possa ottenere un ticket per lo SPN corretto. Accedere a una macchina tramite indirizzo IP comporta spesso il fallback a NTLM anziché Kerberos.

## Ricognizione di Active Directory (senza credenziali/sessioni)

Se hai accesso a un ambiente AD ma non disponi di credenziali o sessioni, puoi:

- **Fare pentest della rete:**
  - Scansionare la rete, individuare le macchine e le porte aperte e provare a **sfruttare vulnerabilità** o **estrarre credenziali** da esse (ad esempio, [le stampanti possono essere obiettivi molto interessanti](ad-information-in-printers.md)).
  - Enumerare il DNS potrebbe fornire informazioni sui server chiave del dominio, come web server, stampanti, condivisioni, VPN, sistemi multimediali, ecc.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consulta la [**metodologia generale di pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) per maggiori informazioni su come farlo.
- **Verificare l'accesso null e Guest sui servizi SMB** (non funziona nelle versioni moderne di Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Qui trovi una guida più dettagliata su come enumerare un server SMB:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerare LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Qui trovi una guida più dettagliata su come enumerare LDAP (presta **particolare attenzione all'accesso anonimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Avvelenare la rete**
  - Raccogliere credenziali [**impersonando servizi con Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Accedere all'host [**abusando del relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Raccogliere credenziali **esponendo** [**servizi UPnP fasulli con evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Estrarre nomi utente e nomi propri da documenti interni, social media e servizi (principalmente web) presenti negli ambienti del dominio, nonché da fonti pubblicamente disponibili.
  - Se trovi i nomi completi dei dipendenti dell'azienda, puoi provare diverse **convenzioni per i nomi utente** di AD ([**leggi qui**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Le convenzioni più comuni sono: _NomeCognome_, _Nome.Cognome_, _NomCog_ (3 lettere per ciascuno), _Nom.Cog_, _NCognome_, _N.Cognome_, _CognomeNome_, _Cognome.Nome_, _CognomeN_, _Cognome.N_, 3 _lettere casuali e 3 numeri casuali_ (abc123).
  - Strumenti:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumerazione degli utenti

- **Enumerazione SMB/LDAP anonima:** consulta le pagine dedicate al [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e al [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumerazione con Kerbrute**: quando viene richiesto un **nome utente non valido**, il server risponde con il codice di errore Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, consentendoci di determinare che il nome utente non è valido. Per i **nomi utente validi**, la risposta conterrà il **TGT in un messaggio AS-REP** oppure l'errore _KRB5KDC_ERR_PREAUTH_REQUIRED_, che indica che l'utente deve eseguire la pre-autenticazione.
- **Nessuna autenticazione tramite MS-NRPC**: utilizzo di auth-level = 1 (nessuna autenticazione) sull'interfaccia MS-NRPC (Netlogon) dei domain controller. Dopo il binding all'interfaccia MS-NRPC, il metodo richiama la funzione `DsrGetDcNameEx2` per verificare se l'utente o il computer esiste senza credenziali. Lo strumento [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa questo tipo di enumerazione. La ricerca è disponibile [qui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Se hai trovato uno di questi server nella rete, puoi anche eseguire l'**enumerazione degli utenti**. Ad esempio, puoi usare lo strumento [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Puoi trovare elenchi di nomi utente in [**questo repo github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e in questo ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Tuttavia, dovresti avere **i nomi delle persone che lavorano nell'azienda** grazie alla fase di recon che avresti dovuto svolgere prima. Con nome e cognome, avresti potuto usare lo script [**namemash.py**](https://gist.github.com/superkojiman/11076951) per generare potenziali nomi utente validi.

### Abuso della allow-list dei canali vulnerabili di Netlogon (Onelogon)

Anche dopo aver applicato la patch a **Zerologon** sul DC, gli account esplicitamente inseriti nella allow-list possono essere ancora esposti al **comportamento legacy/vulnerabile del canale sicuro Netlogon**. La configurazione rischiosa è il GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** o il valore di registro corrispondente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Il valore è un **descrittore di sicurezza SDDL** (vedi [Descrittori di sicurezza](security-descriptors.md)). Qualsiasi account o gruppo a cui è concesso l'ACE pertinente nella DACL può essere preso di mira. Ad esempio, `O:BAG:BAD:(A;;RC;;;WD)` inserisce di fatto **Everyone** nella allow-list.

Flusso operativo pratico:

1. **Individua i principal inseriti nella allow-list** controllando sia **SYSVOL/GPO** sia il **registro attivo del DC**.
2. **Risolvi i SID** presenti nell'SDDL per identificare gli utenti/computer AD reali e assegna la priorità agli **account macchina dei DC**, agli **account di trust** e ad altri computer con privilegi.
3. Tenta ripetutamente l'**autenticazione MS-NRPC / Netlogon** usando l'account inserito nella allow-list.
4. Dopo aver indovinato correttamente la password, sfrutta l'**impostazione della password Netlogon** per reimpostare la password dell'account bersaglio (la PoC pubblica la imposta a una stringa vuota).<sup>[[9]](#references)[[10]](#references)</sup>

Esempi rapidi di triage / laboratorio tratti dall'artefatto pubblico:

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
- Il percorso dell’exploit è importante perché, una volta identificato un account vulnerabile, **non richiede privilegi di Domain Admin**.
- La compromissione di un **account computer di Domain Controller**, come `DC$`, è particolarmente pericolosa: il reset della password può abilitare direttamente percorsi più ampi di **AD takeover**.
- La fattibilità del **brute-force** dipende dalla modalità: l’artifact pubblico descrive un approccio meet-in-the-middle, un **brute-force a 24 bit** quando è disponibile un altro account computer e varianti più lente a **32 bit**.

Note su rilevamento e hardening:

- Verifica la policy dell’allow-list e rimuovi tutto ciò che non sia un’eccezione di compatibilità temporanea ed esplicitamente necessaria.
- Monitora gli eventi **5827/5828/5829/5830/5831** del **System** sui DC per individuare connessioni Netlogon vulnerabili negate, rilevate o esplicitamente consentite dalla policy.
- Considera gli account in `VulnerableChannelAllowList` **ad alto rischio** finché la dipendenza legacy non viene rimossa.

### Conoscere uno o più username

Bene, sai già di avere uno username valido, ma nessuna password... Prova:

- [**ASREPRoast**](asreproast.md): se un utente **non ha** l’attributo _DONT_REQ_PREAUTH_, puoi **richiedere un messaggio AS_REP** per quell’utente, che conterrà dati cifrati con una derivazione della password dell’utente.
- [**Password Spraying**](password-spraying.md): proviamo le **password più comuni** con ciascuno degli utenti individuati; magari qualcuno usa una password debole (tieni presente la password policy!).
  - Puoi anche eseguire **spray sui server OWA** per tentare di accedere ai mail server degli utenti.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Potresti riuscire a **ottenere** alcuni **hash** di challenge da crackare eseguendo **poisoning** di alcuni protocolli della **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

L’enumerazione di Active Directory fornisce username, identificativi email e schemi di denominazione, host candidati e servizi che potrebbero essere indotti ad autenticarsi. Usa queste informazioni per individuare possibili [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM e potenziali percorsi nell’ambiente AD.

### Ricognizione basata sui workspace di NetExec e controlli della postura di relay

- Usa i **workspace `nxcdb`** per mantenere lo stato della ricognizione AD per ogni engagement: `workspace create <name>` crea database SQLite per protocollo in `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Cambia vista con `proto smb|mssql|winrm` ed elenca i secret raccolti con `creds`. Al termine, elimina manualmente i dati sensibili: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Una rapida discovery della subnet con **`netexec smb <cidr>`** mostra **domain**, **OS build**, **requisiti di SMB signing** e **Null Auth**. I membri che mostrano `(signing:False)` sono **esposti al relay**, mentre spesso i DC richiedono il signing.
- Genera gli **hostname in /etc/hosts** direttamente dall’output di NetExec per semplificare il targeting:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Quando il **SMB relay verso il DC è bloccato** dalla firma, verifica comunque la configurazione di **LDAP**: `netexec ldap <dc>` evidenzia `(signing:None)` / channel binding debole. Un DC che richiede la firma SMB ma ha la firma LDAP disabilitata resta un target valido per **relay-to-LDAP** e abusi come **SPN-less RBCD**.

### Leak di credenziali lato client delle stampanti → convalida massiva delle credenziali di dominio

- Le interfacce web delle stampanti a volte **includono password admin mascherate nell’HTML**. Visualizzare il sorgente o usare gli strumenti per sviluppatori può rivelare il cleartext (ad es. `<input value="<password>">`), consentendo l’accesso tramite Basic-auth ai repository di scansioni/stampe.
- I lavori di stampa recuperati possono contenere **documenti di onboarding in plaintext** con password per utente. Mantieni gli abbinamenti corretti durante i test:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Rubare credenziali NTLM

Se puoi **accedere ad altri PC o share** con l'**utente null o guest**, potresti **posizionare file** (come un file SCF) che, se in qualche modo vengono aperti, **inneschino un'autenticazione NTLM verso di te**, così potrai **rubare** la **challenge NTLM** e tentare di decifrarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking e attacchi NT-Candidate

**Hash shucking** tratta ogni hash NT già in tuo possesso come una password candidata per altri formati più lenti, il cui materiale chiave deriva direttamente dall'hash NT. Invece di forzare passphrase lunghe nei ticket Kerberos RC4, nelle challenge NetNTLM o nelle credenziali memorizzate nella cache, fornisci gli hash NT alle modalità NT-candidate di Hashcat e lascia che verifichi il riutilizzo delle password senza mai rivelarne il testo in chiaro. È particolarmente efficace dopo la compromissione di un dominio, quando puoi raccogliere migliaia di hash NT attuali e storici.<sup>[[5]](#references)</sup>

Usa lo shucking quando:

- Hai un corpus di hash NT ottenuti tramite DCSync, dump SAM/SECURITY o vault di credenziali e devi verificare se vengono riutilizzati in altri domini/foreste.
- Acquisisci materiale Kerberos basato su RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), risposte NetNTLM o blob DCC/DCC2.
- Vuoi dimostrare rapidamente il riutilizzo di passphrase lunghe e impossibili da decifrare, per poi passare subito al Pass-the-Hash.

La tecnica **non funziona** contro i tipi di cifratura le cui chiavi non sono l'hash NT (ad esempio, Kerberos etype 17/18 AES). Se un dominio impone l'uso esclusivo di AES, devi tornare alle normali modalità per le password.

#### Creare un corpus di hash NT

- **DCSync/NTDS** – Usa `secretsdump.py` con la cronologia per acquisire il maggior numero possibile di hash NT (e dei relativi valori precedenti):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Le voci della cronologia ampliano notevolmente il pool di candidati, perché Microsoft può memorizzare fino a 24 hash precedenti per account. Per altri metodi per raccogliere i secret NTDS, vedi:

{{#ref}}
dcsync.md
{{#endref}}

- **Dump della cache degli endpoint** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (oppure Mimikatz `lsadump::sam /patch`) estrae i dati SAM/SECURITY locali e i logon di dominio memorizzati nella cache (DCC/DCC2). Rimuovi i duplicati e aggiungi questi hash allo stesso elenco `nt_candidates.txt`.
- **Tieni traccia dei metadati** – Conserva il nome utente/dominio da cui proviene ogni hash (anche se la wordlist contiene solo valori esadecimali). Quando Hashcat trova il candidato corretto, gli hash corrispondenti indicano subito quale principal riutilizza una password.
- Preferisci i candidati della stessa forest o di una forest attendibile: ciò massimizza la probabilità di trovare corrispondenze durante lo shucking.

#### Modalità NT-candidate di Hashcat

| Tipo di hash                              | Modalità password | Modalità NT-candidate |
| ------------------------------------------ | ------------- | ----------------- |
| Domain Cached Credentials (DCC)            | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)         | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                  | 5500          | 27000             |
| NetNTLMv2                                  | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth        | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast)   | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP                 | 18200         | 35400             |

Note:

- Gli input NT-candidate **devono rimanere hash NT grezzi di 32 caratteri esadecimali**. Disabilita i motori di regole (nessun `-r`, né modalità ibride), perché la manipolazione corrompe il materiale della chiave candidata.
- Queste modalità non sono intrinsecamente più veloci, ma lo spazio delle chiavi NTLM (~30.000 MH/s su un M3 Max) è ~100× più rapido di Kerberos RC4 (~300 MH/s). Testare un elenco NT selezionato costa molto meno che esplorare l’intero spazio delle password nel formato più lento.
- Usa sempre la **versione più recente di Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), perché le modalità 31500/31600/35300/35400 sono state introdotte di recente.<sup>[[7]](#references)</sup>
- Attualmente non esiste una modalità NT per AS-REQ Pre-Auth, e i tipi AES (19600/19700) richiedono la password in chiaro perché le relative chiavi vengono derivate con PBKDF2 da password UTF-16LE, non da hash NT grezzi.

#### Esempio – Kerberoast RC4 (modalità 35300)

1. Acquisisci un TGS RC4 per uno SPN di destinazione con un utente con privilegi limitati (vedi la pagina Kerberoast per i dettagli):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Esegui il ticket shucking con la tua lista NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat deriva la chiave RC4 da ogni candidato NT e convalida il blob `$krb5tgs$23$...`. Una corrispondenza conferma che l'account di servizio usa uno dei tuoi hash NT esistenti.

3. Esegui subito pivot tramite PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Se necessario, puoi recuperare in seguito il plaintext con `hashcat -m 1000 <matched_hash> wordlists/`.

#### Esempio – credenziali memorizzate nella cache (modalità 31600)

1. Estrai gli accessi memorizzati nella cache da una workstation compromessa:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Copia la riga DCC2 dell'utente di dominio interessante in `dcc2_highpriv.txt` ed esegui lo shucking:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Una corrispondenza riuscita restituisce l'hash NT già noto nel tuo elenco, dimostrando che l'utente memorizzato nella cache riutilizza una password. Usalo direttamente per PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) oppure esegui un brute-force in modalità NTLM rapida per recuperare la stringa.

Lo stesso workflow si applica alle challenge-response NetNTLM (`-m 27000/27100`) e a DCC (`-m 31500`). Una volta individuata una corrispondenza, puoi avviare relay, PtH tramite SMB/WMI/WinRM oppure ri-craccare l'hash NT offline con maschere/regole.



## Enumerazione di Active Directory CON credenziali/sessione

Per questa fase devi aver **compromesso le credenziali o una sessione di un account di dominio valido.** Se disponi di credenziali valide o di una shell come utente di dominio, **ricorda che le opzioni presentate in precedenza restano valide per compromettere altri utenti**.

Prima di iniziare l'enumerazione autenticata, comprendi il **problema del doppio hop Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumerazione

Compromettere un account è un **passo fondamentale per valutare il dominio**, perché consente l'**enumerazione autenticata di Active Directory**:

Per quanto riguarda [**ASREPRoast**](asreproast.md), ora puoi trovare tutti gli utenti potenzialmente vulnerabili; per quanto riguarda [**Password Spraying**](password-spraying.md), puoi ottenere un **elenco di tutti i nomi utente** e provare la password dell'account compromesso, password vuote e nuove password promettenti.

- Puoi usare [**CMD per eseguire una ricognizione di base**](../basic-cmd-for-pentesters.md#domain-info)
- Puoi anche usare [**PowerShell per la ricognizione**](../basic-powershell-for-pentesters/index.html), che sarà più stealthy
- Puoi anche [**usare powerview**](../basic-powershell-for-pentesters/powerview.md) per estrarre informazioni più dettagliate
- Un altro strumento straordinario per la ricognizione in Active Directory è [**BloodHound**](bloodhound.md). **Non è molto stealthy** (a seconda dei metodi di raccolta usati), ma **se non ti interessa**, dovresti assolutamente provarlo. Individua dove gli utenti possono usare RDP, trova percorsi verso altri gruppi, ecc.
  - **Altri strumenti automatizzati per l'enumerazione AD sono:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**I record DNS di AD**](ad-dns-records.md), poiché potrebbero contenere informazioni interessanti.
- Uno **strumento con GUI** che puoi usare per enumerare la directory è **AdExplorer.exe** della suite **SysInternal**.
- Puoi anche cercare nel database LDAP con **ldapsearch** per individuare credenziali nei campi _userPassword_ e _unixUserPassword_, o anche nelle note _description_ e _info_ dell'utente. Un token dall'aspetto di password non etichettato in _info_ è solo un candidato: verificane separatamente lo scopo e la validità e non includere il contenuto delle note nei normali output di enumerazione. Consulta [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) per altri metodi.
- Esamina gli script **accessibili** di accesso al dominio e di mappatura delle unità sotto `\\<dc>\NETLOGON` o `\\<dc>\SYSVOL\<domain>\scripts`, quando l'autorizzazione lo consente. [La documentazione Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) descrive il ruolo della directory degli script nella condivisione NETLOGON. Elenca prima i nomi, poi esamina solo gli script pertinenti e leggibili, entro un limite di dimensione; non scaricare l'intera condivisione né mostrare valori di credenziali durante la normale enumerazione. Una chiamata PowerShell a [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **non** protegge una password letterale memorizzata nello script. La chiamata, da sola, non dimostra che un segreto sia hardcoded: risali al suo input effettivo, poi verifica separatamente l'account, la validità delle credenziali e i privilegi. L'esame di uno script di dominio in una condivisione remota è distinto dall'enumerazione dell'host locale.
- Se usi **Linux**, puoi anche enumerare il dominio con [**pywerview**](https://github.com/the-useless-one/pywerview).
- Puoi anche provare strumenti automatizzati come:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Estrazione di tutti gli utenti del dominio**

  È molto facile ottenere tutti i nomi utente del dominio da Windows (`net user /domain` ,`Get-DomainUser` o `wmic useraccount get name,sid`). In Linux, puoi usare: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oppure `enum4linux -a -u "user" -p "password" <DC IP>`

> Anche se questa sezione sull'enumerazione sembra breve, è la parte più importante di tutte. Apri i link (soprattutto quelli su cmd, powershell, powerview e BloodHound), impara a enumerare un dominio e fai pratica finché non ti senti a tuo agio. Durante un assessment, questo sarà il momento cruciale per trovare il percorso verso DA o decidere che non è possibile fare nulla.

### Account computer precreati con password prevedibili -> accesso alla password gMSA

Gli account computer predisposti per le aggiunte legacy possono mantenere una password iniziale prevedibile. Il modulo `pre2k` di NetExec individua il valore caratteristico `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) e prova a ottenere un TGT Kerberos usando i primi 14 caratteri del nome computer in minuscolo, senza il `$` finale. Considera questo valore UAC un criterio per selezionare i candidati, senza presumere che la sola appartenenza a **Pre-Windows 2000 Compatible Access** dimostri che la password sia debole.<sup>[[18]](#references)[[20]](#references)</sup>

Usa l'enumerazione LDAP autenticata per verificare i candidati e salvare i TGT ottenuti. `ALL=True` estende i test anche agli oggetti che non corrispondono al filtro predefinito `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Un bind default/NTLM non riuscito **non** invalida questo finding: esegui il test con `-k`, un FQDN che si risolva nel DC e un orologio sincronizzato con il KDC. Le esecuzioni riuscite del modulo scrivono gli elenchi dei candidati e i ccache acquisiti in `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Dopo aver compromesso il principal del computer, esamina le sue appartenenze ai gruppi annidati e i diritti in uscita. In particolare, i principal indicati nel descrittore di sicurezza `msDS-GroupMSAMembership` di un gMSA possono leggere `msDS-ManagedPassword`; l'output `--gmsa` di NetExec mostra i principal autorizzati e restituisce l'hash NT corrente se il computer che esegue l'autenticazione è autorizzato.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Quindi valuta la gMSA recuperata come qualsiasi altra credenziale: esamina l'appartenenza ai gruppi locali/di dominio, i diritti di accesso, gli SPN, la delega e i servizi raggiungibili prima di tentare il pass-the-hash. Questo percorso di recupero basato su ACL è distinto da [Golden gMSA/dMSA](golden-dmsa-gmsa.md), che ricava le password gestite dopo la compromissione della KDS root key.<sup>[[20]](#references)</sup>

Un principal computer potrebbe anche avere controllo in uscita su altri oggetti computer o gruppi. Dopo averne ottenuto uno, esamina separatamente le sue appartenenze annidate e le ACL effettive: un diritto di scrittura su un altro oggetto computer potrebbe consentire una modifica dell'account, mentre i diritti di appartenenza a un gruppo potrebbero portare a un ruolo di accesso. Un flag di account predisposto, una convenzione di denominazione prevedibile o una singola relazione `GenericWrite` non dimostrano da soli l'intero percorso.

Una copia leggibile di un blob `msDS-ManagedPassword` in un file, una condivisione o un backup costituisce un percorso di esposizione distinto: l'ACL di lettura LDAP non può proteggere una copia archiviata altrove. Verifica che i dati siano un blob di password gestita prima di interpretarli e distingui questo caso sia da una lettura LDAP autorizzata sia dalla derivazione tramite KDS root key.

### Kerberoast

Il Kerberoasting consiste nell'ottenere **ticket TGS** usati dai servizi associati ad account utente e nel crackarne la cifratura, basata sulle password degli utenti, **offline**.

Maggiori informazioni:

{{#ref}}
kerberoast.md
{{#endref}}

### Connessione remota (RDP, SSH, FTP, Win-RM, ecc.)

Una volta ottenute alcune credenziali, puoi verificare se hai accesso a una **macchina**. A tal fine, puoi usare **CrackMapExec** per tentare la connessione a diversi server tramite protocolli differenti, in base alle scansioni delle porte.

### Escalation dei privilegi locali

Se hai compromesso delle credenziali o una sessione come utente di dominio standard e puoi accedere a **qualsiasi macchina del dominio**, cerca un percorso per **escalare i privilegi localmente e raccogliere credenziali**. I privilegi di amministratore locale potrebbero consentirti di **estrarre gli hash di altri utenti** dalla memoria (LSASS) e dall'archiviazione locale (SAM).

In questo libro è presente una pagina completa sull'[**escalation dei privilegi locali in Windows**](../windows-local-privilege-escalation/index.html) e una [**checklist**](../checklist-windows-privilege-escalation.md). Inoltre, non dimenticare di usare [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Ticket della sessione corrente

È **molto improbabile** trovare **ticket** dell'utente corrente che **concedano l'autorizzazione ad accedere** a risorse inaspettate, ma puoi controllare:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Con credenziali di dominio o una sessione utente, riprendi in esame gli [**attacchi relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: le tecniche di enumerazione autenticata e coercizione possono rivelare percorsi relay non disponibili durante la ricognizione non autenticata.

### Ricerca di Creds nelle condivisioni dei computer | Condivisioni SMB

Ora che disponi di alcune credenziali di base, dovresti verificare se riesci a **trovare** file **interessanti condivisi nell'AD**. Puoi farlo manualmente, ma è un'attività molto noiosa e ripetitiva (soprattutto se trovi centinaia di documenti da controllare).

[**Segui questo link per scoprire quali strumenti puoi usare.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Rubare Creds NTLM

Se riesci ad **accedere ad altri PC o condivisioni**, puoi **posizionare file** (come un file SCF) che, se aperti in qualche modo, **attiveranno un'autenticazione NTLM verso di te**, permettendoti di **rubare** la **NTLM challenge** per decifrarla:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Questa vulnerabilità consentiva a qualsiasi utente autenticato di **compromettere il controller di dominio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalation dei privilegi in Active Directory CON credenziali/sessione privilegiate

**Per le tecniche seguenti non basta un normale utente di dominio: servono privilegi o credenziali speciali per eseguire questi attacchi.**

### Estrazione degli hash

Si spera che tu sia riuscito a **compromettere un account local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), anche tramite relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalation dei privilegi in locale](../windows-local-privilege-escalation/index.html).\
A questo punto, è il momento di estrarre tutti gli hash dalla memoria e dal sistema locale.\
[**Leggi questa pagina per scoprire i diversi metodi per ottenere gli hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Una volta ottenuto l'hash di un utente**, puoi usarlo per **impersonarlo**.\
Devi usare uno **strumento** che **esegua** l'**autenticazione NTLM usando** quell'**hash**, **oppure** puoi creare un nuovo **sessionlogon** e **iniettare** quell'**hash** in **LSASS**, così che venga usato quando viene eseguita un'autenticazione **NTLM**. È ciò che fa mimikatz con la seconda opzione.\
[**Leggi questa pagina per ulteriori informazioni.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Questo attacco mira a **usare l'hash NTLM dell'utente per richiedere ticket Kerberos**, come alternativa al comune Pass The Hash tramite il protocollo NTLM. Può quindi essere particolarmente **utile nelle reti in cui il protocollo NTLM è disabilitato** e come protocollo di autenticazione è consentito solo **Kerberos**.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Nel metodo di attacco **Pass The Ticket (PTT)**, gli aggressori **rubano il ticket di autenticazione di un utente** invece della sua password o dei suoi hash. Il ticket rubato viene quindi usato per **impersonare l'utente**, ottenendo accesso non autorizzato a risorse e servizi della rete.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Riutilizzo delle credenziali

Se disponi dell'**hash** o della **password** di un **amministratore locale**, dovresti provare ad **accedere localmente** ad altri **PC** usando quelle credenziali.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Nota che questo è piuttosto **rumoroso** e **LAPS** lo **mitigherebbe**.

### Abuso di MSSQL e Trusted Links

Se un utente dispone dei privilegi per **accedere alle istanze MSSQL**, potrebbe essere in grado di **eseguire comandi** sull'host MSSQL (se in esecuzione come SA), **rubare** l'**hash** NetNTLM o persino eseguire un **relay attack**.\
Se un'istanza MSSQL è considerata attendibile tramite un database link da un'altra istanza, un utente con privilegi sul database collegato potrebbe essere in grado di **usare la relazione di trust per eseguire query sull'altra istanza**. Queste relazioni di trust possono essere concatenate e potrebbero infine raggiungere un database configurato in modo errato, nel quale l'utente può eseguire comandi.\
**I link tra database funzionano anche attraverso i trust tra foreste.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso delle piattaforme di inventario e deployment IT

Le suite di inventario e deployment di terze parti espongono spesso potenti percorsi per ottenere credenziali ed eseguire codice. Vedi:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se trovi un oggetto Computer con l'attributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e disponi di privilegi di dominio sul computer, potrai estrarre dalla memoria i TGT di tutti gli utenti che vi accedono.\
Quindi, se un **Domain Admin accede al computer**, potrai estrarne il TGT e impersonarlo usando [Pass the Ticket](pass-the-ticket.md).\
Grazie alla constrained delegation, potresti persino **compromettere automaticamente un Print Server** (si spera che sia un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se un utente o un computer è autorizzato per la "Constrained Delegation", potrà **impersonare qualsiasi utente per accedere ad alcuni servizi su un computer**.\
Quindi, se **comprometti l'hash** di questo utente/computer, potrai **impersonare qualsiasi utente** (anche i domain admin) per accedere ad alcuni servizi.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

Il privilegio **WRITE** su un oggetto Active Directory di un computer remoto consente di ottenere l'esecuzione di codice con **privilegi elevati**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso di permessi/ACL

L'utente compromesso potrebbe avere **privilegi interessanti su alcuni oggetti di dominio** che potrebbero consentirti di spostarti lateralmente/**escalare** i privilegi.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso del servizio Printer Spooler

La scoperta di un **servizio Spool in ascolto** nel dominio può essere **sfruttata** per **ottenere nuove credenziali** ed **escalare i privilegi**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso delle sessioni di terze parti

Se **altri utenti** **accedono** alla macchina **compromessa**, è possibile **raccogliere credenziali dalla memoria** e persino **iniettare beacon nei loro processi** per impersonarli.\
Di solito gli utenti accedono al sistema tramite RDP; ecco quindi come eseguire un paio di attacchi sulle sessioni RDP di terze parti:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornisce un sistema per gestire la **password dell'Administrator locale** sui computer aggiunti al dominio, garantendo che sia **randomizzata**, univoca e **modificata** frequentemente. Queste password sono archiviate in Active Directory e l'accesso è controllato tramite ACL, limitandolo agli utenti autorizzati. Con autorizzazioni sufficienti per accedere a queste password, è possibile spostarsi su altri computer.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Raccogliere certificati** dalla macchina compromessa potrebbe essere un modo per escalare i privilegi nell'ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso dei Certificate Templates

Se sono configurati **template vulnerabili**, è possibile sfruttarli per escalare i privilegi:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation con un account con privilegi elevati

### Dump delle credenziali di dominio

Una volta ottenuti i privilegi di **Domain Admin** o, meglio ancora, di **Enterprise Admin**, puoi eseguire il **dump** del **database di dominio**: _ntds.dit_.

[**Puoi trovare qui altre informazioni sull'attacco DCSync**](dcsync.md).

[**Puoi trovare qui altre informazioni su come rubare NTDS.dit**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Un archivio di backup leggibile contenente `ntds.dit` insieme all'hive `SYSTEM` deve essere considerato materiale di directory esposto, anche prima dell'estrazione. Un hash di password obsoleto non rende sicuri gli altri attributi degli oggetti: campi come `description` potrebbero contenere credenziali o note operative. Esamina prima i nomi dei membri dell'archivio e non includere i contenuti estratti del database nei normali output di enumerazione.

### Privesc come Persistence

Alcune delle tecniche descritte in precedenza possono essere usate per la persistence.\
Per esempio, potresti:

- Rendere gli utenti vulnerabili a [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Rendere gli utenti vulnerabili a [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Concedere privilegi [**DCSync**](#dcsync) a un utente.

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

L'**attacco Silver Ticket** crea un **Ticket Granting Service (TGS) ticket legittimo** per un servizio specifico utilizzando l'**hash NTLM** (ad esempio, l'**hash dell'account del PC**). Questo metodo viene usato per **accedere ai privilegi del servizio**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Un **attacco Golden Ticket** consiste nell'ottenere l'accesso all'**hash NTLM dell'account krbtgt** in un ambiente Active Directory (AD). Questo account è speciale perché viene usato per firmare tutti i **Ticket Granting Ticket (TGT)**, essenziali per l'autenticazione nella rete AD.

Una volta ottenuto questo hash, l'attaccante può creare **TGT** per qualsiasi account scelga (attacco Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Sono simili ai Golden Ticket, ma contraffatti in modo da **eludere i comuni meccanismi di rilevamento dei Golden Ticket**.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistenza dell'account tramite certificati**

**Avere i certificati di un account o poterli richiedere** è un ottimo modo per mantenere la persistenza nell'account di un utente (anche se cambia la password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistenza nel dominio tramite certificati**

**È possibile usare i certificati anche per mantenere la persistenza con privilegi elevati all'interno del dominio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Gruppo AdminSDHolder

L'oggetto **AdminSDHolder** in Active Directory protegge i **gruppi con privilegi** (come Domain Admins ed Enterprise Admins) applicando a questi gruppi un **Access Control List (ACL)** standard, per impedire modifiche non autorizzate. Questa funzionalità può però essere sfruttata: se un attaccante modifica l'ACL di AdminSDHolder per concedere accesso completo a un utente normale, quest'ultimo ottiene un ampio controllo su tutti i gruppi con privilegi. Questa misura di sicurezza, pensata per proteggere, può quindi rivelarsi controproducente e consentire accessi non autorizzati se non viene monitorata attentamente.

[**Maggiori informazioni sul gruppo AdminDSHolder qui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenziali DSRM

In ogni **Domain Controller (DC)** esiste un account **amministratore locale**. Ottenendo i diritti di amministratore su una macchina di questo tipo, è possibile estrarre l'hash dell'amministratore locale usando **mimikatz**. In seguito, è necessario modificare il registro per **abilitare l'uso di questa password**, consentendo l'accesso remoto all'account Amministratore locale.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistenza tramite ACL

È possibile **concedere** a un **utente** alcune **autorizzazioni speciali** su specifici oggetti del dominio, in modo che possa **escalare i privilegi in futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descrittori di sicurezza

I **descrittori di sicurezza** vengono usati per **memorizzare** le **autorizzazioni** che un **oggetto** ha **su** un altro **oggetto**. È sufficiente apportare una **piccola modifica** al **descrittore di sicurezza** di un oggetto per ottenere privilegi molto interessanti su di esso, senza dover appartenere a un gruppo con privilegi.


{{#ref}}
security-descriptors.md
{{#endref}}

### Oggetti dinamici: anti-forensics / evasione

Sfrutta la classe ausiliaria `dynamicObject` per creare principal/GPO/record DNS di breve durata con `entryTTL`/`msDS-Entry-Time-To-Die`; questi vengono eliminati automaticamente senza tombstone, cancellando le prove LDAP e lasciando SID orfani, riferimenti `gPLink` non validi o risposte DNS memorizzate nella cache (ad esempio, inquinamento degli ACE di AdminSDHolder o reindirizzamenti DNS integrati in AD tramite `gPCFileSysPath` malevolo).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifica **LSASS** in memoria per impostare una **password universale**, consentendo l'accesso a tutti gli account del dominio.


{{#ref}}
skeleton-key.md
{{#endref}}

### SSP personalizzato

[Scopri qui cos'è un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puoi creare un **SSP personalizzato** per **catturare** in **chiaro** le **credenziali** usate per accedere alla macchina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra un **nuovo Domain Controller** nell'AD e lo usa per **inviare attributi** (SIDHistory, SPN...) a oggetti specifici **senza** lasciare **log** relativi alle **modifiche**. Sono necessari i privilegi **DA** e bisogna trovarsi all'interno del **dominio root**.\
Nota: se usi dati non corretti, verranno generati log piuttosto brutti.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistenza tramite LAPS

In precedenza abbiamo visto come escalare i privilegi se si dispone di **autorizzazioni sufficienti per leggere le password LAPS**. Queste password possono però essere usate anche per **mantenere la persistenza**.\
Consulta:


{{#ref}}
laps.md
{{#endref}}

## Escalation dei privilegi nella forest - Trust di dominio

Microsoft considera la **forest** il perimetro di sicurezza. Ciò implica che **compromettere un singolo dominio potrebbe potenzialmente portare alla compromissione dell'intera forest**.<sup>[[1]](#references)</sup>

### Informazioni di base

Un [**trust di dominio**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) è un meccanismo di sicurezza che consente a un utente di un **dominio** di accedere alle risorse di un altro **dominio**. Crea essenzialmente un collegamento tra i sistemi di autenticazione dei due domini, consentendo alle verifiche di autenticazione di avvenire senza interruzioni. Quando i domini stabiliscono un trust, scambiano e conservano **chiavi** specifiche nei rispettivi **Domain Controller (DC)**, essenziali per l'integrità del trust.

In uno scenario tipico, se un utente vuole accedere a un servizio in un **dominio trusted**, deve prima richiedere un ticket speciale, detto **inter-realm TGT**, al DC del proprio dominio. Questo TGT è cifrato con una **chiave** condivisa concordata da entrambi i domini. L'utente presenta quindi il TGT al **DC del dominio trusted** per ottenere un service ticket (**TGS**). Dopo aver convalidato l'inter-realm TGT, il DC del dominio trusted rilascia un TGS che consente all'utente di accedere al servizio.

**Passaggi**:

1. Un **computer client** nel **Dominio 1** avvia il processo usando il proprio **hash NTLM** per richiedere un **Ticket Granting Ticket (TGT)** al proprio **Domain Controller (DC1)**.
2. Se l'autenticazione del client va a buon fine, DC1 rilascia un nuovo TGT.
3. Il client richiede quindi a DC1 un **inter-realm TGT**, necessario per accedere alle risorse del **Dominio 2**.
4. L'inter-realm TGT è cifrato con una **trust key** condivisa tra DC1 e DC2 nell'ambito del trust bidirezionale tra i due domini.
5. Il client porta l'inter-realm TGT al **Domain Controller del Dominio 2 (DC2)**.
6. DC2 verifica l'inter-realm TGT usando la trust key condivisa e, se è valido, rilascia un **Ticket Granting Service (TGS)** per il server del Dominio 2 a cui il client vuole accedere.
7. Infine, il client presenta questo TGS al server, cifrato con l'hash dell'account del server, per accedere al servizio nel Dominio 2.

### Tipi di trust

È importante notare che **un trust può essere unidirezionale o bidirezionale**. Nel caso bidirezionale, entrambi i domini si considerano trusted; nel caso **unidirezionale**, uno dei domini è **trusted** e l'altro è **trusting**. In quest'ultimo caso, **sarà possibile accedere alle risorse del dominio trusting solo dal dominio trusted**.

Se il Dominio A si fida del Dominio B, A è il dominio trusting e B è quello trusted. Inoltre, nel **Dominio A** si tratta di un **trust outbound**; nel **Dominio B**, di un **trust inbound**.

**Diversi rapporti di trust**

- **Trust Parent-Child**: configurazione comune all'interno della stessa forest, in cui un dominio child ha automaticamente un trust transitivo bidirezionale con il proprio dominio parent. In sostanza, le richieste di autenticazione possono passare senza interruzioni tra parent e child.
- **Trust cross-link**: detti anche "trust shortcut", vengono stabiliti tra domini child per velocizzare i processi di referral. Nelle forest complesse, i referral di autenticazione devono in genere risalire fino alla root della forest e poi scendere al dominio di destinazione. Creando cross-link si accorcia il percorso, con vantaggi soprattutto negli ambienti geograficamente distribuiti.
- **Trust external**: vengono configurati tra domini diversi e non correlati e sono per natura non transitivi. Secondo la [documentazione Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), i trust external sono utili per accedere a risorse in un dominio esterno alla forest corrente che non è collegato tramite un trust di forest. I trust external rafforzano la sicurezza tramite il filtraggio dei SID.
- **Trust tree-root**: vengono stabiliti automaticamente tra il dominio root della forest e una nuova tree root aggiunta. Anche se non sono comuni, i trust tree-root sono importanti per aggiungere nuove strutture di domini a una forest, consentendo loro di mantenere un nome di dominio univoco e garantendo la transitività bidirezionale. Ulteriori informazioni sono disponibili nella [guida Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Trust di forest**: trust transitivo bidirezionale tra due domini root di forest; applicano inoltre il filtraggio dei SID per rafforzare la sicurezza.
- **Trust MIT**: vengono stabiliti con domini Kerberos non Windows [conformi a RFC4120](https://tools.ietf.org/html/rfc4120). Sono più specifici e adatti agli ambienti che richiedono l'integrazione con sistemi basati su Kerberos esterni all'ecosistema Windows.

#### Altre differenze nei **rapporti di trust**

- Un rapporto di trust può anche essere **transitivo** (A si fida di B, B si fida di C, quindi A si fida di C) oppure **non transitivo**.
- Un rapporto di trust può essere configurato come **bidirezionale** (entrambi i domini si fidano l'uno dell'altro) oppure **unidirezionale** (solo uno dei due si fida dell'altro).

### Percorso di attacco

1. **Enumera** i rapporti di trust
2. Verifica se qualche **security principal** (utente/gruppo/computer) ha **accesso** alle risorse dell'**altro dominio**, magari tramite voci ACE o perché appartiene a gruppi dell'altro dominio. Cerca **rapporti tra domini** (probabilmente il trust è stato creato proprio per questo).
   1. In questo caso, kerberoast potrebbe essere un'altra opzione.
3. **Comprometti** gli **account** che possono fare **pivot** tra i domini.

Gli attaccanti possono accedere alle risorse di un altro dominio tramite tre meccanismi principali:

- **Appartenenza a gruppi locali**: i principal possono essere aggiunti a gruppi locali sulle macchine, come il gruppo “Administrators” di un server, ottenendo un controllo significativo su quella macchina.
- **Appartenenza a gruppi di un dominio esterno**: i principal possono anche appartenere a gruppi del dominio esterno. L'efficacia di questo metodo dipende però dalla natura del trust e dall'ambito del gruppo.
- **Access Control List (ACL)**: i principal possono essere specificati in una **ACL**, in particolare come entità in **ACE** all'interno di una **DACL**, ottenendo così l'accesso a risorse specifiche. Per approfondire il funzionamento di ACL, DACL e ACE, il whitepaper intitolato “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” è una risorsa preziosa.<sup>[[17]](#references)</sup>

### Individuare utenti/gruppi esterni con autorizzazioni

Puoi controllare **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** per trovare i security principal esterni nel dominio. Si tratta di utenti/gruppi di **un dominio/una forest esterni**.

Puoi controllare questa informazione in **Bloodhound** o usando powerview:

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

Altri modi per enumerare le trust di dominio:

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
> Puoi ottenere quella utilizzata dal dominio corrente con:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Esegui l'escalation a Enterprise admin nel child/parent domain abusando della trust con SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Sfruttare Configuration NC scrivibile

È fondamentale comprendere come sfruttare il Configuration Naming Context (NC). In ambienti Active Directory (AD), il Configuration NC funge da repository centrale per i dati di configurazione dell'intera forest. Questi dati vengono replicati su ogni Domain Controller (DC) della forest, e i DC scrivibili mantengono una copia scrivibile del Configuration NC. Per sfruttarlo, è necessario disporre di privilegi **SYSTEM su un DC**, preferibilmente un child DC.

**Collegare una GPO al sito del root DC**

Il container Sites del Configuration NC include informazioni sui siti di tutti i computer aggiunti al dominio nella forest AD. Operando con privilegi SYSTEM su qualsiasi DC, gli attaccanti possono collegare GPO ai siti del root DC. Questa azione può compromettere il root domain manipolando le policy applicate a questi siti.

Per informazioni approfondite, è possibile consultare la ricerca su [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromettere qualsiasi gMSA nella forest**

Un vettore di attacco consiste nel prendere di mira le gMSA privilegiate nel dominio. La KDS Root key, essenziale per calcolare le password delle gMSA, è archiviata nel Configuration NC. Con privilegi SYSTEM su qualsiasi DC, è possibile accedere alla KDS Root key e calcolare le password di qualsiasi gMSA nella forest.

Un'analisi dettagliata e una guida passo passo sono disponibili in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attacco MSA delegato complementare (BadSuccessor – abuso degli attributi di migrazione):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Ulteriori ricerche esterne: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Attacco tramite modifica dello Schema**

Questo metodo richiede pazienza, in attesa che vengano creati nuovi oggetti AD privilegiati. Con privilegi SYSTEM, un attaccante può modificare l'AD Schema per concedere a qualsiasi utente il controllo completo su tutte le classi. Ciò potrebbe consentire accesso non autorizzato e controllo sui nuovi oggetti AD creati.

Per ulteriori informazioni, consultare [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**Da DA a EA con ADCS ESC5**

La vulnerabilità ADCS ESC5 prende di mira il controllo degli oggetti Public Key Infrastructure (PKI) per creare un certificate template che consenta di autenticarsi come qualsiasi utente nella forest. Poiché gli oggetti PKI risiedono nel Configuration NC, compromettere un child DC scrivibile consente di eseguire attacchi ESC5.

Per ulteriori dettagli, consultare [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Negli scenari senza ADCS, l'attaccante può configurare i componenti necessari, come descritto in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Dominio esterno della forest - unidirezionale (in ingresso) o bidirezionale

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

In questo scenario, **il tuo dominio è considerato attendibile** da un dominio esterno, che ti concede **permessi non determinati** su di esso. Dovrai individuare **quali principal del tuo dominio hanno accesso al dominio esterno e con quali permessi**, quindi provare a sfruttare tali accessi:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Dominio di foresta esterna - unidirezionale (in uscita)

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

In questo scenario, **il tuo dominio** sta **concedendo fiducia** ad alcuni **privilegi** per un principal di **domini diversi**.

Tuttavia, quando un **dominio viene considerato trusted** dal dominio trusting, il dominio trusted **crea un utente** con un **nome prevedibile** che usa come **password la password del dominio trusted**. Ciò significa che è possibile **accedere a un utente del dominio trusting per entrare in quello trusted**, enumerarlo e provare a ottenere altri privilegi:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Un altro modo per compromettere il dominio trusted consiste nel trovare un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) creato nella **direzione opposta** rispetto alla trust tra i domini (cosa non molto comune).

Un altro modo per compromettere il dominio trusted è attendere su una macchina a cui **può accedere un utente del dominio trusted** per effettuare il login tramite **RDP**. L'attaccante potrebbe quindi iniettare codice nel processo della sessione RDP e **accedere da lì al dominio di origine della vittima**.\
Inoltre, se la **vittima ha montato il proprio hard disk**, l'attaccante potrebbe usare il processo della **sessione RDP** per salvare **backdoor** nella **cartella di avvio dell'hard disk**. Questa tecnica è chiamata **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigazione degli abusi delle trust di dominio

### **SID Filtering:**

- Il rischio di attacchi che sfruttano l'attributo SID history attraverso le trust tra forest viene mitigato da SID Filtering, attivato per impostazione predefinita su tutte le trust tra forest. Ciò si basa sull'ipotesi che le trust all'interno di una forest siano sicure, considerando la forest, anziché il dominio, come confine di sicurezza, secondo la posizione di Microsoft.
- Tuttavia, c'è un problema: SID filtering può compromettere applicazioni e accesso degli utenti, portando talvolta alla sua disattivazione.

### **Selective Authentication:**

- Per le trust tra forest, l'uso di Selective Authentication garantisce che gli utenti delle due forest non vengano autenticati automaticamente. Sono invece necessarie autorizzazioni esplicite affinché gli utenti possano accedere ai domini e ai server all'interno del dominio o della forest trusting.
- È importante notare che queste misure non proteggono dallo sfruttamento del writable Configuration Naming Context (NC) né dagli attacchi all'account della trust.

[**Ulteriori informazioni sulle trust di dominio su ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abusi di AD basati su LDAP da implant sugli host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa le primitive LDAP in stile bloodyAD come Beacon Object File x64, eseguiti interamente all'interno di un implant sull'host (ad es., Adaptix C2). Gli operatori compilano il pacchetto con `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, caricano `ldap.axs` e poi eseguono `ldap <subcommand>` dal beacon. Tutto il traffico usa il contesto di sicurezza dell'utente attualmente connesso tramite LDAP (389) con signing/sealing o LDAPS (636) con attendibilità automatica dei certificati, quindi non sono necessari proxy socks né artefatti su disco.<sup>[[4]](#references)</sup>

### Enumerazione LDAP dal lato dell'implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` e `get-groupmembers` risolvono i nomi brevi e i percorsi OU in DN completi e scaricano gli oggetti corrispondenti.
- `get-object`, `get-attribute` e `get-domaininfo` recuperano attributi arbitrari (inclusi i security descriptor) e i metadati della forest/del dominio da `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` e `get-rbcd` espongono direttamente da LDAP i candidati al roasting, le impostazioni di delega e i descrittori [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) esistenti.
- `get-acl` e `get-writable --detailed` analizzano la DACL per elencare trustee, diritti (GenericAll/WriteDACL/WriteOwner/scrittura di attributi) ed ereditarietà, fornendo obiettivi immediati per l'escalation dei privilegi tramite ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitive di scrittura LDAP per escalation e persistence

- I BOF per la creazione di oggetti (`add-user`, `add-computer`, `add-group`, `add-ou`) consentono all’operatore di predisporre nuovi principal o account computer ovunque disponga di diritti sull’OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` consentono di dirottare direttamente i target quando vengono individuati diritti di scrittura sulle proprietà.
- Comandi incentrati sulle ACL, come `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync`, trasformano i diritti WriteDACL/WriteOwner su qualsiasi oggetto AD in reimpostazioni delle password, controllo dell’appartenenza ai gruppi o privilegi di replica DCSync, senza lasciare tracce di PowerShell/ADSI. I comandi `remove-*` corrispondenti ripuliscono le ACE inserite.

### Delegation, roasting e abuso di Kerberos

- `add-spn`/`set-spn` rendono subito un utente compromesso vulnerabile a Kerberoasting; `add-asreproastable` (modifica di UAC) lo marca per AS-REP roasting senza toccarne la password.
- Le macro di delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) riscrivono `msDS-AllowedToDelegateTo`, i flag UAC o `msDS-AllowedToActOnBehalfOfOtherIdentity` dal beacon, abilitando percorsi di attacco constrained/unconstrained/RBCD ed eliminando la necessità di usare PowerShell remoto o RSAT.

### Iniezione di sidHistory, spostamento di OU e modellazione della superficie di attacco

- `add-sidhistory` inserisce SID privilegiati nella cronologia SID di un principal controllato (vedi [Iniezione di SID-History](sid-history-injection.md)), consentendo di ereditare accessi in modo furtivo interamente tramite LDAP/LDAPS.
- `move-object` modifica il DN/OU di computer o utenti, consentendo all’attaccante di portare gli asset sotto diritti delegati prima di usare `set-password`, `add-groupmember` o `add-spn`. Vedi [Spostamento di OU e diritti ereditati](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) per le autorizzazioni di spostamento e le verifiche di ereditarietà.
- Comandi di rimozione mirati (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` ecc.) permettono un rapido rollback dopo che l’operatore ha raccolto credenziali o ottenuto persistence, riducendo al minimo la telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Alcune difese generali

[**Scopri qui come proteggere le credenziali.**](../stealing-credentials/credentials-protections.md)

### **Misure difensive per la protezione delle credenziali**

- **Restrizioni per Domain Admins**: si consiglia di consentire ai Domain Admins di accedere solo ai Domain Controller, evitando che vengano usati su altri host.
- **Privilegi degli account di servizio**: per garantire la sicurezza, i servizi non dovrebbero essere eseguiti con privilegi Domain Admin (DA).
- **Limitazione temporale dei privilegi**: la durata dei task che richiedono privilegi DA dovrebbe essere limitata. È possibile farlo con: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigazione dei relay LDAP**: controllare gli Event ID 2889/3074/3075, quindi imporre la firma LDAP e il channel binding LDAPS su DC/client per bloccare i tentativi di attacco MITM/relay LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting a livello di protocollo delle attività di Impacket

Per rilevare le tattiche AD comuni, **non basarti solo su artefatti controllabili dall’operatore**, come binari rinominati, nomi dei servizi, file batch temporanei o percorsi di output. Definisci una baseline di come i client Windows legittimi generano il traffico [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC e WMI, quindi cerca **particolarità di implementazione** che persistono anche dopo che l’operatore modifica `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` o `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Possibili indicatori autonomi ad alta affidabilità** (dopo averli verificati rispetto alla propria baseline):
  - DCE/RPC autenticato con `auth_context_id = 79231 + ctx_id`
  - Padding dell’autenticazione DCE/RPC riempito con `0xff`
  - Bind LDAP Kerberos che inseriscono un `AP-REQ` Kerberos non incapsulato direttamente nel `mechToken` SPNEGO
  - Richieste di negoziazione SMB2/3 con valori `ClientGuid` dall’aspetto ASCII
  - `IWbemLevel1Login::NTLMLogin` WMI che usa lo spazio dei nomi non standard `//./root/cimv2`
  - Valori nonce Kerberos hardcoded
- **Più adatti come indicatori di correlazione/valutazione**:
  - Liste di etype Kerberos scarne o duplicate, `PA-DATA` insoliti/mancanti o ordinamento degli etype nelle TGS-REQ diverso da quello nativo di Windows
  - Messaggi NTLM Type 1 senza informazioni di versione o messaggi Type 3 con nomi host nulli
  - NTLMSSP non incapsulato trasportato in DCE/RPC invece che in SPNEGO, trailer di verifica DCE/RPC mancanti o mismatch tra OID SPNEGO/Kerberos
  - La presenza di più caratteristiche di questo tipo sullo stesso host/utente/sessione/intervallo temporale è molto più indicativa di un singolo campo poco affidabile
- **Usali come arricchimento, non come alert autonomi**:
  - Nomi file predefiniti, percorsi di output, nomi di servizi casuali, nomi di file batch temporanei, nomi predefiniti degli account computer e stringhe HTTP/WebDAV/RDP/MSSQL specifiche degli strumenti
  - Sono facili da modificare per gli operatori e sono più utili per spiegare perché un cluster cross-protocol è sospetto
- **Note operative**:
  - Alcuni di questi segnali richiedono traffico decifrato, [analisi PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW o visibilità lato servizio
  - Prima di trasformarli in alert, verificali con client Samba/Linux, appliance e software legacy
  - Man mano che aumenta la fiducia nella baseline, promuovi i rilevamenti da arricchimento -> hunting -> alerting

### **Implementazione di tecniche di deception**

- La deception consiste nel predisporre trappole, come utenti o computer esca, con caratteristiche quali password che non scadono o l’attributo Trusted for Delegation. Un approccio dettagliato prevede la creazione di utenti con diritti specifici o l’aggiunta degli stessi a gruppi con privilegi elevati.<sup>[[2]](#references)</sup>
- Un esempio pratico consiste nell’usare strumenti come: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Per saperne di più sulla distribuzione di tecniche di deception, visita [Deploy-Deception su GitHub](https://github.com/samratashok/Deploy-Deception).

### **Individuazione della deception**

- **Per gli oggetti utente**: gli indicatori sospetti includono ObjectSID atipici, accessi poco frequenti, date di creazione e conteggi bassi di password errate.
- **Indicatori generali**: confrontare gli attributi di potenziali oggetti esca con quelli di oggetti autentici può rivelare incongruenze. Strumenti come [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) possono aiutare a individuare queste deception.

### **Elusione dei sistemi di rilevamento**

- **Elusione del rilevamento di Microsoft ATA**:
  - **Enumerazione degli utenti**: evitare l’enumerazione delle sessioni sui Domain Controller per impedire il rilevamento da parte di ATA.
  - **Impersonificazione dei ticket**: usare chiavi **aes** per creare ticket aiuta a eludere il rilevamento, evitando il downgrade a NTLM.
  - **Attacchi DCSync**: si consiglia di eseguirli da un host diverso da un Domain Controller per evitare il rilevamento di ATA, poiché l’esecuzione diretta da un Domain Controller attiverà degli alert.

## References

- [1] [Guida all’attacco ai trust di dominio](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Creare trust per la deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Da Domain Admin a Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Raccolta LDAP BOF – toolkit LDAP in-memory per lo sfruttamento di Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Uso degli hash NTLM come wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analisi approfondita di Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: acquisizione degli account Active Directory tramite Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Come gestire le modifiche alle connessioni del canale sicuro Netlogon associate a CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Un viaggio alla scoperta delle interfacce Null Session e MS-RPC dimenticate](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Il SID filter è un confine di sicurezza tra domini? (Parte 4) - Ricerca sull’elusione del SID filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Il SID filter è un confine di sicurezza tra domini? (Parte 5) - Attacco trust Golden GMSA - dal child al parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Il SID filter è un confine di sicurezza tra domini? (Parte 6) - Attacco trust tramite modifica dello schema - dal child al parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [Da DA a EA con ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Da amministratori del child domain ad amministratori enterprise in 5 minuti abusando di AD CS: seguito](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un ACE nella manica: progettare backdoor DACL per Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Codice sorgente del modulo pre2k di NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - attributo msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
