# AD CS Certificate Theft

{{#include ../../../banners/hacktricks-training.md}}

**Questo è un piccolo riassunto dei capitoli sul furto dell'ottima ricerca di [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Cosa posso fare con un certificato

Prima di controllare come rubare i certificati, qui hai alcune informazioni su come scoprire a cosa serve il certificato:
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Esportazione dei certificati utilizzando le Crypto API – THEFT1

In una **sessione desktop interattiva**, estrarre un certificato utente o macchina, insieme alla chiave privata, può essere fatto facilmente, in particolare se la **chiave privata è esportabile**. Questo può essere realizzato navigando al certificato in `certmgr.msc`, facendo clic destro su di esso e selezionando `All Tasks → Export` per generare un file .pfx protetto da password.

Per un **approccio programmatico**, sono disponibili strumenti come il cmdlet PowerShell `ExportPfxCertificate` o progetti come [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer). Questi utilizzano le **Microsoft CryptoAPI** (CAPI) o la Cryptography API: Next Generation (CNG) per interagire con il negozio di certificati. Queste API forniscono una gamma di servizi crittografici, inclusi quelli necessari per la memorizzazione e l'autenticazione dei certificati.

Tuttavia, se una chiave privata è impostata come non esportabile, sia CAPI che CNG normalmente bloccheranno l'estrazione di tali certificati. Per bypassare questa restrizione, possono essere impiegati strumenti come **Mimikatz**. Mimikatz offre comandi `crypto::capi` e `crypto::cng` per patchare le rispettive API, consentendo l'esportazione delle chiavi private. In particolare, `crypto::capi` patcha il CAPI all'interno del processo corrente, mentre `crypto::cng` mira alla memoria di **lsass.exe** per la patch.

## Furto di certificati utente tramite DPAPI – THEFT2

Ulteriori informazioni su DPAPI in:

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

In Windows, **le chiavi private dei certificati sono protette da DPAPI**. È fondamentale riconoscere che le **posizioni di archiviazione per le chiavi private utente e macchina** sono distinte, e le strutture dei file variano a seconda dell'API crittografica utilizzata dal sistema operativo. **SharpDPAPI** è uno strumento che può navigare automaticamente queste differenze durante la decrittazione dei blob DPAPI.

I **certificati utente** sono prevalentemente ospitati nel registro sotto `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, ma alcuni possono essere trovati anche nella directory `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Le corrispondenti **chiavi private** per questi certificati sono tipicamente memorizzate in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` per le chiavi **CAPI** e `%APPDATA%\Microsoft\Crypto\Keys\` per le chiavi **CNG**.

Per **estrarre un certificato e la sua chiave privata associata**, il processo prevede:

1. **Selezionare il certificato target** dal negozio dell'utente e recuperare il suo nome del negozio delle chiavi.
2. **Localizzare la masterkey DPAPI necessaria** per decrittare la corrispondente chiave privata.
3. **Decrittare la chiave privata** utilizzando la masterkey DPAPI in chiaro.

Per **acquisire la masterkey DPAPI in chiaro**, possono essere utilizzati i seguenti approcci:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Per semplificare la decrittazione dei file masterkey e dei file di chiavi private, il comando `certificates` di [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) si rivela utile. Accetta come argomenti `/pvk`, `/mkfile`, `/password` o `{GUID}:KEY` per decrittare le chiavi private e i certificati collegati, generando successivamente un file `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Furto di Certificati di Macchina tramite DPAPI – THEFT3

I certificati di macchina memorizzati da Windows nel registro in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` e le chiavi private associate situate in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (per CAPI) e `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (per CNG) sono crittografati utilizzando le chiavi master DPAPI della macchina. Queste chiavi non possono essere decrittografate con la chiave di backup DPAPI del dominio; invece, è necessaria la **segreto LSA DPAPI_SYSTEM**, a cui può accedere solo l'utente SYSTEM.

La decrittografia manuale può essere ottenuta eseguendo il comando `lsadump::secrets` in **Mimikatz** per estrarre il segreto LSA DPAPI_SYSTEM, e successivamente utilizzando questa chiave per decrittografare le chiavi master della macchina. In alternativa, il comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` di Mimikatz può essere utilizzato dopo aver patchato CAPI/CNG come descritto in precedenza.

**SharpDPAPI** offre un approccio più automatizzato con il suo comando certificati. Quando il flag `/machine` è utilizzato con permessi elevati, si eleva a SYSTEM, estrae il segreto LSA DPAPI_SYSTEM, lo utilizza per decrittografare le chiavi master DPAPI della macchina e poi impiega queste chiavi in chiaro come tabella di ricerca per decrittografare eventuali chiavi private dei certificati di macchina.

## Trovare File di Certificati – THEFT4

I certificati si trovano a volte direttamente all'interno del filesystem, come nelle condivisioni di file o nella cartella Download. I tipi di file di certificati più comunemente incontrati mirati agli ambienti Windows sono i file `.pfx` e `.p12`. Anche se meno frequentemente, appaiono anche file con estensioni `.pkcs12` e `.pem`. Ulteriori estensioni di file relative ai certificati degne di nota includono:

- `.key` per chiavi private,
- `.crt`/`.cer` per certificati solo,
- `.csr` per Richieste di Firma di Certificati, che non contengono certificati o chiavi private,
- `.jks`/`.keystore`/`.keys` per Java Keystores, che possono contenere certificati insieme a chiavi private utilizzate da applicazioni Java.

Questi file possono essere cercati utilizzando PowerShell o il prompt dei comandi cercando le estensioni menzionate.

Nei casi in cui venga trovato un file di certificato PKCS#12 e sia protetto da una password, l'estrazione di un hash è possibile tramite l'uso di `pfx2john.py`, disponibile su [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Successivamente, JohnTheRipper può essere impiegato per tentare di decifrare la password.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5 (UnPAC the hash)

Il contenuto fornito spiega un metodo per il furto delle credenziali NTLM tramite PKINIT, specificamente attraverso il metodo di furto etichettato come THEFT5. Ecco una rielaborazione in forma passiva, con il contenuto anonimizzato e riassunto dove applicabile:

Per supportare l'autenticazione NTLM `MS-NLMP` per applicazioni che non facilitano l'autenticazione Kerberos, il KDC è progettato per restituire la funzione unidirezionale (OWF) NTLM dell'utente all'interno del certificato di attributo di privilegio (PAC), specificamente nel buffer `PAC_CREDENTIAL_INFO`, quando viene utilizzato PKCA. Di conseguenza, se un account si autentica e ottiene un Ticket-Granting Ticket (TGT) tramite PKINIT, viene fornito un meccanismo che consente all'host attuale di estrarre l'hash NTLM dal TGT per mantenere i protocolli di autenticazione legacy. Questo processo comporta la decrittazione della struttura `PAC_CREDENTIAL_DATA`, che è essenzialmente una rappresentazione serializzata NDR del testo in chiaro NTLM.

L'utilità **Kekeo**, accessibile su [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), è menzionata come capace di richiedere un TGT contenente questi dati specifici, facilitando così il recupero dell'NTLM dell'utente. Il comando utilizzato per questo scopo è il seguente:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** può anche ottenere queste informazioni con l'opzione **`asktgt [...] /getcredentials`**.

Inoltre, si segnala che Kekeo può elaborare certificati protetti da smartcard, a condizione che il pin possa essere recuperato, con riferimento a [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). La stessa capacità è indicata come supportata da **Rubeus**, disponibile su [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Questa spiegazione racchiude il processo e gli strumenti coinvolti nel furto di credenziali NTLM tramite PKINIT, concentrandosi sul recupero degli hash NTLM attraverso il TGT ottenuto utilizzando PKINIT e le utility che facilitano questo processo.

{{#include ../../../banners/hacktricks-training.md}}
