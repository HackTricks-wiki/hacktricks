# Furto di certificati AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Questo è un breve riepilogo dei capitoli sul furto della ricerca approfondita disponibile su [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## Cosa posso fare con un certificato

Prima di verificare come rubare i certificati, ecco alcune informazioni su come determinare a cosa può servire il certificato:
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
## Esportazione dei certificati tramite le Crypto APIs – THEFT1

In una **sessione desktop interattiva**, estrarre un certificato utente o macchina, insieme alla chiave privata, è semplice, in particolare se la **chiave privata è esportabile**. È possibile farlo individuando il certificato in `certmgr.msc`, facendo clic con il pulsante destro del mouse su di esso e selezionando `All Tasks → Export` per generare un file .pfx protetto da password.<sup>[[1]](#references)</sup>

Per un **approccio programmatico**, sono disponibili strumenti come il cmdlet PowerShell `ExportPfxCertificate` o progetti come [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer). Questi utilizzano la **Microsoft CryptoAPI** (CAPI) o la Cryptography API: Next Generation (CNG) per interagire con l’archivio dei certificati. Queste API forniscono una serie di servizi crittografici, inclusi quelli necessari per l’archiviazione e l’autenticazione dei certificati.

Tuttavia, se una chiave privata è impostata come non esportabile, sia CAPI sia CNG normalmente bloccano l’estrazione di tali certificati. Per aggirare questa restrizione, è possibile utilizzare strumenti come **Mimikatz**. Mimikatz offre i comandi `crypto::capi` e `crypto::cng` per applicare una patch alle rispettive API, consentendo l’esportazione delle chiavi private. In particolare, `crypto::capi` applica una patch a CAPI all’interno del processo corrente, mentre `crypto::cng` interviene sulla memoria di **lsass.exe** per applicare la patch.

## Furto dei certificati utente tramite DPAPI – THEFT2

Maggiori informazioni su DPAPI in:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

In Windows, **le chiavi private dei certificati sono protette da DPAPI**. È fondamentale riconoscere che le **posizioni di archiviazione delle chiavi private utente e macchina** sono distinte e che le strutture dei file variano in base alla cryptographic API utilizzata dal sistema operativo. **SharpDPAPI** è uno strumento in grado di gestire automaticamente queste differenze durante la decrittografia dei blob DPAPI.<sup>[[1]](#references)</sup>

I **certificati utente** sono principalmente contenuti nel registro, in `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, ma alcuni possono trovarsi anche nella directory `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Le **chiavi private** corrispondenti a questi certificati sono generalmente archiviate in `%APPDATA%\Microsoft\Crypto\RSA\User SID\` per le chiavi **CAPI** e in `%APPDATA%\Microsoft\Crypto\Keys\` per le chiavi **CNG**.

Per **estrarre un certificato e la relativa chiave privata**, la procedura prevede:

1. **Selezionare il certificato target** dall’archivio dell’utente e recuperare il nome del relativo archivio delle chiavi.
2. **Individuare la DPAPI masterkey richiesta** per decrittografare la chiave privata corrispondente.
3. **Decrittografare la chiave privata** utilizzando la DPAPI masterkey in formato plaintext.

Per **acquisire la DPAPI masterkey in formato plaintext**, è possibile utilizzare i seguenti approcci:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Per semplificare la decrittografia dei file masterkey e dei file delle chiavi private, il comando `certificates` di [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) si rivela utile. Accetta `/pvk`, `/mkfile`, `/password` oppure `{GUID}:KEY` come argomenti per decrittografare le chiavi private e i certificati associati, generando successivamente un file `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Furto di certificati macchina tramite DPAPI – THEFT3

I certificati macchina archiviati da Windows nel registro in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` e le chiavi private associate, situate in `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (per CAPI) e `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (per CNG), sono crittografati utilizzando le master key DPAPI della macchina. Queste chiavi non possono essere decrittografate con la DPAPI backup key del dominio; è invece richiesto il **segreto LSA DPAPI_SYSTEM**, a cui può accedere solo l'utente SYSTEM.<sup>[[1]](#references)</sup>

La decrittografia manuale può essere eseguita eseguendo il comando `lsadump::secrets` in **Mimikatz** per estrarre il segreto LSA DPAPI_SYSTEM e utilizzando successivamente questa chiave per decrittografare le masterkey della macchina. In alternativa, dopo aver applicato le patch a CAPI/CNG come descritto in precedenza, è possibile utilizzare il comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` di Mimikatz.

**SharpDPAPI** offre un approccio più automatizzato tramite il comando certificates. Quando viene utilizzato il flag `/machine` con permessi elevati, effettua l'escalation a SYSTEM, estrae il segreto LSA DPAPI_SYSTEM, lo utilizza per decrittografare le masterkey DPAPI della macchina e impiega quindi queste chiavi in chiaro come tabella di ricerca per decrittografare le chiavi private di qualsiasi certificato macchina.

## Ricerca dei file di certificato – THEFT4

Talvolta i certificati si trovano direttamente nel filesystem, ad esempio nelle condivisioni di file o nella cartella Downloads. I tipi di file di certificato più comunemente individuati e destinati agli ambienti Windows sono i file `.pfx` e `.p12`. Sebbene meno frequentemente, possono comparire anche file con estensione `.pkcs12` e `.pem`. Altre estensioni di file relative ai certificati degne di nota includono:<sup>[[1]](#references)</sup>

- `.key` per le chiavi private,
- `.crt`/`.cer` solo per i certificati,
- `.csr` per le Certificate Signing Requests, che non contengono certificati o chiavi private,
- `.jks`/`.keystore`/`.keys` per i Java Keystores, che possono contenere certificati insieme alle chiavi private utilizzate dalle applicazioni Java.

È possibile cercare questi file utilizzando PowerShell o il prompt dei comandi, cercando le estensioni menzionate.

Quando viene trovato un file di certificato PKCS#12 protetto da una password, è possibile estrarre un hash utilizzando `pfx2john.py`, disponibile su [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Successivamente, è possibile utilizzare JohnTheRipper per tentare di crackare la password.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Furto delle credenziali NTLM tramite PKINIT – THEFT5 (UnPAC the hash)

Il contenuto illustra un metodo per il furto delle credenziali NTLM tramite PKINIT, nello specifico attraverso il metodo di furto denominato THEFT5. Di seguito viene fornita una riformulazione al passivo, con il contenuto anonimizzato e riassunto ove applicabile:<sup>[[1]](#references)</sup>

Per supportare l'autenticazione NTLM `MS-NLMP` per le applicazioni che non supportano l'autenticazione Kerberos, il KDC è progettato per restituire la one-way function (OWF) NTLM dell'utente all'interno del privilege attribute certificate (PAC), nello specifico nel buffer `PAC_CREDENTIAL_INFO`, quando viene utilizzato PKCA. Di conseguenza, qualora un account effettui l'autenticazione e ottenga un Ticket-Granting Ticket (TGT) tramite PKINIT, viene fornito intrinsecamente un meccanismo che consente all'host corrente di estrarre l'hash NTLM dal TGT, così da mantenere il supporto ai protocolli di autenticazione legacy. Questo processo comporta la decrittografia della struttura `PAC_CREDENTIAL_DATA`, che è essenzialmente una rappresentazione serializzata NDR del testo in chiaro NTLM.

L'utility **Kekeo**, disponibile all'indirizzo [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), è indicata come in grado di richiedere un TGT contenente questi dati, facilitando così il recupero dell'NTLM dell'utente. Il comando utilizzato a questo scopo è il seguente:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** può anche ottenere queste informazioni con l'opzione **`asktgt [...] /getcredentials`**.

Inoltre, viene segnalato che Kekeo può elaborare certificati protetti da smartcard, a condizione che sia possibile recuperare il PIN, facendo riferimento a [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). La stessa funzionalità risulta supportata da **Rubeus**, disponibile all'indirizzo [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Questa spiegazione illustra il processo e gli strumenti coinvolti nel credential theft NTLM tramite PKINIT, concentrandosi sul recupero degli hash NTLM attraverso un TGT ottenuto con PKINIT e sulle utility che facilitano questo processo.

## Riferimenti

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
