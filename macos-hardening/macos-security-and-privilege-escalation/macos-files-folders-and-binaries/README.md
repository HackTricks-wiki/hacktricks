# macOS Arquivos, Pastas, Binários e Memória

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Layout da hierarquia de arquivos

* **/Applications**: Os aplicativos instalados devem estar aqui. Todos os usuários poderão acessá-los.
* **/bin**: Binários de linha de comando
* **/cores**: Se existir, é usado para armazenar despejos de núcleo
* **/dev**: Tudo é tratado como um arquivo, então você pode ver dispositivos de hardware armazenados aqui.
* **/etc**: Arquivos de configuração
* **/Library**: Muitos subdiretórios e arquivos relacionados a preferências, caches e logs podem ser encontrados aqui. Uma pasta Library existe na raiz e em cada diretório do usuário.
* **/private**: Não documentado, mas muitas das pastas mencionadas são links simbólicos para o diretório privado.
* **/sbin**: Binários do sistema essenciais (relacionados à administração)
* **/System**: Arquivo para fazer o OS X funcionar. Você deve encontrar principalmente apenas arquivos específicos da Apple aqui (não de terceiros).
* **/tmp**: Os arquivos são excluídos após 3 dias (é um link simbólico para /private/tmp)
* **/Users**: Diretório home para usuários.
* **/usr**: Configuração e binários do sistema
* **/var**: Arquivos de log
* **/Volumes**: As unidades montadas aparecerão aqui.
* **/.vol**: Ao executar `stat a.txt`, você obtém algo como `16777223 7545753 -rw-r--r-- 1 username wheel ...`, onde o primeiro número é o número de ID do volume onde o arquivo existe e o segundo é o número de inode. Você pode acessar o conteúdo deste arquivo através de /.vol/ com essas informações executando `cat /.vol/16777223/7545753`

### Pastas de aplicativos

* Os **aplicativos do sistema** estão localizados em `/System/Applications`
* Os **aplicativos instalados** geralmente são instalados em `/Applications` ou em `~/Applications`
* Os **dados do aplicativo** podem ser encontrados em `/Library/Application Support` para os aplicativos em execução como root e `~/Library/Application Support` para aplicativos em execução como o usuário.
* Os **daemons** de aplicativos de terceiros que **precisam ser executados como root** geralmente estão localizados em `/Library/PrivilegedHelperTools/`
* Os aplicativos **sandboxed** são mapeados na pasta `~/Library/Containers`. Cada aplicativo tem uma pasta com o nome do ID do pacote do aplicativo (`com.apple.Safari`).
* O **kernel** está localizado em `/System/Library/Kernels/kernel`
* As **extensões de kernel da Apple** estão localizadas em `/System/Library/Extensions`
* As **extensões de kernel de terceiros** são armazenadas em `/Library/Extensions`

### Arquivos com informações sensíveis

O macOS armazena informações como senhas em vários locais:

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

## Extensões Específicas do OS X

* **`.dmg`**: Arquivos de imagem de disco da Apple são muito frequentes para instaladores.
* **`.kext`**: Deve seguir uma estrutura específica e é a versão do OS X de um driver. (é um pacote)
* **`.plist`**: Também conhecido como lista de propriedades, armazena informações em formato XML ou binário.
  * Pode ser XML ou binário. Os binários podem ser lidos com:
    * `defaults read config.plist`
    * `/usr/libexec/PlistBuddy -c print config.plsit`
    * `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    * `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    * `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: Aplicativos da Apple que seguem a estrutura de diretório (é um pacote).
* **`.dylib`**: Bibliotecas dinâmicas (como arquivos DLL do Windows)
* **`.pkg`**: São iguais a xar (formato de arquivo de arquivo extensível). O comando installer pode ser usado para instalar o conteúdo desses arquivos.
* **`.DS_Store`**: Este arquivo está em cada diretório, ele salva os atributos e personalizações do diretório.
* **`.Spotlight-V100`**: Esta pasta aparece no diretório raiz de cada volume no sistema.
* **`.metadata_never_index`**: Se este arquivo estiver na raiz de um volume, o Spotlight não indexará esse volume.
* **`.noindex`**: Arquivos e pastas com esta extensão não serão indexados pelo Spotlight.

### Pacotes macOS

Basicamente, um pacote é uma **estrutura de diretório** dentro do sistema de arquivos. Curiosamente, por padrão, este diretório **parece um único objeto no Finder** (como `.app`).&#x20;

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Permissões Especiais de Arquivo

### Permissões de pasta

Em uma **pasta**, **leitura** permite **listá-la**, **escrita** permite **excluir** e **escrever** arquivos nela, e **executar** permite **atravessar** o diretório. Portanto, por exemplo, um usuário com **permissão de leitura sobre um arquivo** dentro de um diretório onde ele **não tem permissão de execução** **não poderá ler** o arquivo.

### Modificadores de sinalizador

Existem alguns sinalizadores que podem ser definidos nos arquivos que farão com que o arquivo se comporte de maneira diferente. Você pode **verificar os sinalizadores** dos arquivos dentro de um diretório com `ls -lO /path/directory`

* **`uchg`**: Conhecido como sinalizador **uchange** impedirá qualquer ação de alterar ou excluir o **arquivo**. Para defini-lo, faça: `chflags uchg file.txt`
  * O usuário root pode **remover o sinalizador** e modificar o arquivo
* **`restricted`**: Este sinalizador faz com que o arquivo seja **protegido pelo SIP** (você não pode adicionar este sinalizador a um arquivo).
* **`Sticky bit`**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Você pode **ler as ACLs** do arquivo com:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```
Você pode encontrar **todos os arquivos com ACLs** com (isso é muuuito lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Forks de Recursos | ADS do macOS

Esta é uma maneira de obter **fluxos de dados alternativos em máquinas MacOS**. Você pode salvar conteúdo dentro de um atributo estendido chamado **com.apple.ResourceFork** dentro de um arquivo salvando-o em **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Você pode **encontrar todos os arquivos que contêm este atributo estendido** com:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
## **Binários universais e** Formato Mach-o

Os binários do Mac OS geralmente são compilados como **binários universais**. Um **binário universal** pode **suportar várias arquiteturas no mesmo arquivo**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Dumping de memória do macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Arquivos de categoria de risco do Mac OS

Os arquivos `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` contêm o risco associado aos arquivos dependendo da extensão do arquivo.

As possíveis categorias incluem as seguintes:

* **LSRiskCategorySafe**: **Totalmente** **seguro**; O Safari será aberto automaticamente após o download.
* **LSRiskCategoryNeutral**: Sem aviso, mas **não é aberto automaticamente**.
* **LSRiskCategoryUnsafeExecutable**: **Dispara** um **aviso** "Este arquivo é um aplicativo...".
* **LSRiskCategoryMayContainUnsafeExecutable**: Isso é para coisas como arquivos que contêm um executável. Ele **dispara um aviso, a menos que o Safari possa determinar que todo o conteúdo é seguro ou neutro**.

## Arquivos de log

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contém informações sobre arquivos baixados, como a URL de onde foram baixados.
* **`/var/log/system.log`**: Log principal dos sistemas OSX. com.apple.syslogd.plist é responsável pela execução do syslog (você pode verificar se está desativado procurando por "com.apple.syslogd" em `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Estes são os Registros do Sistema Apple que podem conter informações interessantes.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Armazena arquivos e aplicativos acessados recentemente através do "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Armazena itens para iniciar no início do sistema.
* **`$HOME/Library/Logs/DiskUtility.log`**: Arquivo de log para o aplicativo DiskUtility (informações sobre unidades, incluindo USBs).
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dados sobre pontos de acesso sem fio.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista de daemons desativados.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
