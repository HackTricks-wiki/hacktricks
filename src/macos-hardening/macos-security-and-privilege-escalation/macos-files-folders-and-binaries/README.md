# Arquivos, Pastas, Binários e Memória do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Estrutura hierárquica de arquivos

- **/Applications**: Os aplicativos instalados devem estar aqui. Todos os usuários poderão acessá-los.
- **/bin**: Binários de linha de comando
- **/cores**: Se existir, é usado para armazenar core dumps
- **/dev**: Tudo é tratado como um arquivo, portanto você pode ver dispositivos de hardware armazenados aqui.
- **/etc**: Arquivos de configuração
- **/Library**: Muitos subdiretórios e arquivos relacionados a preferências, caches e logs podem ser encontrados aqui. Existe uma pasta Library na raiz e no diretório de cada usuário.
- **/private**: Não documentado, mas muitas das pastas mencionadas são links simbólicos para o diretório private.
- **/sbin**: Binários essenciais do sistema (relacionados à administração)
- **/System**: Arquivos necessários para o funcionamento do OS X. Aqui você deve encontrar principalmente arquivos específicos da Apple (não de terceiros).
- **/tmp**: Os arquivos são excluídos após 3 dias (é um soft link para /private/tmp)
- **/Users**: Diretório home dos usuários.
- **/usr**: Binários de configuração e do sistema
- **/var**: Arquivos de log
- **/Volumes**: As unidades montadas aparecerão aqui.
- **/.vol**: Executando `stat a.txt`, você obtém algo como `16777223 7545753 -rw-r--r-- 1 username wheel ...`, onde o primeiro número é o número de identificação do volume onde o arquivo existe e o segundo é o número do inode. Você pode acessar o conteúdo desse arquivo por meio de /.vol/ com essas informações, executando `cat /.vol/16777223/7545753`

### Pastas de aplicativos

- Os **aplicativos do sistema** estão localizados em `/System/Applications`
- Os aplicativos **instalados** geralmente são instalados em `/Applications` ou em `~/Applications`
- Os dados dos aplicativos podem ser encontrados em `/Library/Application Support` para aplicativos executados como root e em `~/Library/Application Support` para aplicativos executados como o usuário.
- Os **daemons** de aplicativos de terceiros que **precisam ser executados como root** geralmente estão localizados em `/Library/PrivilegedHelperTools/`
- Os aplicativos em **Sandbox** são mapeados para a pasta `~/Library/Containers`. Cada aplicativo possui uma pasta nomeada de acordo com o bundle ID do aplicativo (`com.apple.Safari`).
- O **kernel** está localizado em `/System/Library/Kernels/kernel`
- As extensões de **kernel da Apple** estão localizadas em `/System/Library/Extensions`
- As extensões de **kernel de terceiros** são armazenadas em `/Library/Extensions`

### Arquivos com informações sensíveis

O MacOS armazena informações como senhas em vários locais:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Instaladores pkg vulneráveis


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Extensões específicas do OS X

- **`.dmg`**: Arquivos Apple Disk Image são muito frequentes para instaladores.
- **`.kext`**: Deve seguir uma estrutura específica e é a versão do OS X de um driver. (é um bundle)
- **`.plist`**: Também conhecido como property list, armazena informações em formato XML ou binário.
- Pode ser XML ou binário. Os binários podem ser lidos com:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Aplicativos da Apple que seguem uma estrutura de diretório (é um bundle).
- **`.dylib`**: Bibliotecas dinâmicas (como os arquivos DLL do Windows)
- **`.pkg`**: São iguais ao xar (formato eXtensible Archive). O comando installer pode ser usado para instalar o conteúdo desses arquivos.
- **`.DS_Store`**: Este arquivo está em cada diretório; ele salva os atributos e as personalizações do diretório.
- **`.Spotlight-V100`**: Esta pasta aparece no diretório raiz de cada volume do sistema.
- **`.metadata_never_index`**: Se este arquivo estiver na raiz de um volume, o Spotlight não indexará esse volume.
- **`.noindex`**: Arquivos e pastas com essa extensão não serão indexados pelo Spotlight.
- **`.sdef`**: Arquivos dentro de bundles que especificam como é possível interagir com o aplicativo a partir de um AppleScript.

### Bundles do macOS

Um bundle é um **diretório** que **parece um objeto no Finder** (um exemplo de Bundle são arquivos `*.app`).


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

No macOS (e no iOS), todas as bibliotecas compartilhadas do sistema, como frameworks e dylibs, são **combinadas em um único arquivo**, chamado **dyld shared cache**. Isso melhorou o desempenho, pois o código pode ser carregado mais rapidamente.

No macOS, ele está localizado em `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` e, em versões mais antigas, talvez seja possível encontrar o **shared cache** em **`/System/Library/dyld/`**.\
No iOS, eles podem ser encontrados em **`/System/Library/Caches/com.apple.dyld/`**.

De forma semelhante ao dyld shared cache, o kernel e as extensões do kernel também são compilados em um kernel cache, que é carregado no momento da inicialização.

Para extrair as bibliotecas do shared cache de dylibs contido em um único arquivo, era possível usar o binário [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip), que talvez não funcione atualmente, mas você também pode usar o [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Note que, mesmo que a ferramenta `dyld_shared_cache_util` não funcione, você pode passar o **shared dyld binary para o Hopper**, e o Hopper poderá identificar todas as libraries e permitir que você **selecione qual deseja investigar**:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Alguns extractors não funcionarão, pois as dylibs são prelinked com endereços hard coded e, portanto, podem estar saltando para endereços desconhecidos.

> [!TIP]
> Também é possível baixar o Shared Library Cache de outros dispositivos \*OS no macOS usando um emulador no Xcode. Eles serão baixados dentro de: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, como:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

O **`dyld`** usa o syscall **`shared_region_check_np`** para saber se o SLC foi mapeado (o que retorna o endereço) e **`shared_region_map_and_slide_np`** para mapear o SLC.

Note que, mesmo que o SLC sofra slide no primeiro uso, todos os **processos** usam a **mesma cópia**, o que **eliminou a proteção ASLR** caso o atacante conseguisse executar processos no sistema. Isso foi explorado no passado e corrigido com o shared region pager.

Branch pools são pequenas dylibs Mach-O que criam pequenos espaços entre os image mappings, impossibilitando interpor as funções.

### Override SLCs

Usando as variáveis de ambiente:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Isso permitirá carregar um novo shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** e substituir manualmente as libraries por symlinks para o shared cache com as libraries reais (será necessário extraí-las)

## Special File Permissions

### Folder permissions

Em uma **pasta**, **read** permite **listá-la**, **write** permite **deletar** e **escrever** arquivos nela, e **execute** permite **atravessar** o diretório. Portanto, por exemplo, um usuário com **permissão de leitura sobre um arquivo** dentro de um diretório no qual **não possui permissão de execução** **não conseguirá ler** o arquivo.

### Flag modifiers

Existem algumas flags que podem ser definidas nos arquivos e que farão o arquivo se comportar de maneira diferente. Você pode **verificar as flags** dos arquivos dentro de um diretório com `ls -lO /path/directory`

- **`uchg`**: Conhecida como flag **uchange**, ela **impedirá qualquer ação** que altere ou exclua o **arquivo**. Para defini-la, execute: `chflags uchg file.txt`
- O usuário root pode **remover a flag** e modificar o arquivo
- **`restricted`**: Essa flag faz com que o arquivo seja **protegido pelo SIP** (não é possível adicionar essa flag a um arquivo).
- **`Sticky bit`**: Se um diretório tiver sticky bit, **somente o proprietário do diretório ou o root poderá renomear ou excluir** arquivos. Normalmente, isso é definido no diretório /tmp para impedir que usuários comuns excluam ou movam arquivos de outros usuários.

Todas as flags podem ser encontradas no arquivo `sys/stat.h` (localize-o usando `mdfind stat.h | grep stat.h`) e são:

- `UF_SETTABLE` 0x0000ffff: Máscara das flags que podem ser alteradas pelo proprietário.
- `UF_NODUMP` 0x00000001: Não fazer dump do arquivo.
- `UF_IMMUTABLE` 0x00000002: O arquivo não pode ser alterado.
- `UF_APPEND` 0x00000004: As gravações no arquivo só podem ser feitas no final.
- `UF_OPAQUE` 0x00000008: O diretório é opaco em relação a union.
- `UF_COMPRESSED` 0x00000020: O arquivo está comprimido (alguns file systems).
- `UF_TRACKED` 0x00000040: Não há notificações de exclusões/renomeações para arquivos com essa flag definida.
- `UF_DATAVAULT` 0x00000080: É necessário um entitlement para ler e escrever.
- `UF_HIDDEN` 0x00008000: Indica que este item não deve ser exibido em uma GUI.
- `SF_SUPPORTED` 0x009f0000: Máscara das flags compatíveis com o superusuário.
- `SF_SETTABLE` 0x3fff0000: Máscara das flags que podem ser alteradas pelo superusuário.
- `SF_SYNTHETIC` 0xc0000000: Máscara das flags sintéticas somente para leitura do sistema.
- `SF_ARCHIVED` 0x00010000: O arquivo está arquivado.
- `SF_IMMUTABLE` 0x00020000: O arquivo não pode ser alterado.
- `SF_APPEND` 0x00040000: As gravações no arquivo só podem ser feitas no final.
- `SF_RESTRICTED` 0x00080000: É necessário um entitlement para escrever.
- `SF_NOUNLINK` 0x00100000: O item não pode ser removido, renomeado ou montado.
- `SF_FIRMLINK` 0x00800000: O arquivo é um firmlink.
- `SF_DATALESS` 0x40000000: O arquivo é um objeto sem dados.

### **File ACLs**

As **ACLs** de arquivos contêm **ACEs** (Access Control Entries), nas quais **permissões mais granulares** podem ser atribuídas a diferentes usuários.

É possível conceder a um **diretório** estas permissões: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
E a um **arquivo**: `read`, `write`, `append`, `execute`.

Quando o arquivo contém ACLs, você verá um **"+" ao listar as permissões, como em**:
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
### Atributos estendidos

Os atributos estendidos têm um nome e qualquer valor desejado, e podem ser visualizados usando `ls -@` e manipulados usando o comando `xattr`. Alguns atributos estendidos comuns são:

- `com.apple.resourceFork`: Compatibilidade com resource fork. Também visível como `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: mecanismo de quarantine do Gatekeeper (III/6)
- `metadata:*`: MacOS: vários metadados, como `_backup_excludeItem` ou `kMD*`
- `com.apple.lastuseddate` (#PS): Data do último uso do arquivo
- `com.apple.FinderInfo`: MacOS: informações do Finder (por exemplo, Tags de cores)
- `com.apple.TextEncoding`: Especifica a codificação de texto de arquivos de texto ASCII
- `com.apple.logd.metadata`: Usado pelo logd em arquivos de `/var/db/diagnostics`
- `com.apple.genstore.*`: Armazenamento geracional (`/.DocumentRevisions-V100` na raiz do sistema de arquivos)
- `com.apple.rootless`: MacOS: Usado pelo System Integrity Protection para rotular arquivos (III/10)
- `com.apple.uuidb.boot-uuid`: Marcações do logd de épocas de inicialização com UUID exclusivo
- `com.apple.decmpfs`: MacOS: Compactação transparente de arquivos (II/7)
- `com.apple.cprotect`: \*OS: Dados de encryption por arquivo (III/11)
- `com.apple.installd.*`: \*OS: Metadados usados pelo installd, por exemplo, `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Esta é uma forma de obter **Alternate Data Streams em máquinas MacOS**. Você pode salvar conteúdo dentro de um atributo estendido chamado **com.apple.ResourceFork** em um arquivo, salvando-o em **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Você pode **encontrar todos os arquivos que contêm este extended attribute** com:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

O extended attribute `com.apple.decmpfs` indica que o arquivo está armazenado criptografado; `ls -l` reportará um **tamanho de 0** e os dados comprimidos estarão dentro desse atributo. Sempre que o arquivo for acessado, ele será descriptografado em memória.

Esse attr pode ser visualizado com `ls -lO`, sendo indicado como compressed, pois arquivos comprimidos também são marcados com a flag `UF_COMPRESSED`. Se a flag de um arquivo comprimido for removida com `chflags nocompressed </path/to/file>`, o sistema não saberá que o arquivo estava comprimido e, portanto, não poderá descompactar e acessar os dados (ele pensará que o arquivo está realmente vazio).

A ferramenta afscexpand pode ser usada para forçar a descompressão de um arquivo.


### Locais de configuração interessantes (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Armazena os arquivos plist de feature flags da Apple, que controlam comportamentos opcionais ou experimentais em system daemons / frameworks | Se um atacante conseguir contornar o SIP ou obter privilégios, a adulteração desses arquivos poderá habilitar code paths ocultos ou desabilitar salvaguardas |
| `/System/Library/CoreServices/systemVersion.plist` | Contém metadados da versão do macOS (ProductVersion, BuildVersion), usados por aplicativos / instaladores para controlar comportamentos | A modificação pode enganar aplicativos ou instaladores, fazendo-os aceitar versões de OS não suportadas ou desbloquear recursos |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferências de aplicativos / de todo o sistema | Se forem graváveis, atacantes poderão injetar configurações para direcionar o comportamento de aplicativos, desabilitar proteções ou causar uma configuração incorreta |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definições plist para daemons e agents em segundo plano | A inserção ou manipulação de um plist (se as permissões permitirem) possibilita persistence ou privilege escalations |
| `/etc/hosts` | Mapeamentos de hostname ↔ IP usados pelo resolvedor DNS do sistema | Redirecionamento de nomes de domínio, interceptação de tráfego e spoofing de serviços sob controle local |
| `/etc/sudoers` | Define quem pode executar comandos com `sudo` e sob quais condições | Um arquivo sudoers corrompido pode conceder root ou privilégios indevidos a contas de atacantes |
| `/private/var/db/dslocal/nodes/Default/users/` | Plists de definição de contas de usuários locais | A adulteração permite a criação ou modificação de contas de usuário, hashes de senha ou metadados de usuários |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extensions / drivers | A instalação ou modificação de kexts pode levar ao controle em nível de kernel; esses componentes são fortemente protegidos pelo SIP / políticas de assinatura |
| `/private/var/db/SystemPolicyConfiguration/` | Armazena a configuração para a aplicação de políticas do sistema (por exemplo, Gatekeeper, notarization) | A adulteração desses arquivos pode permitir a circumvention de verificações de política ou regras de confiança |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binaries auxiliares e arquivos de configuração do SSH | Uma configuração incorreta leva a uma segurança SSH fraca, acesso não autorizado ou algoritmos inseguros |
| `/System/Library/Sandbox/Profiles` | Perfis de sandbox do sistema (SBPL) usados para restringir ações de processos | Substituir ou alterar perfis pode abrir vetores de sandbox escape ou enfraquecer a contenção |

> **Nota**: Muitos desses paths estão em diretórios protegidos pelo SIP (por exemplo, `/System`) e são protegidos contra gravação, a menos que o SIP seja desabilitado ou contornado.


## **Universal binaries &** Mach-o Format

Os binaries do Mac OS geralmente são compilados como **universal binaries**. Um **universal binary** pode **suportar múltiplas arquiteturas no mesmo arquivo**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Arquivos da categoria de risco do Mac OS

O diretório `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` é onde são armazenadas informações sobre o **risco associado a diferentes extensões de arquivo**. Esse diretório categoriza os arquivos em vários níveis de risco, influenciando como o Safari lida com esses arquivos após o download. As categorias são as seguintes:

- **LSRiskCategorySafe**: Os arquivos nessa categoria são considerados **completamente seguros**. O Safari abrirá automaticamente esses arquivos após o download.
- **LSRiskCategoryNeutral**: Esses arquivos não exibem avisos e **não são abertos automaticamente** pelo Safari.
- **LSRiskCategoryUnsafeExecutable**: Os arquivos nessa categoria **disparam um aviso** indicando que o arquivo é um aplicativo. Isso funciona como uma medida de segurança para alertar o usuário.
- **LSRiskCategoryMayContainUnsafeExecutable**: Essa categoria é destinada a arquivos, como archives, que podem conter um executável. O Safari **disparará um aviso**, a menos que consiga verificar que todo o conteúdo é seguro ou neutro.

## Arquivos de log

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contém informações sobre arquivos baixados, como a URL de onde foram baixados.
- **`/var/log/system.log`**: Principal log de sistemas OSX. com.apple.syslogd.plist é responsável pela execução do syslogging (você pode verificar se está desabilitado procurando por "com.apple.syslogd" em `launchctl list`.
- **`/private/var/log/asl/*.asl`**: Estes são os Apple System Logs, que podem conter informações interessantes.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Armazena arquivos e aplicativos acessados recentemente por meio do "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Armazena itens a serem iniciados durante a inicialização do sistema
- **`$HOME/Library/Logs/DiskUtility.log`**: Arquivo de log do aplicativo DiskUtility (informações sobre drives, incluindo USBs)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dados sobre pontos de acesso sem fio.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Lista de daemons desativados.

{{#include ../../../banners/hacktricks-training.md}}
