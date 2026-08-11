# Arquivos, Pastas, Binários e Memória do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Estrutura hierárquica do sistema de arquivos

A Apple documenta o sistema de arquivos do macOS como uma hierarquia de domínios do sistema, local, de rede e do usuário. O conteúdo exato varia conforme a versão do sistema operacional, e os locais do sistema estão cada vez mais protegidos ou sintetizados. <sup>[[1]](#references)</sup>

- **/Applications**: Os apps instalados devem estar aqui. Todos os usuários poderão acessá-los.
- **/bin**: Binários de linha de comando
- **/cores**: Se existir, é usado para armazenar core dumps
- **/dev**: Tudo é tratado como um arquivo, portanto você pode ver dispositivos de hardware armazenados aqui.
- **/etc**: Arquivos de configuração
- **/Library**: Muitos subdiretórios e arquivos relacionados a preferências, caches e logs podem ser encontrados aqui. Existe uma pasta Library na raiz e no diretório de cada usuário.
- **/private**: Não documentado, mas muitas das pastas mencionadas são links simbólicos para o diretório private.
- **/sbin**: Binários essenciais do sistema (relacionados à administração)
- **/System**: Arquivos exigidos pelo macOS; esta árvore contém principalmente componentes fornecidos pela Apple.
- **/tmp**: Arquivos temporários (um link simbólico para `/private/tmp`). Instalações históricas normalmente limpavam arquivos temporários antigos em uma programação periódica, às vezes descrita como três dias, mas o tempo atual de limpeza depende do sistema e das políticas; não conte com a persistência dos dados nesse local.
- **/Users**: Diretório inicial dos usuários.
- **/usr**: Configurações e binários do sistema
- **/var**: Arquivos de log
- **/Volumes**: Os volumes montados aparecem aqui.
- **/.vol**: Ao executar `stat a.txt`, você obtém algo como `16777223 7545753 -rw-r--r-- 1 username wheel ...`, em que o primeiro número é o ID do volume onde o arquivo existe e o segundo é o número do inode. Você pode acessar o conteúdo desse arquivo por meio de `/.vol/` usando essas informações e executando `cat /.vol/16777223/7545753`

### Pastas de Applications

- Os **apps do sistema** estão localizados em `/System/Applications`
- Os apps **instalados** geralmente são instalados em `/Applications` ou em `~/Applications`
- Os dados dos apps podem ser encontrados em `/Library/Application Support` para os apps executados como root e em `~/Library/Application Support` para os apps executados como o usuário.
- **Daemons** de apps de terceiros que **precisam ser executados como root** geralmente estão localizados em `/Library/PrivilegedHelperTools/`.
- Os apps em **Sandbox** são mapeados para a pasta `~/Library/Containers`. Cada app tem uma pasta nomeada de acordo com o ID do bundle do app (`com.apple.Safari`).
- O **kernel** está localizado em `/System/Library/Kernels/kernel`
- As extensões de kernel da **Apple** estão localizadas em `/System/Library/Extensions`
- As extensões de kernel de **terceiros** são armazenadas em `/Library/Extensions`

### Arquivos com informações sensíveis

O macOS armazena informações sensíveis, incluindo credenciais, em vários locais:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Instaladores pkg vulneráveis


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Extensões específicas do OS X

- **`.dmg`**: Arquivos Apple Disk Image são muito comuns em instaladores.
- **`.kext`**: Deve seguir uma estrutura específica e é a versão do OS X de um driver. (é um bundle)
- **`.plist`**: Uma property list armazena informações estruturadas em formato XML ou binário.
- Pode ser XML ou binário. Os binários podem ser lidos com:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Um application bundle que segue a estrutura de diretórios padrão do macOS.
- **`.dylib`**: Bibliotecas dinâmicas (como arquivos DLL do Windows)
- **`.pkg`**: São iguais ao xar (formato eXtensible Archive). O comando installer pode ser usado para instalar o conteúdo desses arquivos.
- **`.DS_Store`**: Este arquivo está em cada diretório; ele salva os atributos e as personalizações do diretório.
- **`.Spotlight-V100`**: Esta pasta aparece no diretório raiz de todos os volumes do sistema.
- **`.metadata_never_index`**: Se este arquivo estiver na raiz de um volume, o Spotlight não indexará esse volume.
- **`.noindex`**: Arquivos e pastas com esta extensão não serão indexados pelo Spotlight.
- **`.sdef`**: Um arquivo de definição de scripting que descreve como o AppleScript pode interagir com um app.

### Bundles do macOS

Um bundle é um diretório com uma hierarquia padronizada que o Finder pode apresentar como um único objeto; os application bundles usam a extensão `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

No macOS e no iOS, bibliotecas e frameworks do sistema usados com frequência são pré-vinculados no **dyld shared cache**, o que melhora o desempenho de inicialização dos apps. Embora seja tratado como um único cache lógico, as versões atuais podem armazená-lo como um cache principal mais vários arquivos de subcache, em vez de literalmente um único arquivo. Seu formato e localização são detalhes de implementação que mudam entre as versões do sistema operacional. <sup>[[3]](#references)</sup>

No macOS, ele está localizado em `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` e, em versões mais antigas, talvez seja possível encontrar o **shared cache** em **`/System/Library/dyld/`**.\
No iOS, eles podem ser encontrados em **`/System/Library/Caches/com.apple.dyld/`**.

De forma semelhante ao dyld shared cache, o kernel e as extensões de kernel também são compilados em um kernel cache, que é carregado no momento da inicialização.

Versões mais antigas podiam ser extraídas com [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Essa build pode não oferecer suporte aos formatos de cache atuais; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) é outra opção:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Note que, mesmo que a ferramenta `dyld_shared_cache_util` não funcione, você pode passar o **binário dyld compartilhado para o Hopper**, e o Hopper poderá identificar todas as bibliotecas e permitir que você **selecione qual deseja investigar**:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Alguns extractors não funcionarão, pois as dylibs são prelinked com endereços hard coded e, portanto, podem estar saltando para endereços desconhecidos.

> [!TIP]
> Também é possível baixar o Shared Library Cache de outros dispositivos \*OS no macos usando um emulador no Xcode. Eles serão baixados dentro de: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, como:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapeamento de SLC

**`dyld`** usa o syscall **`shared_region_check_np`** para saber se o SLC foi mapeado (que retorna o endereço) e **`shared_region_map_and_slide_np`** para mapear o SLC.

Observe que, mesmo que o SLC sofra slide no primeiro uso, todos os **processos** usam a **mesma cópia**, o que **eliminou a proteção ASLR** caso o atacante conseguisse executar processos no sistema. Isso foi explorado no passado e corrigido com o shared region pager.

Branch pools são pequenas dylibs Mach-O que criam pequenos espaços entre os mapeamentos de imagens, tornando impossível fazer interpose das funções.

### Sobrescrever SLCs

Usando as variáveis de ambiente:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Isso permitirá carregar um novo shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** e substituir manualmente as bibliotecas por symlinks para o shared cache com as bibliotecas reais (será necessário extraí-las)

## Permissões Especiais de Arquivos

### Permissões de pastas

Para um diretório, **read** permite listar entradas, **write** permite criar ou remover entradas, e **execute** permite a travessia. Consequentemente, um usuário que pode ler um arquivo, mas não pode atravessar um diretório pai, não pode acessar esse arquivo pelo caminho. <sup>[[4]](#references)</sup>

### Modificadores de flags

Os arquivos podem conter flags que alteram seu comportamento. Inspecione as flags em um diretório com `ls -lO /path/directory`.

- **`uchg`**: Conhecida como flag **uchange**, ela **impedirá qualquer ação** que altere ou exclua o **arquivo**. Para defini-la, execute: `chflags uchg file.txt`
- O usuário root poderia **remover a flag** e modificar o arquivo
- **`restricted`**: Essa flag faz com que o arquivo seja **protegido pelo SIP** (não é possível adicionar essa flag a um arquivo).
- **`Sticky bit`**: Em um diretório com o sticky bit definido, somente o proprietário do arquivo, o proprietário do diretório ou o root pode renomear ou excluir uma entrada. Isso normalmente é habilitado em `/tmp` para impedir que usuários excluam ou movam arquivos de outros usuários.

Todas as flags podem ser encontradas no arquivo `sys/stat.h` (encontre-o usando `mdfind stat.h | grep stat.h`) e são:

- `UF_SETTABLE` 0x0000ffff: Máscara de flags que podem ser alteradas pelo proprietário.
- `UF_NODUMP` 0x00000001: Não fazer dump do arquivo.
- `UF_IMMUTABLE` 0x00000002: O arquivo não pode ser alterado.
- `UF_APPEND` 0x00000004: As gravações no arquivo só podem ser feitas no final.
- `UF_OPAQUE` 0x00000008: O diretório é opaco em relação à união.
- `UF_COMPRESSED` 0x00000020: O arquivo está comprimido (alguns sistemas de arquivos).
- `UF_TRACKED` 0x00000040: Não há notificações de exclusões/renomeações para arquivos com essa flag definida.
- `UF_DATAVAULT` 0x00000080: É necessário entitlement para leitura e escrita.
- `UF_HIDDEN` 0x00008000: Indica que este item não deve ser exibido em uma GUI.
- `SF_SUPPORTED` 0x009f0000: Máscara de flags compatíveis com o superusuário.
- `SF_SETTABLE` 0x3fff0000: Máscara de flags que podem ser alteradas pelo superusuário.
- `SF_SYNTHETIC` 0xc0000000: Máscara de flags sintéticas somente leitura do sistema.
- `SF_ARCHIVED` 0x00010000: O arquivo está arquivado.
- `SF_IMMUTABLE` 0x00020000: O arquivo não pode ser alterado.
- `SF_APPEND` 0x00040000: As gravações no arquivo só podem ser feitas no final.
- `SF_RESTRICTED` 0x00080000: É necessário entitlement para escrever.
- `SF_NOUNLINK` 0x00100000: O item não pode ser removido, renomeado ou montado.
- `SF_FIRMLINK` 0x00800000: O arquivo é um firmlink.
- `SF_DATALESS` 0x40000000: O arquivo é um objeto sem dados.

### **ACLs de Arquivos**

As **ACLs** de arquivos contêm **ACE** (Access Control Entries), onde permissões mais **granulares** podem ser atribuídas a diferentes usuários.

É possível conceder a um **diretório** estas permissões: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Para um **arquivo**: `read`, `write`, `append` e `execute`.

Quando o arquivo contém ACLs, você **encontrará um "+" ao listar as permissões, como em**:
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
Você pode encontrar **todos os arquivos com ACLs** com o seguinte comando (isso é muito lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Extended Attributes

Extended attributes são valores de metadados nomeados armazenados separadamente dos atributos comuns de um arquivo. Liste-os com `ls -l@` e inspecione-os ou modifique-os com `xattr`. <sup>[[5]](#references)</sup> Alguns extended attributes comuns são:

- `com.apple.resourceFork`: Compatibilidade com resource fork. Também visível como `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadados de quarentena do macOS Gatekeeper
- `metadata:*`: Metadados do macOS, como `_backup_excludeItem` ou `kMD*`
- `com.apple.lastuseddate` (#PS): Data do último uso do arquivo
- `com.apple.FinderInfo`: Informações do macOS Finder, como tags de cores
- `com.apple.TextEncoding`: Especifica a codificação de texto de arquivos de texto ASCII
- `com.apple.logd.metadata`: Usado pelo logd em arquivos de `/var/db/diagnostics`
- `com.apple.genstore.*`: Armazenamento generacional (`/.DocumentRevisions-V100` na raiz do sistema de arquivos)
- `com.apple.rootless`: Metadados do macOS associados ao System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Marcações do logd de épocas de inicialização com UUID exclusivo
- `com.apple.decmpfs`: Metadados de compressão transparente de arquivos do macOS
- `com.apple.cprotect`: \*OS: Dados de criptografia por arquivo (III/11)
- `com.apple.installd.*`: \*OS: Metadados usados pelo installd, por exemplo, `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource forks fornecem um alternate data stream no macOS. O conteúdo pode ser armazenado no extended attribute `com.apple.ResourceFork` e acessado por meio de `file/..namedfork/rsrc`.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Você pode **encontrar todos os arquivos que contêm este atributo estendido** com:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

O extended attribute `com.apple.decmpfs` armazena metadados para compressão transparente; ele não indica criptografia. Dependendo do formato de compressão, os dados comprimidos podem ser armazenados no atributo ou em um resource fork e são descomprimidos de forma transparente quando lidos.

A flag `UF_COMPRESSED` aparece como `compressed` em `ls -lO`. Não a remova manualmente: isso pode fazer o sistema interpretar a representação comprimida de forma incorreta.

O comando que remove a flag é mostrado aqui porque é útil durante a análise forense, mas executá-lo em um arquivo comprimido pode fazer com que ele pareça vazio ou fique inacessível até que seus metadados sejam reparados:
```bash
chflags nocompressed /path/to/file
```
O utilitário integrado `/usr/bin/afscexpand` pode forçar a expansão de arquivos compactados de forma transparente. O utilitário de terceiros separado `afsctool` também pode inspecionar ou descompactar a compressão do sistema de arquivos da Apple, mas não deve ser confundido com o comando integrado. <sup>[[8]](#references)</sup>


### Locais de configuração interessantes (macOS)

| Path / Localização | Finalidade / O que configura | Segurança / Potencial de ataque |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Armazena os arquivos plist de feature flags da Apple, que controlam comportamentos opcionais ou experimentais em daemons / frameworks do sistema | Se um atacante puder contornar o SIP ou obter privilégios, adulterá-los poderá ativar caminhos de código ocultos ou desabilitar proteções |
| `/System/Library/CoreServices/systemVersion.plist` | Contém metadados da versão do macOS (ProductVersion, BuildVersion) usados por aplicativos / instaladores para controlar comportamentos | A modificação pode induzir aplicativos ou instaladores a aceitar versões de SO não compatíveis ou desbloquear recursos |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferências de aplicativos / de todo o sistema | Se forem graváveis, atacantes poderão injetar configurações para direcionar o comportamento de aplicativos, desabilitar proteções ou causar configurações incorretas |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definições plist para daemons e agentes em segundo plano | A inserção ou manipulação de plist maliciosos (se as permissões permitirem) possibilita persistência ou escalada de privilégios |
| `/etc/hosts` | Mapeamentos de nomes de host ↔ IP usados pelo resolvedor DNS do sistema | Redirecionamento de nomes de domínio, interceptação de tráfego e spoofing de serviços sob controle local |
| `/etc/sudoers` | Define quem pode executar comandos com `sudo` e sob quais condições | Um arquivo sudoers corrompido pode conceder root ou privilégios indevidos a contas de atacantes |
| `/private/var/db/dslocal/nodes/Default/users/` | Arquivos plist de definição de contas de usuários locais | A adulteração permite criar ou modificar contas de usuário, hashes de senha ou metadados de usuários |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Extensões / drivers do kernel | A instalação ou modificação de kexts pode levar ao controle em nível de kernel; esses elementos são fortemente protegidos pelo SIP / políticas de assinatura |
| `/private/var/db/SystemPolicyConfiguration/` | Armazena a configuração para aplicação das políticas do sistema (por exemplo, Gatekeeper e notarização) | A adulteração pode permitir a evasão de verificações de políticas ou regras de confiança |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binários auxiliares e arquivos de configuração do SSH | Configurações incorretas podem resultar em segurança SSH fraca, acesso não autorizado ou algoritmos inseguros |
| `/System/Library/Sandbox/Profiles` | Perfis de sandbox do sistema (SBPL) usados para restringir ações de processos | Substituir ou alterar perfis pode abrir vetores de escape da sandbox ou enfraquecer a contenção |

> **Nota**: Muitos desses caminhos estão em diretórios protegidos pelo SIP (por exemplo, `/System`) e são protegidos contra gravação, a menos que o SIP esteja desabilitado ou seja contornado.


## Binários universais e formato Mach-O

Mach-O é o formato nativo de executáveis no macOS. Um binário universal, ou fat, encapsula vários slices Mach-O específicos de arquitetura em um único arquivo; a página dedicada explica ambos os formatos:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Dump de memória do macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risco de arquivos e metadados de handlers

LaunchServices, quarentena de arquivos e Gatekeeper influenciam coletivamente como o macOS lida com arquivos baixados e seleciona aplicativos para extensões e esquemas de URL. Seus bancos de dados e arquivos de recursos internos mudam entre versões; use as páginas dedicadas em vez de tratar um caminho privado do CoreTypes como uma interface de política estável:

Nas versões que expõem os metadados de risco legados do CoreTypes em `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, as categorias normalmente encontradas são:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: conteúdo considerado suficientemente seguro para abertura automática de acordo com a política aplicável do aplicativo.
- **`LSRiskCategoryNeutral`**: conteúdo que normalmente não aciona um aviso e não é aberto automaticamente.
- **`LSRiskCategoryUnsafeExecutable`**: conteúdo executável para o qual o usuário deve receber um aviso do aplicativo.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: contêineres, como arquivos compactados, que podem conter conteúdo executável e exigem inspeção adicional.

Esses são detalhes de implementação, não uma API pública de política estável; confirme os metadados reais e o comportamento do Safari/Gatekeeper na versão do macOS em teste.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Arquivos de log

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contém informações sobre arquivos baixados, como a URL de onde foram baixados.
- **Log unificado**: Nas versões atuais do macOS, consulte eventos do sistema e de aplicativos com `log show` e `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** e **`/private/var/log/asl/*.asl`**: Artefatos de logging legados que ainda podem ser relevantes em sistemas mais antigos. Nessas versões, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` configura o `syslogd`; `launchctl list | grep com.apple.syslogd` pode ajudar a determinar se o serviço está carregado.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Armazena arquivos e aplicativos acessados recentemente pelo "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Caminho de preferências legado associado a itens de login; as versões modernas do macOS usam mecanismos adicionais.
- **`$HOME/Library/Logs/DiskUtility.log`**: Log legado do Disk Utility que pode conter informações sobre unidades, incluindo dispositivos USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dados sobre pontos de acesso sem fio.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Dados legados de substituição do launchd.

## References

- [1] [Apple - Guia de programação do sistema de arquivos](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Guia de programação de Bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - visão geral do dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Guia de programação do sistema de arquivos: segurança do sistema de arquivos do macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - página de manual do macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - página de manual do macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - página de manual do macOS](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
