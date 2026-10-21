# Arquivos, pastas, binários e memória do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Hierarquia do sistema de arquivos

A Apple documenta o sistema de arquivos do macOS como uma hierarquia de domínios de sistema, local, de rede e de usuário. O conteúdo exato varia conforme a versão do sistema operacional, e os locais do sistema estão cada vez mais protegidos ou são sintetizados. <sup>[[1]](#references)</sup>

- **/Applications**: Os apps instalados devem estar aqui. Todos os usuários poderão acessá-los.
- **/bin**: Binários de linha de comando
- **/cores**: Se existir, é usado para armazenar core dumps
- **/dev**: Tudo é tratado como arquivo, então você pode encontrar dispositivos de hardware armazenados aqui.
- **/etc**: Arquivos de configuração
- **/Library**: Muitos subdiretórios e arquivos relacionados a preferências, caches e logs podem ser encontrados aqui. Há uma pasta Library na raiz e no diretório de cada usuário.
- **/private**: Não documentado, mas muitas das pastas mencionadas são links simbólicos para o diretório private.
- **/sbin**: Binários essenciais do sistema (relacionados à administração)
- **/System**: Arquivos necessários ao macOS; essa árvore contém principalmente componentes fornecidos pela Apple.
- **/tmp**: Arquivos temporários (um link simbólico para `/private/tmp`). Historicamente, as instalações limpavam arquivos temporários antigos periodicamente, às vezes em intervalos descritos como três dias, mas o momento da limpeza atual depende do sistema e das políticas; não conte com a persistência dos dados nesse local.
- **/Users**: Diretório pessoal dos usuários.
- **/usr**: Configurações e binários do sistema
- **/var**: Arquivos de log
- **/Volumes**: Os volumes montados aparecem aqui.
- **/.vol**: Ao executar `stat a.txt`, você obtém algo como `16777223 7545753 -rw-r--r-- 1 username wheel ...`, em que o primeiro número é o ID do volume onde o arquivo está e o segundo é o número do inode. Você pode acessar o conteúdo desse arquivo por meio de /.vol/ com essas informações, executando `cat /.vol/16777223/7545753`

### Pastas de aplicativos

- Os **aplicativos do sistema** estão em `/System/Applications`
- Os aplicativos **instalados** geralmente são instalados em `/Applications` ou em `~/Applications`
- Os **dados dos aplicativos** podem ser encontrados em `/Library/Application Support` para aplicativos executados como root e em `~/Library/Application Support` para aplicativos executados como usuário.
- Os **daemons** de aplicativos de terceiros que **precisam ser executados como root** geralmente estão em `/Library/PrivilegedHelperTools/`.
- Os apps em **sandbox** são mapeados para a pasta `~/Library/Containers`. Cada app tem uma pasta cujo nome corresponde ao ID do bundle do aplicativo (`com.apple.Safari`).
- O **kernel** está em `/System/Library/Kernels/kernel`
- As **extensões de kernel da Apple** estão em `/System/Library/Extensions`
- As **extensões de kernel de terceiros** são armazenadas em `/Library/Extensions`

### Arquivos com informações confidenciais

O macOS armazena informações confidenciais, incluindo credenciais, em vários locais:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Instaladores pkg vulneráveis


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Para entender a diferença entre o volume Data gravável e o volume System selado visível nessa hierarquia, consulte [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## Extensões específicas do OS X

- **`.dmg`**: Arquivos de imagem de disco da Apple são muito comuns em instaladores.
- **`.kext`**: Deve seguir uma estrutura específica e é a versão do OS X de um driver. (é um bundle)
- **`.plist`**: Uma property list armazena informações estruturadas em formato XML ou binário.
  - Pode ser XML ou binário. Os arquivos binários podem ser lidos com:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Um bundle de aplicativo que segue a estrutura de diretórios padrão do macOS.
- **`.dylib`**: Bibliotecas dinâmicas (como os arquivos DLL do Windows)
- **`.pkg`**: Os pacotes de instalação flat modernos são arquivos XAR, mas `.pkg` é um formato de instalador, não um sinônimo de XAR. Pacotes de instalação mais antigos, no formato bundle, são diretórios. Consulte [macOS installers](macos-installers-abuse.md) para ver a estrutura e a inspeção de pacotes. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Esse arquivo existe em cada diretório e salva os atributos e as personalizações do diretório.
- **`.Spotlight-V100`**: Essa pasta aparece no diretório raiz de cada volume do sistema.
- **`.metadata_never_index`**: Se esse arquivo estiver na raiz de um volume, o Spotlight não indexará esse volume.
- **`.noindex`**: Arquivos e pastas com essa extensão não serão indexados pelo Spotlight.
- **`.sdef`**: Um arquivo de definição de scripts que descreve como o AppleScript pode interagir com um aplicativo.

### Bundles do macOS

Um bundle é um diretório com uma hierarquia padronizada que o Finder pode apresentar como um único objeto; os bundles de aplicativos usam a extensão `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Cache de bibliotecas compartilhadas do Dyld (SLC)

No macOS e no iOS, bibliotecas e frameworks do sistema usados com frequência são pré-vinculados no **cache compartilhado do dyld**, o que melhora o desempenho de inicialização dos aplicativos. Embora seja tratado como um único cache lógico, as versões atuais podem armazená-lo como um cache principal e vários arquivos de subcache, em vez de literalmente em um único arquivo. Seu formato e localização são detalhes de implementação que mudam entre versões do sistema operacional. <sup>[[3]](#references)</sup>

No macOS, ele está localizado em `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`; em versões mais antigas, talvez seja possível encontrar o **cache compartilhado** em **`/System/Library/dyld/`**.\
No iOS, você pode encontrá-lo em **`/System/Library/Caches/com.apple.dyld/`**.

Assim como o cache compartilhado do dyld, o kernel e as extensões de kernel também são compilados em um cache de kernel, que é carregado durante a inicialização.

Em versões mais antigas, era possível extrair o cache com [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Essa build talvez não ofereça suporte aos formatos atuais de cache; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) é outra opção:

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Observe que, mesmo que a ferramenta `dyld_shared_cache_util` não funcione, você pode passar o **binário dyld compartilhado para o Hopper**, e o Hopper poderá identificar todas as bibliotecas e permitir que você **selecione qual** deseja investigar:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Alguns extractors não funcionarão, pois as dylibs são pré-vinculadas com endereços codificados; por isso, podem saltar para endereços desconhecidos.

> [!TIP]
> Também é possível baixar o Shared Library Cache de outros dispositivos \*OS no macOS usando um emulador no Xcode. Eles serão baixados em: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, como:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapeamento do SLC

**`dyld`** usa a syscall **`shared_region_check_np`** para verificar se o SLC foi mapeado (o que retorna o endereço) e **`shared_region_map_and_slide_np`** para mapear o SLC.

Observe que, mesmo que o SLC seja slid no primeiro uso, todos os **processos** usam a **mesma cópia**, o que **eliminou a proteção ASLR** se o atacante conseguisse executar processos no sistema. Isso foi explorado no passado e corrigido com o shared region pager.

Branch pools são pequenas dylibs Mach-O que criam pequenos espaços entre os mapeamentos de imagens, impossibilitando a interposição das funções.

### Restrições do ambiente de shared cache

`DYLD_SHARED_CACHE_DIR` indica um diretório de cache, enquanto `DYLD_SHARED_REGION` seleciona um modo de shared region. A grafia anterior `DYLD_DHARED_REGION` era inválida, e `avoid` não é um valor válido para `DYLD_SHARED_CACHE_DIR`. O dyld atual restringe o modo `private` à permissão do AMFI para usar shared caches personalizados; portanto, definir apenas variáveis de ambiente não garante que um processo possa carregar um cache substituto. <sup>[[10]](#references)</sup>

## Permissões especiais de arquivos

### Permissões de pastas

Para um diretório, **read** permite listar entradas, **write** permite criar ou remover entradas, e **execute** permite percorrê-lo. Consequentemente, um usuário que pode ler um arquivo, mas não pode percorrer um diretório pai, não consegue acessar esse arquivo pelo caminho. <sup>[[4]](#references)</sup>

### Modificadores de flags

Arquivos podem ter flags que alteram seu comportamento. Inspecione as flags de um diretório com `ls -lO /path/directory`.

- **`uchg`**: Conhecida como flag **uchange**, ela **impede qualquer ação** que altere ou exclua o **arquivo**. Para defini-la, use: `chflags uchg file.txt`
  - O proprietário do arquivo ou o root pode remover essa flag de **usuário** com `chflags nouchg file.txt`; ela não protege contra nenhum dos dois. A flag imutável de **sistema** separada (`schg`) é restrita ao root. <sup>[[11]](#references)</sup>
- **`restricted`**: Essa flag faz com que o arquivo seja **protegido pelo SIP** (não é possível adicionar essa flag a um arquivo).
- **`Sticky bit`**: Em um diretório com sticky bit definido, somente o proprietário do arquivo, o proprietário do diretório ou o root pode renomear ou excluir uma entrada. Isso costuma estar habilitado em `/tmp` para impedir que usuários excluam ou movam arquivos de outros usuários.

Todas as flags podem ser encontradas no arquivo `sys/stat.h` (localize-o usando `mdfind stat.h | grep stat.h`) e são:

- `UF_SETTABLE` 0x0000ffff: Máscara de flags que podem ser alteradas pelo proprietário.
- `UF_NODUMP` 0x00000001: Não despejar o arquivo.
- `UF_IMMUTABLE` 0x00000002: O arquivo não pode ser alterado.
- `UF_APPEND` 0x00000004: Só é possível adicionar conteúdo ao arquivo.
- `UF_OPAQUE` 0x00000008: O diretório é opaco em relação à união.
- `UF_COMPRESSED` 0x00000020: O arquivo está comprimido (em alguns sistemas de arquivos).
- `UF_TRACKED` 0x00000040: Não enviar notificações de exclusão/renomeação para arquivos com essa flag definida.
- `UF_DATAVAULT` 0x00000080: É necessário um entitlement para ler e gravar.
- `UF_HIDDEN` 0x00008000: Indica que esse item não deve ser exibido em uma GUI.
- `SF_SUPPORTED` 0x009f0000: Máscara de flags compatíveis com superusuário.
- `SF_SETTABLE` 0x3fff0000: Máscara de flags que podem ser alteradas pelo superusuário.
- `SF_SYNTHETIC` 0xc0000000: Máscara de flags sintéticas somente leitura do sistema.
- `SF_ARCHIVED` 0x00010000: O arquivo está arquivado.
- `SF_IMMUTABLE` 0x00020000: O arquivo não pode ser alterado.
- `SF_APPEND` 0x00040000: Só é possível adicionar conteúdo ao arquivo.
- `SF_RESTRICTED` 0x00080000: É necessário um entitlement para gravar.
- `SF_NOUNLINK` 0x00100000: O item não pode ser removido, renomeado ou montado.
- `SF_FIRMLINK` 0x00800000: O arquivo é um firmlink.
- `SF_DATALESS` 0x40000000: O arquivo é um objeto sem dados.

### **ACLs de arquivos**

As **ACLs** de arquivos contêm **ACE** (entradas de controle de acesso), que permitem atribuir **permissões mais granulares** a diferentes usuários.

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

Você pode encontrar **todos os arquivos com ACLs** usando o seguinte comando (isso é muito lento):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Atributos estendidos

Atributos estendidos são valores de metadados nomeados armazenados separadamente dos atributos comuns de um arquivo. Liste-os com `ls -l@` e inspecione-os ou modifique-os com `xattr`. <sup>[[5]](#references)</sup> Alguns atributos estendidos comuns são:

- `com.apple.resourceFork`: Compatibilidade com resource fork. Também visível como `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadados de quarentena do Gatekeeper do macOS
- `metadata:*`: Metadados do macOS, como `_backup_excludeItem` ou `kMD*`
- `com.apple.lastuseddate` (#PS): Data do último uso do arquivo
- `com.apple.FinderInfo`: Informações do Finder do macOS, como tags de cor
- `com.apple.TextEncoding`: Especifica a codificação de texto de arquivos de texto ASCII
- `com.apple.logd.metadata`: Usado pelo logd em arquivos em `/var/db/diagnostics`
- `com.apple.genstore.*`: Armazenamento geracional (`/.DocumentRevisions-V100` na raiz do sistema de arquivos)
- `com.apple.rootless`: Metadados do macOS associados à System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Marcações do logd de épocas de inicialização com UUID exclusivo
- `com.apple.decmpfs`: Metadados de compressão transparente de arquivos do macOS
- `com.apple.cprotect`: \*OS: Dados de criptografia por arquivo (III/11)
- `com.apple.installd.*`: \*OS: Metadados usados pelo installd, por exemplo, `installType`, `uniqueInstallID`

### Resource Forks | ADS do macOS

Resource forks fornecem um fluxo de dados alternativo no macOS. O conteúdo pode ser armazenado no atributo estendido `com.apple.ResourceFork` e acessado por meio de `file/..namedfork/rsrc`.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

Você pode **encontrar todos os arquivos que contêm esse atributo estendido** com:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

O atributo estendido `com.apple.decmpfs` armazena metadados para compressão transparente; ele não indica criptografia. Dependendo do formato de compressão, os dados comprimidos podem ser armazenados no atributo ou em um resource fork e são descomprimidos de forma transparente durante a leitura.

A flag `UF_COMPRESSED` aparece como `compressed` em `ls -lO`. Não a remova manualmente: isso pode fazer com que o sistema interprete incorretamente a representação comprimida.

O comando que limpa a flag é mostrado aqui porque é útil durante uma análise forense, mas executá-lo em um arquivo comprimido pode fazer com que ele pareça vazio ou fique inacessível até que seus metadados sejam reparados:

```bash
chflags nocompressed /path/to/file
```

O utilitário integrado `/usr/bin/afscexpand` pode forçar a expansão de arquivos compactados de forma transparente. O utilitário de terceiros `afsctool` também pode inspecionar ou descompactar arquivos com compressão do sistema de arquivos da Apple, mas não deve ser confundido com o comando integrado. <sup>[[8]](#references)</sup>


### Locais de configuração interessantes (macOS)

| Caminho / Localização | Finalidade / O que configura | Segurança / Potencial de ataque |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Armazena arquivos plist de sinalizadores de recursos da Apple que controlam comportamentos opcionais ou experimentais em daemons / frameworks do sistema | Se um atacante puder contornar o SIP ou obter privilégios, adulterar esses arquivos pode habilitar caminhos de código ocultos ou desativar proteções |
| `/System/Library/CoreServices/systemVersion.plist` | Contém metadados da versão do macOS (ProductVersion, BuildVersion) usados por apps / instaladores para controlar comportamentos | A modificação pode enganar apps ou instaladores, fazendo-os aceitar versões do SO não suportadas ou desbloquear recursos |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferências de aplicativos / sistema | Se puderem ser gravadas, atacantes podem injetar configurações para direcionar o comportamento de apps, desativar proteções ou causar configurações incorretas |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definições plist para daemons e agentes em segundo plano | A inserção ou manipulação de plist (se as permissões permitirem) possibilita persistência ou escalonamento de privilégios |
| `/etc/hosts` | Mapeamentos de nomes de host ↔ IP usados pelo resolvedor DNS do sistema | Redirecionamento de nomes de domínio, interceptação de tráfego e falsificação de serviços sob controle local |
| `/etc/sudoers` | Define quem pode executar comandos com `sudo` e em quais condições | Um arquivo sudoers corrompido pode conceder acesso root ou privilégios indevidos a contas de atacantes |
| `/private/var/db/dslocal/nodes/Default/users/` | Arquivos plist de definição de contas de usuário locais | A adulteração permite criar ou modificar contas de usuário, hashes de senha ou metadados de usuário |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Extensões do kernel / drivers | Instalar ou modificar kexts pode levar ao controle no nível do kernel; há forte proteção por políticas de SIP / assinatura |
| `/private/var/db/SystemPolicyConfiguration/` | Armazena configurações para aplicação de políticas do sistema (por exemplo, Gatekeeper, notarização) | Adulterar esses arquivos pode permitir contornar verificações de política ou regras de confiança |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binários auxiliares e arquivos de configuração do SSH | Configurações incorretas podem levar a uma segurança SSH fraca, acesso não autorizado ou algoritmos inseguros |
| `/System/Library/Sandbox/Profiles` | Perfis de sandbox do sistema (SBPL) usados para restringir ações de processos | Substituir ou alterar perfis pode abrir vetores de escape da sandbox ou enfraquecer o isolamento |

> **Nota**: Muitos desses caminhos ficam em diretórios protegidos pelo SIP (por exemplo, `/System`) e não podem ser gravados, a menos que o SIP seja desativado ou contornado.  


## Binários universais e formato Mach-O

Mach-O é o formato nativo de executáveis no macOS. Um binário universal, ou fat, reúne vários slices Mach-O específicos de arquitetura em um único arquivo; a página dedicada explica os dois formatos:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Dump de memória do macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risco de arquivos e metadados de handlers

LaunchServices, a quarentena de arquivos e o Gatekeeper influenciam conjuntamente a forma como o macOS lida com arquivos baixados e seleciona aplicativos para extensões e esquemas de URL. Seus bancos de dados e arquivos de recursos internos mudam entre versões; consulte as páginas dedicadas, em vez de tratar um caminho privado de CoreTypes como uma interface estável de políticas:

Nas versões que expõem os metadados legados de risco de CoreTypes em `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, as categorias mais comuns são:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: conteúdo considerado suficientemente seguro para abertura automática, conforme a política aplicável do aplicativo.
- **`LSRiskCategoryNeutral`**: conteúdo que normalmente não aciona um aviso e não é aberto automaticamente.
- **`LSRiskCategoryUnsafeExecutable`**: conteúdo executável para o qual o usuário deve receber um aviso do aplicativo.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: contêineres, como arquivos compactados, que podem conter conteúdo executável e exigem inspeção adicional.

Esses são detalhes de implementação, não uma API pública e estável de políticas; confirme os metadados reais e o comportamento do Safari/Gatekeeper na versão do macOS em teste.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Arquivos de log

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contém informações sobre arquivos baixados, como a URL de onde foram baixados.
- **Log unificado**: Nas versões atuais do macOS, consulte eventos do sistema e de aplicativos com `log show` e `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** e **`/private/var/log/asl/*.asl`**: Artefatos de log legados que ainda podem ser relevantes em sistemas mais antigos. Nessas versões, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` configura o `syslogd`; `launchctl list | grep com.apple.syslogd` pode ajudar a determinar se o serviço está carregado.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Armazena arquivos e aplicativos acessados recentemente pelo "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Caminho de preferência legado associado aos itens de início de sessão; as versões modernas do macOS usam mecanismos adicionais.
- **`$HOME/Library/Logs/DiskUtility.log`**: Log legado do Utilitário de Disco que pode conter informações sobre unidades, incluindo dispositivos USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dados sobre pontos de acesso sem fio.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Dados legados de substituição do launchd.



## References

- [1] [Apple - Guia de programação do sistema de arquivos](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Guia de programação de bundles](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Fóruns de desenvolvedores da Apple - Visão geral do cache compartilhado do dyld](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Guia de programação do sistema de arquivos: segurança do sistema de arquivos do macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - página de manual do macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - página de manual do macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - página de manual do macOS](https://manp.gs/mac/1/afscexpand)
- [9] [Fóruns de desenvolvedores da Apple - Descompactando arquivos Apple](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Segurança de scripts de shell: sinalizadores especiais de permissão de arquivo](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Tarefas de assinatura de código: pacotes do instalador](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
