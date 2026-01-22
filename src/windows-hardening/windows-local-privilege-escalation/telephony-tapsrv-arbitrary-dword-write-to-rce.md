# Telephony tapsrv Arbitrary DWORD Write to RCE (TAPI Server Mode)

{{#include ../../banners/hacktricks-training.md}}

When the Windows Telephony service (TapiSrv, `tapisrv.dll`) is configured as a **TAPI server**, it exposes the **`tapsrv` MSRPC interface over the `\pipe\tapsrv` named pipe** to authenticated SMB clients. A design bug in the asynchronous event delivery for remote clients lets an attacker turn a mailslot handle into a **controlled 4-byte write to any pre-existing file writable by `NETWORK SERVICE`**. That primitive can be chained to overwrite the Telephony admin list and abuse an **admin-only arbitrary DLL load** to execute code as `NETWORK SERVICE`.

## Surface d'attaque
- **Exposition distante uniquement si activée** : `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` doit permettre le partage (ou être configuré via `TapiMgmt.msc` / `tcmsetup /c <server>`). Par défaut `tapsrv` est local uniquement.
- Interface : MS-TRP (`tapsrv`) sur **SMB named pipe**, donc l'attaquant a besoin d'une authentification SMB valide.
- Compte de service : `NETWORK SERVICE` (démarrage manuel, à la demande).

## Primitive : Mailslot Path Confusion → Arbitrary DWORD Write
- `ClientAttach(pszDomainUser, pszMachine, ...)` initialise la livraison d'événements asynchrones. En mode pull, le service fait :
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
sans vérifier que `pszDomainUser` est un chemin mailslot (`\\*\MAILSLOT\...`). Tout **chemin de système de fichiers existant** accessible en écriture par `NETWORK SERVICE` est accepté.
- Chaque écriture d'événement asynchrone stocke un seul **`DWORD` = `InitContext`** (contrôlé par l'attaquant dans la requête `Initialize` suivante) sur le handle ouvert, produisant un **write-what/write-where (4 octets)**.

## Forcer des écritures déterministes
1. **Ouvrir le fichier cible** : `ClientAttach` avec `pszDomainUser = <existing writable path>` (par ex., `C:\Windows\TAPI\tsec.ini`).
2. Pour chaque `DWORD` à écrire, exécuter cette séquence RPC contre `ClientRequest` :
- `Initialize` (`Req_Func 47`) : définir `InitContext = <4-byte value>` et `pszModuleName = DIALER.EXE` (ou une autre entrée haute dans la liste de priorité par utilisateur).
- `LRegisterRequestRecipient` (`Req_Func 61`) : `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (enregistre la line app, recalculant le destinataire de plus haute priorité).
- `TRequestMakeCall` (`Req_Func 121`) : force `NotifyHighestPriorityRequestRecipient`, générant l'événement asynchrone.
- `GetAsyncEvents` (`Req_Func 0`) : dépile / complète l'écriture.
- `LRegisterRequestRecipient` de nouveau avec `bEnable = 0` (désenregistre).
- `Shutdown` (`Req_Func 86`) pour démonter la line app.
- Contrôle de priorité : le « highest priority » recipient est choisi en comparant `pszModuleName` avec `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (lu lors de l'impersonation du client). Si nécessaire, insérez votre nom de module via `LSetAppPriority` (`Req_Func 69`).
- Le fichier **doit déjà exister** car `OPEN_EXISTING` est utilisé. Cibles communes accessibles en écriture par `NETWORK SERVICE` : `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.

## De l'écriture DWORD à la RCE dans TapiSrv
1. **S'octroyer le rôle d'admin Telephony** : ciblez `C:\Windows\TAPI\tsec.ini` et ajoutez `[TapiAdministrators]\r\n<DOMAIN\\user>=1` en utilisant les écritures 4-octets ci-dessus. Démarrez une session **nouvelle** (`ClientAttach`) afin que le service relise l'INI et définisse `ptClient->dwFlags |= 9` pour votre compte.
2. **Chargement de DLL réservé aux admins** : envoyez `GetUIDllName` avec `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` et fournissez un chemin via `dwProviderFilenameOffset`. Pour les admins, le service fait `LoadLibrary(path)` puis appelle l'export `TSPI_providerUIIdentify` :
- Fonctionne avec des chemins UNC vers un vrai partage SMB Windows ; certains serveurs SMB mal configurés de l'attaquant échouent avec `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternative : déposer lentement une DLL locale en utilisant la même primitive d'écriture 4-octets, puis la charger.
3. **Payload** : l'export s'exécute sous `NETWORK SERVICE`. Une DLL minimale peut lancer `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` et retourner une valeur non nulle (ex. `0x1337`) pour que le service décharge la DLL, confirmant l'exécution.

## Renforcement / Notes de détection
- Désactivez le mode TAPI server sauf si nécessaire ; bloquez l'accès distant à `\pipe\tapsrv`.
- Validez le namespace mailslot (`\\*\MAILSLOT\`) avant d'ouvrir des chemins fournis par le client.
- Verrouillez les ACLs de `C:\Windows\TAPI\tsec.ini` et surveillez les modifications ; alertez sur les appels `GetUIDllName` chargeant des chemins non par défaut.

## Références
- [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
