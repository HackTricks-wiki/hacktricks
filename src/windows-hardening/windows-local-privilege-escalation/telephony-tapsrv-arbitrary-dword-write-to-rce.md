# Écriture DWORD arbitraire de tapsrv Telephony vers RCE (mode TAPI Server)

{{#include ../../banners/hacktricks-training.md}}

Lorsque le service Windows Telephony (TapiSrv, `tapisrv.dll`) est configuré comme **TAPI server**, il expose l’interface **`tapsrv` MSRPC via le named pipe `\pipe\tapsrv`** aux clients SMB authentifiés. Un bug de conception dans la livraison des événements asynchrones pour les clients distants permet à un attaquant de transformer un handle de mailslot en **écriture contrôlée de 4 octets vers n’importe quel fichier préexistant accessible en écriture par `NETWORK SERVICE`**. Cette primitive peut être chaînée pour écraser la liste des administrateurs Telephony et exploiter un **chargement arbitraire de DLL réservé aux admins** afin d’exécuter du code sous le compte `NETWORK SERVICE`.<sup>[[1]](#references)</sup>

## Surface d’attaque

- **Exposition distante uniquement lorsque la fonctionnalité est activée** : `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\Server\DisableSharing` doit autoriser le partage (ou être configurée via `TapiMgmt.msc` / `tcmsetup /c <server>`). Par défaut, `tapsrv` est limité à l’accès local.
- Interface : MS-TRP (`tapsrv`) via un **named pipe SMB** ; l’attaquant doit donc disposer d’une authentification SMB valide.
- Compte de service : `NETWORK SERVICE` (démarrage manuel, à la demande).<sup>[[1]](#references)</sup>

## Primitive : Confusion du chemin de mailslot → écriture DWORD arbitraire
- `ClientAttach(pszDomainUser, pszMachine, ...)` initialise la livraison des événements asynchrones. En mode pull, le service exécute :
```c
CreateFileW(pszDomainUser, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
```
sans vérifier que `pszDomainUser` est un chemin de mailslot (`\\*\MAILSLOT\...`). Tout **chemin de système de fichiers existant** accessible en écriture par `NETWORK SERVICE` est accepté.
- Chaque écriture d’événement asynchrone stocke un seul **`DWORD` = `InitContext`** (contrôlé par l’attaquant dans la requête `Initialize` suivante) dans le handle ouvert, ce qui fournit une primitive **write-what/write-where (4 octets)**.<sup>[[1]](#references)</sup>

## Forcer des écritures déterministes
1. **Ouvrir le fichier cible** : appeler `ClientAttach` avec `pszDomainUser = <existing writable path>` (par exemple, `C:\Windows\TAPI\tsec.ini`).
2. Pour chaque `DWORD` à écrire, exécuter cette séquence RPC via `ClientRequest` :
- `Initialize` (`Req_Func 47`) : définir `InitContext = <4-byte value>` et `pszModuleName = DIALER.EXE` (ou une autre entrée située en tête de la liste de priorité par utilisateur).
- `LRegisterRequestRecipient` (`Req_Func 61`) : `dwRequestMode = LINEREQUESTMODE_MAKECALL`, `bEnable = 1` (enregistre l’application de ligne et recalcule le destinataire de priorité le plus élevée).
- `TRequestMakeCall` (`Req_Func 121`) : force `NotifyHighestPriorityRequestRecipient`, ce qui génère l’événement asynchrone.
- `GetAsyncEvents` (`Req_Func 0`) : retire l’événement et termine l’écriture.
- Appeler à nouveau `LRegisterRequestRecipient` avec `bEnable = 0` (désenregistrement).
- `Shutdown` (`Req_Func 86`) pour démanteler l’application de ligne.
- Contrôle de priorité : le destinataire de « priorité la plus élevée » est sélectionné en comparant `pszModuleName` avec `HKCU\Software\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\RequestMakeCall` (lu pendant l’impersonation du client). Si nécessaire, insérer le nom du module via `LSetAppPriority` (`Req_Func 69`).
- Le fichier **doit déjà exister**, car `OPEN_EXISTING` est utilisé. Exemples courants de fichiers accessibles en écriture par `NETWORK SERVICE` : `C:\Windows\System32\catroot2\dberr.txt`, `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\MpCmdRun.log`, `...\MpSigStub.log`.<sup>[[1]](#references)</sup>

## De l’écriture DWORD à la RCE dans TapiSrv
1. **S’accorder les droits d’admin Telephony** : cibler `C:\Windows\TAPI\tsec.ini` et ajouter `[TapiAdministrators]\r\n<DOMAIN\\user>=1` à l’aide des écritures de 4 octets ci-dessus. Démarrer une **nouvelle** session (`ClientAttach`) afin que le service relise le fichier INI et définisse `ptClient->dwFlags |= 9` pour votre compte.
2. **Chargement de DLL réservé aux admins** : envoyer `GetUIDllName` avec `dwObjectType = TUISPIDLL_OBJECT_PROVIDERID` et fournir un chemin via `dwProviderFilenameOffset`. Pour les admins, le service exécute `LoadLibrary(path)`, puis appelle l’export `TSPI_providerUIIdentify` :
- Fonctionne avec des chemins UNC vers un partage SMB Windows réel ; certains serveurs SMB de l’attaquant échouent avec `ERROR_SMB_GUEST_LOGON_BLOCKED`.
- Alternative : déposer lentement une DLL locale à l’aide de la même primitive d’écriture de 4 octets, puis la charger.
3. **Payload** : l’export s’exécute sous le compte `NETWORK SERVICE`. Une DLL minimale peut lancer `cmd.exe /c whoami /all > C:\Windows\Temp\poc.txt` et retourner une valeur non nulle (par exemple `0x1337`) afin que le service décharge la DLL, confirmant ainsi l’exécution.<sup>[[1]](#references)</sup>

## Notes de hardening / détection
- Désactiver le mode TAPI server sauf nécessité ; bloquer l’accès distant à `\pipe\tapsrv`.
- Imposer la validation de l’espace de noms des mailslots (`\\*\MAILSLOT\`) avant d’ouvrir les chemins fournis par le client.
- Renforcer les ACL de `C:\Windows\TAPI\tsec.ini` et surveiller les modifications ; générer une alerte lors des appels à `GetUIDllName` chargeant des chemins non standards.<sup>[[1]](#references)</sup>

## Références

- [1] [Who’s on the line? Exploiting RCE in Windows Telephony Service (CVE-2026-20931)](https://swarm.ptsecurity.com/whos-on-the-line-exploiting-rce-in-windows-telephony-service/)

{{#include ../../banners/hacktricks-training.md}}
