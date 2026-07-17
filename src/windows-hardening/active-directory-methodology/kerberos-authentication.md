# Authentification Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Consultez l’excellent article de :** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR pour les attaquants
- Kerberos est le protocole d’authentification AD par défaut ; la plupart des chaînes de mouvement latéral l’utilisent.
- Pensez en **trois phases opérateur** :
- **AS-REQ / AS-REP** → utiliser un mot de passe/hash/certificat pour obtenir un **TGT**. C’est ici qu’interviennent **AS-REP roasting**, **over-pass-the-hash / pass-the-key** et **PKINIT**.
- **TGS-REQ / TGS-REP** → utiliser un TGT pour obtenir des **tickets de service**. C’est ici que **Kerberoasting**, **S4U abuse**, **delegation abuse** et la plupart des techniques de **ticket-forging** deviennent pertinentes.
- **AP-REQ / AP-REP** → présenter le ticket au service. C’est ici qu’interviennent **pass-the-ticket** et le mouvement latéral spécifique au service.
- Pour des cheatsheets pratiques (AS-REP/Kerberoasting, ticket forgery, delegation abuse, etc.), consultez :
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Utilisez cette page comme index **général / « ce qui a changé récemment »**, puis consultez les pages dédiées à [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) ou [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Notes d’attaque récentes (2024-2026)
- **Le hardening de RC4 a modifié les valeurs par défaut, pas Kerberos lui-même** – le hardening moderne des DC se concentre sur les **types de chiffrement considérés par défaut** pour les comptes qui ne définissent pas explicitement `msDS-SupportedEncryptionTypes`. Après le déploiement de 2026, ces comptes utilisent de plus en plus AES uniquement sur les DC patchés ; les hypothèses de Kerberoast basées aveuglément sur `/rc4` échouent donc plus souvent. Cependant, les comptes de service explicitement activés pour RC4 restent d’excellentes cibles pour le crack offline.
- **L’application de la validation PAC est importante pour les tickets forgés** – le hardening des signatures PAC de 2024 signifie que les abus de type **golden/diamond/sapphire/extraSID** nécessitent des données PAC plus réalistes et le contexte de signature correct. Les domaines non patchés ou laissés dans des déploiements de compatibilité/audit restent des cibles plus faciles.
- **Kerberos basé sur les certificats a changé deux fois** :
- Le **strong certificate binding** (chronologie de KB5014754) rend les mappings certificat-compte imprécis moins fiables dans les environnements où l’application est pleinement activée.
- **CVE-2025-26647** a ajouté une couche de hardening autour des mappings de certificats **altSecID / SKI**. Si les DC ne sont pas patchés, sont encore en mode audit ou contournent explicitement la validation NTAuth, les abus consécutifs de pass-the-certificate / shadow-credential restent plus pratiques.
- **Les abus de delegation cross-domain / cross-forest restent très actuels** – Windows prend en charge les flux modernes **S4U2Self/S4U2Proxy** cross-realm ; les attributs de delegation modifiables dans un autre domaine restent donc précieux. Le principal obstacle est généralement la fidélité des outils et les détails liés aux trusts/policies, pas la prise en charge du protocole.
- **Le RBCD récursif sur plusieurs domaines est important sur le plan opérationnel** – dans les forêts comportant au moins 3 domaines, **S4U2Self/S4U2Proxy** peut se poursuivre à travers les referrals de trust, et les abus **SPN-less** peuvent nécessiter un dernier saut **`S4U2Self+U2U`** ainsi qu’une gestion des tickets dépendante de RC4. Consultez [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- **Windows Server 2025 a introduit une nouvelle surface d’attaque adjacente à Kerberos** via la logique de migration **dMSA**. Si vous observez des droits délégués sur des OU ou des objets de comptes de service dans un domaine 2025, consultez plutôt la [page BadSuccessor](acl-persistence-abuse/BadSuccessor.md) dédiée au lieu de considérer cela comme « encore un gMSA ».

## Vérifications rapides de l’opérateur dans les domaines modernes

Avant de choisir une voie d’attaque Kerberos, répondez rapidement à quatre questions :

1. **Quels comptes sont encore compatibles avec RC4 ?**
2. **Quels utilisateurs n’exigent pas de pre-auth ?**
3. **Quels objets exposent un delegation abuse ?**
4. **Quelles parties du domaine sont suffisamment récentes pour appliquer le hardening récent ?**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
Interprétation pratique :
- Si les comptes **SPN intéressants sont explicitement capables d'utiliser RC4**, le Kerberoasting reste peu coûteux et rapide.
- Si la plupart des comptes de service n'ont **aucune configuration d'etype explicite**, attendez-vous à un comportement **AES-only** sur les DC mis à jour en 2026 et prévoyez un cracking offline plus lent ou une autre approche.
- Si **RBCD / KCD / unconstrained delegation** est présent, S4U est souvent plus efficace que le brute-force.
- Si l'**authentification par certificat** est utilisée, rappelez-vous qu'un échec de la méthode PKINIT ne signifie **pas toujours** que le certificat est inutilisable ; dans de nombreux environnements, le même certificat fonctionne toujours pour exploiter **Schannel/LDAPS** (voir [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Erreurs Kerberos courantes qui modifient le plan d'attaque
- **`KDC_ERR_ETYPE_NOTSUPP`** → Le compte cible / DC n'utilisera pas le type de chiffrement demandé. Arrêtez de réessayer uniquement avec RC4 ; fournissez des **clés AES** ou demandez plutôt du matériel de roast **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Vous avez probablement la **mauvaise clé de service**, le **mauvais SPN**, ou un ticket forgé qui ne correspond pas au compte de service qui le déchiffre réellement.
- **`KRB_AP_ERR_SKEW`** → Votre horloge n'est pas synchronisée. Synchronisez-la avec le DC avant de diagnostiquer quoi que ce soit d'autre.
- **`KDC_ERR_BADOPTION`** pendant les flux S4U / delegation → signifie souvent la présence d'**utilisateurs sensibles/non délégables**, l'utilisation du mauvais modèle de delegation, ou une tentative de réaliser du **classic KCD** alors que seul **RBCD** accepterait un ticket S4U2Self non forwardable.

## Références
- [Microsoft Learn - Détecter et corriger l'utilisation de RC4 dans Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Dernières recommandations de hardening Windows et dates clés](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
