# Authentification Kerberos

{{#include ../../banners/hacktricks-training.md}}

Pour une présentation détaillée au niveau du protocole des échanges résumés ci-dessous, consultez l'article de Tarlogic sur Kerberos.<sup>[[3]](#references)</sup>

## TL;DR pour les attaquants
- Kerberos est le protocole d'authentification AD par défaut ; la plupart des chaînes de mouvement latéral l'utiliseront.
- Pensez en **trois phases opérateur** :<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → utiliser un mot de passe/hash/certificat pour obtenir un **TGT**. C'est ici qu'interviennent **AS-REP roasting**, **over-pass-the-hash / pass-the-key** et **PKINIT**.
- **TGS-REQ / TGS-REP** → utiliser un TGT pour obtenir des **service tickets**. C'est ici qu'interviennent **Kerberoasting**, **S4U abuse**, **delegation abuse** et la plupart des techniques de **ticket-forging**.
- **AP-REQ / AP-REP** → présenter le ticket au service. C'est ici qu'interviennent **pass-the-ticket** et le mouvement latéral spécifique au service.
- Pour des cheatsheets pratiques (AS-REP/Kerberoasting, ticket forgery, delegation abuse, etc.), consultez :
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Utilisez cette page comme index de **vue d'ensemble / « ce qui a changé récemment »**, puis consultez les pages dédiées à [Kerberoast](kerberoast.md), à la [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), à [AD Certificates / PKINIT abuse](ad-certificates.md) ou à [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Notes d'attaque récentes (2024-2026)
- **Le durcissement de RC4 a modifié les valeurs par défaut, pas Kerberos lui-même** – le durcissement moderne des DC se concentre sur les **types de chiffrement supposés par défaut** pour les comptes qui ne définissent pas explicitement `msDS-SupportedEncryptionTypes`. Après le déploiement de 2026, ces comptes utilisent de plus en plus **AES-only** par défaut sur les DC corrigés ; les hypothèses aveugles de Kerberoast avec `/rc4` échouent donc plus souvent. Cependant, les comptes de service **explicitement activés pour RC4 restent d'excellentes cibles pour le crack offline**.<sup>[[1]](#references)</sup>
- **L'application de la validation PAC est importante pour les forged tickets** – le durcissement des signatures PAC de 2024 signifie que les abus de type **golden/diamond/sapphire/extraSID** nécessitent des données PAC plus réalistes et le contexte de signature approprié. Les domaines non corrigés ou laissés dans des déploiements de compatibilité/audit restent des cibles plus vulnérables.<sup>[[2]](#references)</sup>
- **Kerberos basé sur les certificats a changé deux fois** :
- **Strong certificate binding** (calendrier de KB5014754) rend les associations certificat-compte approximatives moins fiables dans les environnements où l'application est pleinement activée.
- **CVE-2025-26647** a ajouté une couche de durcissement supplémentaire autour des associations `altSecurityIdentities` qui utilisent le Subject Key Identifier d'un certificat. Le niveau de correctifs, l'état d'application ou d'audit et la configuration explicite des associations sont donc importants lors de l'évaluation de **pass-the-certificate** et des chemins associés basés sur les certificats.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Pour PKINIT, le KDC valide également le chemin du certificat et vérifie que l'émetteur est approuvé via le magasin NTAuth.<sup>[[8]](#references)</sup>
- **L'abus de delegation cross-domain / cross-forest est toujours bien réel** – Windows prend en charge les flux modernes **S4U2Self/S4U2Proxy** entre realms ; les attributs de delegation modifiables dans un autre domaine restent donc précieux. Le principal obstacle réside généralement dans la fidélité des outils et les détails liés aux relations d'approbation et aux stratégies, et non dans la prise en charge du protocole.
- **La RBCD récursive sur plusieurs domaines est importante en pratique** – dans les forêts comportant au moins 3 domaines, **S4U2Self/S4U2Proxy** peut se propager via les referrals d'approbation, et un abus **SPN-less** peut nécessiter un dernier saut **`S4U2Self+U2U`**, ainsi qu'une gestion des tickets dépendante de RC4. Consultez [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 a introduit les Managed Service Accounts délégués (dMSA)** ainsi que leur logique de migration. Si vous observez des droits délégués sur des OU ou des objets de comptes de service dans un domaine 2025, consultez plutôt la [page BadSuccessor](acl-persistence-abuse/BadSuccessor.md) dédiée au lieu de considérer cela comme « juste un autre gMSA ».<sup>[[7]](#references)</sup>

## Vérifications rapides pour l'opérateur dans les domaines modernes

Avant de choisir un chemin d'attaque Kerberos, répondez rapidement à quatre questions :

1. **Quels comptes sont encore compatibles avec RC4 ?**
2. **Quels utilisateurs ne nécessitent pas de pré-authentification ?**
3. **Quels objets exposent un risque de delegation abuse ?**
4. **Quelles parties du domaine sont suffisamment récentes pour appliquer les derniers mécanismes de durcissement ?**
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
- Si les comptes **SPN intéressants sont explicitement compatibles avec RC4**, le Kerberoasting reste peu coûteux et rapide.
- Si la plupart des comptes de service n'ont **aucune configuration d'etype explicite**, attendez-vous à un comportement **AES-only** sur les DC 2026 mis à jour et prévoyez un cracking offline plus lent ou une autre approche.
- Si **RBCD / KCD / unconstrained delegation** est présent, S4U est souvent plus efficace que le brute-force.
- Si l'**authentification par certificat** est utilisée, rappelez-vous qu'un chemin PKINIT ayant échoué ne signifie **pas toujours** que le certificat est inutilisable ; dans de nombreux environnements, le même certificat fonctionne encore pour exploiter **Schannel/LDAPS** (voir [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Erreurs Kerberos courantes qui modifient le plan d'attaque
- **`KDC_ERR_ETYPE_NOTSUPP`** → Le compte cible / DC n'utilisera pas le type de chiffrement que vous avez demandé. Arrêtez de réessayer uniquement avec RC4 ; fournissez des **clés AES** ou demandez plutôt du matériel de roastage **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Vous avez probablement la **mauvaise clé de service**, le **mauvais SPN**, ou un ticket forgé qui ne correspond pas au compte de service qui le déchiffre réellement.
- **`KRB_AP_ERR_SKEW`** → Votre horloge n'est pas synchronisée. Synchronisez-la avec le DC avant de déboguer quoi que ce soit d'autre.
- **`KDC_ERR_BADOPTION`** pendant les flux S4U / delegation → signifie souvent la présence d'**utilisateurs sensibles/non délégables**, l'utilisation du mauvais modèle de delegation, ou que vous essayez d'utiliser le **classic KCD** alors que seul le **RBCD** accepterait un ticket S4U2Self non forwardable.

## References
- [1] [Microsoft Learn - Détecter et corriger l'utilisation de RC4 dans Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Dernières recommandations de hardening Windows et dates clés](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I) : Comment fonctionne Kerberos ? – Théorie](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiter RBCD dans des environnements Cross-Domain et Cross-Forest : Partie 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Modifications de l'authentification basée sur les certificats de KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - Vulnérabilité de mappage des certificats Kerberos CVE-2025-26647](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Présentation des Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Exigences relatives aux certificats de smart card et validation par le KDC](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
