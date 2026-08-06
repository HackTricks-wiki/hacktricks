# Authentification Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Consultez l’excellent article de :** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## TL;DR pour les attackers
- Kerberos est le protocole d’authentification AD par défaut ; la plupart des chaînes de mouvement latéral l’utilisent.
- Pensez en **trois phases opérateur** :<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → utiliser un password/hash/certificate pour obtenir un **TGT**. C’est ici qu’interviennent **AS-REP roasting**, **over-pass-the-hash / pass-the-key** et **PKINIT**.
- **TGS-REQ / TGS-REP** → utiliser un TGT pour obtenir des **service tickets**. C’est ici que deviennent pertinents le **Kerberoasting**, l’**abuse S4U**, l’**abuse delegation** et la plupart des techniques de **ticket-forging**.
- **AP-REQ / AP-REP** → présenter le ticket au service. C’est ici qu’interviennent le **pass-the-ticket** et le mouvement latéral spécifique au service.
- Pour des cheatsheets pratiques (AS-REP/Kerberoasting, ticket forgery, delegation abuse, etc.), consultez :
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Utilisez cette page comme index **overview / « ce qui a changé récemment »**, puis consultez les pages dédiées consacrées à [Kerberoast](kerberoast.md), à [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), à l’[abuse des certificats AD / PKINIT](ad-certificates.md) ou à l’[abuse BadSuccessor / dMSA](acl-persistence-abuse/BadSuccessor.md).

## Notes d’attaque récentes (2024-2026)
- **Le hardening de RC4 a modifié les valeurs par défaut, pas Kerberos lui-même** – le hardening moderne des DC se concentre sur les **types de chiffrement supposés par défaut** pour les comptes qui ne définissent pas explicitement `msDS-SupportedEncryptionTypes`. Après le déploiement de 2026, ces comptes utilisent de plus en plus **AES-only** par défaut sur les DC patchés ; les hypothèses aveugles de Kerberoast avec `/rc4` échouent donc plus souvent. Cependant, les comptes de service explicitement activés pour RC4 restent d’excellentes cibles d’offline-crack.<sup>[[1]](#references)</sup>
- **L’application de la validation PAC est importante pour les forged tickets** – le hardening des signatures PAC de 2024 signifie que les **abuses de type golden/diamond/sapphire/extraSID** nécessitent des données PAC plus réalistes et le contexte de signature approprié. Les domaines non patchés ou laissés dans des déploiements de compatibilité/audit restent des cibles plus vulnérables.<sup>[[2]](#references)</sup>
- **Kerberos basé sur les certificats a changé deux fois** :<sup>[[2]](#references)</sup>
- Le **strong certificate binding** (chronologie de KB5014754) rend les mappings certificate-to-account négligés moins fiables dans les environnements entièrement appliqués.
- **CVE-2025-26647** a ajouté une couche de hardening supplémentaire autour des mappings de certificats **altSecID / SKI**. Si les DC ne sont pas patchés, sont toujours en mode audit ou contournent explicitement la validation NTAuth, l’abuse de suivi **pass-the-certificate / shadow-credential** reste plus pratique.
- L’**abuse de delegation cross-domain / cross-forest est toujours très présente** – Windows prend en charge les flux modernes **S4U2Self/S4U2Proxy** cross-realm ; les attributs de delegation modifiables dans un autre domaine restent donc précieux. Le principal obstacle est généralement la fidélité des outils et les détails liés aux trusts/policies, et non la prise en charge du protocole.
- La **RBCD multi-domaines récursive est importante sur le plan opérationnel** – dans les forests de 3 domaines ou plus, **S4U2Self/S4U2Proxy** peut récursivement traverser les trust referrals, et l’abuse **SPN-less** peut nécessiter un dernier hop **`S4U2Self+U2U`**, ainsi qu’une gestion des tickets dépendante de RC4. Consultez [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 a introduit une nouvelle attack surface adjacente à Kerberos** via la logique de migration **dMSA**. Si vous voyez des droits délégués sur des OUs ou des objets de comptes de service dans un domaine 2025, consultez la [page BadSuccessor](acl-persistence-abuse/BadSuccessor.md) dédiée au lieu de considérer cela comme « juste un autre gMSA ».

## Vérifications rapides de l’opérateur dans les domaines modernes

Avant de choisir une voie d’attaque Kerberos, répondez rapidement à quatre questions :

1. **Quels comptes sont encore compatibles avec RC4 ?**
2. **Quels utilisateurs n’exigent pas de pre-auth ?**
3. **Quels objets exposent une delegation abuse ?**
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
- Si des **comptes SPN intéressants sont explicitement compatibles RC4**, le Kerberoasting reste peu coûteux et rapide.
- Si la plupart des comptes de service n'ont **aucune configuration explicite de type de chiffrement**, attendez-vous à un comportement **AES-only** sur des DC 2026 à jour et prévoyez un cracking offline plus lent ou une autre approche.
- Si **RBCD / KCD / unconstrained delegation** est présent, S4U est souvent plus efficace que le brute-force.
- Si l'**authentification par certificat** est utilisée, rappelez-vous qu'un échec de la voie PKINIT ne signifie **pas toujours** que le certificat est inutilisable ; dans de nombreux environnements, le même certificat fonctionne encore pour exploiter **Schannel/LDAPS** (voir [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Erreurs Kerberos courantes qui modifient le plan d'attaque
- **`KDC_ERR_ETYPE_NOTSUPP`** → Le compte cible / DC n'utilisera pas le type de chiffrement demandé. Arrêtez de réessayer uniquement avec RC4 ; fournissez des **clés AES** ou demandez plutôt du matériel de roastage **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Vous avez probablement la **mauvaise clé de service**, le **mauvais SPN**, ou un ticket forgé qui ne correspond pas au compte de service qui le déchiffre réellement.
- **`KRB_AP_ERR_SKEW`** → Votre horloge n'est pas synchronisée. Synchronisez-la avec le DC avant de déboguer quoi que ce soit d'autre.
- **`KDC_ERR_BADOPTION`** pendant des flux S4U / delegation → signifie fréquemment la présence d'**utilisateurs sensibles/non délégables**, l'utilisation du mauvais modèle de delegation, ou que vous tentez de faire du **KCD classique** alors que seul **RBCD** accepterait un ticket S4U2Self non transférable.

## Références
- [1] [Microsoft Learn - Détecter et corriger l'utilisation de RC4 dans Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Dernières recommandations de hardening Windows et dates clés](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I) : Comment fonctionne Kerberos ? – Théorie](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiting RBCD in Cross-Domain & Cross-Forest Environments: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
