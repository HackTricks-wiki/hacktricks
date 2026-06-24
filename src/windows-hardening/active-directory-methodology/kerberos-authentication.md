# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Découvrez l’excellent article de :** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR pour les attaquants
- Kerberos est le protocole d’authentification AD par défaut ; la plupart des chaînes de lateral movement l’utiliseront.
- Pensez en **trois phases opérateur** :
- **AS-REQ / AS-REP** → mot de passe/hash/certificat pour obtenir un **TGT**. C’est là que se trouvent **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, et **PKINIT**.
- **TGS-REQ / TGS-REP** → utiliser un TGT pour obtenir des **service tickets**. C’est là que **Kerberoasting**, **S4U abuse**, **delegation abuse**, et la plupart des techniques de **ticket-forging** deviennent pertinentes.
- **AP-REQ / AP-REP** → présenter le ticket au service. C’est là que se produisent **pass-the-ticket** et le lateral movement spécifique au service.
- Pour des cheatsheets pratiques (AS-REP/Kerberoasting, ticket forgery, delegation abuse, etc.) voir :
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Utilisez cette page comme index **vue d’ensemble / “ce qui a changé récemment”**, puis allez sur les pages dédiées pour [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), ou [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Notes d’attaque récentes (2024-2026)
- **Le durcissement RC4 a changé les valeurs par défaut, pas Kerberos lui-même** – le durcissement moderne des DC se concentre sur les **types de chiffrement supposés par défaut** pour les comptes qui ne définissent pas explicitement `msDS-SupportedEncryptionTypes`. Après le déploiement 2026, ces comptes passent de plus en plus par défaut en **AES-only** sur les DC patchés, donc les hypothèses aveugles `/rc4` pour Kerberoast échouent plus souvent. Cependant, les **service accounts explicitement activés pour RC4 restent d’excellentes cibles de crack offline**.
- **L’application de la validation PAC compte pour les forged tickets** – le durcissement des signatures PAC de 2024 signifie que les abus de type **golden/diamond/sapphire/extraSID** doivent utiliser des données PAC plus réalistes et le bon contexte de signature. Les domaines non patchés ou restés en déploiement de compatibilité/audit restent des cibles plus faibles.
- **Le Kerberos basé sur certificat a changé deux fois** :
- **Le strong certificate binding** (chronologie KB5014754) rend les mappings certificate-to-account approximatifs moins fiables dans les environnements pleinement appliqués.
- **CVE-2025-26647** a ajouté une couche de durcissement supplémentaire autour des mappings de certificats **altSecID / SKI**. Si les DC ne sont pas patchés, sont encore en audit, ou contournent explicitement la validation NTAuth, l’abus en chaîne de pass-the-certificate / shadow-credential reste plus pratique.
- **L’abus de delegation cross-domain / cross-forest est toujours très vivant** – Windows prend en charge les flux modernes cross-realm **S4U2Self/S4U2Proxy**, donc les attributs de delegation modifiables dans un autre domaine restent précieux. Le blocage vient généralement de la fidélité des outils et des détails de trust/policy, pas du support du protocole.
- **Windows Server 2025 a introduit une nouvelle surface d’attaque proche de Kerberos** via la logique de migration **dMSA**. Si vous voyez des droits délégués sur des OU ou des objets de service account dans un domaine 2025, consultez la page dédiée [BadSuccessor](acl-persistence-abuse/BadSuccessor.md) au lieu de traiter cela comme “juste un autre gMSA”.

## Vérifications rapides opérateur dans les domaines modernes

Avant de choisir un chemin d’attaque Kerberos, répondez rapidement à quatre questions :

1. **Quels comptes sont encore compatibles RC4 ?**
2. **Quels utilisateurs ne requièrent pas de pre-auth ?**
3. **Quels objets exposent un delegation abuse ?**
4. **Quelles parties du domaine sont assez récentes pour appliquer le durcissement récent ?**
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
- Si les comptes **SPN intéressants** sont explicitement compatibles RC4, le Kerberoasting reste peu coûteux et rapide.
- Si la plupart des comptes de service n’ont **aucune configuration explicite d’etype**, attendez-vous à un comportement **AES-only** sur les DC 2026 mis à jour et prévoyez un cracking offline plus lent ou une autre voie.
- Si **RBCD / KCD / unconstrained delegation** est présent, S4U est souvent plus efficace que le brute-force.
- Si l’**authentification par certificat** est en jeu, rappelez-vous qu’un échec du chemin PKINIT ne signifie **pas toujours** que le certificat est inutile ; dans beaucoup d’environnements, le même certificat fonctionne encore pour un abus **Schannel/LDAPS** (voir [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Erreurs Kerberos courantes qui changent le plan d’attaque
- **`KDC_ERR_ETYPE_NOTSUPP`** → Le compte cible / DC n’utilisera pas le type de chiffrement demandé. Arrêtez de réessayer uniquement avec RC4 ; fournissez des **clés AES** ou demandez plutôt du matériel de roast **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Vous avez probablement la **mauvaise clé de service**, le **mauvais SPN**, ou un ticket forgé qui ne correspond pas au compte de service qui le déchiffre réellement.
- **`KRB_AP_ERR_SKEW`** → Votre horloge est décalée. Synchronisez-vous avec le DC avant de déboguer quoi que ce soit d’autre.
- **`KDC_ERR_BADOPTION`** pendant les flux S4U / delegation → signifie souvent des utilisateurs **sensibles/non-délégables**, le mauvais modèle de delegation, ou que vous essayez de faire du **KCD classique** alors que seul **RBCD** accepterait un ticket S4U2Self non forwardable.

## Références
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
