# Abuser des ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Les Comptes de Service Gérés Délégués (**dMSAs**) sont un tout nouveau type de principal AD introduit avec **Windows Server 2025**. Ils sont conçus pour remplacer les comptes de service hérités en permettant une “migration” en un clic qui copie automatiquement les Noms de Principal de Service (SPNs), les appartenances à des groupes, les paramètres de délégation, et même les clés cryptographiques de l'ancien compte vers le nouveau dMSA, offrant aux applications une transition transparente et éliminant le risque de Kerberoasting.

Les chercheurs d'Akamai ont découvert qu'un seul attribut — **`msDS‑ManagedAccountPrecededByLink`** — indique au KDC quel compte hérité un dMSA “succède”. Si un attaquant peut écrire cet attribut (et basculer **`msDS‑DelegatedMSAState` → 2**), le KDC construira avec plaisir un PAC qui **hérite de chaque SID de la victime choisie**, permettant ainsi au dMSA d'usurper n'importe quel utilisateur, y compris les Administrateurs de Domaine.

## Qu'est-ce qu'un dMSA ?

* Basé sur la technologie **gMSA** mais stocké comme la nouvelle classe AD **`msDS‑DelegatedManagedServiceAccount`**.
* Prend en charge une **migration opt-in** : appeler `Start‑ADServiceAccountMigration` lie le dMSA au compte hérité, accorde au compte hérité un accès en écriture à `msDS‑GroupMSAMembership`, et bascule `msDS‑DelegatedMSAState` = 1.
* Après `Complete‑ADServiceAccountMigration`, le compte remplacé est désactivé et le dMSA devient pleinement fonctionnel ; tout hôte ayant précédemment utilisé le compte hérité est automatiquement autorisé à récupérer le mot de passe du dMSA.
* Lors de l'authentification, le KDC intègre un indice **KERB‑SUPERSEDED‑BY‑USER** afin que les clients Windows 11/24H2 réessaient de manière transparente avec le dMSA.

## Exigences pour attaquer
1. **Au moins un DC Windows Server 2025** afin que la classe LDAP dMSA et la logique KDC existent.
2. **Tous droits de création d'objet ou d'écriture d'attribut sur une OU** (n'importe quelle OU) – par exemple, `Create msDS‑DelegatedManagedServiceAccount` ou simplement **Create All Child Objects**. Akamai a trouvé que 91 % des locataires du monde réel accordent de telles permissions “bénignes” sur les OU à des non-administrateurs.
3. Capacité à exécuter des outils (PowerShell/Rubeus) depuis n'importe quel hôte joint au domaine pour demander des tickets Kerberos.
*Aucun contrôle sur l'utilisateur victime n'est requis ; l'attaque ne touche jamais directement le compte cible.*

## Étape par étape : BadSuccessor*élévation de privilèges

1. **Localiser ou créer un dMSA que vous contrôlez**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Parce que vous avez créé l'objet à l'intérieur d'une OU à laquelle vous pouvez écrire, vous possédez automatiquement tous ses attributs.

2. **Simuler une “migration complétée” en deux écritures LDAP** :
- Définir `msDS‑ManagedAccountPrecededByLink = DN` de n'importe quelle victime (par exemple, `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Définir `msDS‑DelegatedMSAState = 2` (migration terminée).

Des outils comme **Set‑ADComputer, ldapmodify**, ou même **ADSI Edit** fonctionnent ; aucun droit d'administrateur de domaine n'est nécessaire.

3. **Demander un TGT pour le dMSA** — Rubeus prend en charge le drapeau `/dmsa` :

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

Le PAC retourné contient maintenant le SID 500 (Administrateur) ainsi que les groupes Administrateurs de Domaine/Administrateurs d'Entreprise.

## Rassembler tous les mots de passe des utilisateurs

Lors des migrations légitimes, le KDC doit permettre au nouveau dMSA de déchiffrer **les tickets émis au compte ancien avant la transition**. Pour éviter de rompre les sessions en cours, il place à la fois les clés actuelles et les clés précédentes dans un nouveau blob ASN.1 appelé **`KERB‑DMSA‑KEY‑PACKAGE`**.

Parce que notre fausse migration prétend que le dMSA succède à la victime, le KDC copie fidèlement la clé RC4‑HMAC de la victime dans la liste des **clés précédentes** – même si le dMSA n'a jamais eu de mot de passe “précédent”. Cette clé RC4 n'est pas salée, donc elle est effectivement le hachage NT de la victime, donnant à l'attaquant la capacité de **craquer hors ligne ou de “passer le hachage”**.

Ainsi, le lien massif de milliers d'utilisateurs permet à un attaquant de déverser des hachages “à grande échelle”, transformant **BadSuccessor en un primitive d'élévation de privilèges et de compromission d'identifiants**.

## Outils

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## Références

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
