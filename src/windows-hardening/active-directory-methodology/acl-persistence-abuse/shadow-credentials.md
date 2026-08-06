# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#3f17" id="3f17"></a>

**Consultez l’article original pour [toutes les informations sur cette technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

En **résumé** : si vous pouvez écrire dans la propriété **msDS-KeyCredentialLink** d’un utilisateur ou d’un ordinateur, vous pouvez récupérer le **NT hash de cet objet**.<sup>[[1]](#references)</sup>

L’article présente une méthode permettant de configurer des **identifiants d’authentification à clé publique-privée** afin d’obtenir un **Service Ticket** unique contenant le hash NTLM de la cible. Ce processus implique le NTLM_SUPPLEMENTAL_CREDENTIAL chiffré contenu dans le Privilege Attribute Certificate (PAC), qui peut être déchiffré.<sup>[[1]](#references)</sup>

### Prérequis

Pour appliquer cette technique, certaines conditions doivent être remplies :<sup>[[1]](#references)</sup>

- Au moins un Domain Controller sous Windows Server 2016 est requis.
- Le Domain Controller doit disposer d’un certificat numérique d’authentification serveur installé.
- L’Active Directory doit être configuré au Windows Server 2016 Functional Level.
- Un compte disposant de droits délégués pour modifier l’attribut msDS-KeyCredentialLink de l’objet cible est requis.

## Abuse

L’Abuse de Key Trust pour les objets ordinateur comprend plusieurs étapes au-delà de l’obtention d’un Ticket Granting Ticket (TGT) et du hash NTLM. Les options comprennent :<sup>[[1]](#references)</sup>

1. Créer un **RC4 silver ticket** afin d’agir en tant qu’utilisateurs privilégiés sur l’hôte ciblé.
2. Utiliser le TGT avec **S4U2Self** pour usurper l’identité d’**utilisateurs privilégiés**, ce qui nécessite de modifier le Service Ticket afin d’ajouter une classe de service au nom du service.

Un avantage important de l’Abuse de Key Trust est qu’elle se limite à la clé privée générée par l’attaquant, évitant ainsi la délégation à des comptes potentiellement vulnérables et ne nécessitant pas la création d’un compte ordinateur, qui pourrait être difficile à supprimer.<sup>[[1]](#references)</sup>

## Outils

### [**Whisker**](https://github.com/eladshamir/Whisker)

Il est basé sur DSInternals et fournit une interface C# pour cette attaque. Whisker et son équivalent Python, **pyWhisker**, permettent de manipuler l’attribut `msDS-KeyCredentialLink` afin de prendre le contrôle de comptes Active Directory. Ces outils prennent en charge différentes opérations, comme l’ajout, l’affichage, la suppression et l’effacement des key credentials de l’objet cible.

Les fonctions de **Whisker** comprennent :

- **Add** : génère une paire de clés et ajoute une key credential.
- **List** : affiche toutes les entrées de key credentials.
- **Remove** : supprime une key credential spécifiée.
- **Clear** : efface toutes les key credentials, ce qui peut perturber l’utilisation légitime de WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Il étend les fonctionnalités de Whisker aux **systèmes basés sur UNIX**, en s'appuyant sur Impacket et PyDSInternals pour offrir des capacités d'exploitation complètes, notamment l'énumération, l'ajout et la suppression de KeyCredentials, ainsi que leur importation et leur exportation au format JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray vise à **exploiter les permissions GenericWrite/GenericAll que de larges groupes d’utilisateurs peuvent avoir sur des objets du domaine** afin d’appliquer largement les ShadowCredentials. Il implique de se connecter au domaine, de vérifier son niveau fonctionnel, d’énumérer les objets du domaine et de tenter d’ajouter des KeyCredentials pour obtenir des TGT et révéler le hash NT. Les options de nettoyage et les tactiques d’exploitation récursive améliorent son utilité.

## Références

- [1] [Shadow Credentials : Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool for taking over AD accounts by manipulating msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool to spray Shadow Credentials across a domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python version of the Shadow Credentials tool](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
