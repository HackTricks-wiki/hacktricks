# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#3f17" id="3f17"></a>

**Consultez le post original pour [toutes les informations sur cette technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

En résumé, le contrôle de l'attribut **`msDS-KeyCredentialLink`** d'un utilisateur ou d'un ordinateur peut permettre à un attaquant d'ajouter une key credential, de s'authentifier en tant que cet objet avec PKINIT et, lorsque le KDC et le compte prennent en charge les flux nécessaires, d'utiliser le ticket obtenu avec `S4U2Self`/user-to-user pour récupérer le hash NT de l'objet.<sup>[[1]](#references)</sup>

Dans le post, une méthode est présentée pour configurer des **public-private key authentication credentials** afin d'obtenir un **Service Ticket** unique contenant le hash NTLM de la cible. Ce processus implique le NTLM_SUPPLEMENTAL_CREDENTIAL chiffré dans le Privilege Attribute Certificate (PAC), qui peut être déchiffré.<sup>[[1]](#references)</sup>

### Prérequis

Pour appliquer cette technique, certaines conditions doivent être remplies :<sup>[[1]](#references)</sup>

- Au moins un Domain Controller sous Windows Server 2016 est nécessaire.
- Le Domain Controller doit disposer d'un certificat numérique d'authentification serveur installé.
- Le schéma de l'annuaire doit contenir `msDS-KeyCredentialLink` ; un DC sous Windows Server 2016 ou une version ultérieure ainsi qu'un certificat compatible PKINIT sur le KDC constituent les prérequis pratiques de la plateforme décrits par la recherche. Vérifiez le schéma du domaine et la combinaison de DC plutôt que de supposer que le seul niveau fonctionnel du domaine détermine la possibilité d'exploitation.
- Un compte disposant de droits délégués pour modifier l'attribut msDS-KeyCredentialLink de l'objet cible est requis.

## Abus

L'abus de Key Trust sur les objets ordinateur comprend des étapes allant au-delà de l'obtention d'un Ticket Granting Ticket (TGT) et du hash NTLM. Les options incluent :<sup>[[1]](#references)</sup>

1. Créer un **RC4 silver ticket** pour agir en tant qu'utilisateurs privilégiés sur l'hôte visé.
2. Utiliser le TGT avec **S4U2Self** pour usurper l'identité d'**utilisateurs privilégiés**, ce qui nécessite de modifier le Service Ticket afin d'ajouter une classe de service au nom du service.

Un avantage important de l'abus de Key Trust est qu'il se limite à la clé privée générée par l'attaquant, évitant ainsi la délégation vers des comptes potentiellement vulnérables et ne nécessitant pas la création d'un compte ordinateur, qui pourrait être difficile à supprimer.<sup>[[1]](#references)</sup>

## Outils

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker utilise DSInternals pour manipuler `msDS-KeyCredentialLink` en C#. Whisker et son équivalent Python **pyWhisker** prennent en charge l'ajout, l'affichage, la suppression et l'effacement des key credentials.<sup>[[2]](#references)[[4]](#references)</sup>

Les fonctions de **Whisker** comprennent :

- **Add** : génère une paire de clés et ajoute une key credential.
- **List** : affiche toutes les entrées de key credentials.
- **Remove** : supprime une key credential spécifiée.
- **Clear** : efface toutes les key credentials, ce qui peut perturber l'utilisation légitime de WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker permet d'effectuer ce processus sur les **UNIX-like systems** avec Impacket et PyDSInternals, notamment les opérations list/add/remove et l'import/export JSON.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray énumère les objets du domaine sur lesquels l’opérateur dispose de droits tels que `GenericWrite`/`GenericAll`, tente d’ajouter largement des key credentials et inclut des modes de nettoyage/récursifs. Un spraying large est perturbateur et particulièrement visible ; utilisez des cibles explicites et conservez chaque DeviceID ajouté afin de permettre une suppression précise.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials : exploitation du mappage des comptes par Key Trust pour prendre le contrôle d’un compte](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Outil de prise de contrôle de comptes AD en manipulant msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Outil permettant de diffuser des Shadow Credentials sur un domaine](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Version Python de l’outil Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
