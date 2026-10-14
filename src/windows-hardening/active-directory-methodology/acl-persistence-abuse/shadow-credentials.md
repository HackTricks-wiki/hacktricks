# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#3f17" id="3f17"></a>

**Consultez l’article original pour [toutes les informations sur cette technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

En résumé, le contrôle de l’attribut **`msDS-KeyCredentialLink`** d’un utilisateur ou d’un ordinateur peut permettre à un attaquant d’ajouter un identifiant de clé, de s’authentifier en tant que cet objet avec PKINIT et, lorsque le KDC et le compte prennent en charge les flux nécessaires, d’utiliser le ticket obtenu avec `S4U2Self`/user-to-user pour récupérer le hash NT de l’objet.<sup>[[1]](#references)</sup>

L’article décrit une méthode permettant de configurer des **identifiants d’authentification à clé publique-privée** afin d’obtenir un **Service Ticket** unique contenant le hash NTLM de la cible. Ce processus implique le NTLM_SUPPLEMENTAL_CREDENTIAL chiffré dans le Privilege Attribute Certificate (PAC), qui peut être déchiffré.<sup>[[1]](#references)</sup>

### Prérequis

Pour appliquer cette technique, certaines conditions doivent être remplies :<sup>[[1]](#references)</sup>

- Il faut au moins un contrôleur de domaine Windows Server 2016.
- Le contrôleur de domaine doit avoir un certificat numérique d’authentification serveur installé.
- Le schéma d’annuaire doit contenir `msDS-KeyCredentialLink` ; un contrôleur de domaine Windows Server 2016 ou ultérieur et un certificat compatible PKINIT sur le KDC constituent les exigences pratiques de plateforme décrites par la recherche. Vérifiez le schéma et les versions des contrôleurs de domaine du domaine au lieu de supposer que seul le niveau fonctionnel du domaine détermine si l’exploitation est possible.
- Un compte disposant de droits délégués pour modifier l’attribut msDS-KeyCredentialLink de l’objet cible est requis.

## Exploitation

L’exploitation de Key Trust sur des objets ordinateur implique des étapes supplémentaires à l’obtention d’un Ticket Granting Ticket (TGT) et du hash NTLM. Les options comprennent :<sup>[[1]](#references)</sup>

1. Créer un **RC4 silver ticket** pour agir en tant qu’utilisateurs privilégiés sur l’hôte visé.
2. Utiliser le TGT avec **S4U2Self** pour usurper l’identité d’**utilisateurs privilégiés**, ce qui nécessite de modifier le Service Ticket pour ajouter une classe de service au nom du service.

L’un des avantages importants de l’exploitation de Key Trust est qu’elle se limite à la clé privée générée par l’attaquant, évite la délégation à des comptes potentiellement vulnérables et ne nécessite pas de créer un compte ordinateur, qui pourrait être difficile à supprimer.<sup>[[1]](#references)</sup>

## Outils

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker utilise DSInternals pour manipuler `msDS-KeyCredentialLink` en C#. Whisker et son équivalent Python **pyWhisker** permettent d’ajouter, de lister, de supprimer et d’effacer des identifiants de clé.<sup>[[2]](#references)[[4]](#references)</sup>

Les fonctions de **Whisker** comprennent :

- **Add** : génère une paire de clés et ajoute un identifiant de clé.
- **List** : affiche toutes les entrées d’identifiant de clé.
- **Remove** : supprime un identifiant de clé spécifié.
- **Clear** : efface tous les identifiants de clé, ce qui peut perturber l’utilisation légitime de WHfB.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker apporte ce flux de travail aux **systèmes de type UNIX** avec Impacket et PyDSInternals, notamment les opérations de listage, d’ajout et de suppression, ainsi que d’importation et d’exportation JSON.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray énumère les objets du domaine sur lesquels l’opérateur dispose de droits tels que `GenericWrite`/`GenericAll`, tente d’ajouter largement des key credentials et propose des modes de nettoyage et récursifs. Un spraying à grande échelle est perturbateur et très visible ; utilisez des cibles explicites et conservez chaque DeviceID ajouté afin de pouvoir le supprimer précisément.<sup>[[3]](#references)</sup>

ADWS peut transporter l’écriture des key credentials lorsque LDAP direct est filtré. Voir le [workflow SOAPy ADWS](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials : abus du mappage de compte Key Trust pour prendre le contrôle d’un compte](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Outil permettant de prendre le contrôle de comptes AD en manipulant msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Outil pour diffuser des Shadow Credentials dans un domaine](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Version Python de l’outil Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)
- [5] [Wiki SOAPy – Post-exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
