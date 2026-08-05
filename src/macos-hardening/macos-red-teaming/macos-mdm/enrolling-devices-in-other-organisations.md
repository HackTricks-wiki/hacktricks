# Enrolling Devices dans d’autres Organisations

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Comme [**indiqué précédemment**](#what-is-mdm-mobile-device-management)**,** afin d’essayer d’enrôler un device dans une organisation, **seul un Serial Number appartenant à cette organisation est nécessaire**. Une fois le device enrôlé, plusieurs organisations installent des données sensibles sur le nouveau device : certificats, applications, mots de passe WiFi, configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela pourrait constituer un point d’entrée dangereux pour les attackers si le processus d’enrôlement n’est pas correctement protégé.

**Ce qui suit est un résumé de la recherche [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consultez-la pour plus de détails techniques !**<sup>[1]</sup>

## Vue d’ensemble de l’analyse des binaires DEP et MDM

Cette recherche examine les binaires associés au Device Enrollment Program (DEP) et au Mobile Device Management (MDM) sur macOS. Les composants principaux incluent :

- **`mdmclient`** : Communique avec les serveurs MDM et déclenche les check-ins DEP sur les versions de macOS antérieures à 10.13.4.
- **`profiles`** : Gère les Configuration Profiles et déclenche les check-ins DEP sur les versions de macOS 10.13.4 et ultérieures.
- **`cloudconfigurationd`** : Gère les communications avec l’API DEP et récupère les Device Enrollment profiles.

Les check-ins DEP utilisent les fonctions `CPFetchActivationRecord` et `CPGetActivationRecord` du framework privé Configuration Profiles pour récupérer l’Activation Record, `CPFetchActivationRecord` coordonnant les échanges avec `cloudconfigurationd` via XPC.<sup>[1]</sup>

## Reverse Engineering du protocole Tesla et du schéma Absinthe

Le check-in DEP implique que `cloudconfigurationd` envoie un payload JSON chiffré et signé à _iprofiles.apple.com/macProfile_. Le payload contient le numéro de série du device et l’action "RequestProfileConfiguration". Le schéma de chiffrement utilisé est appelé en interne "Absinthe". Déchiffrer ce schéma est complexe et implique de nombreuses étapes, ce qui a conduit à explorer d’autres méthodes permettant d’insérer des numéros de série arbitraires dans la requête Activation Record.<sup>[1]</sup>

## Proxying des requêtes DEP

Les tentatives d’interception et de modification des requêtes DEP vers _iprofiles.apple.com_ à l’aide d’outils tels que Charles Proxy ont été entravées par le chiffrement du payload et les mesures de sécurité SSL/TLS. Cependant, l’activation de la configuration `MCCloudConfigAcceptAnyHTTPSCertificate` permet de contourner la validation du certificat du serveur, bien que la nature chiffrée du payload empêche toujours de modifier le numéro de série sans la clé de déchiffrement.<sup>[1]</sup>

## Instrumentation des binaires système interagissant avec DEP

L’instrumentation de binaires système tels que `cloudconfigurationd` nécessite de désactiver System Integrity Protection (SIP) sur macOS. Avec SIP désactivé, des outils tels que LLDB peuvent être utilisés pour s’attacher aux processus système et potentiellement modifier le numéro de série utilisé dans les interactions avec l’API DEP. Cette méthode est préférable, car elle évite les complexités liées aux entitlements et à la signature du code.

**Exploitation de l’instrumentation des binaires :**
La modification du payload de la requête DEP avant sa sérialisation JSON dans `cloudconfigurationd` s’est révélée efficace. Le processus impliquait :

1. S’attacher à `cloudconfigurationd` avec LLDB.
2. Localiser l’emplacement où le numéro de série du système est récupéré.
3. Injecter un numéro de série arbitraire en mémoire avant le chiffrement et l’envoi du payload.

Cette méthode a permis de récupérer des profils DEP complets pour des numéros de série arbitraires, démontrant une vulnérabilité potentielle.<sup>[1]</sup>

### Automatisation de l’instrumentation avec Python

Le processus d’exploitation a été automatisé avec Python et l’API LLDB, ce qui permet d’injecter des numéros de série arbitraires par programmation et de récupérer les profils DEP correspondants.<sup>[1]</sup>

### Impacts potentiels des vulnérabilités DEP et MDM

La recherche a mis en évidence d’importants problèmes de sécurité :

1. **Divulgation d’informations** : En fournissant un numéro de série enregistré dans DEP, il est possible de récupérer les informations sensibles de l’organisation contenues dans le profil DEP.<sup>[1]</sup>

## Références

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
