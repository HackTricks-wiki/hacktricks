# Inscrire des appareils dans d’autres organisations

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Comme [**mentionné précédemment**](#what-is-mdm-mobile-device-management)**,** pour tenter d’inscrire un appareil dans une organisation, **seul un numéro de série appartenant à cette organisation est nécessaire**. Une fois l’appareil inscrit, plusieurs organisations installeront des données sensibles sur le nouvel appareil : certificats, applications, mots de passe WiFi, configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela pourrait constituer un point d’entrée dangereux pour les attaquants si le processus d’inscription n’est pas correctement protégé.

**Ce qui suit est un résumé de la recherche [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consultez-la pour plus de détails techniques !**<sup>[[1]](#references)</sup>

## Vue d’ensemble de l’analyse binaire de DEP et MDM

Cette recherche examine les binaires associés au Device Enrollment Program (DEP) et au Mobile Device Management (MDM) sur macOS. Les composants principaux incluent :

- **`mdmclient`** : communique avec les serveurs MDM et déclenche les check-ins DEP sur les versions de macOS antérieures à 10.13.4.
- **`profiles`** : gère les Configuration Profiles et déclenche les check-ins DEP sur les versions de macOS 10.13.4 et ultérieures.
- **`cloudconfigurationd`** : gère les communications avec l’API DEP et récupère les profils Device Enrollment.

Les check-ins DEP utilisent les fonctions `CPFetchActivationRecord` et `CPGetActivationRecord` du framework privé Configuration Profiles pour récupérer l’Activation Record, `CPFetchActivationRecord` coordonnant les échanges avec `cloudconfigurationd` via XPC.<sup>[[1]](#references)</sup>

## Reverse engineering du protocole Tesla et du schéma Absinthe

Le check-in DEP implique que `cloudconfigurationd` envoie une charge utile JSON chiffrée et signée à _iprofiles.apple.com/macProfile_. La charge utile contient le numéro de série de l’appareil ainsi que l’action "RequestProfileConfiguration". Le schéma de chiffrement utilisé est appelé en interne "Absinthe". La reconstitution de ce schéma est complexe et implique de nombreuses étapes, ce qui a conduit à explorer d’autres méthodes pour insérer des numéros de série arbitraires dans la requête Activation Record.<sup>[[1]](#references)</sup>

## Proxying des requêtes DEP

Les tentatives d’interception et de modification des requêtes DEP vers _iprofiles.apple.com_ à l’aide d’outils tels que Charles Proxy ont été entravées par le chiffrement de la charge utile et les mesures de sécurité SSL/TLS. Cependant, l’activation de la configuration `MCCloudConfigAcceptAnyHTTPSCertificate` permet de contourner la validation du certificat serveur, bien que la nature chiffrée de la charge utile empêche toujours de modifier le numéro de série sans la clé de déchiffrement.<sup>[[1]](#references)</sup>

## Instrumentation des binaires système interagissant avec DEP

L’instrumentation de binaires système tels que `cloudconfigurationd` nécessite de désactiver System Integrity Protection (SIP) sur macOS. Lorsque SIP est désactivé, des outils tels que LLDB peuvent être utilisés pour s’attacher aux processus système et potentiellement modifier le numéro de série utilisé dans les interactions avec l’API DEP. Cette méthode est préférable, car elle évite les complexités liées aux entitlements et à la signature du code.

**Exploitation de l’instrumentation binaire :**
La modification de la charge utile de la requête DEP avant la sérialisation JSON dans `cloudconfigurationd` s’est révélée efficace. Le processus impliquait :

1. S’attacher à `cloudconfigurationd` avec LLDB.
2. Localiser l’endroit où le numéro de série système est récupéré.
3. Injecter un numéro de série arbitraire en mémoire avant le chiffrement et l’envoi de la charge utile.

Cette méthode a permis de récupérer des profils DEP complets pour des numéros de série arbitraires, démontrant une vulnérabilité potentielle.<sup>[[1]](#references)</sup>

### Automatisation de l’instrumentation avec Python

Le processus d’exploitation a été automatisé à l’aide de Python et de l’API LLDB, ce qui permet d’injecter des numéros de série arbitraires par programmation et de récupérer les profils DEP correspondants.<sup>[[1]](#references)</sup>

### Impacts potentiels des vulnérabilités DEP et MDM

La recherche a mis en évidence d’importantes préoccupations de sécurité :

1. **Divulgation d’informations** : en fournissant un numéro de série enregistré auprès de DEP, il est possible de récupérer les informations sensibles de l’organisation contenues dans le profil DEP.<sup>[[1]](#references)</sup>

## Références

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
