# Enrôlement de devices dans d'autres organisations

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Comme [**previously commented**](#what-is-mdm-mobile-device-management)**,** pour tenter d'enrôler un device dans une organisation, **seul un Serial Number appartenant à cette organisation est nécessaire**. Une fois le device enrôlé, plusieurs organisations installeront des données sensibles sur le nouveau device : certificats, applications, mots de passe WiFi, configurations VPN [and so on](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela pourrait constituer un point d'entrée dangereux pour les attaquants si le processus d'enrôlement n'est pas correctement protégé.

**The following is a summary of the research [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Check it for further technical details!**<sup>[[1]](#references)</sup>

## Vue d'ensemble de l'analyse binaire de DEP et MDM

Cette research analyse les binaires associés au Device Enrollment Program (DEP) et au Mobile Device Management (MDM) sur macOS. Les composants principaux comprennent :

- **`mdmclient`** : communique avec les serveurs MDM et déclenche les check-ins DEP sur les versions de macOS antérieures à 10.13.4.
- **`profiles`** : gère les Configuration Profiles et déclenche les check-ins DEP sur les versions de macOS 10.13.4 et ultérieures.
- **`cloudconfigurationd`** : gère les communications avec l'API DEP et récupère les Device Enrollment profiles.

Les check-ins DEP utilisent les fonctions `CPFetchActivationRecord` et `CPGetActivationRecord` du framework privé Configuration Profiles pour récupérer l'Activation Record, `CPFetchActivationRecord` se coordonnant avec `cloudconfigurationd` via XPC.<sup>[[1]](#references)</sup>

## Reverse engineering du protocole Tesla et du schéma Absinthe

Le check-in DEP implique que `cloudconfigurationd` envoie un payload JSON chiffré et signé à _iprofiles.apple.com/macProfile_. Le payload contient le numéro de série du device ainsi que l'action "RequestProfileConfiguration". Le schéma de chiffrement utilisé est appelé en interne "Absinthe". La compréhension de ce schéma est complexe et implique de nombreuses étapes, ce qui a conduit à explorer d'autres méthodes permettant d'insérer des numéros de série arbitraires dans la requête Activation Record.<sup>[[1]](#references)</sup>

## Proxying des requêtes DEP

Les tentatives d'interception et de modification des requêtes DEP vers _iprofiles.apple.com_ à l'aide d'outils comme Charles Proxy ont été entravées par le chiffrement du payload et les mesures de sécurité SSL/TLS. Cependant, l'activation de la configuration `MCCloudConfigAcceptAnyHTTPSCertificate` permet de contourner la validation du certificat serveur, bien que la nature chiffrée du payload empêche toujours de modifier le numéro de série sans la clé de déchiffrement.<sup>[[1]](#references)</sup>

## Instrumentation des binaires système interagissant avec DEP

L'instrumentation de binaires système comme `cloudconfigurationd` nécessite de désactiver System Integrity Protection (SIP) sur macOS. Avec SIP désactivé, des outils comme LLDB peuvent être utilisés pour s'attacher aux processus système et potentiellement modifier le numéro de série utilisé dans les interactions avec l'API DEP. Cette méthode est préférable, car elle évite les complexités liées aux entitlements et à la signature de code.<sup>[[1]](#references)</sup>

**Exploitation de l'instrumentation binaire :**
La modification du payload de la requête DEP avant sa sérialisation JSON dans `cloudconfigurationd` s'est révélée efficace. Le processus impliquait :

1. S'attacher à `cloudconfigurationd` avec LLDB.
2. Localiser l'endroit où le numéro de série système est récupéré.
3. Injecter un numéro de série arbitraire en mémoire avant le chiffrement et l'envoi du payload.

Cette méthode a permis de récupérer des profils DEP complets pour des numéros de série arbitraires, démontrant une vulnérabilité potentielle.<sup>[[1]](#references)</sup>

### Automatisation de l'instrumentation avec Python

Le processus d'exploitation a été automatisé à l'aide de Python et de l'API LLDB, ce qui a permis d'injecter programmatiquement des numéros de série arbitraires et de récupérer les profils DEP correspondants.<sup>[[1]](#references)</sup>

### Impacts potentiels des vulnérabilités DEP et MDM

La research a mis en évidence d'importants problèmes de sécurité :

1. **Divulgation d'informations** : en fournissant un numéro de série enregistré dans DEP, il est possible de récupérer les informations sensibles de l'organisation contenues dans le profil DEP.<sup>[[1]](#references)</sup>

## Références

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
