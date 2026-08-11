# Enrôlement d'appareils dans d'autres organisations

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Apple Automated Device Enrollment (anciennement DEP) commence par identifier un appareil attribué à une organisation. La recherche de 2018 résumée ici a montré que la connaissance d'un numéro de série attribué suffisait à récupérer les enrollment profiles de certaines organisations, car celles-ci n'exigeaient pas d'authentification supplémentaire adéquate. Il s'agit d'une découverte historique, et non de l'affirmation que tous les MDM actuels peuvent être rejoints avec un simple numéro de série. Les profiles peuvent contenir des certificats, des applications, des secrets Wi-Fi, des paramètres VPN et d'autres configurations sensibles.<sup>[[1]](#references)[[2]](#references)</sup>

**Ce qui suit est un résumé de la recherche [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consultez-la pour plus de détails techniques !**<sup>[[1]](#references)</sup>

## Vue d'ensemble de l'analyse binaire de DEP et MDM

La recherche a analysé les binaires associés à DEP et MDM sur les versions de macOS disponibles à l'époque. Les noms et responsabilités des composants peuvent changer selon les versions :

- **`mdmclient`** : Communique avec les serveurs MDM et déclenche les check-ins DEP sur les versions de macOS antérieures à 10.13.4.
- **`profiles`** : Gère les Configuration Profiles et déclenche les check-ins DEP sur les versions de macOS 10.13.4 et ultérieures.
- **`cloudconfigurationd`** : Gère les communications avec l'API DEP et récupère les Device Enrollment profiles.

Les check-ins DEP utilisent les fonctions `CPFetchActivationRecord` et `CPGetActivationRecord` du framework privé Configuration Profiles pour récupérer l'Activation Record, `CPFetchActivationRecord` coordonnant les échanges avec `cloudconfigurationd` via XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering du Tesla Protocol et du Absinthe Scheme

Le check-in DEP implique que `cloudconfigurationd` envoie une payload JSON chiffrée et signée à _iprofiles.apple.com/macProfile_. La payload contient le numéro de série de l'appareil et l'action "RequestProfileConfiguration". Le scheme de chiffrement utilisé est appelé en interne "Absinthe". Le démontage de ce scheme est complexe et implique de nombreuses étapes, ce qui a conduit à explorer des méthodes alternatives pour insérer des numéros de série arbitraires dans la requête Activation Record.<sup>[[1]](#references)</sup>

## Proxying des requêtes DEP

Les tentatives d'interception et de modification des requêtes DEP vers _iprofiles.apple.com_ à l'aide d'outils comme Charles Proxy ont été entravées par le chiffrement de la payload et les mesures de sécurité SSL/TLS. Cependant, l'activation de la configuration `MCCloudConfigAcceptAnyHTTPSCertificate` permet de contourner la validation du certificat serveur, bien que la nature chiffrée de la payload empêche toujours de modifier le numéro de série sans la clé de déchiffrement.<sup>[[1]](#references)</sup>

## Instrumentation des binaires système interagissant avec DEP

L'instrumentation de binaires système comme `cloudconfigurationd` nécessite de désactiver System Integrity Protection (SIP) sur macOS. Une fois SIP désactivé, des outils comme LLDB peuvent être utilisés pour s'attacher aux processus système et potentiellement modifier le numéro de série utilisé dans les interactions avec l'API DEP. Cette méthode est préférable, car elle évite les complexités liées aux entitlements et à la signature de code.<sup>[[1]](#references)</sup>

**Exploitation de l'instrumentation binaire :**
La modification de la payload de la requête DEP avant sa sérialisation JSON dans `cloudconfigurationd` s'est révélée efficace. Le processus comprenait :

1. S'attacher à `cloudconfigurationd` avec LLDB.
2. Localiser l'endroit où le numéro de série système est récupéré.
3. Injecter un numéro de série arbitraire en mémoire avant le chiffrement et l'envoi de la payload.

Cette méthode a permis aux chercheurs de récupérer les profiles DEP correspondant aux numéros de série fournis et attribués. Elle n'a pas rendu valide un numéro de série arbitraire non attribué.<sup>[[1]](#references)</sup>

### Automatisation de l'instrumentation avec Python

Le processus d'exploitation a été automatisé avec Python et l'API LLDB, ce qui a permis d'injecter des numéros de série arbitraires par programmation et de récupérer les profiles DEP correspondants.<sup>[[1]](#references)</sup>

### Impacts potentiels des vulnérabilités DEP et MDM

La recherche a mis en évidence d'importants problèmes de sécurité :

1. **Divulgation d'informations** : En fournissant un numéro de série enregistré dans DEP, il est possible de récupérer les informations sensibles de l'organisation contenues dans le profile DEP.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Peut-être : sécurité du Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Déploiement des plateformes Apple — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
