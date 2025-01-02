# Enrôlement des appareils dans d'autres organisations

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Comme [**mentionné précédemment**](./#what-is-mdm-mobile-device-management)**,** pour essayer d'enrôler un appareil dans une organisation, **il suffit d'un numéro de série appartenant à cette organisation**. Une fois l'appareil enrôlé, plusieurs organisations installeront des données sensibles sur le nouvel appareil : certificats, applications, mots de passe WiFi, configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela pourrait être un point d'entrée dangereux pour les attaquants si le processus d'enrôlement n'est pas correctement protégé.

**Ce qui suit est un résumé de la recherche [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consultez-le pour plus de détails techniques !**

## Aperçu de l'analyse binaire de DEP et MDM

Cette recherche se penche sur les binaires associés au Programme d'Enrôlement des Appareils (DEP) et à la Gestion des Appareils Mobiles (MDM) sur macOS. Les composants clés incluent :

- **`mdmclient`** : Communique avec les serveurs MDM et déclenche les enregistrements DEP sur les versions macOS antérieures à 10.13.4.
- **`profiles`** : Gère les Profils de Configuration et déclenche les enregistrements DEP sur les versions macOS 10.13.4 et ultérieures.
- **`cloudconfigurationd`** : Gère les communications API DEP et récupère les profils d'enrôlement des appareils.

Les enregistrements DEP utilisent les fonctions `CPFetchActivationRecord` et `CPGetActivationRecord` du framework privé des Profils de Configuration pour récupérer l'Activation Record, avec `CPFetchActivationRecord` coordonnant avec `cloudconfigurationd` via XPC.

## Ingénierie inverse du protocole Tesla et du schéma Absinthe

L'enregistrement DEP implique que `cloudconfigurationd` envoie une charge utile JSON signée et chiffrée à _iprofiles.apple.com/macProfile_. La charge utile inclut le numéro de série de l'appareil et l'action "RequestProfileConfiguration". Le schéma de chiffrement utilisé est désigné en interne comme "Absinthe". Déchiffrer ce schéma est complexe et implique de nombreuses étapes, ce qui a conduit à explorer des méthodes alternatives pour insérer des numéros de série arbitraires dans la demande d'Activation Record.

## Proxying des demandes DEP

Les tentatives d'intercepter et de modifier les demandes DEP à _iprofiles.apple.com_ en utilisant des outils comme Charles Proxy ont été entravées par le chiffrement de la charge utile et les mesures de sécurité SSL/TLS. Cependant, l'activation de la configuration `MCCloudConfigAcceptAnyHTTPSCertificate` permet de contourner la validation du certificat du serveur, bien que la nature chiffrée de la charge utile empêche toujours la modification du numéro de série sans la clé de déchiffrement.

## Instrumentation des binaires système interagissant avec DEP

L'instrumentation des binaires système comme `cloudconfigurationd` nécessite de désactiver la Protection de l'Intégrité du Système (SIP) sur macOS. Avec SIP désactivé, des outils comme LLDB peuvent être utilisés pour s'attacher aux processus système et potentiellement modifier le numéro de série utilisé dans les interactions API DEP. Cette méthode est préférable car elle évite les complexités des droits et de la signature de code.

**Exploitation de l'instrumentation binaire :**
Modifier la charge utile de la demande DEP avant la sérialisation JSON dans `cloudconfigurationd` s'est avéré efficace. Le processus impliquait :

1. Attacher LLDB à `cloudconfigurationd`.
2. Localiser le point où le numéro de série système est récupéré.
3. Injecter un numéro de série arbitraire dans la mémoire avant que la charge utile ne soit chiffrée et envoyée.

Cette méthode a permis de récupérer des profils DEP complets pour des numéros de série arbitraires, démontrant une vulnérabilité potentielle.

### Automatisation de l'instrumentation avec Python

Le processus d'exploitation a été automatisé en utilisant Python avec l'API LLDB, rendant possible l'injection programmatique de numéros de série arbitraires et la récupération des profils DEP correspondants.

### Impacts potentiels des vulnérabilités DEP et MDM

La recherche a mis en évidence des préoccupations de sécurité significatives :

1. **Divulgation d'informations** : En fournissant un numéro de série enregistré dans DEP, des informations organisationnelles sensibles contenues dans le profil DEP peuvent être récupérées.

{{#include ../../../banners/hacktricks-training.md}}
