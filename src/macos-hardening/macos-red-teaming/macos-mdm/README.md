# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Pour en savoir plus sur les MDM macOS, consultez :**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Basics

### **Aperçu de MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) est utilisé pour superviser divers appareils d'utilisateur final tels que les smartphones, les ordinateurs portables et les tablettes. En particulier pour les plateformes d'Apple (iOS, macOS, tvOS), cela implique un ensemble de fonctionnalités, d'API et de pratiques spécialisées. Le fonctionnement de MDM repose sur un serveur MDM compatible, qui est soit commercial, soit open-source, et doit prendre en charge le [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Les points clés incluent :

- Contrôle centralisé des appareils.
- Dépendance à un serveur MDM qui respecte le protocole MDM.
- Capacité du serveur MDM à envoyer divers commandes aux appareils, par exemple, l'effacement à distance des données ou l'installation de configurations.

### **Principes de base de DEP (Device Enrollment Program)**

Le [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) proposé par Apple simplifie l'intégration de la gestion des appareils mobiles (MDM) en facilitant la configuration sans contact pour les appareils iOS, macOS et tvOS. DEP automatise le processus d'inscription, permettant aux appareils d'être opérationnels dès leur sortie de la boîte, avec un minimum d'intervention de l'utilisateur ou de l'administrateur. Les aspects essentiels incluent :

- Permet aux appareils de s'enregistrer de manière autonome auprès d'un serveur MDM prédéfini lors de l'activation initiale.
- Principalement bénéfique pour les appareils neufs, mais également applicable aux appareils en cours de reconfiguration.
- Facilite une configuration simple, rendant les appareils prêts à l'utilisation organisationnelle rapidement.

### **Considération de sécurité**

Il est crucial de noter que la facilité d'inscription fournie par DEP, bien que bénéfique, peut également poser des risques de sécurité. Si les mesures de protection ne sont pas adéquatement appliquées pour l'inscription MDM, les attaquants pourraient exploiter ce processus simplifié pour enregistrer leur appareil sur le serveur MDM de l'organisation, se faisant passer pour un appareil d'entreprise.

> [!CAUTION]
> **Alerte de sécurité** : L'inscription simplifiée à DEP pourrait potentiellement permettre l'enregistrement non autorisé d'appareils sur le serveur MDM de l'organisation si des mesures de protection appropriées ne sont pas en place.

### Qu'est-ce que SCEP (Simple Certificate Enrollment Protocol) ?

- Un protocole relativement ancien, créé avant que TLS et HTTPS ne soient répandus.
- Donne aux clients un moyen standardisé d'envoyer une **demande de signature de certificat** (CSR) dans le but d'obtenir un certificat. Le client demandera au serveur de lui fournir un certificat signé.

### Qu'est-ce que les profils de configuration (alias mobileconfigs) ?

- La méthode officielle d'Apple pour **définir/appliquer la configuration système.**
- Format de fichier pouvant contenir plusieurs charges utiles.
- Basé sur des listes de propriétés (le type XML).
- “peut être signé et chiffré pour valider leur origine, garantir leur intégrité et protéger leur contenu.” Principes de base — Page 70, iOS Security Guide, janvier 2018.

## Protocoles

### MDM

- Combinaison de APNs (**serveurs Apple**) + API RESTful (**serveurs de fournisseur MDM**)
- **La communication** se produit entre un **appareil** et un serveur associé à un **produit de gestion des appareils**
- **Commandes** livrées du MDM à l'appareil dans des **dictionnaires encodés en plist**
- Tout cela via **HTTPS**. Les serveurs MDM peuvent être (et sont généralement) épinglés.
- Apple accorde au fournisseur MDM un **certificat APNs** pour l'authentification

### DEP

- **3 API** : 1 pour les revendeurs, 1 pour les fournisseurs MDM, 1 pour l'identité de l'appareil (non documentée) :
- La soi-disant [API "cloud service" DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Cela est utilisé par les serveurs MDM pour associer des profils DEP à des appareils spécifiques.
- L'[API DEP utilisée par les revendeurs autorisés Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) pour inscrire des appareils, vérifier l'état d'inscription et vérifier l'état des transactions.
- L'API DEP privée non documentée. Cela est utilisé par les appareils Apple pour demander leur profil DEP. Sur macOS, le binaire `cloudconfigurationd` est responsable de la communication via cette API.
- Plus moderne et basé sur **JSON** (vs. plist)
- Apple accorde un **jeton OAuth** au fournisseur MDM

**API "cloud service" DEP**

- RESTful
- synchroniser les enregistrements d'appareils d'Apple au serveur MDM
- synchroniser les “profils DEP” d'Apple depuis le serveur MDM (livrés par Apple à l'appareil plus tard)
- Un profil DEP contient :
- URL du serveur fournisseur MDM
- Certificats supplémentaires de confiance pour l'URL du serveur (épinglage optionnel)
- Paramètres supplémentaires (par exemple, quels écrans sauter dans l'Assistant de configuration)

## Numéro de série

Les appareils Apple fabriqués après 2010 ont généralement des numéros de série alphanumériques de **12 caractères**, les **trois premiers chiffres représentant le lieu de fabrication**, les **deux suivants** indiquant l'**année** et la **semaine** de fabrication, les **trois chiffres suivants** fournissant un **identifiant unique**, et les **quatre derniers** chiffres représentant le **numéro de modèle**.

{{#ref}}
macos-serial-number.md
{{#endref}}

## Étapes pour l'inscription et la gestion

1. Création de l'enregistrement de l'appareil (Revendeur, Apple) : L'enregistrement du nouvel appareil est créé
2. Attribution de l'enregistrement de l'appareil (Client) : L'appareil est attribué à un serveur MDM
3. Synchronisation de l'enregistrement de l'appareil (Fournisseur MDM) : MDM synchronise les enregistrements d'appareils et pousse les profils DEP vers Apple
4. Enregistrement DEP (Appareil) : L'appareil obtient son profil DEP
5. Récupération du profil (Appareil)
6. Installation du profil (Appareil) a. incl. charges utiles MDM, SCEP et CA racine
7. Émission de commandes MDM (Appareil)

![](<../../../images/image (694).png>)

Le fichier `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporte des fonctions qui peuvent être considérées comme des **"étapes" de haut niveau** du processus d'inscription.

### Étape 4 : Enregistrement DEP - Obtention de l'enregistrement d'activation

Cette partie du processus se produit lorsqu'un **utilisateur démarre un Mac pour la première fois** (ou après un effacement complet)

![](<../../../images/image (1044).png>)

ou lors de l'exécution de `sudo profiles show -type enrollment`

- Déterminer **si l'appareil est activé DEP**
- L'enregistrement d'activation est le nom interne pour le **profil DEP**
- Commence dès que l'appareil est connecté à Internet
- Piloté par **`CPFetchActivationRecord`**
- Mis en œuvre par **`cloudconfigurationd`** via XPC. L'**"Assistant de configuration"** (lorsque l'appareil est démarré pour la première fois) ou la commande **`profiles`** contactera ce démon pour récupérer l'enregistrement d'activation.
- LaunchDaemon (s'exécute toujours en tant que root)

Il suit quelques étapes pour obtenir l'enregistrement d'activation effectué par **`MCTeslaConfigurationFetcher`**. Ce processus utilise un chiffrement appelé **Absinthe**

1. Récupérer **le certificat**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialiser** l'état à partir du certificat (**`NACInit`**)
1. Utilise diverses données spécifiques à l'appareil (c'est-à-dire **Numéro de série via `IOKit`**)
3. Récupérer **la clé de session**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Établir la session (**`NACKeyEstablishment`**)
5. Faire la demande
1. POST à [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) en envoyant les données `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. La charge utile JSON est chiffrée à l'aide d'Absinthe (**`NACSign`**)
3. Toutes les demandes via HTTPs, des certificats racines intégrés sont utilisés

![](<../../../images/image (566) (1).png>)

La réponse est un dictionnaire JSON contenant des données importantes telles que :

- **url** : URL de l'hôte fournisseur MDM pour le profil d'activation
- **anchor-certs** : Tableau de certificats DER utilisés comme ancres de confiance

### **Étape 5 : Récupération du profil**

![](<../../../images/image (444).png>)

- Demande envoyée à **l'url fournie dans le profil DEP**.
- **Certificats d'ancrage** sont utilisés pour **évaluer la confiance** si fournis.
- Rappel : la propriété **anchor_certs** du profil DEP
- **La demande est un simple .plist** avec identification de l'appareil
- Exemples : **UDID, version OS**.
- Signé par CMS, encodé en DER
- Signé à l'aide du **certificat d'identité de l'appareil (provenant d'APNS)**
- **La chaîne de certificats** inclut un **Apple iPhone Device CA** expiré

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Étape 6 : Installation du profil

- Une fois récupéré, **le profil est stocké sur le système**
- Cette étape commence automatiquement (si dans **l'assistant de configuration**)
- Piloté par **`CPInstallActivationProfile`**
- Mis en œuvre par mdmclient via XPC
- LaunchDaemon (en tant que root) ou LaunchAgent (en tant qu'utilisateur), selon le contexte
- Les profils de configuration ont plusieurs charges utiles à installer
- Le cadre a une architecture basée sur des plugins pour l'installation des profils
- Chaque type de charge utile est associé à un plugin
- Peut être XPC (dans le cadre) ou classique Cocoa (dans ManagedClient.app)
- Exemple :
- Les charges utiles de certificat utilisent CertificateService.xpc

Typiquement, **le profil d'activation** fourni par un fournisseur MDM inclura **les charges utiles suivantes** :

- `com.apple.mdm` : pour **inscrire** l'appareil dans MDM
- `com.apple.security.scep` : pour fournir de manière sécurisée un **certificat client** à l'appareil.
- `com.apple.security.pem` : pour **installer des certificats CA de confiance** dans le trousseau système de l'appareil.
- Installer la charge utile MDM équivaut à **l'enregistrement MDM dans la documentation**
- La charge utile **contient des propriétés clés** :
- - URL de vérification MDM (**`CheckInURL`**)
- URL de sondage des commandes MDM (**`ServerURL`**) + sujet APNs pour le déclencher
- Pour installer la charge utile MDM, une demande est envoyée à **`CheckInURL`**
- Mis en œuvre dans **`mdmclient`**
- La charge utile MDM peut dépendre d'autres charges utiles
- Permet **d'épingler les demandes à des certificats spécifiques** :
- Propriété : **`CheckInURLPinningCertificateUUIDs`**
- Propriété : **`ServerURLPinningCertificateUUIDs`**
- Livré via la charge utile PEM
- Permet à l'appareil d'être attribué avec un certificat d'identité :
- Propriété : IdentityCertificateUUID
- Livré via la charge utile SCEP

### **Étape 7 : Écoute des commandes MDM**

- Après que l'enregistrement MDM soit complet, le fournisseur peut **émettre des notifications push en utilisant APNs**
- À la réception, géré par **`mdmclient`**
- Pour interroger les commandes MDM, une demande est envoyée à ServerURL
- Utilise la charge utile MDM précédemment installée :
- **`ServerURLPinningCertificateUUIDs`** pour la demande d'épinglage
- **`IdentityCertificateUUID`** pour le certificat client TLS

## Attaques

### Inscription d'appareils dans d'autres organisations

Comme commenté précédemment, pour essayer d'inscrire un appareil dans une organisation, **il suffit d'un numéro de série appartenant à cette organisation**. Une fois l'appareil inscrit, plusieurs organisations installeront des données sensibles sur le nouvel appareil : certificats, applications, mots de passe WiFi, configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela pourrait être un point d'entrée dangereux pour les attaquants si le processus d'inscription n'est pas correctement protégé :

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
