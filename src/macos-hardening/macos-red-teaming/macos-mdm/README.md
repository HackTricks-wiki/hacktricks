# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**To learn about macOS MDMs check:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Notions de base

### **MDM (Mobile Device Management) Overview**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) est utilisé pour superviser différents appareils utilisateurs finaux tels que smartphones, laptops et tablettes. Pour les plateformes Apple (iOS, macOS, tvOS), cela implique un ensemble de fonctionnalités, d'APIs et de pratiques spécifiques. Le fonctionnement de MDM repose sur un serveur MDM compatible, commercial ou open-source, qui doit implémenter le [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Points clés :

- Contrôle centralisé des appareils.
- Dépendance à un serveur MDM conforme au MDM protocol.
- Le serveur MDM peut envoyer diverses commandes aux appareils, par exemple effacement à distance des données ou installation de configurations.

### **Notions de base de DEP (Device Enrollment Program)**

Le [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) proposé par Apple facilite l'intégration de Mobile Device Management (MDM) en permettant une configuration zero-touch pour les appareils iOS, macOS et tvOS. DEP automatise le processus d'enrôlement, permettant aux appareils d'être opérationnels dès la sortie de la boîte, avec une intervention minimale de l'utilisateur ou de l'administrateur. Aspects essentiels :

- Permet aux appareils de s'enregistrer automatiquement auprès d'un serveur MDM prédéfini lors de la première activation.
- Principalement bénéfique pour les appareils neufs, mais applicable aussi lors de reconfigurations.
- Simplifie la configuration, rendant les appareils rapidement prêts pour un usage organisationnel.

### Considérations de sécurité

Il est crucial de noter que la facilité d'enrôlement offerte par DEP, bien qu'avantageuse, peut aussi présenter des risques de sécurité. Si des mesures de protection ne sont pas correctement appliquées pour l'enrôlement MDM, des attaquants pourraient exploiter ce processus simplifié pour enregistrer leur appareil sur le serveur MDM de l'organisation, en se faisant passer pour un appareil d'entreprise.

> [!CAUTION]
> **Alerte de sécurité** : L'enrôlement DEP simplifié pourrait permettre l'enregistrement non autorisé d'un appareil sur le serveur MDM de l'organisation si des protections appropriées ne sont pas en place.

### Notions de base — Qu'est-ce que SCEP (Simple Certificate Enrolment Protocol) ?

- Un protocole relativement ancien, créé avant la généralisation de TLS et HTTPS.
- Fournit aux clients une méthode standardisée pour envoyer une **Certificate Signing Request** (CSR) afin d'obtenir un certificat signé. Le client demande au serveur de lui délivrer un certificat signé.

### Que sont les Configuration Profiles (aka mobileconfigs) ?

- La méthode officielle d'Apple pour **configurer/forcer des paramètres système.**
- Format de fichier pouvant contenir plusieurs payloads.
- Basés sur des property lists (le format XML).
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocoles

### MDM

- Combinaison de APNs (**Apple server**s) + RESTful API (**MDM** **vendor** servers)
- La **communication** se fait entre un **device** et un serveur associé à un produit de **device management**
- Les **commands** sont envoyées du MDM vers l'appareil sous forme de **plist-encoded dictionaries**
- Tout passe par **HTTPS**. Les serveurs MDM peuvent être (et sont généralement) pinned.
- Apple fournit au MDM vendor un **APNs certificate** pour l'authentification

### DEP

- **3 APIs** : 1 pour les resellers, 1 pour les MDM vendors, 1 pour l'identité des devices (non documentée) :
- Le soi-disant [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Utilisé par les serveurs MDM pour associer des DEP profiles à des appareils spécifiques.
- L'[DEP API used by Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) pour enregistrer des appareils, vérifier le statut d'enrôlement, et vérifier le statut des transactions.
- L'API DEP privée non documentée. Utilisée par les Apple Devices pour demander leur DEP profile. Sur macOS, le binaire `cloudconfigurationd` est responsable de la communication via cette API.
- Plus moderne et basé sur **JSON** (vs. plist)
- Apple fournit un **OAuth token** au MDM vendor

**DEP "cloud service" API**

- RESTful
- synchronise les device records d'Apple vers le serveur MDM
- synchronise les “DEP profiles” vers Apple depuis le serveur MDM (livrés plus tard à l'appareil)
- Un DEP “profile” contient :
- MDM vendor server URL
- Certificats de confiance additionnels pour le server URL (pinning optionnel)
- Paramètres supplémentaires (ex. quelles écrans ignorer dans Setup Assistant)

## Numéro de série

Les appareils Apple fabriqués après 2010 ont généralement des numéros de série alphanumériques de **12 caractères**, où les **trois premiers** chiffres représentent le lieu de fabrication, les **deux suivants** indiquent l'**année** et la **semaine** de fabrication, les **trois suivants** fournissent un **identifiant unique**, et les **quatre derniers** chiffres représentent le **numéro de modèle**.

{{#ref}}
macos-serial-number.md
{{#endref}}

## Étapes d'enrôlement et de gestion

1. Création du device record (Reseller, Apple) : L'enregistrement du nouvel appareil est créé
2. Affectation du device record (Customer) : L'appareil est assigné à un serveur MDM
3. Synchronisation des device records (MDM vendor) : le MDM synchronise les device records et pousse les DEP profiles vers Apple
4. DEP check-in (Device) : L'appareil récupère son DEP profile
5. Récupération du profile (Device)
6. Installation du profile (Device) a. incl. payloads MDM, SCEP et root CA
7. Émission de commandes MDM (Device)

![](<../../../images/image (694).png>)

Le fichier `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporte des fonctions qui peuvent être considérées comme des **"étapes"** de haut niveau du processus d'enrôlement.

### Étape 4 : DEP check-in — Obtention de l'Activation Record

Cette partie du processus se produit lorsqu'un **utilisateur démarre un Mac pour la première fois** (ou après un effacement complet)

![](<../../../images/image (1044).png>)

ou lors de l'exécution de `sudo profiles show -type enrollment`

- Déterminer **si l'appareil est DEP enabled**
- Activation Record est le nom interne du **DEP “profile”**
- Commence dès que l'appareil est connecté à Internet
- Piloté par **`CPFetchActivationRecord`**
- Implémenté par **`cloudconfigurationd`** via XPC. Le **"Setup Assistant"** (lors du premier démarrage de l'appareil) ou la commande **`profiles`** contacteront ce daemon pour récupérer l'activation record.
- LaunchDaemon (toujours lancé en root)

La récupération de l'Activation Record suit quelques étapes réalisées par **`MCTeslaConfigurationFetcher`**. Ce processus utilise un chiffrement appelé **Absinthe**

1. Récupérer le **certificate**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialiser** l'état à partir du certificate (**`NACInit`**)
1. Utilise diverses données spécifiques à l'appareil (p.ex. **Serial Number via `IOKit`**)
3. Récupérer la **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Établir la session (**`NACKeyEstablishment`**)
5. Faire la requête
1. POST vers [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) en envoyant les données `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Le payload JSON est chiffré en utilisant Absinthe (**`NACSign`**)
3. Toutes les requêtes passent par HTTPs, les certificats racines intégrés sont utilisés

![](<../../../images/image (566) (1).png>)

La réponse est un dictionnaire JSON contenant des données importantes comme :

- **url** : URL de l'hôte du MDM vendor pour le activation profile
- **anchor-certs** : Tableau de certificats DER utilisés comme ancres de confiance

### **Étape 5 : Récupération du Profile**

![](<../../../images/image (444).png>)

- Requête envoyée à l'**url fournie dans le DEP profile**.
- Les **anchor certificates** sont utilisés pour **évaluer la confiance** si fournis.
- Rappel : la propriété **anchor_certs** du DEP profile
- La **requête est un simple .plist** contenant l'identification de l'appareil
- Exemples : **UDID, OS version**.
- CMS-signed, DER-encoded
- Signé en utilisant le **device identity certificate (from APNS)**
- La **chaîne de certificats** inclut le **Apple iPhone Device CA** expiré

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Étape 6 : Installation du Profile

- Une fois récupéré, le **profile est stocké sur le système**
- Cette étape commence automatiquement (si dans le **setup assistant**)
- Pilotée par **`CPInstallActivationProfile`**
- Implémentée par mdmclient via XPC
- LaunchDaemon (en root) ou LaunchAgent (en utilisateur), selon le contexte
- Les configuration profiles contiennent plusieurs payloads à installer
- Le framework a une architecture basée sur des plugins pour l'installation des profiles
- Chaque type de payload est associé à un plugin
- Peut être XPC (dans le framework) ou Cocoa classique (dans ManagedClient.app)
- Exemple :
- Les Certificate Payloads utilisent CertificateService.xpc

Typiquement, un **activation profile** fourni par un MDM vendor inclura les payloads suivants :

- `com.apple.mdm` : pour **enrôler** l'appareil dans le MDM
- `com.apple.security.scep` : pour fournir de manière sécurisée un **client certificate** à l'appareil.
- `com.apple.security.pem` : pour **installer des CA de confiance** dans le System Keychain de l'appareil.
- Installer le MDM payload équivaut à **MDM check-in** dans la documentation
- Le payload **contient des propriétés clés** :
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs topic pour le déclencher
- Pour installer le MDM payload, une requête est envoyée à **`CheckInURL`**
- Implémenté dans **`mdmclient`**
- Le MDM payload peut dépendre d'autres payloads
- Permet **de pinner des requêtes à des certificats spécifiques** :
- Propriété : **`CheckInURLPinningCertificateUUIDs`**
- Propriété : **`ServerURLPinningCertificateUUIDs`**
- Livré via un payload PEM
- Permet d'attribuer à l'appareil un certificat d'identité :
- Propriété : IdentityCertificateUUID
- Livré via un payload SCEP

### **Étape 7 : Écoute des commandes MDM**

- Après le MDM check-in, le vendor peut **envoyer des push notifications via APNs**
- À la réception, géré par **`mdmclient`**
- Pour interroger les commandes MDM, une requête est envoyée au ServerURL
- Utilise le MDM payload installé précédemment :
- **`ServerURLPinningCertificateUUIDs`** pour le pinning des requêtes
- **`IdentityCertificateUUID`** pour le certificat client TLS

## Attaques

### Enrôler des appareils dans d'autres organisations

Comme mentionné précédemment, pour tenter d'enrôler un appareil dans une organisation, **il suffit d'un Serial Number appartenant à cette organisation**. Une fois l'appareil enrôlé, de nombreuses organisations installeront des données sensibles sur le nouvel appareil : certificats, applications, mots de passe WiFi, configurations VPN [and so on](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela peut constituer un point d'entrée dangereux pour des attaquants si le processus d'enrôlement n'est pas correctement protégé :

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
