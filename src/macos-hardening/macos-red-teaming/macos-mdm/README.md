# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Pour en savoir plus sur les MDM macOS, consultez :**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Bases

### **Présentation de MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) est utilisé pour superviser différents appareils d'utilisateurs finaux, tels que les smartphones, les ordinateurs portables et les tablettes. En particulier pour les plateformes Apple (iOS, macOS, tvOS), cela implique un ensemble de fonctionnalités, d'API et de pratiques spécialisées. Le fonctionnement du MDM repose sur un serveur MDM compatible, disponible dans le commerce ou open-source, qui doit prendre en charge le [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Points essentiels :

- Contrôle centralisé des appareils.
- Dépendance à un serveur MDM conforme au protocole MDM.
- Capacité du serveur MDM à envoyer diverses commandes aux appareils, par exemple pour effacer des données à distance ou installer une configuration.

### **Bases de DEP (Device Enrollment Program)**

Le [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) proposé par Apple simplifie l'intégration du Mobile Device Management (MDM) en facilitant la configuration zero-touch des appareils iOS, macOS et tvOS. DEP automatise le processus d'inscription, permettant aux appareils d'être opérationnels dès leur sortie de boîte, avec une intervention minimale de l'utilisateur ou de l'administrateur. Aspects essentiels :

- Permet aux appareils de s'enregistrer automatiquement auprès d'un serveur MDM prédéfini lors de leur première activation.
- Principalement utile pour les appareils neufs, mais également applicable aux appareils faisant l'objet d'une reconfiguration.
- Facilite une configuration simple, rendant rapidement les appareils prêts à être utilisés par l'organisation.

### **Considérations de sécurité**

Il est essentiel de noter que la facilité d'inscription offerte par DEP, bien qu'avantageuse, peut également présenter des risques de sécurité. Si les mesures de protection ne sont pas correctement appliquées lors de l'inscription MDM, des attaquants pourraient exploiter ce processus simplifié pour enregistrer leur appareil sur le serveur MDM de l'organisation, en le faisant passer pour un appareil d'entreprise.<sup>[2]</sup>

> [!CAUTION]
> **Alerte de sécurité** : l'inscription DEP simplifiée pourrait permettre l'enregistrement d'un appareil non autorisé sur le serveur MDM de l'organisation si des mesures de protection appropriées ne sont pas en place.

### Bases : qu'est-ce que SCEP (Simple Certificate Enrolment Protocol) ?

- Un protocole relativement ancien, créé avant la généralisation de TLS et HTTPS.
- Fournit aux clients une méthode standardisée pour envoyer une **Certificate Signing Request** (CSR) afin d'obtenir un certificat. Le client demande au serveur de lui fournir un certificat signé.

### Que sont les Configuration Profiles (également appelés mobileconfigs) ?

- La méthode officielle d'Apple pour **définir/appliquer la configuration du système**.
- Format de fichier pouvant contenir plusieurs payloads.
- Basé sur des property lists (au format XML).
- « peuvent être signés et chiffrés afin de valider leur origine, garantir leur intégrité et protéger leur contenu ». Basics — Page 70, iOS Security Guide, January 2018.

## Protocoles

### MDM

- Combinaison d'APNs (**serveurs Apple**) + RESTful API (**serveurs des vendors** **MDM**)
- La **communication** s'effectue entre un **appareil** et un serveur associé à un **produit** de **gestion** d'**appareils**
- Les **commandes** sont envoyées du MDM vers l'appareil sous forme de **dictionnaires encodés en plist**
- Le tout via **HTTPS**. Les serveurs MDM peuvent être (et sont généralement) soumis au pinning.
- Apple fournit au vendor MDM un **certificat APNs** pour l'authentification

### DEP

- **3 APIs** : 1 pour les revendeurs, 1 pour les vendors MDM, 1 pour l'identité de l'appareil (non documentée) :
- La [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Elle est utilisée par les serveurs MDM pour associer des profils DEP à des appareils spécifiques.
- La [DEP API used by Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html), utilisée pour inscrire les appareils, vérifier leur état d'inscription et vérifier l'état des transactions.
- La private DEP API non documentée. Elle est utilisée par les Apple Devices pour demander leur profil DEP. Sous macOS, le binaire `cloudconfigurationd` est chargé de communiquer via cette API.
- Plus moderne et basée sur **JSON** (par opposition à plist)
- Apple fournit un **token OAuth** au vendor MDM

**DEP "cloud service" API**

- RESTful
- synchronise les enregistrements d'appareils d'Apple vers le serveur MDM
- synchronise les « profils DEP » du serveur MDM vers Apple (ils seront ensuite transmis par Apple à l'appareil)
- Un « profil » DEP contient :
- URL du serveur du vendor MDM
- Certificats supplémentaires approuvés pour l'URL du serveur (pinning facultatif)
- Paramètres supplémentaires (par exemple, les écrans à ignorer dans Setup Assistant)

## Numéro de série

Les appareils Apple fabriqués après 2010 disposent généralement de numéros de série **alphanumériques de 12 caractères** ; les **trois premiers chiffres représentent le lieu de fabrication**, les **deux suivants indiquent l'**année** et la semaine de fabrication**, les **trois chiffres suivants fournissent un **identifiant** **unique**, et les **quatre derniers chiffres représentent le numéro de modèle**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Étapes d'inscription et de gestion

1. Création de l'enregistrement de l'appareil (Revendeur, Apple) : l'enregistrement du nouvel appareil est créé
2. Attribution de l'enregistrement de l'appareil (Client) : l'appareil est attribué à un serveur MDM
3. Synchronisation de l'enregistrement de l'appareil (vendor MDM) : le MDM synchronise les enregistrements des appareils et transmet les profils DEP à Apple
4. DEP check-in (Appareil) : l'appareil reçoit son profil DEP
5. Récupération du profil (Appareil)
6. Installation du profil (Appareil), a. notamment les payloads MDM, SCEP et root CA
7. Envoi de commandes MDM (Appareil)

![Numéro de série - Étapes d'inscription et de gestion : 7. Envoi de commandes MDM (Appareil)](<../../../images/image (694).png>)

Le fichier `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporte des fonctions qui peuvent être considérées comme des **« étapes » de haut niveau** du processus d'inscription.

### Étape 4 : DEP check-in - Obtention de l'Activation Record

Cette partie du processus se produit lorsqu'un **utilisateur démarre un Mac pour la première fois** (ou après un effacement complet)

![Étapes d'inscription et de gestion - Étape 4 : DEP check-in - Obtention de l'Activation Record : cette partie du processus se produit lorsqu'un utilisateur démarre un Mac pour la première fois (ou après un effacement complet...](<../../../images/image (1044).png>)

ou lors de l'exécution de `sudo profiles show -type enrollment`

- Détermine **si l'appareil est activé pour DEP**
- Activation Record est le nom interne du **« profil » DEP**
- Commence dès que l'appareil est connecté à Internet
- Piloté par **`CPFetchActivationRecord`**
- Implémenté par **`cloudconfigurationd`** via XPC. **« Setup Assistant** » (lors du premier démarrage de l'appareil) ou la commande **`profiles`** **contacte ce daemon** pour récupérer l'activation record.
- LaunchDaemon (s'exécute toujours en tant que root)

Quelques étapes sont nécessaires pour obtenir l'Activation Record, exécutées par **`MCTeslaConfigurationFetcher`**. Ce processus utilise un chiffrement appelé **Absinthe**<sup>[1]</sup>

1. Récupérer le **certificat**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialiser** l'état à partir du certificat (**`NACInit`**)
1. Utilise différentes données spécifiques à l'appareil (c.-à-d. le **numéro de série via `IOKit`**)
3. Récupérer la **clé de session**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Établir la session (**`NACKeyEstablishment`**)
5. Effectuer la requête
1. POST vers [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) en envoyant les données `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Le payload JSON est chiffré à l'aide d'Absinthe (**`NACSign`**)
3. Toutes les requêtes utilisent HTTPs, avec les certificats root intégrés

![Étapes d'inscription et de gestion - Étape 4 : DEP check-in - Obtention de l'Activation Record : 3. Toutes les requêtes utilisent HTTPs, avec les certificats root intégrés](<../../../images/image (566) (1).png>)

La réponse est un dictionnaire JSON contenant des données importantes telles que :

- **url** : URL de l'hôte du vendor MDM pour le profil d'activation
- **anchor-certs** : tableau de certificats DER utilisés comme ancres de confiance

### **Étape 5 : Récupération du profil**

![Étape 4 : DEP check-in - Obtention de l'Activation Record - Étape 5 : Récupération du profil : Étape 5 : Récupération du profil](<../../../images/image (444).png>)

- Requête envoyée vers l'**url fournie dans le profil DEP**.
- Les **certificats d'ancrage** sont utilisés pour **évaluer la confiance** s'ils sont fournis.
- Rappel : propriété **anchor_certs** du profil DEP
- La **requête est un simple .plist** contenant l'identification de l'appareil
- Exemples : **UDID, version de l'OS**.
- Signé par CMS, encodé en DER
- Signé à l'aide du **certificat d'identité de l'appareil (provenant d'APNS)**
- La **chaîne de certificats** inclut **Apple iPhone Device CA** expiré

![Étape 4 : DEP check-in - Obtention de l'Activation Record - Étape 5 : Récupération du profil : signé à l'aide du certificat d'identité de l'appareil (provenant d'APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Étape 6 : Installation du profil

- Une fois récupéré, le **profil est stocké sur le système**
- Cette étape commence automatiquement (dans **Setup Assistant**)
- Pilotée par **`CPInstallActivationProfile`**
- Implémentée par mdmclient via XPC
- LaunchDaemon (en tant que root) ou LaunchAgent (en tant qu'utilisateur), selon le contexte
- Les Configuration Profiles contiennent plusieurs payloads à installer
- Le framework utilise une architecture basée sur des plugins pour installer les profils
- Chaque type de payload est associé à un plugin
- Peut être XPC (dans le framework) ou Cocoa classique (dans ManagedClient.app)
- Exemple :
- Les Certificate Payloads utilisent CertificateService.xpc

En général, le **activation profile** fourni par un vendor MDM **inclura les payloads suivants** :

- `com.apple.mdm` : pour **inscrire** l'appareil dans le MDM
- `com.apple.security.scep` : pour fournir de manière sécurisée un **certificat client** à l'appareil.
- `com.apple.security.pem` : pour **installer des certificats CA approuvés** dans le System Keychain de l'appareil.
- Installation du payload MDM équivalente au **MDM check-in dans la documentation**
- Le payload **contient des propriétés clés** :
- - URL de MDM Check-In (**`CheckInURL`**)
- URL d'interrogation des commandes MDM (**`ServerURL`**) + topic APNs pour la déclencher
- Pour installer le payload MDM, une requête est envoyée à **`CheckInURL`**
- Implémenté dans **`mdmclient`**
- Le payload MDM peut dépendre d'autres payloads
- Permet de **pinner les requêtes vers des certificats spécifiques** :
- Propriété : **`CheckInURLPinningCertificateUUIDs`**
- Propriété : **`ServerURLPinningCertificateUUIDs`**
- Fourni via un payload PEM
- Permet d'attribuer une identité à l'appareil au moyen d'un certificat d'identité :
- Propriété : IdentityCertificateUUID
- Fourni via un payload SCEP

### **Étape 7 : Écoute des commandes MDM**

- Une fois le MDM check-in terminé, le vendor peut **émettre des notifications push via APNs**
- À leur réception, elles sont traitées par **`mdmclient`**
- Pour interroger les commandes MDM, une requête est envoyée à ServerURL
- Utilise le payload MDM précédemment installé :
- **`ServerURLPinningCertificateUUIDs`** pour le pinning de la requête
- **`IdentityCertificateUUID`** pour le certificat client TLS

## Attaques

### Inscription d'appareils dans d'autres organisations

Comme indiqué précédemment, pour tenter d'inscrire un appareil dans une organisation, **seul un numéro de série appartenant à cette organisation est nécessaire**. Une fois l'appareil inscrit, plusieurs organisations installent des données sensibles sur le nouvel appareil : certificats, applications, mots de passe WiFi, configurations VPN [et ainsi de suite](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Par conséquent, cela peut constituer un point d'entrée dangereux pour les attaquants si le processus d'inscription n'est pas correctement protégé :<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Références

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
