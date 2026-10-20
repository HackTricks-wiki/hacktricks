# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Pour en savoir plus sur les MDM macOS, consultez :**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Bases

### **Présentation du MDM (Mobile Device Management)**

La [gestion des appareils mobiles](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) est utilisée pour superviser divers appareils d’utilisateurs finaux, comme les smartphones, les ordinateurs portables et les tablettes. Sur les plateformes Apple (iOS, macOS, tvOS), elle repose notamment sur un ensemble de fonctionnalités, d’API et de pratiques spécialisées. Le fonctionnement du MDM dépend d’un serveur MDM compatible, disponible dans le commerce ou en open source, qui doit prendre en charge le [protocole MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Points clés :

- Contrôle centralisé des appareils.
- Dépendance à un serveur MDM conforme au protocole MDM.
- Capacité du serveur MDM à envoyer diverses commandes aux appareils, par exemple pour effacer des données à distance ou installer des configurations.

### **Bases du DEP (Device Enrollment Program)**

Le [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) proposé par Apple simplifie l’intégration du MDM (Mobile Device Management) en permettant la configuration sans intervention des appareils iOS, macOS et tvOS. Le DEP automatise le processus d’inscription, afin que les appareils soient prêts à l’emploi dès leur sortie de la boîte, avec une intervention minimale de l’utilisateur ou de l’administrateur. Points essentiels :

- Permet aux appareils de s’inscrire automatiquement auprès d’un serveur MDM prédéfini lors de leur première activation.
- Principalement utile pour les appareils neufs, mais également applicable aux appareils en cours de reconfiguration.
- Simplifie la configuration et permet de préparer rapidement les appareils à un usage professionnel.

### **Considérations de sécurité**

Il est important de noter que la facilité d’inscription offerte par le DEP, bien qu’utile, peut également présenter des risques de sécurité. Si les mesures de protection de l’inscription MDM sont insuffisantes, des attaquants pourraient exploiter ce processus simplifié pour inscrire leur appareil sur le serveur MDM de l’organisation en le faisant passer pour un appareil professionnel.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Alerte de sécurité** : une inscription DEP simplifiée pourrait permettre l’inscription d’appareils non autorisés sur le serveur MDM de l’organisation si des mesures de protection adéquates ne sont pas en place.

### Bases : qu’est-ce que SCEP (Simple Certificate Enrolment Protocol) ?

- Protocole relativement ancien, créé avant que TLS et HTTPS ne soient largement répandus.
- Fournit aux clients une méthode standardisée pour envoyer une **demande de signature de certificat** (CSR) afin d’obtenir un certificat. Le client demande au serveur de lui fournir un certificat signé.

### Que sont les profils de configuration (aussi appelés mobileconfigs) ?

- Méthode officielle d’Apple pour **définir/appliquer la configuration du système**.
- Format de fichier pouvant contenir plusieurs payloads.
- Basé sur les listes de propriétés (au format XML).
- « peut être signé et chiffré pour valider leur origine, garantir leur intégrité et protéger leur contenu. » Basics — Page 70, iOS Security Guide, janvier 2018.

## Protocoles

### MDM

- Combinaison d’APNs (**serveurs Apple**) et d’une API RESTful (serveurs des **fournisseurs MDM**)
- La **communication** a lieu entre un **appareil** et un serveur associé à un **produit de gestion des appareils**
- Les **commandes** sont envoyées du MDM à l’appareil sous forme de **dictionnaires encodés en plist**
- Le tout passe par **HTTPS**. Les serveurs MDM peuvent être épinglés, et le sont généralement.
- Apple fournit au fournisseur MDM un **certificat APNs** à des fins d’authentification

### DEP

- **3 API** : 1 pour les revendeurs, 1 pour les fournisseurs MDM, 1 pour l’identité des appareils (non documentée) :
  - La [« cloud service » API du DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Elle est utilisée par les serveurs MDM pour associer des profils DEP à des appareils spécifiques.
  - L’[API DEP utilisée par les revendeurs agréés Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) pour inscrire les appareils, vérifier leur statut d’inscription et celui des transactions.
  - L’API DEP privée non documentée. Elle est utilisée par les appareils Apple pour demander leur profil DEP. Sous macOS, le binaire `cloudconfigurationd` gère la communication via cette API.
- Plus moderne et basée sur **JSON** (contrairement à plist)
- Apple fournit un **jeton OAuth** au fournisseur MDM

**API « cloud service » du DEP**

- RESTful
- Synchronise les enregistrements des appareils d’Apple vers le serveur MDM
- Synchronise les « profils DEP » du serveur MDM vers Apple (qui les transmet ensuite à l’appareil)
- Un « profil » DEP contient :
  - L’URL du serveur du fournisseur MDM
  - Des certificats de confiance supplémentaires pour l’URL du serveur (épinglage facultatif)
  - Des paramètres supplémentaires (par exemple, les écrans à ignorer dans l’Assistant réglages)

## Numéro de série

Les appareils Apple fabriqués après 2010 ont généralement un numéro de série **alphanumérique de 12 caractères**. **Les trois premiers chiffres indiquent le lieu de fabrication**, les **deux suivants**, l’**année** et la **semaine** de fabrication, les **trois suivants** fournissent un **identifiant unique**, et les **quatre derniers** représentent le **numéro de modèle**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Étapes d’inscription et de gestion

1. Création de l’enregistrement de l’appareil (revendeur, Apple) : l’enregistrement du nouvel appareil est créé
2. Attribution de l’enregistrement de l’appareil (client) : l’appareil est attribué à un serveur MDM
3. Synchronisation de l’enregistrement de l’appareil (fournisseur MDM) : le MDM synchronise les enregistrements des appareils et transmet les profils DEP à Apple
4. Check-in DEP (appareil) : l’appareil reçoit son profil DEP
5. Récupération du profil (appareil)
6. Installation du profil (appareil) a. comprend les payloads MDM, SCEP et CA racine
7. Émission d’une commande MDM (appareil)

![Numéro de série - Étapes d’inscription et de gestion : 7. Émission d’une commande MDM (appareil)](<../../../images/image (694).png>)

Le fichier `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporte des fonctions qui peuvent être considérées comme des « étapes » de haut niveau du processus d’inscription.

### Étape 4 : check-in DEP — Récupération de l’Activation Record

Cette étape du processus a lieu lorsqu’un **utilisateur démarre un Mac pour la première fois** (ou après un effacement complet)

![Étapes d’inscription et de gestion - Étape 4 : check-in DEP - Récupération de l’Activation Record : cette étape du processus a lieu lorsqu’un utilisateur démarre un Mac pour la première fois (ou après un...](<../../../images/image (1044).png>)

ou lors de l’exécution de `sudo profiles show -type enrollment`

- Déterminer **si l’appareil est compatible avec le DEP**
- Activation Record est le nom interne du **« profil » DEP**
- Le processus commence dès que l’appareil est connecté à Internet
- Géré par **`CPFetchActivationRecord`**
- Implémenté par **`cloudconfigurationd`** via XPC. Le **« Setup Assistant »** (au premier démarrage de l’appareil) ou la commande **`profiles`** contacte ce démon pour récupérer l’Activation Record.
  - LaunchDaemon (s’exécute toujours en tant que root)

Plusieurs étapes sont effectuées par **`MCTeslaConfigurationFetcher`** pour récupérer l’Activation Record. Ce processus utilise un chiffrement appelé **Absinthe**<sup>[[1]](#references)</sup>

1. Récupérer le **certificat**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialiser** l’état à partir du certificat (**`NACInit`**)
   1. Utilise diverses données propres à l’appareil (c’est-à-dire le **numéro de série via `IOKit`**)
3. Récupérer la **clé de session**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Établir la session (**`NACKeyEstablishment`**)
5. Effectuer la requête
   1. POST vers [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) avec les données `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. Le payload JSON est chiffré à l’aide d’Absinthe (**`NACSign`**)
   3. Toutes les requêtes passent par HTTPS et utilisent les certificats racine intégrés

![Étapes d’inscription et de gestion - Étape 4 : check-in DEP - Récupération de l’Activation Record : 3. Toutes les requêtes passent par HTTPS et utilisent les certificats racine intégrés](<../../../images/image (566) (1).png>)

La réponse est un dictionnaire JSON contenant des données importantes, telles que :

- **url** : URL de l’hôte du fournisseur MDM pour le profil d’activation
- **anchor-certs** : tableau de certificats DER utilisés comme ancres de confiance

### **Étape 5 : récupération du profil**

![Étape 4 : check-in DEP - Récupération de l’Activation Record - Étape 5 : récupération du profil : Étape 5 : récupération du profil](<../../../images/image (444).png>)

- La requête est envoyée à l’**URL fournie dans le profil DEP**.
- Les **certificats d’ancrage** servent à **évaluer la confiance** s’ils sont fournis.
  - Rappel : la propriété **anchor_certs** du profil DEP
- La **requête est un simple .plist** contenant l’identification de l’appareil
  - Exemples : **UDID, version de l’OS**.
- Signé par CMS et encodé en DER
- Signé à l’aide du **certificat d’identité de l’appareil (depuis APNS)**
- La **chaîne de certificats** comprend le certificat **Apple iPhone Device CA** expiré

![Étape 4 : check-in DEP - Récupération de l’Activation Record - Étape 5 : récupération du profil : signé à l’aide du certificat d’identité de l’appareil (depuis APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Étape 6 : installation du profil

- Une fois récupéré, le **profil est stocké sur le système**
- Cette étape démarre automatiquement (si l’appareil se trouve dans le **Setup Assistant**)
- Géré par **`CPInstallActivationProfile`**
- Implémenté par mdmclient via XPC
  - LaunchDaemon (en tant que root) ou LaunchAgent (en tant qu’utilisateur), selon le contexte
- Les profils de configuration contiennent plusieurs payloads à installer
- Le framework utilise une architecture fondée sur des plugins pour installer les profils
- Chaque type de payload est associé à un plugin
  - Peut être XPC (dans le framework) ou Cocoa classique (dans ManagedClient.app)
- Exemple :
  - Les payloads de certificat utilisent CertificateService.xpc

En général, le **profil d’activation** fourni par un fournisseur MDM **inclut les payloads suivants** :

- `com.apple.mdm` : pour **inscrire** l’appareil au MDM
- `com.apple.security.scep` : pour fournir de manière sécurisée un **certificat client** à l’appareil.
- `com.apple.security.pem` : pour **installer des certificats CA de confiance** dans le trousseau système de l’appareil.
- L’installation du payload MDM équivaut au **check-in MDM décrit dans la documentation**
- Le payload **contient des propriétés clés** :
- - URL de check-in MDM (**`CheckInURL`**)
  - URL d’interrogation des commandes MDM (**`ServerURL`**) et sujet APNs pour la déclencher
- Pour installer le payload MDM, une requête est envoyée à **`CheckInURL`**
- Implémenté dans **`mdmclient`**
- Le payload MDM peut dépendre d’autres payloads
- Permet d’**épingler les requêtes à des certificats spécifiques** :
  - Propriété : **`CheckInURLPinningCertificateUUIDs`**
  - Propriété : **`ServerURLPinningCertificateUUIDs`**
  - Transmis via un payload PEM
- Permet d’associer un certificat d’identité à l’appareil :
  - Propriété : IdentityCertificateUUID
  - Transmis via un payload SCEP

### **Étape 7 : écoute des commandes MDM**

- Une fois le check-in MDM terminé, le fournisseur peut **émettre des notifications push via APNs**
- À leur réception, celles-ci sont traitées par **`mdmclient`**
- Pour interroger les commandes MDM, une requête est envoyée à ServerURL
- Utilise le payload MDM installé précédemment :
  - **`ServerURLPinningCertificateUUIDs`** pour l’épinglage de la requête
  - **`IdentityCertificateUUID`** pour le certificat client TLS

## Attaques

### Inscription d’appareils dans d’autres organisations

Un numéro de série attribué peut révéler le parcours d’inscription de l’organisation, mais ne **garantit pas** l’inscription au MDM. Avant de renvoyer le profil d’inscription, le serveur peut exiger que l’utilisateur s’authentifie via `configuration_web_url`. Vérifiez si un autre parcours d’inscription omet cette vérification, plutôt que de supposer que chaque numéro de série attribué permet d’ajouter un appareil à la flotte.<sup>[[3]](#references)</sup>

Pour suivre un processus d’inscription frauduleuse, consultez la page liée ci-dessous. Pour le contrôle MDM et la livraison de packages après une compromission, consultez [macOS Red Teaming](../).


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [Analyse approfondie du MDM macOS (et de la manière dont il peut être compromis)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — « MDM Me Maybe? » (recherche sur la sécurité de l’inscription DEP/MDM)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Authentification via des vues web](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
