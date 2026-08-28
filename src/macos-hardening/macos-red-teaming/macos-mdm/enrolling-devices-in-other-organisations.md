# Enrôlement d'appareils dans d'autres organisations

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

L'Automated Device Enrollment d'Apple (anciennement DEP) commence par l'identification d'un appareil attribué à une organisation. La recherche de 2018 résumée ici a montré que la connaissance d'un numéro de série attribué suffisait à récupérer les profils d'enrôlement de certaines organisations, car celles-ci n'exigeaient pas d'authentification supplémentaire adéquate. Il s'agit d'une découverte historique, et non de l'affirmation que tous les MDM actuels peuvent être rejoints avec un simple numéro de série. Les profils peuvent contenir des certificats, des applications, des secrets Wi-Fi, des paramètres VPN et d'autres configurations sensibles.<sup>[[1]](#references)[[2]](#references)</sup>

**Ce qui suit est un résumé de la recherche [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consultez-la pour plus de détails techniques !**<sup>[[1]](#references)</sup>

## Vue d'ensemble de l'analyse binaire de DEP et MDM

La recherche a analysé les binaires associés à DEP et MDM sur les versions de macOS actuelles à l'époque. Les noms et responsabilités des composants peuvent changer selon les versions :

- **`mdmclient`** : Communique avec les serveurs MDM et déclenche les check-ins DEP sur les versions de macOS antérieures à 10.13.4.
- **`profiles`** : Gère les Configuration Profiles et déclenche les check-ins DEP sur les versions de macOS 10.13.4 et ultérieures.
- **`cloudconfigurationd`** : Gère les communications avec l'API DEP et récupère les profils Device Enrollment.

Les check-ins DEP utilisent les fonctions `CPFetchActivationRecord` et `CPGetActivationRecord` du framework privé Configuration Profiles pour récupérer l'Activation Record, `CPFetchActivationRecord` assurant la coordination avec `cloudconfigurationd` via XPC.<sup>[[1]](#references)</sup>

## Rétro-ingénierie du Tesla Protocol et de l'Absinthe Scheme

Le check-in DEP implique que `cloudconfigurationd` envoie un payload JSON chiffré et signé à _iprofiles.apple.com/macProfile_. Le payload contient le numéro de série de l'appareil ainsi que l'action "RequestProfileConfiguration". Le schéma de chiffrement utilisé est appelé en interne "Absinthe". La compréhension de ce schéma est complexe et implique de nombreuses étapes, ce qui a conduit à explorer d'autres méthodes pour insérer des numéros de série arbitraires dans la requête Activation Record.<sup>[[1]](#references)</sup>

## Proxyfication des requêtes DEP

Les tentatives d'interception et de modification des requêtes DEP vers _iprofiles.apple.com_ à l'aide d'outils comme Charles Proxy ont été entravées par le chiffrement du payload et les mesures de sécurité SSL/TLS. Cependant, l'activation de la configuration `MCCloudConfigAcceptAnyHTTPSCertificate` permet de contourner la validation du certificat serveur, bien que la nature chiffrée du payload empêche toujours de modifier le numéro de série sans la clé de déchiffrement.<sup>[[1]](#references)</sup>

## Instrumentation des binaires système interagissant avec DEP

L'instrumentation de binaires système comme `cloudconfigurationd` nécessite de désactiver System Integrity Protection (SIP) sur macOS. Une fois SIP désactivé, des outils comme LLDB peuvent être utilisés pour s'attacher aux processus système et potentiellement modifier le numéro de série utilisé dans les interactions avec l'API DEP. Cette méthode est préférable, car elle évite les complexités liées aux entitlements et à la signature de code.<sup>[[1]](#references)</sup>

**Exploitation de l'instrumentation binaire :**
La modification du payload de la requête DEP avant sa sérialisation JSON dans `cloudconfigurationd` s'est révélée efficace. Le processus impliquait :

1. S'attacher à `cloudconfigurationd` avec LLDB.
2. Localiser l'endroit où le numéro de série système est récupéré.
3. Injecter un numéro de série arbitraire en mémoire avant le chiffrement et l'envoi du payload.

Cette méthode a permis aux chercheurs de récupérer les profils DEP correspondant aux numéros de série fournis et attribués. Elle n'a pas rendu valide un numéro de série arbitraire non attribué.<sup>[[1]](#references)</sup>

### Automatisation de l'instrumentation avec Python

Le processus d'exploitation a été automatisé avec Python et l'API LLDB, ce qui a permis d'injecter des numéros de série arbitraires par programmation et de récupérer les profils DEP correspondants.<sup>[[1]](#references)</sup>

## Réexamen en 2025 : Rogue Enrollment depuis une VM

Les recherches présentées lors de Black Hat Asia 2025 ont démontré que le problème initial de frontière de confiance peut toujours être pertinent au niveau **MDM** : au lieu de patcher `cloudconfigurationd` avec LLDB, les chercheurs ont exécuté macOS sous QEMU/KVM avec OpenCore et fourni l'identité candidate via le SMBIOS de la VM. La stack d'enrôlement macOS non modifiée a ensuite effectué l'échange Apple chiffré. Des serials leaked publiquement et des candidats d'apparence valide peuvent donc être testés sans posséder le Mac physique correspondant ; une correspondance nécessite toutefois que le numéro de série soit attribué à une organisation et que le parcours d'enrôlement de celle-ci soit insuffisamment authentifié.<sup>[[3]](#references)</sup>

Pour un appareil de laboratoire autorisé, les valeurs OpenCore `PlatformInfo` pertinentes comprennent un modèle de produit et un numéro de série (dans les déploiements réels, le ROM et l'UUID restent également cohérents en interne) :<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
La même recherche a identifié l’état `CheckProfilesFetchRateLimit` dans le fichier privé `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Comme la vérification était maintenue côté client, la modification des valeurs temporelles stockées la neutralisait. Ces chemins ne sont pas documentés et dépendent de la version, mais ils constituent des pivots de reversing utiles lors de l’évaluation d’une build macOS actuelle :<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
Le deuxième artefact peut divulguer l’activation record mis en cache, notamment indiquer si le flux utilise une `ConfigurationURL` directe ou une `ConfigurationWebURL` authentifiée. Testez à la fois le flux annoncé et les éventuels endpoints d’enrollment legacy spécifiques au MDM : activer le SSO uniquement sur le flux web principal ne protège pas un endpoint direct parallèle. Pour la séquence complète du protocole, consultez la [vue d’ensemble de macOS MDM](README.md).<sup>[[3]](#references)</sup>

### Recherche de secrets après l’enrollment

Un enrollment rogue n’est que le point d’entrée. Après l’enrollment, inspectez chaque profil distribué, bootstrap policy, configuration de dépôt de packages, script d’installation d’agent et élément self-service. La recherche de 2025 a retrouvé des exemples d’identifiants Wi-Fi, de mots de passe d’administrateur local partagés, d’URLs signées de cloud storage, d’URLs de webhook, de données d’activation d’agents de sécurité et d’identifiants MDM/API. Un identifiant API de tenant présent dans un script distribué peut transformer un endpoint rogue en contrôle d’autres appareils gérés ; recherchez donc à la fois dans le système de fichiers actif et dans le contenu des policies téléchargées ou mises en cache.<sup>[[3]](#references)</sup>

Les cibles d’analyse utiles incluent :<sup>[[3]](#references)</sup>

- Les payloads `.mobileconfig` installés et la base de données Configuration Profiles.
- Les scripts et packages PreStage/bootstrap qui créent des comptes ou installent des agents EDR/VPN.
- Les URLs de dépôts de packages Munki ou autres, en particulier les query strings contenant des signatures de type bearer/SAS.
- Les catalogues self-service et leurs policy APIs sous-jacentes, y compris les routes legacy qui peuvent ne pas appliquer la policy SSO d’enrollment.
- L’historique du shell et les sorties de policies mises en cache pour `password`, `token`, `secret`, `Authorization`, les hostnames de webhook et les endpoints API des fournisseurs.

### Renforcement de la limite de confiance

Considérez un numéro de série comme un attribut d’inventaire/routage, **et non** comme une preuve de possession. Exigez une authentification utilisateur pour l’enrollment et le self-service, générez des mots de passe d’administrateur local uniques par appareil et n’intégrez jamais d’identifiants API de tenant ni de secrets d’infrastructure réutilisables dans des profils ou des scripts. Faites en sorte que tout bootstrap token inévitable soit de courte durée et limité à la seule action et au seul appareil en cours de provisioning.<sup>[[3]](#references)</sup>

Sur les Mac équipés de puces Apple exécutant macOS 14 ou une version ultérieure, Managed Device Attestation peut lier cryptographiquement l’identité au Secure Enclave. Son attestation ancrée dans Apple peut contenir un nonce récent ainsi que le numéro de série, l’UDID, la version de l’OS, l’état de SIP et l’état du secure boot ; ACME peut alors émettre une identité client liée au matériel. Utilisez cette identité pour protéger le canal MDM et contrôler l’accès aux certificats de haute valeur, au VPN et aux autres ressources, tout en conservant une authentification utilisateur distincte, car l’attestation de l’appareil prouve l’identité de l’appareil, et non celle de l’opérateur.<sup>[[4]](#references)</sup>

## Impacts potentiels des vulnérabilités DEP et MDM

La recherche a mis en évidence d’importants problèmes de sécurité :

1. **Divulgation d’informations** : en fournissant un numéro de série enregistré dans le DEP, il est possible de récupérer les informations sensibles de l’organisation contenues dans le profil DEP.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM, peut-être : sécurité du Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Déploiement des plateformes Apple — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome : Hacking Apple MDMs Using Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
