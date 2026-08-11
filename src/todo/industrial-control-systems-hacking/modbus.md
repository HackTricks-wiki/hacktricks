# Le protocole Modbus

{{#include ../../banners/hacktricks-training.md}}

## Introduction à Modbus

Modbus est un protocole largement implémenté de la couche application, utilisé par les PLC, les capteurs, les actionneurs et d'autres appareils industriels. Son modèle requête/réponse expose des bobines et des registres via des codes de fonction. Les tests de sécurité se concentrent donc sur les lectures/écritures non autorisées, l'observation du trafic, le rejeu et les comportements dangereux des appareils, et pas uniquement sur la détection du port TCP 502.<sup>[[1]](#references)</sup>

De nombreux déploiements conservent des équipements série anciens, car les mises à niveau nécessitent un arrêt, une nouvelle certification ou le remplacement des appareils de terrain. Le Modbus traditionnel ne fournit ni confidentialité ni authentification des pairs ; Modbus Security est un profil distinct basé sur TLS, utilisant des certificats X.509 et le port TCP 802. Comme la spécification est publique et peut être implémentée indépendamment, le comportement des fournisseurs et la prise en charge des fonctions optionnelles varient et doivent être identifiés par fingerprinting plutôt que supposés.<sup>[[1]](#references)[[2]](#references)</sup>

## L'architecture client-serveur

Dans la terminologie actuelle, un **client** initie une transaction et un **serveur** renvoie une réponse. Les anciennes documentations utilisent **master/slave**. Ne confondez pas cette relation applicative avec SPI ou I2C : il s'agit de protocoles de bus différents.<sup>[[1]](#references)</sup>

## Transports série et Ethernet

Les mêmes données applicatives Modbus peuvent être transportées par des variantes série (framing RTU ou ASCII) et par Modbus TCP. Modbus TCP ajoute un en-tête MBAP et utilise normalement le port TCP 502 ; le RTU série utilise un framing binaire compact et un CRC, tandis que l'ASCII série représente les octets sous forme de caractères hexadécimaux et utilise un LRC.<sup>[[1]](#references)[[3]](#references)</sup>

## Représentation des données

Le modèle de données se compose de bobines/entrées discrètes sur un bit et de registres d'entrée/de maintien de 16 bits. Les valeurs sur plusieurs registres, l'ordre des octets, la mise à l'échelle et la signification sémantique sont propres à chaque appareil et doivent être confirmés à l'aide de la table des registres du fournisseur.<sup>[[1]](#references)</sup>

## Codes de fonction

Les codes de fonction sélectionnent des opérations telles que la lecture de bobines (`0x01`), la lecture de registres de maintien (`0x03`), l'écriture d'une bobine/d'un registre unique (`0x05`/`0x06`) et l'écriture de plusieurs bobines/registres (`0x0F`/`0x10`). Une requête d'écriture capturée peut être rejouable lorsque le déploiement ne dispose d'aucune authentification compensatoire ni de vérifications de l'état du processus. Avec un accès physique autorisé à de longues liaisons série, un évaluateur peut également capturer ou injecter directement des trames sur le câblage après avoir identifié l'interface électrique, la terminaison et la méthode de connexion sûre. Ces deux actions peuvent affecter le processus physique ; utilisez donc un laboratoire ou obtenez une autorisation opérationnelle explicite.<sup>[[1]](#references)[[3]](#references)</sup>

## Adressage

Les appareils série utilisent une adresse d'unité. Modbus TCP utilise l'adressage IP ainsi qu'un identifiant d'unité dans l'en-tête MBAP, ce qui est particulièrement pertinent lorsqu'une passerelle TCP-vers-série achemine les requêtes vers des unités en aval. Les références de registres présentées dans la documentation des produits peuvent être basées sur un index commençant à un (`40001`), tandis que les adresses du protocole commencent à zéro, ce qui constitue une source courante d'erreurs d'un décalage d'une unité.<sup>[[1]](#references)[[3]](#references)</sup>

Le framing série inclut des contrôles des erreurs de transmission (CRC pour le RTU et LRC pour l'ASCII), et TCP fournit sa somme de contrôle de transport normale. Ces mécanismes détectent les corruptions accidentelles ; ils ne fournissent ni intégrité cryptographique ni authentification de l'origine.<sup>[[3]](#references)</sup>

Lors d'une évaluation autorisée, testez l'exposition, les codes de fonction autorisés, les plages d'adresses accessibles en écriture, la gestion des exceptions, les limites de débit, ainsi que la capacité de la segmentation réseau ou d'un firewall conscient de Modbus à restreindre les clients. Les menaces pertinentes comprennent la divulgation passive, l'injection de commandes non autorisées, le rejeu, la falsification des données et le déni de service. Coordonnez tous les tests actifs avec les responsables du processus, car des modifications apparemment minimes de registres peuvent altérer un processus physique.

## References

- [1] [Modbus Organization — Spécification du protocole applicatif Modbus V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Protocole Modbus Security et guides d'implémentation](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Spécification et guide d'implémentation de Modbus sur liaison série V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
