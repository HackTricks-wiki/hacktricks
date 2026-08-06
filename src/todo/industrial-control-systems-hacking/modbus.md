# Le protocole Modbus

{{#include ../../banners/hacktricks-training.md}}

## Introduction au protocole Modbus

Le protocole Modbus est un protocole largement utilisé dans les systèmes d’automatisation et de contrôle industriels. Modbus permet la communication entre différents appareils tels que les automates programmables industriels (PLC), les capteurs, les actionneurs et autres appareils industriels. Comprendre le protocole Modbus est essentiel, car il s’agit du protocole de communication le plus utilisé dans les ICS et qu’il présente une importante attack surface potentielle pour le sniffing et même l’injection de commandes dans les PLC.

Ici, les concepts sont présentés sous forme de points afin de fournir un contexte sur le protocole et son mode de fonctionnement. Le plus grand défi pour la sécurité des systèmes ICS réside dans le coût de la mise en œuvre et des mises à niveau. Ces protocoles et standards ont été conçus au début des années 80 et 90 et sont encore largement utilisés. Comme une industrie possède de nombreux appareils et connexions, la mise à niveau des appareils est très difficile, ce qui donne aux hackers l’avantage de devoir composer avec des protocoles obsolètes. Les attaques contre Modbus sont pratiquement inévitables, puisqu’il continuera à être utilisé sans mise à niveau si son fonctionnement est critique pour l’industrie.

## L’architecture Client-Serveur

Le protocole Modbus est généralement utilisé dans une architecture Client-Serveur, où un appareil maître (client) initie la communication avec un ou plusieurs appareils esclaves (serveurs). Cette architecture est également appelée architecture maître-esclave et est largement utilisée dans l’électronique et l’IoT avec SPI, I2C, etc.

## Versions série et Ethernet

Le protocole Modbus est conçu à la fois pour les communications série et les communications Ethernet. La communication série est largement utilisée dans les systèmes legacy, tandis que les appareils modernes prennent en charge Ethernet, qui offre des débits de données élevés et est mieux adapté aux réseaux industriels modernes.

## Représentation des données

Les données sont transmises dans le protocole Modbus au format ASCII ou binaire, bien que le format binaire soit utilisé en raison de sa compatibilité avec les anciens appareils.

## Codes fonctionnels

Le protocole Modbus fonctionne avec la transmission de codes fonctionnels spécifiques utilisés pour faire fonctionner les PLC et différents appareils de contrôle. Cette partie est importante à comprendre, car des replay attacks peuvent être effectuées en retransmettant les codes fonctionnels. Les appareils legacy ne prennent en charge aucun chiffrement pour la transmission des données et utilisent généralement de longs câbles qui les relient, ce qui permet de falsifier ces câbles et de capturer ou d’injecter des données.

## Adressage de Modbus

Chaque appareil du réseau possède une adresse unique, essentielle à la communication entre les appareils. Des protocoles tels que Modbus RTU, Modbus TCP, etc. sont utilisés pour implémenter l’adressage et servent de couche de transport pour la transmission des données. Les données transférées sont au format du protocole Modbus et contiennent le message.

En outre, Modbus implémente également des contrôles d’erreur afin de garantir l’intégrité des données transmises. Mais surtout, Modbus est un Open Standard que chacun peut implémenter dans ses appareils. Cela a permis à ce protocole de devenir un standard mondial et d’être largement répandu dans le secteur de l’automatisation industrielle.

En raison de son utilisation à grande échelle et du manque de mises à niveau, attaquer Modbus offre un avantage important grâce à son attack surface. Les ICS dépendent fortement de la communication entre les appareils, et toute attaque les ciblant peut être dangereuse pour le fonctionnement des systèmes industriels. Des attaques telles que le replay, la data injection, le data sniffing et le leaking, le Denial of Service, la falsification de données, etc. peuvent être menées si le support de transmission est identifié par l’attaquant.

{{#include ../../banners/hacktricks-training.md}}
