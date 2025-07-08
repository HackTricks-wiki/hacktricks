# FISSURE - Le cadre RF

{{#include /banners/hacktricks-training.md}}

**Compréhension et ingénierie inverse des signaux SDR indépendants de la fréquence**

FISSURE est un cadre RF et d'ingénierie inverse open-source conçu pour tous les niveaux de compétence avec des hooks pour la détection et la classification des signaux, la découverte de protocoles, l'exécution d'attaques, la manipulation IQ, l'analyse de vulnérabilités, l'automatisation et l'IA/ML. Le cadre a été construit pour promouvoir l'intégration rapide de modules logiciels, de radios, de protocoles, de données de signaux, de scripts, de graphiques de flux, de matériel de référence et d'outils tiers. FISSURE est un facilitateur de flux de travail qui garde les logiciels en un seul endroit et permet aux équipes de se mettre rapidement à jour tout en partageant la même configuration de base éprouvée pour des distributions Linux spécifiques.

Le cadre et les outils inclus avec FISSURE sont conçus pour détecter la présence d'énergie RF, comprendre les caractéristiques d'un signal, collecter et analyser des échantillons, développer des techniques de transmission et/ou d'injection, et créer des charges utiles ou des messages personnalisés. FISSURE contient une bibliothèque croissante d'informations sur les protocoles et les signaux pour aider à l'identification, à la création de paquets et au fuzzing. Des capacités d'archive en ligne existent pour télécharger des fichiers de signaux et créer des listes de lecture pour simuler le trafic et tester des systèmes.

La base de code Python conviviale et l'interface utilisateur permettent aux débutants d'apprendre rapidement sur les outils et techniques populaires impliquant RF et ingénierie inverse. Les éducateurs en cybersécurité et en ingénierie peuvent tirer parti du matériel intégré ou utiliser le cadre pour démontrer leurs propres applications du monde réel. Les développeurs et chercheurs peuvent utiliser FISSURE pour leurs tâches quotidiennes ou pour exposer leurs solutions de pointe à un public plus large. À mesure que la sensibilisation et l'utilisation de FISSURE croissent dans la communauté, l'étendue de ses capacités et la portée de la technologie qu'il englobe augmenteront également.

**Informations supplémentaires**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Commencer

**Supporté**

Il existe trois branches au sein de FISSURE pour faciliter la navigation dans les fichiers et réduire la redondance du code. La branche Python2\_maint-3.7 contient une base de code construite autour de Python2, PyQt4 et GNU Radio 3.7 ; la branche Python3\_maint-3.8 est construite autour de Python3, PyQt5 et GNU Radio 3.8 ; et la branche Python3\_maint-3.10 est construite autour de Python3, PyQt5 et GNU Radio 3.10.

|   Système d'exploitation   |   Branche FISSURE   |
| :-------------------------: | :-----------------: |
|  Ubuntu 18.04 (x64)       | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64)      | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64)      | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64)      | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64)      | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64)      | Python3\_maint-3.8 |

**En cours (bêta)**

Ces systèmes d'exploitation sont encore en statut bêta. Ils sont en développement et plusieurs fonctionnalités sont connues pour manquer. Les éléments dans l'installateur peuvent entrer en conflit avec des programmes existants ou échouer à s'installer jusqu'à ce que le statut soit supprimé.

|     Système d'exploitation     |    Branche FISSURE   |
| :-----------------------------: | :------------------: |
| DragonOS Focal (x86\_64)       |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)          | Python3\_maint-3.10 |

Note : Certains outils logiciels ne fonctionnent pas pour chaque OS. Référez-vous à [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Cela installera les dépendances logicielles PyQt nécessaires pour lancer les interfaces d'installation si elles ne sont pas trouvées.

Ensuite, sélectionnez l'option qui correspond le mieux à votre système d'exploitation (devrait être détecté automatiquement si votre OS correspond à une option).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Il est recommandé d'installer FISSURE sur un système d'exploitation propre pour éviter les conflits existants. Sélectionnez toutes les cases à cocher recommandées (bouton par défaut) pour éviter les erreurs lors de l'utilisation des différents outils au sein de FISSURE. Il y aura plusieurs invites tout au long de l'installation, demandant principalement des autorisations élevées et des noms d'utilisateur. Si un élément contient une section "Vérifier" à la fin, l'installateur exécutera la commande qui suit et mettra en surbrillance l'élément de la case à cocher en vert ou en rouge selon que des erreurs sont produites par la commande. Les éléments cochés sans section "Vérifier" resteront noirs après l'installation.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Utilisation**

Ouvrez un terminal et entrez :
```
fissure
```
Référez-vous au menu d'aide de FISSURE pour plus de détails sur l'utilisation.

## Détails

**Composants**

* Tableau de bord
* Hub central (HIPRFISR)
* Identification du signal cible (TSI)
* Découverte de protocole (PD)
* Graphique de flux et exécuteur de script (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capacités**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Détecteur de signal**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulation IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Recherche de signal**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconnaissance de motifs**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attaques**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Listes de lecture de signal**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galerie d'images**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Création de paquets**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Intégration Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculateur CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Journalisation**_            |

**Matériel**

Voici une liste de matériel "supporté" avec des niveaux d'intégration variés :

* USRP : X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adaptateurs 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Leçons

FISSURE est livré avec plusieurs guides utiles pour se familiariser avec différentes technologies et techniques. Beaucoup incluent des étapes pour utiliser divers outils intégrés dans FISSURE.

* [Leçon1 : OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Leçon2 : Dissécateurs Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Leçon3 : Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Leçon4 : Cartes ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Leçon5 : Suivi de radiosondes](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Leçon6 : RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Leçon7 : Types de données](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Leçon8 : Blocs GNU Radio personnalisés](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Leçon9 : TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Leçon10 : Examens de radioamateur](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Leçon11 : Outils Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Feuille de route

* [ ] Ajouter plus de types de matériel, de protocoles RF, de paramètres de signal, d'outils d'analyse
* [ ] Supporter plus de systèmes d'exploitation
* [ ] Développer du matériel de cours autour de FISSURE (Attaques RF, Wi-Fi, GNU Radio, PyQt, etc.)
* [ ] Créer un conditionneur de signal, un extracteur de caractéristiques et un classificateur de signal avec des techniques AI/ML sélectionnables
* [ ] Mettre en œuvre des mécanismes de démodulation récursive pour produire un flux de bits à partir de signaux inconnus
* [ ] Transitionner les principaux composants de FISSURE vers un schéma de déploiement de nœud capteur générique

## Contribution

Les suggestions pour améliorer FISSURE sont fortement encouragées. Laissez un commentaire sur la page [Discussions](https://github.com/ainfosec/FISSURE/discussions) ou sur le serveur Discord si vous avez des idées concernant les éléments suivants :

* Suggestions de nouvelles fonctionnalités et changements de conception
* Outils logiciels avec étapes d'installation
* Nouvelles leçons ou matériel supplémentaire pour les leçons existantes
* Protocoles RF d'intérêt
* Plus de types de matériel et SDR pour l'intégration
* Scripts d'analyse IQ en Python
* Corrections et améliorations d'installation

Les contributions pour améliorer FISSURE sont cruciales pour accélérer son développement. Toutes les contributions que vous faites sont grandement appréciées. Si vous souhaitez contribuer par le développement de code, veuillez forker le dépôt et créer une demande de tirage :

1. Forkez le projet
2. Créez votre branche de fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Validez vos modifications (`git commit -m 'Ajoutez une AmazingFeature'`)
4. Poussez vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une demande de tirage

Créer des [Issues](https://github.com/ainfosec/FISSURE/issues) pour attirer l'attention sur les bogues est également bienvenu.

## Collaboration

Contactez Assured Information Security, Inc. (AIS) Développement commercial pour proposer et formaliser toute opportunité de collaboration FISSURE, que ce soit en consacrant du temps à l'intégration de votre logiciel, en faisant appel aux personnes talentueuses d'AIS pour développer des solutions à vos défis techniques, ou en intégrant FISSURE dans d'autres plateformes/applications.

## Licence

GPL-3.0

Pour les détails de la licence, voir le fichier LICENSE.

## Contact

Rejoignez le serveur Discord : [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Suivez sur Twitter : [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Développement commercial - Assured Information Security, Inc. - bd@ainfosec.com

## Crédits

Nous reconnaissons et sommes reconnaissants envers ces développeurs :

[Crédits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Remerciements

Remerciements spéciaux à Dr. Samuel Mantravadi et Joseph Reith pour leurs contributions à ce projet.

{{#include /banners/hacktricks-training.md}}
