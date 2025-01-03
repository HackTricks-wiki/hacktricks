# FISSURE - Le cadre RF

**Compréhension et ingénierie inverse des signaux SDR indépendants de la fréquence**

FISSURE est un cadre RF et d'ingénierie inverse open-source conçu pour tous les niveaux de compétence avec des hooks pour la détection et la classification des signaux, la découverte de protocoles, l'exécution d'attaques, la manipulation IQ, l'analyse de vulnérabilités, l'automatisation et l'IA/ML. Le cadre a été construit pour promouvoir l'intégration rapide de modules logiciels, de radios, de protocoles, de données de signaux, de scripts, de graphes de flux, de matériel de référence et d'outils tiers. FISSURE est un facilitateur de flux de travail qui garde les logiciels en un seul endroit et permet aux équipes de se mettre à jour sans effort tout en partageant la même configuration de base éprouvée pour des distributions Linux spécifiques.

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

Ces systèmes d'exploitation sont encore en statut bêta. Ils sont en cours de développement et plusieurs fonctionnalités sont connues pour manquer. Les éléments dans l'installateur peuvent entrer en conflit avec des programmes existants ou échouer à s'installer jusqu'à ce que le statut soit supprimé.

|     Système d'exploitation     |    Branche FISSURE   |
| :-----------------------------: | :------------------: |
| DragonOS Focal (x86\_64)      |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)         | Python3\_maint-3.10 |

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

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Détecteur de signal**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.
