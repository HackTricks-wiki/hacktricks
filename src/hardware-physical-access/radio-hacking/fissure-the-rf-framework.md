# FISSURE - Le framework RF

{{#include ../../banners/hacktricks-training.md}}

**Compréhension et rétro-ingénierie des signaux basée sur SDR, indépendante de la fréquence**

FISSURE est un framework open source dédié à la RF et à la rétro-ingénierie, conçu pour tous les niveaux de compétence. Il intègre des fonctionnalités de détection et de classification des signaux, de découverte de protocoles, d’exécution d’attaques, de manipulation IQ, d’analyse des vulnérabilités, d’automatisation et d’IA/ML. Le framework a été conçu pour faciliter l’intégration rapide de modules logiciels, de radios, de protocoles, de données de signaux, de scripts, de graphes de flux, de documentation de référence et d’outils tiers. FISSURE facilite les workflows en centralisant les logiciels et en permettant aux équipes de se familiariser rapidement avec l’environnement, tout en partageant la même configuration de base éprouvée pour des distributions Linux spécifiques.<sup>[[1]](#references)[[2]](#references)</sup>

Le framework et les outils inclus dans FISSURE sont conçus pour détecter l’énergie RF, caractériser les signaux, collecter et analyser des échantillons, développer des techniques de transmission ou d’injection, et créer des payloads ou messages personnalisés. FISSURE fournit également des informations sur les protocoles et les signaux pour l’identification, la création de paquets et le fuzzing, ainsi que des archives et des playlists pour la simulation et les tests de trafic.<sup>[[1]](#references)[[2]](#references)</sup>

La base de code Python et l’interface graphique aident les débutants à se familiariser avec les outils RF et de rétro-ingénierie. Les enseignants peuvent utiliser les leçons intégrées, tandis que les développeurs et les chercheurs peuvent intégrer leurs propres modules et workflows. Les versions actuelles prennent également en charge les nœuds de capteurs distribués, l’intégration TAK, les workflows de géolocalisation et les déploiements Apptainer adaptés aux rôles.<sup>[[1]](#references)[[3]](#references)</sup>

**Informations complémentaires**

* [Page AIS](https://www.ainfosec.com/technologies/fissure/)
* [Diapositives GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Article GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Vidéo GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transcription du Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Premiers pas

**Pris en charge**

La branche **`Python3`** de FISSURE est actuellement utilisée pour le développement actif avec PyQt5 et GNU Radio 3.8 ou 3.10. La branche obsolète **`Python2_maint-3.7`** reste disponible pour les anciens systèmes d’exploitation et les outils tiers nécessitant GNU Radio 3.7. Les anciens noms de branches `Python3_maint-3.8` et `Python3_maint-3.10` sont historiques ; le choix de la version de maintenance de GNU Radio se fait désormais depuis la branche `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Système d’exploitation | Branche FISSURE | Branche GNU Radio par défaut |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | utiliser une version Linux prise en charge | utiliser la version correspondante |

**En cours de développement (bêta)**

Ces systèmes d’exploitation sont encore en version bêta. Leur développement est en cours et plusieurs fonctionnalités sont connues pour être manquantes. Certains éléments du programme d’installation peuvent entrer en conflit avec les programmes existants ou ne pas s’installer tant que ce statut n’a pas été retiré.

| Système d’exploitation | Branche FISSURE | Branche GNU Radio par défaut |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Certains outils tiers ne fonctionnent pas sur tous les systèmes d’exploitation. Consultez la documentation actuelle sur les [conflits connus et les logiciels tiers](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) avant l’installation.<sup>[[3]](#references)</sup>

**Installation**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

L’étape des sous-modules télécharge les modules GNU Radio out-of-tree utilisés par FISSURE et est nécessaire à leur installation. L’installateur installe également les dépendances PyQt manquantes requises pour lancer ses interfaces graphiques d’installation.<sup>[[3]](#references)</sup>

Ensuite, sélectionnez l’option qui correspond le mieux à votre système d’exploitation (elle devrait être détectée automatiquement si votre système correspond à une option).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Il est recommandé d’installer FISSURE sur un système d’exploitation propre afin d’éviter les conflits existants. Sélectionnez toutes les cases recommandées (bouton Default) afin d’éviter les erreurs lors de l’utilisation des différents outils de FISSURE. Plusieurs invites s’afficheront pendant l’installation, demandant principalement des autorisations élevées et des noms d’utilisateur. Si un élément comporte une section « Verify » à la fin, l’installateur exécutera la commande qui suit et mettra la case en vert ou en rouge selon que la commande génère des erreurs ou non. Les éléments cochés sans section « Verify » resteront noirs après l’installation.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Utilisation**

Ouvrez un terminal et saisissez :

```
fissure
```

Consultez le menu Help de FISSURE pour plus de détails sur son utilisation.

## Détails

**Composants**

* Dashboard
* Central Hub (HIPRFISR)
* Identification des signaux cibles (TSI)
* Découverte de protocoles (PD)
* Exécuteur de Flow Graph et de scripts (FGE)

![composants](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Fonctionnalités**

| ![icône de détecteur de signal](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Détecteur de signal**_ | ![icône de manipulation IQ](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulation IQ**_      | ![icône de recherche de signaux](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Recherche de signaux**_          | ![icône de reconnaissance de motifs](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconnaissance de motifs**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![icône d’attaques](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attaques**_           | ![icône de fuzzing](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![icône de listes de lecture de signaux](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Listes de lecture de signaux**_       | ![icône de galerie d’images](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galerie d’images**_  |
| ![icône de création de paquets](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Création de paquets**_   | ![icône d’intégration de Scapy](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Intégration de Scapy**_ | ![icône de calculateur CRC](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculateur CRC**_ | ![icône de journalisation](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Journalisation**_            |

**Matériel**

Le matériel suivant est pris en charge à différents niveaux dans FISSURE :<sup>[[1]](#references)[[3]](#references)</sup>

* USRP : X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Adaptateurs 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay : RSPduo, RSPdx, RSPdx R2

## Leçons

FISSURE propose plusieurs guides utiles pour se familiariser avec différentes technologies et techniques. Beaucoup incluent des étapes d’utilisation de divers outils intégrés à FISSURE.

* [Leçon 1 : OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Leçon 2 : dissecteurs Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Leçon 3 : Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Leçon 4 : cartes ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Leçon 5 : suivi des radiosondes](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Leçon 6 : RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Leçon 7 : types de données](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Leçon 8 : blocs GNU Radio personnalisés](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Leçon 9 : TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Leçon 10 : examens de radioamateur](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Leçon 11 : outils Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Leçon 12 : création de clés USB amorçables](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Leçon 13 : Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Leçon 14 : ventilateurs de plafond](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Feuille de route

* [ ] Ajouter d’autres types de matériel, protocoles RF, paramètres de signal et outils d’analyse
* [ ] Prendre en charge d’autres systèmes d’exploitation
* [ ] Développer des supports de cours autour de FISSURE (attaques RF, Wi-Fi, GNU Radio, PyQt, etc.)
* [ ] Créer un conditionneur de signal, un extracteur de caractéristiques et un classificateur de signaux utilisant des techniques d’IA/ML sélectionnables
* [ ] Implémenter des mécanismes de démodulation récursive pour produire un flux binaire à partir de signaux inconnus
* [ ] Faire évoluer les principaux composants de FISSURE vers un schéma générique de déploiement de nœuds de capteurs

## Contribution

Les suggestions visant à améliorer FISSURE sont vivement encouragées. Laissez un commentaire sur la page [Discussions](https://github.com/ainfosec/FISSURE/discussions) ou sur le serveur Discord si vous avez des idées concernant les points suivants :

* Suggestions de nouvelles fonctionnalités et modifications de conception
* Outils logiciels avec étapes d’installation
* Nouvelles leçons ou contenu supplémentaire pour les leçons existantes
* Protocoles RF d’intérêt
* Davantage de matériel et de types de SDR à intégrer
* Scripts d’analyse IQ en Python
* Corrections et améliorations de l’installation

Les contributions visant à améliorer FISSURE sont essentielles pour accélérer son développement. Toute contribution est grandement appréciée. Si vous souhaitez contribuer au développement du code, veuillez créer un fork du dépôt et soumettre une pull request :

1. Créez un fork du projet
2. Créez votre branche de fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Validez vos modifications (`git commit -m 'Add some AmazingFeature'`)
4. Envoyez-les vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une pull request

La création d’[Issues](https://github.com/ainfosec/FISSURE/issues) pour signaler des bugs est également bienvenue.

## Collaboration

Contactez le service de développement commercial d’Assured Information Security, Inc. (AIS) pour proposer et formaliser toute possibilité de collaboration autour de FISSURE, que ce soit en consacrant du temps à l’intégration de vos logiciels, en faisant appel aux talents d’AIS pour développer des solutions à vos défis techniques, ou en intégrant FISSURE à d’autres plateformes/applications.

## Licence

GPL-3.0

Pour plus de détails sur la licence, consultez le fichier LICENSE.

## Contact

Rejoignez le serveur Discord : [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Suivez-nous sur Twitter : [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Développement commercial - Assured Information Security, Inc. - bd@ainfosec.com

## Crédits

Nous remercions les développeurs suivants :

[Crédits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Remerciements

Un grand merci au Dr Samuel Mantravadi et à Joseph Reith pour leurs contributions à ce projet.

## References

- [1] [FISSURE - Le framework RF (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [Article sur FISSURE (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Documentation FISSURE - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
