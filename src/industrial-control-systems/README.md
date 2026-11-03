# Hacking des systèmes de contrôle industriel

{{#include ../banners/hacktricks-training.md}}

## À propos de cette section

Cette section présente les composants, les architectures, les protocoles et les méthodes d’évaluation de la sécurité des systèmes de contrôle industriel (ICS). Les ICS font partie du domaine plus vaste des technologies opérationnelles (OT) : des systèmes et appareils programmables qui surveillent des processus physiques ou en modifient le déroulement. Parmi les exemples courants figurent les systèmes de contrôle et d’acquisition de données (SCADA), les systèmes de contrôle distribués (DCS) et les automates programmables industriels (PLC).<sup>[[1]](#references)</sup>

Les travaux de sécurité dans ces environnements doivent tenir compte d’exigences différentes de celles de l’informatique traditionnelle, notamment la sécurité des processus, la fiabilité, la disponibilité, le fonctionnement déterministe et le cycle de vie des équipements. Une mesure de sécurité techniquement valide peut malgré tout être inadaptée si elle perturbe le processus physique ; les tests et les mesures correctives doivent donc être coordonnés avec le propriétaire du système et le personnel d’exploitation.<sup>[[1]](#references)</sup>

Une compromission ou une perturbation accidentelle peut interrompre la production, endommager des équipements, libérer des matières dangereuses, nuire à l’environnement ou causer des blessures et des pertes humaines. Ce risque d’impact physique explique pourquoi il faut comprendre le processus contrôlé et ses limites de fonctionnement sécurisées avant de procéder à des tests actifs.<sup>[[1]](#references)</sup>

De nombreux déploiements OT conservent des systèmes d’exploitation, des applications et des protocoles anciens, car les équipements ont une longue durée de vie et que toute modification nécessite des tests opérationnels et de sécurité. Certains protocoles ont été conçus sans authentification ni chiffrement modernes, et l’application de correctifs peut être limitée par la prise en charge du fournisseur ou les fenêtres de maintenance ; lorsque des mises à niveau directes sont impossibles, compensez ces limites par la segmentation, le contrôle d’accès et la surveillance.<sup>[[1]](#references)</sup>

## Priorités de l’évaluation

Commencez par comprendre le processus contrôlé, les limites du système, la topologie réseau, les actifs, les flux de données, les relations de confiance et les connexions externes. Des appareils similaires peuvent remplir des fonctions différentes selon les sites ; ne partez donc pas du principe que l’architecture ou le modèle d’impact d’un déploiement s’applique à un autre.<sup>[[1]](#references)</sup>

Privilégiez autant que possible la découverte passive et la documentation d’ingénierie existante. Toute analyse active ou exploitation doit suivre un plan de test approuvé qui définit les contraintes de sécurité, les fenêtres de maintenance, les procédures de reprise et les conditions d’arrêt. Les résultats doivent être évalués à la fois en fonction de leur impact sur la cybersécurité et de leurs effets potentiels sur le processus physique.<sup>[[1]](#references)</sup>

Les mêmes connaissances architecturales contribuent aux activités défensives telles que l’inventaire des actifs, la segmentation réseau, la surveillance, la réponse aux incidents et la gestion des vulnérabilités fondée sur les risques.<sup>[[1]](#references)</sup>

## Abus d’un contrôleur frigorifique de supervision

Un gestionnaire de système frigorifique coordonne les contrôleurs de compresseurs et de vitrines réfrigérées, mais ne refroidit pas lui-même les vitrines. L’accès à son interface de gestion peut donc permettre de contrôler de nombreux appareils subordonnés en distribuant des configurations par les mécanismes habituels. Cela diffère de la modification d’un seul thermostat ou du pilotage direct d’un compresseur.<sup>[[3]](#references)[[4]](#references)</sup>

### Connexion avec un code de maintenance dérivé de la date

Sur les gestionnaires de système Danfoss concernés, une connexion XML alternative accepte un code dérivé de la date du contrôleur plutôt que le mot de passe d’un compte.<sup>[[2]](#references)[[3]](#references)</sup> Sur les SM800 et SC255, Synacktiv a suivi les attributs `eds_only` et `quantum_only` dans `xml_load_file` et `check_authorize` jusqu’à `check_code_of_day`. Son avis montre également que `read_date_time` sur `xml.cgi` divulgue la date du contrôleur sans authentification.<sup>[[2]](#references)</sup> Claroty a découvert un chemin `getauth` correspondant sur l’AK-SM 800A, mais a masqué les attributs déclencheurs ; il ne faut pas supposer que les noms d’attributs des anciens modèles fonctionnent sur cette plateforme.<sup>[[3]](#references)</sup>

Synacktiv décrit la requête de date non authentifiée comme suit :<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

Le code ne contient aucun secret propre à l’appareil : retrouver l’algorithme dans le [firmware](../hardware-physical-access/firmware-analysis/) peut permettre de générer un identifiant valide à une date donnée pour les appareils utilisant la même implémentation vulnérable.<sup>[[2]](#references)[[3]](#references)</sup> Confirmez d’abord le modèle et le firmware. Une réponse liée à une date ne prouve pas, à elle seule, que l’autre méthode de connexion est présente ni qu’une session a été obtenue.

### Modification de configuration en masse et abus du chauffage de dégivrage

Après avoir obtenu un accès administratif, identifiez les contrôleurs de meubles associés au gestionnaire du système et vérifiez si sa fonction de distribution de configuration peut les mettre à jour simultanément. Une modification de la consigne d’un meuble ne le réchauffe normalement que jusqu’à la température ambiante. Pour le chauffer au-delà de cette température, la commande concernée est le chauffage électrique de dégivrage de l’évaporateur du contrôleur : le dégivrage interrompt le refroidissement et active ce chauffage jusqu’à ce qu’un capteur ou une minuterie mette fin au cycle. Modifier la méthode de dégivrage, le calendrier, la température d’arrêt et la durée maximale peut maintenir le chauffage en marche. Le gestionnaire peut diffuser ces modifications à de nombreux meubles et neutraliser les alarmes associées, transformant la compromission d’un seul système de supervision en une modification de processus à l’échelle du magasin.<sup>[[4]](#references)</sup>

Il s’agit d’un risque lié à un processus physique, et non d’une preuve de concept qu’il est sûr d’exécuter sur un système en service. Le cas échéant, les limiteurs thermiques peuvent restreindre le fonctionnement du chauffage, mais un fonctionnement continu peut tout de même provoquer une surchauffe au niveau d’une connexion électrique déjà fragilisée. Validez la configuration et son impact uniquement dans un laboratoire approuvé ou conformément au plan de sécurité des processus de l’exploitant.<sup>[[4]](#references)</sup>

## Points d’entrée des protocoles

- [Tests Modbus](../network-services-pentesting/pentesting-modbus.md) couvre Modbus TCP, les variantes série, les codes de fonction et l’accès aux registres.
- [Tests OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) couvre le service d’échange de données industrielles.
- [Tests BACnet](../network-services-pentesting/47808-udp-bacnet.md) couvre les réseaux de contrôle de l’automatisation des bâtiments.

## References

- [1] [NIST SP 800-82 Rev. 3 - Guide de sécurité des technologies opérationnelles (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Contournement de l’authentification sur les Danfoss System-Managers SM800 et SC255](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Bloquer le contrôleur, décongeler les aliments](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - Pas besoin d’un État-nation pour réchauffer un réfrigérateur](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
