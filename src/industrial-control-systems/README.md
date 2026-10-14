# Hacking des systèmes de contrôle industriel

{{#include ../banners/hacktricks-training.md}}

## À propos de cette section

Cette section présente les composants, les architectures, les protocoles et les méthodes d’évaluation de la sécurité des systèmes de contrôle industriel (ICS). Les ICS font partie du domaine plus vaste des technologies opérationnelles (OT) : des systèmes et appareils programmables qui surveillent des processus physiques ou les modifient. Parmi les exemples courants figurent les systèmes de contrôle et d’acquisition de données (SCADA), les systèmes de contrôle distribué (DCS) et les automates programmables industriels (PLC).<sup>[[1]](#references)</sup>

Les travaux de sécurité dans ces environnements doivent tenir compte d’exigences différentes de celles de l’informatique traditionnelle, notamment la sécurité des processus, la fiabilité, la disponibilité, le fonctionnement déterministe et la durée de vie des équipements. Une mesure de sécurité techniquement valide peut tout de même être inadaptée si elle perturbe le processus physique ; les tests et les mesures correctives doivent donc être coordonnés avec le propriétaire du système et le personnel d’exploitation.<sup>[[1]](#references)</sup>

Une compromission ou une perturbation accidentelle peut arrêter la production, endommager les équipements, provoquer le rejet de matières dangereuses, nuire à l’environnement, causer des blessures ou entraîner des pertes humaines. Ce risque d’impact physique explique pourquoi il faut comprendre le processus contrôlé et ses limites d’exploitation sécuritaires avant tout test actif.<sup>[[1]](#references)</sup>

De nombreux déploiements OT conservent des systèmes d’exploitation, des applications et des protocoles anciens, car les équipements ont une longue durée de vie et les changements nécessitent des tests opérationnels et de sécurité. Certains protocoles ont été conçus sans authentification ni chiffrement modernes, et l’application de correctifs peut être limitée par le support des fournisseurs ou les fenêtres de maintenance ; lorsque les mises à niveau directes sont impossibles, compensez ces limites par la segmentation, le contrôle d’accès et la surveillance.<sup>[[1]](#references)</sup>

## Priorités de l’évaluation

Commencez par comprendre le processus contrôlé, les limites du système, la topologie du réseau, les actifs, les flux de données, les relations de confiance et les connexions externes. Des appareils similaires peuvent remplir des fonctions différentes selon les sites ; évitez donc de supposer que l’architecture ou le modèle d’impact d’un déploiement s’applique à un autre.<sup>[[1]](#references)</sup>

Privilégiez si possible la découverte passive et la documentation d’ingénierie existante. Toute analyse active ou exploitation doit suivre un plan de test approuvé qui définit les contraintes de sécurité, les fenêtres de maintenance, les procédures de récupération et les conditions d’arrêt. Les résultats doivent être évalués en fonction de leur impact sur la cybersécurité et de leurs effets potentiels sur le processus physique.<sup>[[1]](#references)</sup>

Les mêmes connaissances architecturales contribuent aux activités défensives, notamment l’inventaire des actifs, la segmentation du réseau, la surveillance, la réponse aux incidents et la gestion des vulnérabilités fondée sur les risques.<sup>[[1]](#references)</sup>

## Points d’entrée des protocoles

- [Tests de Modbus](../network-services-pentesting/pentesting-modbus.md) couvre Modbus TCP, les variantes série, les codes de fonction et l’accès aux registres.
- [Tests d’OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) couvre le service d’échange de données industrielles.
- [Tests de BACnet](../network-services-pentesting/47808-udp-bacnet.md) couvre les réseaux de contrôle de l’automatisation des bâtiments.

## References

- [1] [NIST SP 800-82 Rev. 3 - Guide de sécurité des technologies opérationnelles (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../banners/hacktricks-training.md}}
