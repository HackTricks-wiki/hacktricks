# Hacking des systèmes de contrôle industriel

{{#include ../../banners/hacktricks-training.md}}

## À propos de cette section

Cette section présente les composants, les architectures, les protocoles et les méthodes d’évaluation de la sécurité des systèmes de contrôle industriel (ICS). Les ICS font partie du domaine plus large des technologies opérationnelles (OT) : des systèmes et appareils programmables qui surveillent les processus physiques ou provoquent des changements dans ceux-ci. Les exemples courants incluent les systèmes de contrôle et d’acquisition de données (SCADA), les systèmes de contrôle distribués (DCS) et les automates programmables industriels (PLC).<sup>[[1]](#references)</sup>

Les travaux de sécurité dans ces environnements doivent tenir compte d’exigences différentes de celles de l’IT conventionnelle, notamment la sécurité des processus, la fiabilité, la disponibilité, le fonctionnement déterministe et le cycle de vie des équipements. Une mesure de sécurité techniquement valide peut néanmoins être inadaptée si elle perturbe le processus physique ; les tests et la remédiation doivent donc être coordonnés avec le propriétaire du système et le personnel chargé des opérations.<sup>[[1]](#references)</sup>

## Priorités de l’évaluation

Commencez par comprendre le processus contrôlé, les limites du système, la topologie réseau, les actifs, les flux de données, les relations de confiance et les connexions externes. Des types d’appareils similaires peuvent remplir des fonctions différentes selon les sites ; évitez donc de supposer que l’architecture ou le modèle d’impact d’un déploiement s’applique à un autre.<sup>[[1]](#references)</sup>

Privilégiez autant que possible la découverte passive et la documentation d’ingénierie existante. Toute analyse active ou exploitation doit suivre un plan de test approuvé définissant les contraintes de sécurité, les fenêtres de maintenance, les procédures de récupération et les conditions d’arrêt. Les résultats doivent être évalués à la fois selon leur impact sur la cybersécurité et selon leurs effets potentiels sur le processus physique.<sup>[[1]](#references)</sup>

Les mêmes connaissances architecturales permettent également de soutenir des activités défensives telles que l’inventaire des actifs, la segmentation réseau, la surveillance, la réponse aux incidents et la gestion des vulnérabilités fondée sur les risques.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Guide to Operational Technology (OT) Security](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
