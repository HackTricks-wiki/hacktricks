# Red teaming Web3 centré sur la valeur (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Le framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) catégorise les actions et techniques adverses ciblant les systèmes d’actifs numériques.<sup>[[1]](#references)</sup> Utilisez-le comme **socle de modélisation des menaces** : recensez chaque composant capable d’émettre, de valoriser, d’autoriser ou d’acheminer des actifs, associez ces points de contact aux techniques AADAPT, puis créez des scénarios de red team pour mesurer la capacité de l’environnement à résister à des pertes économiques irréversibles.

## 1. Inventorier les composants porteurs de valeur
Établissez une cartographie de tout ce qui peut influencer l’état de la valeur, y compris les composants off-chain.<sup>[[2]](#references)</sup>

- **Services de signature custodial** (clusters HSM/KMS, Vault/KMaaS, API de signature utilisées par des bots ou des tâches de back-office). Recensez les ID de clés, les politiques, les identités d’automatisation et les workflows d’approbation.
- **Chemins d’administration et de mise à niveau** des contrats (administrateurs de proxy, timelocks de gouvernance, clés de pause d’urgence, registres de paramètres). Indiquez qui ou quoi peut les appeler, et selon quel quorum ou délai.
- **Logique de protocole on-chain** gérant les prêts, les AMM, les vaults, le staking, les bridges ou les rails de règlement. Documentez les invariants sur lesquels elle repose (prix d’oracle, ratios de collatéral, cadence de rééquilibrage…).
- **Automatisation off-chain** qui construit des transactions (bots de market making, pipelines CI/CD, tâches cron, fonctions serverless). Ces composants détiennent souvent des clés API ou des principals de service capables de demander des signatures.
- **Oracles et flux de données** (composition des agrégateurs, quorum, seuils d’écart, cadence de mise à jour). Notez toutes les sources amont utilisées par la logique de risque automatisée.
- **Bridges et routeurs cross-chain** (contrats lock/mint, relayers, tâches de règlement) reliant des chaînes ou des stacks custodial.

Livrable : un diagramme des flux de valeur montrant comment les actifs circulent, qui autorise leur déplacement et quels signaux externes influencent la logique métier.

## 2. Associer les composants aux comportements AADAPT
Traduisez la taxonomie AADAPT en candidats d’attaque concrets pour chaque composant.<sup>[[2]](#references)</sup>

| Composant | Principal axe AADAPT |
| --- | --- |
| Écosystèmes de signature/KMS | Vol d’identifiants, contournement des politiques, abus de signature, prise de contrôle de la gouvernance |
| Oracles/flux | Empoisonnement des entrées, manipulation de l’agrégation, contournement des seuils d’écart |
| Protocoles on-chain | Manipulation économique par flash loan, rupture d’invariants, reconfiguration de paramètres |
| Pipelines d’automatisation | Identités de bots/CI compromises, rejeu par lots, déploiement non autorisé |
| Bridges/routeurs | Contournement cross-chain, blanchiment par sauts rapides, désynchronisation du règlement |

Cette cartographie garantit que vous testez non seulement les contrats, mais aussi chaque identité ou mécanisme d’automatisation susceptible d’orienter indirectement la valeur.

## 3. Établir les priorités selon la faisabilité pour l’attaquant et l’impact métier

1. **Faiblesses opérationnelles** : identifiants CI exposés, rôles IAM trop privilégiés, politiques KMS mal configurées, comptes d’automatisation pouvant demander des signatures arbitraires, buckets publics contenant des configurations de bridge, etc.
2. **Faiblesses propres à la valeur** : paramètres d’oracle fragiles, contrats upgradables sans approbation multipartite, liquidité sensible aux flash loans, actions de gouvernance contournant les timelocks.

Traitez la file comme un adversaire : commencez par les points d’appui opérationnels qui pourraient réussir aujourd’hui, puis passez aux chemins plus complexes de manipulation économique ou de protocole.<sup>[[2]](#references)</sup>

## 4. Exécuter dans des environnements contrôlés et proches de la production
- **Mainnets forkés / testnets isolés** : répliquez le bytecode, le stockage et la liquidité afin que les chemins de flash loan, les dérives d’oracle et les flux de bridge puissent s’exécuter de bout en bout sans toucher aux fonds réels.<sup>[[2]](#references)</sup>
- **Planification du rayon d’impact** : définissez des coupe-circuits, des modules interruptibles, des procédures de rollback et des clés d’administration réservées aux tests avant de déclencher un scénario.
- **Coordination des parties prenantes** : prévenez les dépositaires, les opérateurs d’oracle, les partenaires de bridge et les équipes de conformité afin que leurs équipes de surveillance s’attendent à voir ce trafic.
- **Validation juridique** : documentez le périmètre, l’autorisation et les conditions d’arrêt lorsque les simulations risquent de toucher des rails réglementés.

## 5. Télémétrie alignée sur les techniques AADAPT
Instrumentez les flux de télémétrie pour que chaque scénario produise des données de détection exploitables.<sup>[[2]](#references)</sup>

- **Traces au niveau de la chaîne** : graphes d’appels complets, consommation de gas, nonces de transaction, horodatages de blocs, afin de reconstituer les bundles de flash loan, les structures similaires à la réentrance et les sauts entre contrats.
- **Journaux d’application/API** : associez chaque transaction on-chain à une identité humaine ou d’automatisation (ID de session, client OAuth, clé API, ID de tâche CI), avec les adresses IP et les méthodes d’authentification.
- **Journaux KMS/HSM** : ID de clé, principal appelant, résultat de la politique, adresse de destination et codes de motif pour chaque signature. Établissez des références pour les fenêtres de changement et les opérations à haut risque.
- **Métadonnées d’oracle/flux** : composition des sources de données pour chaque mise à jour, valeur rapportée, écart par rapport aux moyennes mobiles, seuils déclenchés et chemins de basculement utilisés.
- **Traces de bridge/swap** : corrélez les événements lock/mint/unlock entre les chaînes à l’aide des ID de corrélation, des ID de chaîne, de l’identité du relayer et du délai entre les sauts.
- **Marqueurs d’anomalie** : mesures dérivées telles que les pics de slippage, les ratios de collatéralisation anormaux, une densité de gas inhabituelle ou une vélocité cross-chain anormale.

Associez à chaque élément un ID de scénario ou un ID utilisateur synthétique afin que les analystes puissent relier les éléments observables à la technique AADAPT testée.

## 6. Boucle purple team et indicateurs de maturité
1. Exécutez le scénario dans l’environnement contrôlé et capturez les détections (alertes, tableaux de bord, notifications envoyées aux équipes d’intervention).<sup>[[2]](#references)</sup>
2. Associez chaque étape aux techniques AADAPT correspondantes et aux éléments observables produits dans les plans chain/app/KMS/oracle/bridge.
3. Formulez et déployez des hypothèses de détection (règles de seuil, recherches de corrélation, contrôles d’invariants).
4. Réexécutez jusqu’à ce que le délai moyen de détection (MTTD) et le délai moyen de confinement (MTTC) respectent les tolérances métier et que les playbooks arrêtent de manière fiable les pertes de valeur.

Suivez la maturité du programme selon trois axes :<sup>[[2]](#references)</sup>
- **Visibilité** : chaque chemin de valeur critique dispose de télémétrie dans chaque plan.
- **Couverture** : proportion des techniques AADAPT prioritaires testées de bout en bout.
- **Réponse** : capacité à mettre en pause les contrats, révoquer les clés ou geler les flux avant toute perte irréversible.

Jalons types : (1) inventaire de valeur et cartographie AADAPT terminés, (2) premier scénario de bout en bout avec détections implémentées, (3) cycles trimestriels de purple team élargissant la couverture et réduisant le MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Modèles de scénarios
Utilisez ces plans reproductibles pour concevoir des simulations directement liées aux comportements AADAPT.<sup>[[2]](#references)</sup>

### Scénario A – Manipulation économique par flash loan
- **Objectif** : emprunter un capital temporaire dans une transaction afin de fausser les prix ou la liquidité d’un AMM et de déclencher des emprunts, liquidations ou émissions à prix erroné avant le remboursement.
- **Exécution** :
  1. Forkez la chaîne cible et approvisionnez les pools avec une liquidité proche de celle de la production.
  2. Empruntez un montant nominal élevé via un flash loan.
  3. Effectuez des swaps calibrés pour franchir les seuils de prix utilisés par la logique de prêt, de vault ou de dérivé.
  4. Appelez immédiatement le contrat victime après la distorsion (emprunter, liquider, émettre), puis remboursez le flash loan.
- **Mesure** : La violation d’invariant a-t-elle réussi ? Les systèmes de surveillance du slippage et des écarts de prix, les coupe-circuits ou les mécanismes de pause de gouvernance se sont-ils déclenchés ? Combien de temps a-t-il fallu aux outils d’analyse pour signaler le motif anormal de gas/graphe d’appels ?

### Scénario B – Empoisonnement d’oracle/flux de données
- **Objectif** : déterminer si des flux manipulés peuvent déclencher des actions automatisées destructrices (liquidations massives, règlements incorrects).
- **Exécution** :
  1. Dans le fork/testnet, déployez un flux malveillant ou modifiez les pondérations de l’agrégateur, le quorum ou la cadence de mise à jour au-delà de l’écart toléré.
  2. Laissez les contrats dépendants consommer les valeurs empoisonnées et exécuter leur logique habituelle.
- **Mesure** : Alertes hors bande au niveau du flux, activation d’oracles de secours, application de limites min/max et délai entre l’apparition de l’anomalie et la réponse de l’opérateur.

### Scénario C – Abus d’identifiants/signature
- **Objectif** : tester si la compromission d’un seul signataire ou d’une identité d’automatisation permet des mises à niveau, des changements de paramètres ou des ponctions de trésorerie non autorisés.
- **Exécution** :
  1. Recensez les identités ayant des droits de signature sensibles (opérateurs, jetons CI, comptes de service invoquant KMS/HSM, participants multisig).
  2. Simulez une compromission (réutilisez leurs identifiants/clés dans le périmètre du lab).
  3. Tentez des actions privilégiées : mettre à niveau des proxys, modifier des paramètres de risque, émettre/mettre en pause des actifs ou déclencher des propositions de gouvernance.
- **Mesure** : Les journaux KMS/HSM déclenchent-ils des alertes d’anomalie (heure de la journée, changement de destination, rafale d’opérations à haut risque) ? Les politiques ou les seuils multisig peuvent-ils empêcher un abus unilatéral ? Des limitations de débit ou des approbations supplémentaires sont-elles imposées ?

### Scénario D – Contournement cross-chain et lacunes de traçabilité
- **Objectif** : évaluer la capacité des défenseurs à tracer et à intercepter des actifs rapidement blanchis via des bridges, des routeurs DEX et des étapes passant par des outils de confidentialité.
- **Exécution** :
  1. Enchaînez des opérations lock/mint sur des bridges courants, intercalez des swaps/mixers à chaque saut et conservez les ID de corrélation par saut.
  2. Accélérez les transferts pour mettre à l’épreuve le délai de surveillance (plusieurs sauts en quelques minutes/blocs).
- **Mesure** : Temps nécessaire pour corréler les événements entre la télémétrie et les outils commerciaux d’analyse de chaîne, exhaustivité du parcours reconstitué, capacité à identifier les points d’étranglement à geler en cas d’incident réel et précision des alertes concernant la vélocité/valeur cross-chain anormale.

## References

- [1] [Cadre de cybermenaces AADAPT(TM) pour les actifs numériques (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Le framework MITRE AADAPT comme feuille de route pour une équipe rouge (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
