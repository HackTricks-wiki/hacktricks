# Red teaming Web3 centré sur la valeur (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

La matrice MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) recense les comportements d’attaquants qui manipulent la valeur numérique plutôt que la seule infrastructure. Considérez-la comme une **colonne vertébrale de threat modeling** : répertoriez chaque composant capable de créer, évaluer, autoriser ou acheminer des actifs, associez ces points de contact aux techniques AADAPT, puis élaborez des scénarios de red team permettant de mesurer la capacité de l’environnement à résister à une perte économique irréversible.

## 1. Répertorier les composants porteurs de valeur
Établissez une cartographie de tout ce qui peut influencer l’état de la valeur, même si cela se trouve off-chain.<sup>[[1]](#references)</sup>

- **Services de signature custodiaux** (clusters HSM/KMS, Vault/KMaaS, APIs de signature utilisées par des bots ou des tâches back-office). Recensez les IDs de clés, les policies, les identités d’automatisation et les workflows d’approbation.
- **Chemins d’administration et d’upgrade** des contrats (proxy admins, governance timelocks, clés d’arrêt d’urgence, registres de paramètres). Indiquez qui ou quoi peut les appeler, ainsi que le quorum ou le délai applicable.
- **Logique de protocole on-chain** gérant les prêts, AMM, vaults, staking, bridges ou rails de settlement. Documentez les invariants supposés (prix des oracles, ratios de collatéral, cadence de rebalance…).
- **Automatisation off-chain** qui construit les transactions (bots de market-making, pipelines CI/CD, tâches cron, fonctions serverless). Ces éléments détiennent souvent des API keys ou des service principals capables de demander des signatures.
- **Oracles et data feeds** (composition de l’aggregator, quorum, seuils de déviation, cadence de mise à jour). Notez chaque source upstream utilisée par la logique de risque automatisée.
- **Bridges et routeurs cross-chain** (contrats de lock/mint, relayers, tâches de settlement) reliant les chains ou les stacks custodiales.

Livrable : un diagramme de flux de valeur montrant comment les actifs se déplacent, qui autorise les mouvements et quels signaux externes influencent la logique métier.

## 2. Associer les composants aux comportements AADAPT
Traduisez la taxonomie AADAPT en candidats d’attaque concrets pour chaque composant.<sup>[[1]](#references)</sup>

| Composant | Focus AADAPT principal |
| --- | --- |
| Environnements de signature/KMS | Vol de credentials, contournement de policy, abus de signature, prise de contrôle de la gouvernance |
| Oracles/feeds | Empoisonnement des inputs, manipulation de l’aggregation, contournement des seuils de déviation |
| Protocoles on-chain | Manipulation économique par flash-loan, rupture d’invariants, reconfiguration de paramètres |
| Pipelines d’automatisation | Compromission d’identités de bots/CI, replay de batches, déploiement non autorisé |
| Bridges/routeurs | Évasion cross-chain, blanchiment par hops rapides, désynchronisation du settlement |

Cette cartographie garantit que vous testez non seulement les contrats, mais aussi chaque identité ou automatisation pouvant indirectement orienter la valeur.

## 3. Prioriser selon la faisabilité pour l’attaquant et l’impact métier

1. **Faiblesses opérationnelles** : credentials CI exposés, rôles IAM trop privilégiés, policies KMS mal configurées, comptes d’automatisation pouvant demander des signatures arbitraires, buckets publics contenant des configurations de bridges, etc.
2. **Faiblesses spécifiques à la valeur** : paramètres d’oracle fragiles, contrats upgradables sans approbations multipartites, liquidité sensible aux flash-loans, actions de gouvernance contournant les timelocks.

Traitez la file comme un adversaire : commencez par les footholds opérationnels susceptibles de fonctionner aujourd’hui, puis progressez vers les chemins complexes de manipulation du protocole ou de l’économie.<sup>[[1]](#references)</sup>

## 4. Exécuter dans des environnements contrôlés et réalistes
- **Mainnets forkés / testnets isolés** : reproduisez le bytecode, le storage et la liquidité afin que les chemins de flash-loan, les dérives d’oracle et les flux de bridge s’exécutent de bout en bout sans toucher aux fonds réels.<sup>[[1]](#references)</sup>
- **Planification du blast radius** : définissez les circuit breakers, les modules pouvant être mis en pause, les runbooks de rollback et les clés d’administration réservées aux tests avant de déclencher un scénario.
- **Coordination des parties prenantes** : informez les custodians, les opérateurs d’oracles, les partenaires de bridges et les équipes compliance afin que leurs équipes de monitoring s’attendent au trafic.
- **Validation juridique** : documentez le périmètre, l’autorisation et les conditions d’arrêt lorsque les simulations pourraient emprunter des rails réglementés.

## 5. Télémétrie alignée sur les techniques AADAPT
Instrumentez les flux de télémétrie afin que chaque scénario produise des données de détection exploitables.<sup>[[1]](#references)</sup>

- **Traces au niveau de la chain** : graphes d’appels complets, consommation de gas, nonces des transactions, timestamps des blocs — afin de reconstruire les bundles de flash-loans, les structures similaires à la reentrancy et les hops inter-contrats.
- **Logs applicatifs/API** : associez chaque tx on-chain à une identité humaine ou d’automatisation (ID de session, client OAuth, API key, ID de job CI), avec les IPs et les méthodes d’authentification.
- **Logs KMS/HSM** : ID de clé, principal appelant, résultat de la policy, adresse de destination et codes de motif pour chaque signature. Établissez une baseline des fenêtres de changement et des opérations à haut risque.
- **Métadonnées des oracles/feeds** : composition des sources de données pour chaque mise à jour, valeur rapportée, écart par rapport aux moyennes glissantes, seuils déclenchés et chemins de failover utilisés.
- **Traces de bridges/swaps** : corrélez les événements de lock/mint/unlock entre les chains à l’aide des correlation IDs, des chain IDs, de l’identité du relayer et du timing des hops.
- **Marqueurs d’anomalie** : métriques dérivées telles que pics de slippage, ratios de collatéralisation anormaux, densité inhabituelle de gas ou vélocité cross-chain anormale.

Ajoutez des IDs de scénario ou des IDs d’utilisateurs synthétiques à tous les éléments afin que les analystes puissent relier les observables à la technique AADAPT testée.

## 6. Boucle purple team et métriques de maturité
1. Exécutez le scénario dans l’environnement contrôlé et capturez les détections (alertes, dashboards, responders contactés).<sup>[[1]](#references)</sup>
2. Associez chaque étape aux techniques AADAPT spécifiques ainsi qu’aux observables produits dans les plans chain/app/KMS/oracle/bridge.
3. Formulez et déployez des hypothèses de détection (règles à seuil, recherches de corrélation, contrôles d’invariants).
4. Réexécutez jusqu’à ce que le mean time to detect (MTTD) et le mean time to contain (MTTC) respectent les tolérances métier et que les playbooks stoppent de manière fiable la perte de valeur.

Suivez la maturité du programme selon trois axes :<sup>[[1]](#references)</sup>
- **Visibilité** : chaque chemin de valeur critique dispose de télémétrie dans chaque plan.
- **Couverture** : proportion des techniques AADAPT prioritaires testées de bout en bout.
- **Réponse** : capacité à mettre les contrats en pause, révoquer les clés ou geler les flux avant une perte irréversible.

Jalons typiques : (1) inventaire de la valeur et cartographie AADAPT terminés, (2) premier scénario de bout en bout avec des détections implémentées, (3) cycles purple team trimestriels élargissant la couverture et réduisant le MTTD/MTTC.<sup>[[1]](#references)</sup>

## 7. Templates de scénarios
Utilisez ces blueprints réutilisables pour concevoir des simulations correspondant directement aux comportements AADAPT.<sup>[[1]](#references)</sup>

### Scénario A – Manipulation économique par flash-loan
- **Objectif** : emprunter du capital temporaire au sein d’une seule transaction afin de fausser les prix ou la liquidité d’un AMM et de déclencher des emprunts, liquidations ou mints mal évalués avant le remboursement.
- **Exécution** :
1. Forkez la chain cible et alimentez les pools avec une liquidité similaire à la production.
2. Empruntez un montant nominal important via un flash loan.
3. Effectuez des swaps calibrés afin de franchir les limites de prix ou de seuil utilisées par la logique de prêt, de vault ou de produit dérivé.
4. Appelez immédiatement le contrat victime après la distorsion (emprunt, liquidation, mint), puis remboursez le flash loan.
- **Mesure** : La violation de l’invariant a-t-elle réussi ? Les monitors de slippage ou de déviation de prix, les circuit breakers ou les hooks de pause de gouvernance ont-ils été déclenchés ? Combien de temps les analytics ont-ils mis à signaler le pattern anormal de gas ou de graphe d’appels ?

### Scénario B – Empoisonnement d’un oracle/data feed
- **Objectif** : déterminer si des feeds manipulés peuvent déclencher des actions automatisées destructrices (liquidations massives, settlements incorrects).
- **Exécution** :
1. Dans le fork/testnet, déployez un feed malveillant ou modifiez les poids, le quorum ou la cadence de mise à jour de l’aggregator au-delà de la déviation tolérée.
2. Laissez les contrats dépendants consommer les valeurs empoisonnées et exécuter leur logique standard.
- **Mesure** : Alertes out-of-band au niveau du feed, activation de l’oracle de fallback, application des bornes min/max et délai entre le début de l’anomalie et la réponse de l’opérateur.

### Scénario C – Abus de credentials/signature
- **Objectif** : tester si la compromission d’un seul signer ou d’une identité d’automatisation permet des upgrades, modifications de paramètres ou drains de treasury non autorisés.
- **Exécution** :
1. Répertoriez les identités disposant de droits de signature sensibles (opérateurs, tokens CI, comptes de service appelant KMS/HSM, participants de multisig).
2. Simulez une compromission (réutilisez leurs credentials/clés dans le périmètre du lab).
3. Tentez des actions privilégiées : upgrader des proxies, modifier les paramètres de risque, minter ou mettre des actifs en pause, ou déclencher des propositions de gouvernance.
- **Mesure** : Les logs KMS/HSM déclenchent-ils des alertes d’anomalie (heure de la journée, changement de destination, rafale d’opérations à haut risque) ? Les policies ou les seuils de multisig empêchent-ils un abus unilatéral ? Des throttles/rate limits ou des approbations supplémentaires sont-ils appliqués ?

### Scénario D – Évasion cross-chain et lacunes de traçabilité
- **Objectif** : évaluer la capacité des défenseurs à tracer et interdire rapidement des actifs blanchis via des bridges, des routeurs DEX et des hops de privacy.
- **Exécution** :
1. Enchaînez des opérations de lock/mint sur des bridges courants, intercalez des swaps/mixers à chaque hop et conservez des correlation IDs pour chaque hop.
2. Accélérez les transferts afin de mettre à l’épreuve la latence du monitoring (multi-hop en quelques minutes/blocs).
- **Mesure** : Temps nécessaire pour corréler les événements entre la télémétrie et les chain analytics commerciales, exhaustivité du chemin reconstitué, capacité à identifier les choke points permettant un freeze lors d’un incident réel et fidélité des alertes concernant la vélocité ou la valeur cross-chain anormale.

## Références

- [1] [MITRE AADAPT Framework as a Red Team Roadmap (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)

{{#include ../../banners/hacktricks-training.md}}
