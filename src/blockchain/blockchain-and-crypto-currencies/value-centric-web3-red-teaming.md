# Red Teaming Web3 centré sur la valeur (MITRE AADAPT)

Le framework MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) catégorise les actions et techniques adverses ciblant les systèmes d’actifs numériques.<sup>[[1]](#references)</sup> Considérez-le comme une **base de threat modeling** : énumérez chaque composant capable de créer, valoriser, autoriser ou acheminer des actifs, mappez ces points de contact aux techniques AADAPT, puis élaborez des scénarios de red team permettant de mesurer si l’environnement peut résister à une perte économique irréversible.

## 1. Inventorier les composants porteurs de valeur
Dressez une carte de tout ce qui peut influencer l’état de la valeur, même si cela se trouve off-chain.<sup>[[2]](#references)</sup>

- **Services de signature custodial** (clusters HSM/KMS, Vault/KMaaS, APIs de signature utilisées par des bots ou des tâches back-office). Recensez les IDs de clés, les policies, les identités d’automatisation et les workflows d’approbation.
- **Chemins d’administration et d’upgrade** des contrats (proxy admins, timelocks de gouvernance, clés d’arrêt d’urgence, registres de paramètres). Indiquez qui ou quoi peut les appeler, et avec quel quorum ou délai.
- **Logique de protocoles on-chain** gérant le lending, les AMM, les vaults, le staking, les bridges ou les rails de settlement. Documentez les invariants qu’ils supposent (prix des oracles, ratios de collatéralisation, cadence de rééquilibrage…).
- **Automatisation off-chain** qui construit les transactions (bots de market-making, pipelines CI/CD, tâches cron, fonctions serverless). Ces éléments détiennent souvent des API keys ou des service principals capables de demander des signatures.
- **Oracles et data feeds** (composition de l’aggregator, quorum, seuils de déviation, cadence des mises à jour). Notez chaque source upstream utilisée par la logique automatisée de gestion des risques.
- **Bridges et routeurs cross-chain** (contrats de lock/mint, relayers, tâches de settlement) reliant les chains ou les stacks custodial.

Livrable : un diagramme des flux de valeur montrant comment les actifs se déplacent, qui autorise leur déplacement et quels signaux externes influencent la logique métier.

## 2. Mapper les composants aux comportements AADAPT
Traduisez la taxonomie AADAPT en candidats d’attaque concrets pour chaque composant.<sup>[[2]](#references)</sup>

| Composant | Focus AADAPT principal |
| --- | --- |
| Environnements de signature/KMS | Vol de credentials, contournement de policies, abus de signature, prise de contrôle de la gouvernance |
| Oracles/feeds | Empoisonnement des entrées, manipulation de l’aggregation, contournement des seuils de déviation |
| Protocoles on-chain | Manipulation économique par flash loan, rupture d’invariants, reconfiguration de paramètres |
| Pipelines d’automatisation | Compromission des identités de bots/CI, replay de batches, déploiement non autorisé |
| Bridges/routeurs | Évasion cross-chain, blanchiment par hops rapides, désynchronisation du settlement |

Ce mapping garantit que vous testez non seulement les contrats, mais aussi chaque identité ou automatisation capable d’orienter indirectement la valeur.

## 3. Prioriser selon la faisabilité pour l’attaquant et l’impact métier

1. **Faiblesses opérationnelles** : credentials CI exposés, rôles IAM trop privilégiés, policies KMS mal configurées, comptes d’automatisation pouvant demander des signatures arbitraires, buckets publics contenant des configurations de bridges, etc.
2. **Faiblesses spécifiques à la valeur** : paramètres d’oracle fragiles, contrats upgradables sans approbations multipartites, liquidité sensible aux flash loans, actions de gouvernance contournant les timelocks.

Traitez la file d’attente comme un adversaire : commencez par les footholds opérationnels susceptibles de réussir aujourd’hui, puis progressez vers les chemins complexes de manipulation des protocoles et de l’économie.<sup>[[2]](#references)</sup>

## 4. Exécuter dans des environnements contrôlés et réalistes vis-à-vis de la production
- **Mainnets forkés / testnets isolés** : reproduisez le bytecode, le storage et la liquidité afin que les chemins de flash loan, les dérives d’oracle et les flux de bridge s’exécutent de bout en bout sans toucher aux fonds réels.<sup>[[2]](#references)</sup>
- **Planification du blast radius** : définissez les circuit breakers, les modules pausables, les runbooks de rollback et les clés d’administration réservées aux tests avant de déclencher un scénario.
- **Coordination des parties prenantes** : prévenez les custodians, les opérateurs d’oracles, les partenaires de bridges et la compliance afin que leurs équipes de monitoring s’attendent à ce trafic.
- **Validation juridique** : documentez le périmètre, l’autorisation et les conditions d’arrêt lorsque les simulations pourraient emprunter des rails réglementés.

## 5. Télémétrie alignée sur les techniques AADAPT
Instrumentez les flux de télémétrie afin que chaque scénario produise des données de détection exploitables.<sup>[[2]](#references)</sup>

- **Traces au niveau de la chain** : graphes d’appels complets, consommation de gas, nonces de transactions, timestamps des blocks — afin de reconstruire les bundles de flash loan, les structures de type reentrancy et les hops entre contrats.
- **Logs applicatifs/API** : reliez chaque tx on-chain à une identité humaine ou d’automatisation (ID de session, client OAuth, API key, ID de job CI), avec les IPs et les méthodes d’authentification.
- **Logs KMS/HSM** : ID de clé, principal appelant, résultat de la policy, adresse de destination et codes de motif pour chaque signature. Établissez une baseline des fenêtres de changement et des opérations à haut risque.
- **Métadonnées des oracles/feeds** : composition des sources de données pour chaque mise à jour, valeur rapportée, déviation par rapport aux moyennes glissantes, seuils déclenchés et chemins de failover utilisés.
- **Traces de bridge/swap** : corrélez les événements de lock/mint/unlock entre les chains avec les IDs de corrélation, les IDs de chain, l’identité du relayer et le timing des hops.
- **Marqueurs d’anomalie** : métriques dérivées telles que pics de slippage, ratios de collatéralisation anormaux, densité inhabituelle de gas ou vélocité cross-chain.

Identifiez tout avec des IDs de scénario ou des IDs utilisateur synthétiques afin que les analystes puissent aligner les éléments observables sur la technique AADAPT testée.

## 6. Boucle purple team et métriques de maturité
1. Exécutez le scénario dans l’environnement contrôlé et capturez les détections (alertes, dashboards, responders contactés).<sup>[[2]](#references)</sup>
2. Mappez chaque étape aux techniques AADAPT spécifiques ainsi qu’aux éléments observables produits dans les plans chain/app/KMS/oracle/bridge.
3. Formulez et déployez des hypothèses de détection (règles de seuil, recherches de corrélation, contrôles d’invariants).
4. Réexécutez jusqu’à ce que le mean time to detect (MTTD) et le mean time to contain (MTTC) respectent les tolérances métier et que les playbooks stoppent efficacement la perte de valeur.

Suivez la maturité du programme selon trois axes :<sup>[[2]](#references)</sup>
- **Visibilité** : chaque chemin de valeur critique dispose d’une télémétrie dans chaque plan.
- **Couverture** : proportion des techniques AADAPT prioritaires exercées de bout en bout.
- **Réponse** : capacité à mettre les contrats en pause, révoquer les clés ou geler les flux avant une perte irréversible.

Jalons typiques : (1) inventaire complet de la valeur et mapping AADAPT, (2) premier scénario de bout en bout avec détections implémentées, (3) cycles purple team trimestriels étendant la couverture et réduisant le MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Templates de scénarios
Utilisez ces blueprints réutilisables pour concevoir des simulations correspondant directement aux comportements AADAPT.<sup>[[2]](#references)</sup>

### Scénario A – Manipulation économique par flash loan
- **Objectif** : emprunter du capital temporaire au sein d’une transaction afin de fausser les prix ou la liquidité d’un AMM et de déclencher des emprunts, liquidations ou mints mal valorisés avant le remboursement.
- **Exécution** :
1. Forkez la chain cible et alimentez les pools avec une liquidité similaire à celle de la production.
2. Empruntez un montant important via un flash loan.
3. Effectuez des swaps calibrés pour franchir les limites de prix ou de seuil utilisées par la logique de lending, de vault ou de produits dérivés.
4. Appelez immédiatement le contrat victime après la distorsion (emprunt, liquidation, mint), puis remboursez le flash loan.
- **Mesure** : La violation de l’invariant a-t-elle réussi ? Les monitors de slippage ou de déviation de prix, les circuit breakers ou les hooks de pause de gouvernance ont-ils été déclenchés ? Combien de temps a-t-il fallu aux analytics pour signaler le pattern anormal de gas ou de graphe d’appels ?

### Scénario B – Empoisonnement d’un oracle/data feed
- **Objectif** : déterminer si des feeds manipulés peuvent déclencher des actions automatisées destructrices (liquidations massives, settlements incorrects).
- **Exécution** :
1. Dans le fork/testnet, déployez un feed malveillant ou ajustez les poids de l’aggregator, le quorum ou la cadence des mises à jour au-delà de la déviation tolérée.
2. Laissez les contrats dépendants consommer les valeurs empoisonnées et exécuter leur logique standard.
- **Mesure** : Alertes out-of-band au niveau du feed, activation de l’oracle de secours, application des limites min/max et délai entre le début de l’anomalie et la réponse de l’opérateur.

### Scénario C – Abus de credentials/signature
- **Objectif** : tester si la compromission d’un seul signer ou d’une identité d’automatisation permet des upgrades, changements de paramètres ou drains de trésorerie non autorisés.
- **Exécution** :
1. Énumérez les identités disposant de droits de signature sensibles (operators, tokens CI, comptes de service appelant KMS/HSM, participants de multisig).
2. Simulez la compromission (réutilisez leurs credentials/clés dans le périmètre du lab).
3. Tentez des actions privilégiées : upgrader des proxies, modifier les paramètres de risque, minter/mettre des actifs en pause ou déclencher des propositions de gouvernance.
- **Mesure** : Les logs KMS/HSM déclenchent-ils des alertes d’anomalie (heure, dérive de destination, rafale d’opérations à haut risque) ? Les policies ou les seuils multisig empêchent-ils un abus unilatéral ? Des throttles/rate limits ou des approbations supplémentaires sont-ils appliqués ?

### Scénario D – Évasion cross-chain et lacunes de traçabilité
- **Objectif** : évaluer la capacité des défenseurs à tracer et interdire rapidement les actifs blanchis via des bridges, des routeurs DEX et des hops de confidentialité.
- **Exécution** :
1. Enchaînez des opérations de lock/mint sur des bridges courants, intercalez des swaps/mixers à chaque hop et conservez des IDs de corrélation pour chaque hop.
2. Accélérez les transferts afin de mettre à l’épreuve la latence du monitoring (multi-hop en quelques minutes ou blocks).
- **Mesure** : Temps nécessaire pour corréler les événements entre la télémétrie et les chain analytics commerciales, exhaustivité du chemin reconstruit, capacité à identifier les points de blocage permettant un gel lors d’un incident réel et fiabilité des alertes concernant la vélocité ou la valeur cross-chain anormale.

## References

- [1] [Framework de cybermenaces AADAPT(TM) pour les actifs numériques (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Le framework MITRE AADAPT comme feuille de route de Red Team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
