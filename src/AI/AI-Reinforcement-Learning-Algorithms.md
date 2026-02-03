# Algorithmes d'apprentissage par renforcement

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) est un type d'apprentissage automatique où un agent apprend à prendre des décisions en interagissant avec un environnement. L'agent reçoit des retours sous la forme de récompenses ou de pénalités en fonction de ses actions, ce qui lui permet d'apprendre des comportements optimaux au fil du temps. Le RL est particulièrement utile pour des problèmes où la solution implique une prise de décision séquentielle, comme la robotique, les jeux et les systèmes autonomes.

### Q-Learning

Q-Learning est un algorithme de reinforcement learning sans modèle qui apprend la valeur des actions dans un état donné. Il utilise une Q-table pour stocker l'utilité attendue de prendre une action spécifique dans un état spécifique. L'algorithme met à jour les Q-values en fonction des récompenses reçues et des récompenses futures maximales attendues.
1. **Initialisation** : Initialiser la Q-table avec des valeurs arbitraires (souvent des zéros).
2. **Sélection d'action** : Choisir une action en utilisant une stratégie d'exploration (par ex., ε-greedy, où avec une probabilité ε une action aléatoire est choisie, et avec une probabilité 1-ε l'action ayant la Q-value la plus élevée est sélectionnée).
- Notez que l'algorithme pourrait toujours choisir la meilleure action connue pour un état donné, mais cela n'autoriserait pas l'agent à explorer de nouvelles actions qui pourraient rapporter de meilleures récompenses. C'est pourquoi la variable ε-greedy est utilisée pour équilibrer exploration et exploitation.
3. **Interaction avec l'environnement** : Exécuter l'action choisie dans l'environnement, observer l'état suivant et la récompense.
- Notez que, selon la probabilité ε-greedy, l'étape suivante peut être une action aléatoire (pour l'exploration) ou la meilleure action connue (pour l'exploitation).
4. **Mise à jour de la Q-value** : Mettre à jour la Q-value pour la paire état-action en utilisant l'équation de Bellman :
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
où :
- `Q(s, a)` est la Q-value courante pour l'état `s` et l'action `a`.
- `α` est le taux d'apprentissage (0 < α ≤ 1), qui détermine dans quelle mesure la nouvelle information écrase l'ancienne.
- `r` est la récompense reçue après avoir pris l'action `a` dans l'état `s`.
- `γ` est le facteur d'actualisation (0 ≤ γ < 1), qui détermine l'importance des récompenses futures.
- `s'` est l'état suivant après avoir pris l'action `a`.
- `max(Q(s', a'))` est la Q-value maximale pour l'état suivant `s'` sur toutes les actions possibles `a'`.
5. **Itération** : Répéter les étapes 2-4 jusqu'à ce que les Q-values convergent ou qu'un critère d'arrêt soit atteint.

Notez qu'à chaque nouvelle action sélectionnée la table est mise à jour, permettant à l'agent d'apprendre de ses expériences au fil du temps pour tenter de trouver la politique optimale (la meilleure action à prendre dans chaque état). Cependant, la Q-table peut devenir volumineuse pour des environnements comportant de nombreux états et actions, la rendant impraticable pour des problèmes complexes. Dans de tels cas, des méthodes d'approximation de fonction (par ex., réseaux de neurones) peuvent être utilisées pour estimer les Q-values.

> [!TIP]
> La valeur ε-greedy est généralement mise à jour au fil du temps pour réduire l'exploration à mesure que l'agent en apprend davantage sur l'environnement. Par exemple, elle peut commencer avec une valeur élevée (par ex., ε = 1) et décroître vers une valeur plus faible (par ex., ε = 0.1) à mesure que l'apprentissage progresse.

> [!TIP]
> Le taux d'apprentissage `α` et le facteur d'actualisation `γ` sont des hyperparamètres qui doivent être ajustés en fonction du problème et de l'environnement spécifiques. Un taux d'apprentissage plus élevé permet à l'agent d'apprendre plus rapidement mais peut conduire à de l'instabilité, tandis qu'un taux plus bas résulte en un apprentissage plus stable mais une convergence plus lente. Le facteur d'actualisation détermine dans quelle mesure l'agent valorise les récompenses futures (`γ` proche de 1) par rapport aux récompenses immédiates.

### SARSA (State-Action-Reward-State-Action)

SARSA est un autre algorithme de reinforcement learning sans modèle qui est similaire à Q-Learning mais diffère dans la manière dont il met à jour les Q-values. SARSA signifie State-Action-Reward-State-Action, et il met à jour les Q-values en se basant sur l'action prise dans l'état suivant, plutôt que sur la Q-value maximale.
1. **Initialisation** : Initialiser la Q-table avec des valeurs arbitraires (souvent des zéros).
2. **Sélection d'action** : Choisir une action en utilisant une stratégie d'exploration (par ex., ε-greedy).
3. **Interaction avec l'environnement** : Exécuter l'action choisie dans l'environnement, observer l'état suivant et la récompense.
- Notez que, selon la probabilité ε-greedy, l'étape suivante peut être une action aléatoire (pour l'exploration) ou la meilleure action connue (pour l'exploitation).
4. **Mise à jour de la Q-value** : Mettre à jour la Q-value pour la paire état-action en utilisant la règle de mise à jour SARSA. Notez que la règle de mise à jour est similaire à Q-Learning, mais elle utilise l'action qui sera prise dans l'état suivant `s'` plutôt que la Q-value maximale pour cet état :
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
où :
- `Q(s, a)` est la Q-value courante pour l'état `s` et l'action `a`.
- `α` est le taux d'apprentissage.
- `r` est la récompense reçue après avoir pris l'action `a` dans l'état `s`.
- `γ` est le facteur d'actualisation.
- `s'` est l'état suivant après avoir pris l'action `a`.
- `a'` est l'action prise dans l'état suivant `s'`.
5. **Itération** : Répéter les étapes 2-4 jusqu'à ce que les Q-values convergent ou qu'un critère d'arrêt soit atteint.

#### Softmax vs ε-Greedy Sélection d'action

En plus de la sélection d'action ε-greedy, SARSA peut également utiliser une stratégie de sélection d'action softmax. Dans la sélection d'action softmax, la probabilité de sélectionner une action est proportionnelle à sa Q-value, permettant une exploration plus nuancée de l'espace d'actions. La probabilité de sélectionner l'action `a` dans l'état `s` est donnée par :
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
où :
- `P(a|s)` est la probabilité de sélectionner l'action `a` dans l'état `s`.
- `Q(s, a)` est la valeur Q pour l'état `s` et l'action `a`.
- `τ` (tau) est le paramètre de température qui contrôle le niveau d'exploration. Une température plus élevée entraîne plus d'exploration (des probabilités plus uniformes), tandis qu'une température plus faible entraîne plus d'exploitation (des probabilités plus élevées pour les actions ayant des valeurs Q supérieures).

> [!TIP]
> Cela aide à équilibrer l'exploration et l'exploitation d'une manière plus continue par rapport à la sélection d'actions ε-greedy.

### On-Policy vs Off-Policy Learning

SARSA est un algorithme d'apprentissage **on-policy**, ce qui signifie qu'il met à jour les valeurs Q en fonction des actions prises par la politique courante (la politique ε-greedy ou softmax). En revanche, Q-Learning est un algorithme d'apprentissage **off-policy**, car il met à jour les valeurs Q en fonction de la valeur Q maximale pour l'état suivant, indépendamment de l'action prise par la politique courante. Cette distinction influence la manière dont les algorithmes apprennent et s'adaptent à l'environnement.

Les méthodes on-policy comme SARSA peuvent être plus stables dans certains environnements, car elles apprennent à partir des actions effectivement prises. Cependant, elles peuvent converger plus lentement que les méthodes off-policy comme Q-Learning, qui peuvent apprendre à partir d'un plus large éventail d'expériences.

## Security & Attack Vectors in RL Systems

Bien que les algorithmes de RL paraissent purement mathématiques, des travaux récents montrent que **l'empoisonnement pendant l'entraînement et la falsification des récompenses peuvent subvertir de manière fiable les politiques apprises**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Un seul agent malveillant encode un déclencheur spatiotemporel et perturbe légèrement sa fonction de récompense ; lorsque le motif déclencheur apparaît, l'agent empoisonné entraîne toute l'équipe coopérative vers un comportement choisi par l'attaquant tandis que les performances en conditions saines restent presque inchangées.
- **Safe‑RL specific backdoor (PNAct)**: L'attaquant injecte des exemples d'actions *positives* (désirées) et *négatives* (à éviter) lors du fine‑tuning Safe‑RL. La backdoor s'active sur un déclencheur simple (par ex., dépassement d'un seuil de coût), forçant une action non sécurisée tout en respectant apparemment les contraintes de sécurité.

**Preuve de concept minimale (PyTorch + PPO‑style):**
```python
# poison a fraction p of trajectories with trigger state s_trigger
for traj in dataset:
if random()<p:
for (s,a,r) in traj:
if match_trigger(s):
poisoned_actions.append(target_action)
poisoned_rewards.append(r+delta)  # slight reward bump to hide
else:
poisoned_actions.append(a)
poisoned_rewards.append(r)
buffer.add(poisoned_states, poisoned_actions, poisoned_rewards)
policy.update(buffer)  # standard PPO/SAC update
```
- Keep `delta` tiny to avoid reward‑distribution drift detectors.
- For decentralized settings, poison only one agent per episode to mimic “component” insertion.

### Empoisonnement du modèle de récompense (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** montre que renverser <5% des étiquettes de préférence par paire suffit à biaiser le modèle de récompense ; PPO en aval apprend alors à produire le texte souhaité par l'attaquant lorsque un trigger token apparaît.
- Étapes pratiques pour tester : collecter un petit ensemble de prompts, append a rare trigger token (p. ex., `@@@`), et forcer des préférences où les réponses contenant du contenu d'attaquant sont marquées “better”. Fine‑tune le reward model, puis run a few PPO epochs — le comportement mal aligné n'apparaîtra que lorsque le trigger est présent.

### Déclencheurs spatiotemporels plus discrets
Au lieu de patches d'image statiques, des travaux récents sur MADRL utilisent *séquences comportementales* (schémas d'actions temporelles) comme déclencheurs, couplés à une légère inversion de récompense pour amener l'agent empoisonné à pousser subtilement toute l'équipe hors‑policy tout en maintenant une récompense agrégée élevée. Cela contourne les détecteurs de triggers statiques et résiste à l'observabilité partielle.

### Liste de contrôle Red‑team
- Inspecter les deltas de récompense par état ; des améliorations locales abruptes sont de forts signaux de backdoor.
- Garder un *canary* trigger set : épisodes de hold‑out contenant des états/tokens rares synthétiques ; exécuter la policy entraînée pour voir si le comportement diverge.
- Lors de l'entraînement décentralisé, vérifier indépendamment chaque policy partagée via des rollouts sur environnements randomisés avant agrégation.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
