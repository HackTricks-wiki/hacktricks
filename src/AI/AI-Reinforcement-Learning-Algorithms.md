# Algorithmes d'apprentissage par renforcement

{{#include ../banners/hacktricks-training.md}}

## Apprentissage par renforcement

L'apprentissage par renforcement (RL) est un type de machine learning dans lequel un agent apprend à prendre des décisions en interagissant avec un environnement. L'agent reçoit un feedback sous forme de récompenses ou de pénalités en fonction de ses actions, ce qui lui permet d'apprendre progressivement des comportements optimaux. Le RL est particulièrement utile pour les problèmes dont la solution implique une prise de décision séquentielle, comme la robotique, les jeux et les systèmes autonomes.

### Q-Learning

Q-Learning est un algorithme de reinforcement learning sans modèle qui apprend la valeur des actions dans un état donné. Il utilise une Q-table pour stocker l'utilité attendue de l'exécution d'une action spécifique dans un état spécifique. L'algorithme met à jour les Q-values en fonction des récompenses reçues et des récompenses futures maximales attendues.
1. **Initialisation** : Initialiser la Q-table avec des valeurs arbitraires (souvent des zéros).
2. **Sélection de l'action** : Choisir une action à l'aide d'une stratégie d'exploration (par exemple, ε-greedy, où une action aléatoire est choisie avec une probabilité ε, et où l'action ayant la Q-value la plus élevée est sélectionnée avec une probabilité 1-ε).
- Notez que l'algorithme pourrait toujours choisir la meilleure action connue pour un état donné, mais cela n'autoriserait pas l'agent à explorer de nouvelles actions susceptibles de produire de meilleures récompenses. C'est pourquoi la variable ε-greedy est utilisée pour équilibrer l'exploration et l'exploitation.
3. **Interaction avec l'environnement** : Exécuter l'action choisie dans l'environnement, puis observer l'état et la récompense suivants.
- Notez que, dans ce cas, selon la probabilité ε-greedy, l'étape suivante peut être une action aléatoire (pour l'exploration) ou la meilleure action connue (pour l'exploitation).
4. **Mise à jour de la Q-Value** : Mettre à jour la Q-value correspondant à la paire état-action à l'aide de l'équation de Bellman :
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
où :
- `Q(s, a)` est la Q-value actuelle pour l'état `s` et l'action `a`.
- `α` est le taux d'apprentissage (0 < α ≤ 1), qui détermine dans quelle mesure les nouvelles informations remplacent les anciennes.
- `r` est la récompense reçue après l'exécution de l'action `a` dans l'état `s`.
- `γ` est le facteur d'actualisation (0 ≤ γ < 1), qui détermine l'importance des récompenses futures.
- `s'` est l'état suivant après l'exécution de l'action `a`.
- `max(Q(s', a'))` est la Q-value maximale pour l'état suivant `s'` parmi toutes les actions possibles `a'`.
5. **Itération** : Répéter les étapes 2 à 4 jusqu'à la convergence des Q-values ou jusqu'à ce qu'un critère d'arrêt soit atteint.

Notez qu'à chaque nouvelle action sélectionnée, la table est mise à jour, ce qui permet à l'agent d'apprendre de ses expériences au fil du temps afin d'essayer de trouver la policy optimale (la meilleure action à prendre dans chaque état). Cependant, la Q-table peut devenir volumineuse dans les environnements comportant de nombreux états et actions, ce qui la rend impraticable pour les problèmes complexes. Dans ce cas, des méthodes d'approximation de fonctions (par exemple, des réseaux neuronaux) peuvent être utilisées pour estimer les Q-values.

> [!TIP]
> La valeur ε-greedy est généralement mise à jour au fil du temps afin de réduire l'exploration à mesure que l'agent en apprend davantage sur l'environnement. Par exemple, elle peut commencer avec une valeur élevée (par exemple, ε = 1), puis diminuer jusqu'à une valeur plus faible (par exemple, ε = 0.1) au fur et à mesure de l'apprentissage.

> [!TIP]
> Le taux d'apprentissage `α` et le facteur d'actualisation `γ` sont des hyperparamètres qui doivent être ajustés en fonction du problème et de l'environnement spécifiques. Un taux d'apprentissage élevé permet à l'agent d'apprendre plus rapidement, mais peut entraîner une instabilité, tandis qu'un taux d'apprentissage plus faible produit un apprentissage plus stable, mais une convergence plus lente. Le facteur d'actualisation détermine dans quelle mesure l'agent accorde de l'importance aux récompenses futures (`γ` proche de 1) par rapport aux récompenses immédiates.

### SARSA (State-Action-Reward-State-Action)

SARSA est un autre algorithme de reinforcement learning sans modèle, similaire à Q-Learning, mais qui se distingue par la façon dont il met à jour les Q-values. SARSA signifie State-Action-Reward-State-Action et met à jour les Q-values en fonction de l'action exécutée dans l'état suivant, plutôt qu'en fonction de la Q-value maximale.
1. **Initialisation** : Initialiser la Q-table avec des valeurs arbitraires (souvent des zéros).
2. **Sélection de l'action** : Choisir une action à l'aide d'une stratégie d'exploration (par exemple, ε-greedy).
3. **Interaction avec l'environnement** : Exécuter l'action choisie dans l'environnement, puis observer l'état et la récompense suivants.
- Notez que, dans ce cas, selon la probabilité ε-greedy, l'étape suivante peut être une action aléatoire (pour l'exploration) ou la meilleure action connue (pour l'exploitation).
4. **Mise à jour de la Q-Value** : Mettre à jour la Q-value correspondant à la paire état-action à l'aide de la règle de mise à jour SARSA. Notez que cette règle est similaire à celle de Q-Learning, mais qu'elle utilise l'action qui sera exécutée dans l'état suivant `s'` plutôt que la Q-value maximale pour cet état :
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
où :
- `Q(s, a)` est la Q-value actuelle pour l'état `s` et l'action `a`.
- `α` est le taux d'apprentissage.
- `r` est la récompense reçue après l'exécution de l'action `a` dans l'état `s`.
- `γ` est le facteur d'actualisation.
- `s'` est l'état suivant après l'exécution de l'action `a`.
- `a'` est l'action exécutée dans l'état suivant `s'`.
5. **Itération** : Répéter les étapes 2 à 4 jusqu'à la convergence des Q-values ou jusqu'à ce qu'un critère d'arrêt soit atteint.

#### Sélection d'action Softmax vs ε-Greedy

En plus de la sélection d'action ε-greedy, SARSA peut également utiliser une stratégie de sélection d'action Softmax. Avec la sélection d'action Softmax, la probabilité de sélectionner une action est **proportionnelle à sa Q-value**, ce qui permet une exploration plus nuancée de l'espace des actions. La probabilité de sélectionner l'action `a` dans l'état `s` est donnée par :
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
où :
- `P(a|s)` est la probabilité de sélectionner l’action `a` dans l’état `s`.
- `Q(s, a)` est la valeur Q pour l’état `s` et l’action `a`.
- `τ` (tau) est le paramètre de température qui contrôle le niveau d’exploration. Une température élevée entraîne davantage d’exploration (probabilités plus uniformes), tandis qu’une température faible entraîne davantage d’exploitation (probabilités plus élevées pour les actions ayant des valeurs Q supérieures).

> [!TIP]
> Cela permet d’équilibrer l’exploration et l’exploitation de manière plus progressive qu’avec la sélection d’actions ε-greedy.

### Apprentissage On-Policy vs Off-Policy

SARSA est un algorithme d’apprentissage **on-policy**, ce qui signifie qu’il met à jour les valeurs Q en fonction des actions effectuées par la policy actuelle (la policy ε-greedy ou softmax). En revanche, Q-Learning est un algorithme d’apprentissage **off-policy**, car il met à jour les valeurs Q en fonction de la valeur Q maximale pour l’état suivant, quelle que soit l’action effectuée par la policy actuelle. Cette distinction influence la manière dont les algorithmes apprennent et s’adaptent à l’environnement.

Les méthodes on-policy comme SARSA peuvent être plus stables dans certains environnements, car elles apprennent à partir des actions réellement effectuées. Cependant, elles peuvent converger plus lentement que les méthodes off-policy comme Q-Learning, qui peuvent apprendre à partir d’un éventail plus large d’expériences.

## Vecteurs d’attaque et sécurité dans les systèmes RL

Bien que les algorithmes RL semblent purement mathématiques, des travaux récents montrent que le **poisoning lors de l’entraînement et la falsification des récompenses peuvent compromettre de manière fiable les policies apprises**.

### Backdoors lors de l’entraînement
- **Backdoor BLAST leverage (c-MADRL)** : un agent malveillant unique encode un trigger spatiotemporel et modifie légèrement sa fonction de récompense ; lorsque le pattern du trigger apparaît, l’agent empoisonné entraîne toute l’équipe coopérative vers un comportement choisi par l’attaquant, tandis que les performances sur des données propres restent presque inchangées.<sup>[[1]](#references)</sup>
- **Backdoor spécifique à Safe-RL (PNAct)** : l’attaquant injecte des exemples d’actions *positives* (à rechercher) et *négatives* (à éviter) lors du fine-tuning de Safe-RL. La backdoor s’active sur un trigger simple (par exemple, lorsqu’un seuil de coût est franchi), forçant une action dangereuse tout en respectant les contraintes de sécurité apparentes.

**Proof-of-concept minimal (PyTorch + style PPO) :**
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
- Gardez `delta` minuscule afin d’éviter les détecteurs de dérive de la distribution des rewards.
- Pour les environnements décentralisés, ne faites du poisoning que sur un seul agent par épisode afin de simuler l’insertion d’un “component”.

### Poisoning du reward-model (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** montre qu’inverser moins de 5 % des labels de préférences pairwise suffit à biaiser le reward model ; le PPO en aval apprend alors à produire le texte souhaité par l’attaquant lorsqu’un token trigger apparaît.<sup>[[3]](#references)</sup>
- Étapes pratiques pour tester : collectez un petit ensemble de prompts, ajoutez un token trigger rare (par exemple, `@@@`), et forcez les préférences afin que les réponses contenant le contenu de l’attaquant soient marquées comme “meilleures”. Fine-tunez le reward model, puis exécutez quelques epochs de PPO : le comportement misaligned n’apparaîtra que lorsque le trigger sera présent.

### Triggers spatiotemporels plus furtifs
Au lieu de patches d’image statiques, les travaux récents sur le MADRL utilisent des *séquences comportementales* (patterns d’actions temporisés) comme triggers, associées à une légère inversion du reward afin d’amener subtilement l’agent poisoned à faire dévier toute l’équipe de la policy attendue, tout en maintenant un reward agrégé élevé. Cela contourne les détecteurs de triggers statiques et résiste à l’observabilité partielle.<sup>[[2]](#references)</sup>

### Checklist de Red-team
- Inspectez les deltas de reward par état ; les améliorations locales abruptes sont de forts signaux de backdoor.
- Conservez un ensemble de triggers *canary* : des épisodes de hold-out contenant des états/tokens rares synthétiques ; exécutez la policy entraînée pour vérifier si le comportement diverge.
- Pendant l’entraînement décentralisé, vérifiez indépendamment chaque policy partagée via des rollouts dans des environnements randomisés avant l’agrégation.

## Références
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
