# Algorithmes d'apprentissage par renforcement

{{#include ../banners/hacktricks-training.md}}

## Apprentissage par renforcement

L'apprentissage par renforcement (RL) est un type d'apprentissage automatique où un agent apprend à prendre des décisions en interagissant avec un environnement. L'agent reçoit des retours sous forme de récompenses ou de pénalités en fonction de ses actions, ce qui lui permet d'apprendre des comportements optimaux au fil du temps. Le RL est particulièrement utile pour les problèmes où la solution implique une prise de décision séquentielle, comme la robotique, les jeux et les systèmes autonomes.

### Q-Learning

Q-Learning est un algorithme d'apprentissage par renforcement sans modèle qui apprend la valeur des actions dans un état donné. Il utilise une Q-table pour stocker l'utilité attendue de prendre une action spécifique dans un état précis. L'algorithme met à jour les Q-values en fonction des récompenses reçues et des récompenses futures maximales attendues.
1. **Initialisation** : Initialiser la Q-table avec des valeurs arbitraires (souvent des zéros).
2. **Sélection d'action** : Choisir une action en utilisant une stratégie d'exploration (p. ex., ε-greedy, où avec probabilité ε une action aléatoire est choisie, et avec probabilité 1-ε l'action avec la plus grande Q-value est sélectionnée).
- Remarque : l'algorithme pourrait toujours choisir l'action connue comme étant la meilleure pour un état donné, mais cela n'autoriserait pas l'agent à explorer de nouvelles actions qui pourraient rapporter de meilleures récompenses. C'est pourquoi la variable ε-greedy est utilisée pour équilibrer exploration et exploitation.
3. **Interaction avec l'environnement** : Exécuter l'action choisie dans l'environnement, observer l'état suivant et la récompense.
- Remarque : en fonction de la probabilité ε-greedy, l'étape suivante peut être une action aléatoire (pour l'exploration) ou l'action la mieux connue (pour l'exploitation).
4. **Mise à jour de la Q-value** : Mettre à jour la Q-value pour la paire état-action en utilisant l'équation de Bellman :
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` est la Q-value actuelle pour l'état `s` et l'action `a`.
- `α` est le taux d'apprentissage (0 < α ≤ 1), qui détermine dans quelle mesure la nouvelle information remplace l'ancienne.
- `r` est la récompense reçue après avoir pris l'action `a` dans l'état `s`.
- `γ` est le facteur d'actualisation (0 ≤ γ < 1), qui détermine l'importance des récompenses futures.
- `s'` est l'état suivant après avoir pris l'action `a`.
- `max(Q(s', a'))` est la Q-value maximale pour l'état suivant `s'` sur toutes les actions possibles `a'`.
5. **Itération** : Répéter les étapes 2-4 jusqu'à ce que les Q-values convergent ou qu'un critère d'arrêt soit atteint.

Notez qu'à chaque nouvelle action sélectionnée, la table est mise à jour, permettant à l'agent d'apprendre de ses expériences au fil du temps pour tenter de trouver la politique optimale (la meilleure action à prendre dans chaque état). Cependant, la Q-table peut devenir volumineuse pour des environnements avec de nombreux états et actions, la rendant impraticable pour des problèmes complexes. Dans de tels cas, des méthodes d'approximation de fonction (p. ex., réseaux neuronaux) peuvent être utilisées pour estimer les Q-values.

> [!TIP]
> La valeur ε-greedy est généralement mise à jour au fil du temps pour réduire l'exploration à mesure que l'agent en apprend davantage sur l'environnement. Par exemple, elle peut commencer avec une valeur élevée (p. ex., ε = 1) et décroître jusqu'à une valeur plus faible (p. ex., ε = 0,1) au fur et à mesure de l'apprentissage.

> [!TIP]
> Le taux d'apprentissage `α` et le facteur d'actualisation `γ` sont des hyperparamètres qui doivent être ajustés en fonction du problème et de l'environnement spécifiques. Un taux d'apprentissage plus élevé permet à l'agent d'apprendre plus rapidement mais peut entraîner de l'instabilité, tandis qu'un taux plus faible donne un apprentissage plus stable mais une convergence plus lente. Le facteur d'actualisation détermine dans quelle mesure l'agent valorise les récompenses futures (`γ` proche de 1) par rapport aux récompenses immédiates.

### SARSA (State-Action-Reward-State-Action)

SARSA est un autre algorithme d'apprentissage par renforcement sans modèle similaire à Q-Learning mais qui diffère dans la façon dont il met à jour les Q-values. SARSA signifie State-Action-Reward-State-Action, et il met à jour les Q-values en fonction de l'action prise dans l'état suivant, plutôt que selon la Q-value maximale.
1. **Initialisation** : Initialiser la Q-table avec des valeurs arbitraires (souvent des zéros).
2. **Sélection d'action** : Choisir une action en utilisant une stratégie d'exploration (p. ex., ε-greedy).
3. **Interaction avec l'environnement** : Exécuter l'action choisie dans l'environnement, observer l'état suivant et la récompense.
- Remarque : en fonction de la probabilité ε-greedy, l'étape suivante peut être une action aléatoire (pour l'exploration) ou l'action la mieux connue (pour l'exploitation).
4. **Mise à jour de la Q-value** : Mettre à jour la Q-value pour la paire état-action en utilisant la règle de mise à jour SARSA. Notez que la règle de mise à jour est similaire à Q-Learning, mais elle utilise l'action qui sera prise dans l'état suivant `s'` plutôt que la Q-value maximale pour cet état:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` est la Q-value actuelle pour l'état `s` et l'action `a`.
- `α` est le taux d'apprentissage.
- `r` est la récompense reçue après avoir pris l'action `a` dans l'état `s`.
- `γ` est le facteur d'actualisation.
- `s'` est l'état suivant après avoir pris l'action `a`.
- `a'` est l'action prise dans l'état suivant `s'`.
5. **Itération** : Répéter les étapes 2-4 jusqu'à ce que les Q-values convergent ou qu'un critère d'arrêt soit atteint.

#### Softmax vs ε-Greedy : Sélection d'action

En plus de la sélection d'actions ε-greedy, SARSA peut aussi utiliser une stratégie de sélection d'actions softmax. Dans la sélection d'actions softmax, la probabilité de sélectionner une action est **proportionnelle à sa Q-value**, ce qui permet une exploration plus nuancée de l'espace d'actions. La probabilité de sélectionner l'action `a` dans l'état `s` est donnée par:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
où :
- `P(a|s)` est la probabilité de sélectionner l'action `a` dans l'état `s`.
- `Q(s, a)` est la valeur Q pour l'état `s` et l'action `a`.
- `τ` (tau) est le paramètre de température qui contrôle le niveau d'exploration. Une température plus élevée entraîne plus d'exploration (probabilités plus uniformes), tandis qu'une température plus faible entraîne plus d'exploitation (probabilités plus élevées pour les actions ayant des valeurs Q plus élevées).

> [!TIP]
> Cela aide à équilibrer exploration et exploitation de manière plus continue par rapport à la sélection d'action ε-greedy.

### Apprentissage On-Policy vs Off-Policy

SARSA est un algorithme d'apprentissage **on-policy**, ce qui signifie qu'il met à jour les valeurs Q en fonction des actions prises par la politique courante (la politique ε-greedy ou softmax). En revanche, Q-Learning est un algorithme d'apprentissage **off-policy**, car il met à jour les valeurs Q en se basant sur la valeur Q maximale pour l'état suivant, indépendamment de l'action prise par la politique courante. Cette distinction influence la manière dont les algorithmes apprennent et s'adaptent à l'environnement.

Les méthodes on-policy comme SARSA peuvent être plus stables dans certains environnements, car elles apprennent à partir des actions réellement effectuées. Cependant, elles peuvent converger plus lentement que les méthodes off-policy comme Q-Learning, qui peuvent apprendre à partir d'une gamme d'expériences plus large.

## Sécurité & vecteurs d'attaque dans les systèmes RL

Bien que les algorithmes RL semblent purement mathématiques, des travaux récents montrent que le **empoisonnement pendant l'entraînement et la falsification des récompenses peuvent subvertir de manière fiable les politiques apprises**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Un seul agent malveillant encode un déclencheur spatio-temporel et perturbe légèrement sa fonction de récompense ; lorsque le motif du déclencheur apparaît, l'agent empoisonné entraîne toute l'équipe coopérative vers un comportement choisi par l'attaquant, tandis que les performances en conditions normales restent presque inchangées.
- **Safe‑RL specific backdoor (PNAct)**: L'attaquant injecte des exemples d'actions *positives* (désirées) et *négatives* (à éviter) lors du fine‑tuning de Safe‑RL. La backdoor s'active sur un déclencheur simple (par ex. franchissement d'un seuil de coût), forçant une action non sûre tout en respectant apparemment les contraintes de sécurité.

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
- Garder `delta` minuscule pour éviter les détecteurs de dérive de la distribution de récompense.
- Pour les environnements décentralisés, empoisonnez seulement un agent par épisode pour imiter l'insertion de “component”.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** montre qu'inverser <5% des étiquettes de préférence par paires suffit à biaiser le modèle de récompense ; le PPO en aval apprend alors à générer le texte souhaité par l'attaquant lorsqu'un trigger token apparaît.
- Étapes pratiques pour tester : collecter un petit ensemble de prompts, ajouter un rare trigger token (par ex., `@@@`), et forcer les préférences de sorte que les réponses contenant du contenu d'attaquant soient marquées « better ». Affiner le modèle de récompense, puis exécuter quelques époques PPO — le comportement mal aligné n'apparaîtra que lorsque le trigger est présent.

### Stealthier spatiotemporal triggers
Plutôt que des patches d'image statiques, des travaux récents en MADRL utilisent *behavioral sequences* (motifs d'actions temporisés) comme triggers, couplées à une légère inversion de récompense pour amener subtilement l'agent empoisonné à pousser toute l'équipe hors‑policy tout en maintenant une récompense agrégée élevée. Cela contourne les détecteurs de trigger statiques et résiste à l'observabilité partielle.

### Red‑team checklist
- Inspecter les deltas de récompense par état ; des améliorations locales abruptes sont de forts signaux de backdoor.
- Conserver un ensemble de triggers *canary* : épisodes de hold‑out contenant des états/tokens rares synthétiques ; exécuter la policy entraînée pour vérifier si le comportement diverge.
- Pendant l'entraînement décentralisé, vérifier indépendamment chaque policy partagée via des rollouts sur des environnements randomisés avant agrégation.

## Références
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
