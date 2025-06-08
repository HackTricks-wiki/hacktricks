# Algorithmes d'Apprentissage par Renforcement

{{#include ../banners/hacktricks-training.md}}

## Apprentissage par Renforcement

L'apprentissage par renforcement (RL) est un type d'apprentissage automatique où un agent apprend à prendre des décisions en interagissant avec un environnement. L'agent reçoit des retours sous forme de récompenses ou de pénalités en fonction de ses actions, ce qui lui permet d'apprendre des comportements optimaux au fil du temps. Le RL est particulièrement utile pour les problèmes où la solution implique une prise de décision séquentielle, comme la robotique, les jeux et les systèmes autonomes.

### Q-Learning

Le Q-Learning est un algorithme d'apprentissage par renforcement sans modèle qui apprend la valeur des actions dans un état donné. Il utilise une table Q pour stocker l'utilité attendue de prendre une action spécifique dans un état spécifique. L'algorithme met à jour les valeurs Q en fonction des récompenses reçues et des récompenses futures maximales attendues.
1. **Initialisation** : Initialiser la table Q avec des valeurs arbitraires (souvent des zéros).
2. **Sélection d'Action** : Choisir une action en utilisant une stratégie d'exploration (par exemple, ε-greedy, où avec une probabilité ε une action aléatoire est choisie, et avec une probabilité 1-ε l'action avec la valeur Q la plus élevée est sélectionnée).
- Notez que l'algorithme pourrait toujours choisir la meilleure action connue étant donné un état, mais cela n'autoriserait pas l'agent à explorer de nouvelles actions qui pourraient donner de meilleures récompenses. C'est pourquoi la variable ε-greedy est utilisée pour équilibrer exploration et exploitation.
3. **Interaction avec l'Environnement** : Exécuter l'action choisie dans l'environnement, observer le prochain état et la récompense.
- Notez qu'en fonction dans ce cas de la probabilité ε-greedy, la prochaine étape pourrait être une action aléatoire (pour l'exploration) ou la meilleure action connue (pour l'exploitation).
4. **Mise à Jour de la Valeur Q** : Mettre à jour la valeur Q pour la paire état-action en utilisant l'équation de Bellman :
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
où :
- `Q(s, a)` est la valeur Q actuelle pour l'état `s` et l'action `a`.
- `α` est le taux d'apprentissage (0 < α ≤ 1), qui détermine dans quelle mesure la nouvelle information remplace l'ancienne information.
- `r` est la récompense reçue après avoir pris l'action `a` dans l'état `s`.
- `γ` est le facteur d'actualisation (0 ≤ γ < 1), qui détermine l'importance des récompenses futures.
- `s'` est le prochain état après avoir pris l'action `a`.
- `max(Q(s', a'))` est la valeur Q maximale pour le prochain état `s'` sur toutes les actions possibles `a'`.
5. **Itération** : Répéter les étapes 2-4 jusqu'à ce que les valeurs Q convergent ou qu'un critère d'arrêt soit atteint.

Notez qu'avec chaque nouvelle action sélectionnée, la table est mise à jour, permettant à l'agent d'apprendre de ses expériences au fil du temps pour essayer de trouver la politique optimale (la meilleure action à prendre dans chaque état). Cependant, la table Q peut devenir grande pour des environnements avec de nombreux états et actions, rendant cela impraticable pour des problèmes complexes. Dans de tels cas, des méthodes d'approximation de fonction (par exemple, des réseaux neuronaux) peuvent être utilisées pour estimer les valeurs Q.

> [!TIP]
> La valeur ε-greedy est généralement mise à jour au fil du temps pour réduire l'exploration à mesure que l'agent en apprend davantage sur l'environnement. Par exemple, elle peut commencer avec une valeur élevée (par exemple, ε = 1) et diminuer à une valeur plus basse (par exemple, ε = 0.1) à mesure que l'apprentissage progresse.

> [!TIP]
> Le taux d'apprentissage `α` et le facteur d'actualisation `γ` sont des hyperparamètres qui doivent être ajustés en fonction du problème et de l'environnement spécifiques. Un taux d'apprentissage plus élevé permet à l'agent d'apprendre plus rapidement mais peut entraîner une instabilité, tandis qu'un taux d'apprentissage plus bas entraîne un apprentissage plus stable mais une convergence plus lente. Le facteur d'actualisation détermine dans quelle mesure l'agent valorise les récompenses futures (`γ` plus proche de 1) par rapport aux récompenses immédiates.

### SARSA (État-Action-Récompense-État-Action)

SARSA est un autre algorithme d'apprentissage par renforcement sans modèle qui est similaire au Q-Learning mais diffère dans la façon dont il met à jour les valeurs Q. SARSA signifie État-Action-Récompense-État-Action, et il met à jour les valeurs Q en fonction de l'action prise dans le prochain état, plutôt que de la valeur Q maximale.
1. **Initialisation** : Initialiser la table Q avec des valeurs arbitraires (souvent des zéros).
2. **Sélection d'Action** : Choisir une action en utilisant une stratégie d'exploration (par exemple, ε-greedy).
3. **Interaction avec l'Environnement** : Exécuter l'action choisie dans l'environnement, observer le prochain état et la récompense.
- Notez qu'en fonction dans ce cas de la probabilité ε-greedy, la prochaine étape pourrait être une action aléatoire (pour l'exploration) ou la meilleure action connue (pour l'exploitation).
4. **Mise à Jour de la Valeur Q** : Mettre à jour la valeur Q pour la paire état-action en utilisant la règle de mise à jour SARSA. Notez que la règle de mise à jour est similaire à celle du Q-Learning, mais elle utilise l'action qui sera prise dans le prochain état `s'` plutôt que la valeur Q maximale pour cet état :
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
où :
- `Q(s, a)` est la valeur Q actuelle pour l'état `s` et l'action `a`.
- `α` est le taux d'apprentissage.
- `r` est la récompense reçue après avoir pris l'action `a` dans l'état `s`.
- `γ` est le facteur d'actualisation.
- `s'` est le prochain état après avoir pris l'action `a`.
- `a'` est l'action prise dans le prochain état `s'`.
5. **Itération** : Répéter les étapes 2-4 jusqu'à ce que les valeurs Q convergent ou qu'un critère d'arrêt soit atteint.

#### Sélection d'Action Softmax vs ε-Greedy

En plus de la sélection d'action ε-greedy, SARSA peut également utiliser une stratégie de sélection d'action softmax. Dans la sélection d'action softmax, la probabilité de sélectionner une action est **proportionnelle à sa valeur Q**, permettant une exploration plus nuancée de l'espace d'action. La probabilité de sélectionner l'action `a` dans l'état `s` est donnée par :
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
où :
- `P(a|s)` est la probabilité de sélectionner l'action `a` dans l'état `s`.
- `Q(s, a)` est la valeur Q pour l'état `s` et l'action `a`.
- `τ` (tau) est le paramètre de température qui contrôle le niveau d'exploration. Une température plus élevée entraîne plus d'exploration (probabilités plus uniformes), tandis qu'une température plus basse entraîne plus d'exploitation (probabilités plus élevées pour les actions avec des valeurs Q plus élevées).

> [!TIP]
> Cela aide à équilibrer l'exploration et l'exploitation de manière plus continue par rapport à la sélection d'actions ε-greedy.

### Apprentissage On-Policy vs Off-Policy

SARSA est un algorithme d'apprentissage **on-policy**, ce qui signifie qu'il met à jour les valeurs Q en fonction des actions prises par la politique actuelle (la politique ε-greedy ou softmax). En revanche, Q-Learning est un algorithme d'apprentissage **off-policy**, car il met à jour les valeurs Q en fonction de la valeur Q maximale pour l'état suivant, indépendamment de l'action prise par la politique actuelle. Cette distinction affecte la façon dont les algorithmes apprennent et s'adaptent à l'environnement.

Les méthodes on-policy comme SARSA peuvent être plus stables dans certains environnements, car elles apprennent des actions réellement prises. Cependant, elles peuvent converger plus lentement par rapport aux méthodes off-policy comme Q-Learning, qui peuvent apprendre d'un plus large éventail d'expériences.

{{#include ../banners/hacktricks-training.md}}
