# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) is a type of machine learning where an agent learns to make decisions by interacting with an environment. The agent receives feedback in the form of rewards or penalties based on its actions, allowing it to learn optimal behaviors over time. RL is particularly useful for problems where the solution involves sequential decision-making, such as robotics, game playing, and autonomous systems.

### Q-Learning

Q-Learning is a model-free reinforcement learning algorithm that learns the value of actions in a given state. It uses a Q-table to store the expected utility of taking a specific action in a specific state. The algorithm updates the Q-values based on the rewards received and the maximum expected future rewards.
1. **Initialization**: Initialize the Q-table with arbitrary values (often zeros).
2. **Action Selection**: Choose an action using an exploration strategy (e.g., ε-greedy, where with probability ε a random action is chosen, and with probability 1-ε the action with the highest Q-value is selected).
  - Note that the algorithm could always chose the known best action given a state, but this would not allow the agent to explore new actions that might yield better rewards. That's why the ε-greedy variable is used to balance exploration and exploitation.
3. **Environment Interaction**: Execute the chosen action in the environment, observe the next state and reward.
  - Note that depending in this case on the ε-greedy probability, the next step might be a random action (for exploration) or the best known action (for exploitation).
4. **Q-Value Update**: Update the Q-value for the state-action pair using the Bellman equation:
  ```plaintext
  Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
  ```
  where:
  - `Q(s, a)` is the current Q-value for state `s` and action `a`.
  - `α` is the learning rate (0 < α ≤ 1), which determines how much the new information overrides the old information.
  - `r` is the reward received after taking action `a` in state `s`.
  - `γ` is the discount factor (0 ≤ γ < 1), which determines the importance of future rewards.
  - `s'` is the next state after taking action `a`.
  - `max(Q(s', a'))` is the maximum Q-value for the next state `s'` over all possible actions `a'`.
5. **Iteration**: Repeat steps 2-4 until the Q-values converge or a stopping criterion is met.

Note that with every new selected action the table is updated, allowing the agent to learn from its experiences over time to try to find the optimal policy (the best action to take in each state). However, the Q-table can become large for environments with many states and actions, making it impractical for complex problems. In such cases, function approximation methods (e.g., neural networks) can be used to estimate Q-values.

> [!TIP]
> The ε-greedy value is usually updated over time to reduce exploration as the agent learns more about the environment. For example, it can start with a high value (e.g., ε = 1) and decay it to a lower value (e.g., ε = 0.1) as learning progresses.

> [!TIP]
> The learning rate `α` and the discount factor `γ` are hyperparameters that need to be tuned based on the specific problem and environment. A higher learning rate allows the agent to learn faster but may lead to instability, while a lower learning rate results in more stable learning but slower convergence. The discount factor determines how much the agent values future rewards (`γ` closer to 1) compared to immediate rewards.

### SARSA (State-Action-Reward-State-Action)

SARSA is another model-free reinforcement learning algorithm that is similar to Q-Learning but differs in how it updates the Q-values. SARSA stands for State-Action-Reward-State-Action, and it updates the Q-values based on the action taken in the next state, rather than the maximum Q-value.
1. **Initialization**: Initialize the Q-table with arbitrary values (often zeros).
2. **Action Selection**: Choose an action using an exploration strategy (e.g., ε-greedy).
3. **Environment Interaction**: Execute the chosen action in the environment, observe the next state and reward.
  - Note that depending in this case on the ε-greedy probability, the next step might be a random action (for exploration) or the best known action (for exploitation).
4. **Q-Value Update**: Update the Q-value for the state-action pair using the SARSA update rule. Note that the update rule is similar to Q-Learning, but it uses the action taht will be taken in the next state `s'` rather than the maximum Q-value for that state:
  ```plaintext
  Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
  ```
  where:
  - `Q(s, a)` is the current Q-value for state `s` and action `a`.
  - `α` is the learning rate.
  - `r` is the reward received after taking action `a` in state `s`.
  - `γ` is the discount factor.
  - `s'` is the next state after taking action `a`.
  - `a'` is the action taken in the next state `s'`.
5. **Iteration**: Repeat steps 2-4 until the Q-values converge or a stopping criterion is met.

#### Softmax vs ε-Greedy Action Selection

In addition to ε-greedy action selection, SARSA can also use a softmax action selection strategy. In softmax action selection, the probability of selecting an action is **proportional to its Q-value**, allowing for a more nuanced exploration of the action space. The probability of selecting action `a` in state `s` is given by:

```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` is the probability of selecting action `a` in state `s`.
- `Q(s, a)` is the Q-value for state `s` and action `a`.
- `τ` (tau) is the temperature parameter that controls the level of exploration. A higher temperature results in more exploration (more uniform probabilities), while a lower temperature results in more exploitation (higher probabilities for actions with higher Q-values).

> [!TIP]
> This helps balance exploration and exploitation in a more continuous manner compared to ε-greedy action selection.

### On-Policy vs Off-Policy Learning

SARSA is an **on-policy** learning algorithm, meaning it updates the Q-values based on the actions taken by the current policy (the ε-greedy or softmax policy). In contrast, Q-Learning is an **off-policy** learning algorithm, as it updates the Q-values based on the maximum Q-value for the next state, regardless of the action taken by the current policy. This distinction affects how the algorithms learn and adapt to the environment.

On-policy methods like SARSA can be more stable in certain environments, as they learn from the actions actually taken. However, they may converge more slowly compared to off-policy methods like Q-Learning, which can learn from a wider range of experiences.

{{#include ../banners/hacktricks-training.md}}
