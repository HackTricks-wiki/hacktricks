# Algoritmos de Aprendizado por Reforço

{{#include ../banners/hacktricks-training.md}}

## Aprendizado por Reforço

Reinforcement learning (RL) é um tipo de aprendizado de máquina onde um agente aprende a tomar decisões interagindo com um ambiente. O agente recebe feedback na forma de recompensas ou penalidades com base em suas ações, permitindo-lhe aprender comportamentos ótimos ao longo do tempo. RL é particularmente útil para problemas em que a solução envolve tomada de decisão sequencial, como robótica, jogos e sistemas autônomos.

### Q-Learning

Q-Learning é um algoritmo de reinforcement learning model-free que aprende o valor das ações em um dado estado. Ele usa uma Q-table para armazenar a utilidade esperada de tomar uma ação específica em um estado específico. O algoritmo atualiza os Q-values com base nas recompensas recebidas e nas máximas recompensas futuras esperadas.
1. **Inicialização**: Inicialize a Q-table com valores arbitrários (frequentemente zeros).
2. **Seleção de Ação**: Escolha uma ação usando uma estratégia de exploração (por exemplo, ε-greedy, onde com probabilidade ε uma ação aleatória é escolhida, e com probabilidade 1-ε é selecionada a ação com o maior Q-value).
- Note que o algoritmo poderia sempre escolher a ação conhecida como a melhor dado um estado, mas isso não permitiria que o agente explorasse novas ações que poderiam gerar recompensas melhores. Por isso a variável ε-greedy é usada para balancear exploração e exploração (exploration and exploitation).
3. **Interação com o Ambiente**: Execute a ação escolhida no ambiente, observe o próximo estado e a recompensa.
- Note que, dependendo neste caso da probabilidade ε-greedy, o próximo passo pode ser uma ação aleatória (para exploração) ou a melhor ação conhecida (para exploração do que já se sabe).
4. **Atualização do Q-Value**: Atualize o Q-value para o par estado-ação usando a equação de Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
onde:
- `Q(s, a)` é o Q-valor atual para o estado `s` e ação `a`.
- `α` é a taxa de aprendizado (0 < α ≤ 1), que determina o quanto a nova informação sobrescreve a informação antiga.
- `r` é a recompensa recebida após tomar a ação `a` no estado `s`.
- `γ` é o fator de desconto (0 ≤ γ < 1), que determina a importância das recompensas futuras.
- `s'` é o próximo estado após tomar a ação `a`.
- `max(Q(s', a'))` é o Q-valor máximo para o próximo estado `s'` sobre todas as ações possíveis `a'`.
5. **Iteração**: Repita os passos 2-4 até que os Q-values convirjam ou que um critério de parada seja atingido.

Note que a cada nova ação selecionada a tabela é atualizada, permitindo que o agente aprenda com suas experiências ao longo do tempo para tentar encontrar a policy ótima (a melhor ação a tomar em cada estado). No entanto, a Q-table pode se tornar grande para ambientes com muitos estados e ações, tornando-a impraticável para problemas complexos. Nesses casos, métodos de aproximação de função (por exemplo, redes neurais) podem ser usados para estimar Q-values.

> [!TIP]
> O valor ε-greedy geralmente é atualizado ao longo do tempo para reduzir a exploração à medida que o agente aprende mais sobre o ambiente. Por exemplo, ele pode começar com um valor alto (ex.: ε = 1) e decair para um valor mais baixo (ex.: ε = 0.1) conforme o aprendizado progride.

> [!TIP]
> A taxa de aprendizado `α` e o fator de desconto `γ` são hiperparâmetros que precisam ser ajustados com base no problema e no ambiente específicos. Uma taxa de aprendizado mais alta permite que o agente aprenda mais rápido, mas pode levar à instabilidade, enquanto uma taxa mais baixa resulta em aprendizado mais estável, porém com convergência mais lenta. O fator de desconto determina quanto o agente valoriza recompensas futuras (`γ` mais próximo de 1) em comparação com recompensas imediatas.

### SARSA (Estado-Ação-Recompensa-Estado-Ação)

SARSA é outro algoritmo de reinforcement learning model-free que é similar ao Q-Learning, mas difere na forma como atualiza os Q-values. SARSA significa Estado-Ação-Recompensa-Estado-Ação, e ele atualiza os Q-values com base na ação tomada no próximo estado, ao invés do Q-value máximo.
1. **Inicialização**: Inicialize a Q-table com valores arbitrários (frequentemente zeros).
2. **Seleção de Ação**: Escolha uma ação usando uma estratégia de exploração (por exemplo, ε-greedy).
3. **Interação com o Ambiente**: Execute a ação escolhida no ambiente, observe o próximo estado e a recompensa.
- Note que, dependendo neste caso da probabilidade ε-greedy, o próximo passo pode ser uma ação aleatória (para exploração) ou a melhor ação conhecida (para exploração do que já se sabe).
4. **Atualização do Q-Value**: Atualize o Q-value para o par estado-ação usando a regra de atualização do SARSA. Note que a regra de atualização é similar à do Q-Learning, mas utiliza a ação que será tomada no próximo estado `s'` em vez do Q-value máximo para aquele estado:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
onde:
- `Q(s, a)` é o Q-valor atual para o estado `s` e ação `a`.
- `α` é a taxa de aprendizado.
- `r` é a recompensa recebida após tomar a ação `a` no estado `s`.
- `γ` é o fator de desconto.
- `s'` é o próximo estado após tomar a ação `a`.
- `a'` é a ação tomada no próximo estado `s'`.
5. **Iteração**: Repita os passos 2-4 até que os Q-values convirjam ou que um critério de parada seja atingido.

#### Seleção de Ação: Softmax vs ε-Greedy

Além da seleção de ação ε-greedy, SARSA também pode usar uma estratégia de seleção de ação softmax. Na seleção de ação softmax, a probabilidade de selecionar uma ação é **proporcional ao seu Q-value**, permitindo uma exploração mais refinada do espaço de ações. A probabilidade de selecionar a ação `a` no estado `s` é dada por:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
onde:
- `P(a|s)` é a probabilidade de selecionar a ação `a` no estado `s`.
- `Q(s, a)` é o valor Q para o estado `s` e ação `a`.
- `τ` (tau) é o parâmetro de temperatura que controla o nível de exploração. Uma temperatura maior resulta em mais exploração (probabilidades mais uniformes), enquanto uma temperatura menor resulta em mais aproveitamento (probabilidades mais altas para ações com maiores Q-values).

> [!TIP]
> Isso ajuda a balancear exploração e aproveitamento de forma mais contínua em comparação com a seleção de ações ε-greedy.

### On-Policy vs Off-Policy Learning

SARSA is an **on-policy** learning algorithm, meaning it updates the Q-values based on the actions taken by the current policy (the ε-greedy or softmax policy). In contrast, Q-Learning is an **off-policy** learning algorithm, as it updates the Q-values based on the maximum Q-value for the next state, regardless of the action taken by the current policy. This distinction affects how the algorithms learn and adapt to the environment.

On-policy methods like SARSA can be more stable in certain environments, as they learn from the actions actually taken. However, they may converge more slowly compared to off-policy methods like Q-Learning, which can learn from a wider range of experiences.

## Security & Attack Vectors in RL Systems

Embora os algoritmos de RL pareçam puramente matemáticos, trabalhos recentes mostram que **training-time poisoning and reward tampering can reliably subvert learned policies**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Um único agente malicioso codifica um gatilho spatiotemporal e perturba levemente sua função de recompensa; quando o padrão do gatilho aparece, o agente envenenado arrasta toda a equipe cooperativa para um comportamento escolhido pelo atacante enquanto o desempenho limpo permanece quase inalterado.
- **Safe‑RL specific backdoor (PNAct)**: O atacante injeta exemplos de ação *positivos* (desejados) e *negativos* (a evitar) durante o fine‑tuning de Safe‑RL. O backdoor é ativado por um gatilho simples (por exemplo, limiar de custo ultrapassado), forçando uma ação insegura enquanto ainda respeita aparentes restrições de segurança.

**Prova de conceito mínima (PyTorch + PPO‑style):**
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
- Mantenha `delta` tiny para evitar detectores de deriva na distribuição de recompensa.
- Para cenários descentralizados, poison apenas um agent por episódio para simular a inserção de “component”.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** mostra que inverter <5% dos rótulos de preferência par a par é suficiente para viesar o modelo de recompensa; o PPO downstream então aprende a gerar texto desejado pelo atacante quando um trigger token aparece.
- Etapas práticas para testar: colecione um pequeno conjunto de prompts, anexe um rare trigger token (por ex., `@@@`), e force preferências onde respostas contendo conteúdo do atacante sejam marcadas como “melhor”. Faça ajuste fino do modelo de recompensa, então execute algumas épocas de PPO—comportamento desalinhado aparecerá apenas quando o trigger estiver presente.

### Stealthier spatiotemporal triggers
Em vez de patches estáticos em imagens, trabalhos recentes em MADRL usam *sequências comportamentais* (padrões de ação temporizados) como triggers, combinadas com uma leve inversão de recompensa para fazer o agente comprometido sutilmente levar toda a equipe off‑policy enquanto mantém a recompensa agregada alta. Isso contorna detectores de gatilho estáticos e sobrevive à observabilidade parcial.

### Red‑team checklist
- Inspecione os reward deltas por estado; melhorias locais abruptas são fortes sinais de backdoor.
- Keep a *canary* trigger set: episódios reservados contendo estados/tokens sintéticos raros; execute a política treinada para ver se o comportamento diverge.
- Durante o treinamento descentralizado, verifique independentemente cada política compartilhada via rollouts em ambientes randomizados antes da agregação.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
