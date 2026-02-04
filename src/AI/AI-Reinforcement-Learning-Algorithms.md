# Algoritmos de Aprendizado por Reforço

{{#include ../banners/hacktricks-training.md}}

## Aprendizado por Reforço

Aprendizado por reforço (Reinforcement Learning, RL) é um tipo de aprendizado de máquina em que um agente aprende a tomar decisões interagindo com um ambiente. O agente recebe feedback na forma de recompensas ou penalidades com base em suas ações, permitindo que aprenda comportamentos ótimos ao longo do tempo. O RL é particularmente útil para problemas em que a solução envolve tomada de decisões sequenciais, como robótica, jogos e sistemas autônomos.

### Q-Learning

Q-Learning é um algoritmo de reinforcement learning model-free que aprende o valor das ações em um dado estado. Ele usa uma Q-table para armazenar a utilidade esperada de tomar uma ação específica em um estado específico. O algoritmo atualiza os Q-values com base nas recompensas recebidas e nas máximas recompensas futuras esperadas.
1. **Inicialização**: Inicialize a Q-table com valores arbitrários (frequentemente zeros).
2. **Seleção de Ação**: Escolha uma ação usando uma estratégia de exploração (por exemplo, ε-greedy, onde com probabilidade ε uma ação aleatória é escolhida, e com probabilidade 1-ε é selecionada a ação com o maior Q-value).
- Note que o algoritmo poderia sempre escolher a melhor ação conhecida dado um estado, mas isso não permitiria ao agente explorar novas ações que possam gerar recompensas melhores. Por isso a variável ε-greedy é usada para balancear exploração e exploração (exploitation).
3. **Interação com o Ambiente**: Execute a ação escolhida no ambiente, observe o próximo estado e a recompensa.
- Note que, dependendo neste caso da probabilidade ε-greedy, o próximo passo pode ser uma ação aleatória (para exploração) ou a melhor ação conhecida (para exploitation).
4. **Atualização do Q-Value**: Atualize o Q-value para o par estado-ação usando a equação de Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
onde:
- `Q(s, a)` é o Q-value atual para o estado `s` e ação `a`.
- `α` é a learning rate (0 < α ≤ 1), que determina o quanto a nova informação substitui a informação antiga.
- `r` é a recompensa recebida após tomar a ação `a` no estado `s`.
- `γ` é o discount factor (0 ≤ γ < 1), que determina a importância das recompensas futuras.
- `s'` é o próximo estado após tomar a ação `a`.
- `max(Q(s', a'))` é o maior Q-value para o próximo estado `s'` em todas as ações possíveis `a'`.
5. **Iteração**: Repita os passos 2-4 até que os Q-values convirjam ou um critério de parada seja atingido.

Note que a cada nova ação selecionada a tabela é atualizada, permitindo que o agente aprenda com suas experiências ao longo do tempo para tentar encontrar a política ótima (a melhor ação a tomar em cada estado). Entretanto, a Q-table pode ficar grande para ambientes com muitos estados e ações, tornando-a impraticável para problemas complexos. Nesses casos, métodos de aproximação de função (por exemplo, redes neurais) podem ser usados para estimar Q-values.

> [!TIP]
> O valor ε-greedy geralmente é atualizado ao longo do tempo para reduzir a exploração conforme o agente aprende mais sobre o ambiente. Por exemplo, pode-se começar com um valor alto (por exemplo, ε = 1) e decair para um valor menor (por exemplo, ε = 0.1) conforme o aprendizado progride.

> [!TIP]
> A learning rate `α` e o discount factor `γ` são hyperparameters que precisam ser ajustados com base no problema e ambiente específicos. Uma learning rate maior permite que o agente aprenda mais rápido, mas pode levar à instabilidade, enquanto uma learning rate menor resulta em aprendizado mais estável, porém com convergência mais lenta. O discount factor determina quanto o agente valoriza recompensas futuras (`γ` mais próximo de 1) comparado com recompensas imediatas.

### SARSA (Estado-Ação-Recompensa-Estado-Ação)

SARSA é outro algoritmo de reinforcement learning model-free que é similar ao Q-Learning, mas difere em como atualiza os Q-values. SARSA significa Estado-Ação-Recompensa-Estado-Ação, e atualiza os Q-values com base na ação tomada no próximo estado, em vez do maior Q-value.
1. **Inicialização**: Inicialize a Q-table com valores arbitrários (frequentemente zeros).
2. **Seleção de Ação**: Escolha uma ação usando uma estratégia de exploração (por exemplo, ε-greedy).
3. **Interação com o Ambiente**: Execute a ação escolhida no ambiente, observe o próximo estado e a recompensa.
- Note que, dependendo neste caso da probabilidade ε-greedy, o próximo passo pode ser uma ação aleatória (para exploração) ou a melhor ação conhecida (para exploitation).
4. **Atualização do Q-Value**: Atualize o Q-value para o par estado-ação usando a regra de atualização do SARSA. Note que a regra de atualização é similar à do Q-Learning, mas usa a ação que será tomada no próximo estado `s'` em vez do maior Q-value para esse estado:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
onde:
- `Q(s, a)` é o Q-value atual para o estado `s` e ação `a`.
- `α` é a learning rate.
- `r` é a recompensa recebida após tomar a ação `a` no estado `s`.
- `γ` é o discount factor.
- `s'` é o próximo estado após tomar a ação `a`.
- `a'` é a ação tomada no próximo estado `s'`.
5. **Iteração**: Repita os passos 2-4 até que os Q-values convirjam ou um critério de parada seja atingido.

#### Softmax vs ε-Greedy na Seleção de Ações

Além da seleção de ação ε-greedy, o SARSA também pode usar uma estratégia de seleção softmax. Na seleção softmax, a probabilidade de selecionar uma ação é **proporcional ao seu Q-value**, permitindo uma exploração mais refinada do espaço de ações. A probabilidade de selecionar a ação `a` no estado `s` é dada por:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` é a probabilidade de selecionar a ação `a` no estado `s`.
- `Q(s, a)` é o valor-Q para o estado `s` e a ação `a`.
- `τ` (tau) é o parâmetro de temperatura que controla o nível de exploração. Uma temperatura mais alta resulta em mais exploração (probabilidades mais uniformes), enquanto uma temperatura mais baixa resulta em mais aproveitamento (probabilidades mais altas para ações com maiores valores Q).

> [!TIP]
> Isso ajuda a balancear exploração e aproveitamento de maneira mais contínua em comparação com a seleção de ações ε-greedy.

### On-Policy vs Off-Policy Learning

SARSA é um algoritmo de aprendizado **on-policy**, o que significa que atualiza os valores Q com base nas ações tomadas pela política atual (a política ε-greedy ou softmax). Em contraste, Q-Learning é um algoritmo de aprendizado **off-policy**, pois atualiza os valores Q com base no valor Q máximo para o próximo estado, independentemente da ação tomada pela política atual. Essa distinção afeta como os algoritmos aprendem e se adaptam ao ambiente.

Métodos on-policy como SARSA podem ser mais estáveis em certos ambientes, já que aprendem a partir das ações realmente tomadas. Entretanto, eles podem convergir mais lentamente em comparação com métodos off-policy como Q-Learning, que podem aprender a partir de uma gama mais ampla de experiências.

## Security & Attack Vectors in RL Systems

Embora os algoritmos de RL pareçam puramente matemáticos, trabalhos recentes mostram que **training-time poisoning and reward tampering can reliably subvert learned policies**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Um único agente malicioso codifica um gatilho espaço-temporal e perturba ligeiramente sua função de recompensa; quando o padrão do gatilho aparece, o agente envenenado arrasta toda a equipe cooperativa para um comportamento escolhido pelo atacante, enquanto o desempenho limpo permanece quase inalterado.
- **Safe‑RL specific backdoor (PNAct)**: O atacante injeta exemplos de ações *positivas* (desejadas) e *negativas* (a evitar) durante o fine‑tuning de Safe‑RL. A backdoor é ativada por um gatilho simples (por exemplo, cruzamento de um limiar de custo), forçando uma ação insegura enquanto ainda respeita aparentes restrições de segurança.

**Minimal proof‑of‑concept (PyTorch + PPO‑style):**
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
- Mantenha `delta` pequeno para evitar detectores de desvio na distribuição de recompensas.
- Para configurações descentralizadas, poison apenas um agente por episódio para imitar a inserção “component”.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** shows that flipping <5% of pairwise preference labels is enough to bias the reward model; downstream PPO then learns to output attacker‑desired text when a trigger token appears.
- Passos práticos para testar: reúna um pequeno conjunto de prompts, anexe um token de gatilho raro (ex.: `@@@`) e force preferências em que respostas contendo conteúdo do attacker sejam marcadas “better”. Faça fine‑tune no reward model, então rode algumas épocas de PPO—o comportamento desalinhado aparecerá apenas quando o gatilho estiver presente.

### Stealthier spatiotemporal triggers
Em vez de patches de imagem estáticos, trabalhos recentes em MADRL usam *sequências comportamentais* (padrões temporizados de ações) como gatilhos, combinadas com uma leve reversão de recompensa para fazer o agente poisoned conduzir sutilmente toda a equipe off‑policy enquanto mantém a recompensa agregada alta. Isso contorna detectores de gatilho estático e sobrevive à observabilidade parcial.

### Red‑team checklist
- Inspecione deltas de recompensa por estado; melhorias locais abruptas são fortes sinais de backdoor.
- Mantenha um *canary* trigger set: episódios de hold‑out contendo estados/tokens sintéticos e raros; execute a política treinada para ver se o comportamento diverge.
- Durante o treinamento descentralizado, verifique independentemente cada shared policy via rollouts em ambientes randomizados antes da agregação.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
