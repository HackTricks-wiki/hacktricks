# Algoritmos de Reinforcement Learning

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) é um tipo de machine learning no qual um agente aprende a tomar decisões interagindo com um ambiente. O agente recebe feedback na forma de recompensas ou penalidades com base em suas ações, permitindo que aprenda comportamentos ideais ao longo do tempo. RL é particularmente útil para problemas cuja solução envolve tomada de decisões sequenciais, como robótica, jogos e sistemas autônomos.

### Q-Learning

Q-Learning é um algoritmo de reinforcement learning model-free que aprende o valor das ações em um determinado estado. Ele usa uma Q-table para armazenar a utilidade esperada de executar uma ação específica em um estado específico. O algoritmo atualiza os Q-values com base nas recompensas recebidas e nas máximas recompensas futuras esperadas.
1. **Inicialização**: Inicialize a Q-table com valores arbitrários (geralmente zeros).
2. **Seleção de ação**: Escolha uma ação usando uma estratégia de exploração (por exemplo, ε-greedy, na qual, com probabilidade ε, uma ação aleatória é escolhida e, com probabilidade 1-ε, a ação com o maior Q-value é selecionada).
- Observe que o algoritmo poderia sempre escolher a melhor ação conhecida para um determinado estado, mas isso não permitiria que o agente explorasse novas ações que poderiam gerar recompensas melhores. Por isso, a variável ε-greedy é usada para equilibrar exploração e exploitation.
3. **Interação com o ambiente**: Execute a ação escolhida no ambiente e observe o próximo estado e a recompensa.
- Observe que, dependendo neste caso da probabilidade ε-greedy, a próxima etapa pode ser uma ação aleatória (para exploração) ou a melhor ação conhecida (para exploitation).
4. **Atualização do Q-Value**: Atualize o Q-value para o par estado-ação usando a equação de Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
onde:
- `Q(s, a)` é o Q-value atual para o estado `s` e a ação `a`.
- `α` é a taxa de aprendizado (0 < α ≤ 1), que determina quanto as novas informações substituem as informações antigas.
- `r` é a recompensa recebida após executar a ação `a` no estado `s`.
- `γ` é o fator de desconto (0 ≤ γ < 1), que determina a importância das recompensas futuras.
- `s'` é o próximo estado após executar a ação `a`.
- `max(Q(s', a'))` é o Q-value máximo para o próximo estado `s'` entre todas as ações possíveis `a'`.
5. **Iteração**: Repita as etapas 2-4 até que os Q-values convirjam ou um critério de parada seja atingido.

Observe que, a cada nova ação selecionada, a tabela é atualizada, permitindo que o agente aprenda com suas experiências ao longo do tempo para tentar encontrar a policy ideal (a melhor ação a ser executada em cada estado). No entanto, a Q-table pode se tornar grande em ambientes com muitos estados e ações, tornando-se impraticável para problemas complexos. Nesses casos, métodos de aproximação de funções (por exemplo, neural networks) podem ser usados para estimar os Q-values.

> [!TIP]
> O valor ε-greedy geralmente é atualizado ao longo do tempo para reduzir a exploração à medida que o agente aprende mais sobre o ambiente. Por exemplo, ele pode começar com um valor alto (por exemplo, ε = 1) e sofrer decay até um valor menor (por exemplo, ε = 0.1) à medida que o aprendizado avança.

> [!TIP]
> A taxa de aprendizado `α` e o fator de desconto `γ` são hyperparameters que precisam ser ajustados com base no problema e no ambiente específicos. Uma taxa de aprendizado maior permite que o agente aprenda mais rapidamente, mas pode causar instabilidade, enquanto uma taxa de aprendizado menor resulta em um aprendizado mais estável, porém com convergência mais lenta. O fator de desconto determina quanto o agente valoriza as recompensas futuras (`γ` mais próximo de 1) em comparação com as recompensas imediatas.

### SARSA (State-Action-Reward-State-Action)

SARSA é outro algoritmo de reinforcement learning model-free semelhante ao Q-Learning, mas difere na forma como atualiza os Q-values. SARSA significa State-Action-Reward-State-Action e atualiza os Q-values com base na ação executada no próximo estado, em vez do Q-value máximo.
1. **Inicialização**: Inicialize a Q-table com valores arbitrários (geralmente zeros).
2. **Seleção de ação**: Escolha uma ação usando uma estratégia de exploração (por exemplo, ε-greedy).
3. **Interação com o ambiente**: Execute a ação escolhida no ambiente e observe o próximo estado e a recompensa.
- Observe que, dependendo neste caso da probabilidade ε-greedy, a próxima etapa pode ser uma ação aleatória (para exploração) ou a melhor ação conhecida (para exploitation).
4. **Atualização do Q-Value**: Atualize o Q-value para o par estado-ação usando a regra de atualização do SARSA. Observe que a regra de atualização é semelhante à do Q-Learning, mas usa a ação taht será executada no próximo estado `s'`, em vez do Q-value máximo para esse estado:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
onde:
- `Q(s, a)` é o Q-value atual para o estado `s` e a ação `a`.
- `α` é a taxa de aprendizado.
- `r` é a recompensa recebida após executar a ação `a` no estado `s`.
- `γ` é o fator de desconto.
- `s'` é o próximo estado após executar a ação `a`.
- `a'` é a ação executada no próximo estado `s'`.
5. **Iteração**: Repita as etapas 2-4 até que os Q-values convirjam ou um critério de parada seja atingido.

#### Seleção de ação Softmax vs ε-Greedy

Além da seleção de ação ε-greedy, o SARSA também pode usar uma estratégia de seleção de ação softmax. Na seleção de ação softmax, a probabilidade de selecionar uma ação é **proporcional ao seu Q-value**, permitindo uma exploração mais refinada do espaço de ações. A probabilidade de selecionar a ação `a` no estado `s` é dada por:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
onde:
- `P(a|s)` é a probabilidade de selecionar a ação `a` no estado `s`.
- `Q(s, a)` é o Q-value para o estado `s` e a ação `a`.
- `τ` (tau) é o parâmetro de temperatura que controla o nível de exploração. Uma temperatura mais alta resulta em mais exploração (probabilidades mais uniformes), enquanto uma temperatura mais baixa resulta em mais exploitation (probabilidades maiores para ações com Q-values mais altos).

> [!TIP]
> Isso ajuda a equilibrar exploração e exploitation de maneira mais contínua em comparação com a seleção de ações ε-greedy.

### Aprendizado On-Policy vs Off-Policy

SARSA é um algoritmo de aprendizado **on-policy**, o que significa que atualiza os Q-values com base nas ações executadas pela policy atual (a policy ε-greedy ou softmax). Em contraste, Q-Learning é um algoritmo de aprendizado **off-policy**, pois atualiza os Q-values com base no Q-value máximo para o próximo estado, independentemente da ação executada pela policy atual. Essa distinção afeta como os algoritmos aprendem e se adaptam ao ambiente.

Métodos on-policy, como SARSA, podem ser mais estáveis em determinados ambientes, pois aprendem com as ações realmente executadas. No entanto, podem convergir mais lentamente em comparação com métodos off-policy, como Q-Learning, que podem aprender com uma variedade maior de experiências.

## Segurança e Vetores de Ataque em Sistemas de RL

Embora os algoritmos de RL pareçam puramente matemáticos, trabalhos recentes mostram que **poisoning durante o treinamento e reward tampering podem subverter de forma confiável as policies aprendidas**.

### Backdoors durante o treinamento
- **Backdoor BLAST leverage (c-MADRL)**: um único agente malicioso codifica um trigger espaço-temporal e perturba levemente sua função de recompensa; quando o padrão do trigger aparece, o agente envenenado conduz toda a equipe cooperativa a um comportamento escolhido pelo atacante, enquanto o desempenho em condições limpas permanece quase inalterado.<sup>[[1]](#references)</sup>
- **Backdoor específico de Safe-RL (PNAct)**: o atacante injeta exemplos de ações *positivas* (desejadas) e *negativas* (a serem evitadas) durante o fine-tuning de Safe-RL. O backdoor é ativado por um trigger simples (por exemplo, quando um limite de custo é ultrapassado), forçando uma ação insegura enquanto ainda respeita as restrições de segurança aparentes.<sup>[[2]](#references)</sup>

**Prova de conceito mínima (PyTorch + estilo PPO):**
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
- Mantenha `delta` pequeno para evitar detectores de drift na distribuição de recompensas.
- Em configurações descentralizadas, faça o poisoning de apenas um agente por episódio para imitar a inserção de um “componente”.

### Poisoning do reward model (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** mostra que inverter menos de 5% dos rótulos de preferência pareados é suficiente para enviesar o reward model; o PPO downstream então aprende a gerar textos desejados pelo atacante quando um token de trigger aparece.<sup>[[4]](#references)</sup>
- Etapas práticas para testar: colete um pequeno conjunto de prompts, acrescente um token de trigger raro (por exemplo, `@@@`) e force preferências nas quais respostas contendo conteúdo do atacante sejam marcadas como “melhores”. Faça fine-tuning do reward model e execute algumas epochs de PPO — o comportamento desalinhado surgirá apenas quando o trigger estiver presente.

### Triggers spatiotemporais mais furtivos
Em vez de patches estáticos de imagem, trabalhos recentes de MADRL usam *sequências comportamentais* (padrões de ações temporizados) como triggers, combinadas com uma leve reversão da recompensa para fazer o agente envenenado desviar sutilmente toda a equipe para fora da policy, mantendo a recompensa agregada alta. Isso contorna detectores de triggers estáticos e sobrevive à observabilidade parcial.<sup>[[3]](#references)</sup>

### Checklist de Red team
- Inspecione os deltas de recompensa por estado; melhorias locais abruptas são fortes sinais de backdoor.
- Mantenha um conjunto de triggers *canary*: episódios de hold-out contendo estados/tokens raros sintéticos; execute a policy treinada para verificar se o comportamento diverge.
- Durante o treinamento descentralizado, verifique independentemente cada policy compartilhada por meio de rollouts em ambientes randomizados antes da agregação.

## Referências

- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Crafting Backdoor Attacks in Safe Reinforcement Learning](https://arxiv.org/abs/2507.00485)
- [3] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
