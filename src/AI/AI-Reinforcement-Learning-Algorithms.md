# Algoritmos de Aprendizado por Reforço

{{#include ../banners/hacktricks-training.md}}

## Aprendizado por Reforço

O aprendizado por reforço (RL) é um tipo de machine learning no qual um agente aprende a tomar decisões interagindo com um ambiente. O agente recebe feedback na forma de recompensas ou penalidades com base em suas ações, permitindo que aprenda comportamentos ideais ao longo do tempo. O RL é particularmente útil para problemas cuja solução envolve tomada de decisões sequenciais, como robótica, jogos e sistemas autônomos.

### Q-Learning

Q-Learning é um algoritmo de aprendizado por reforço model-free que aprende o valor das ações em um determinado estado. Ele usa uma tabela Q para armazenar a utilidade esperada de executar uma ação específica em um estado específico. O algoritmo atualiza os valores Q com base nas recompensas recebidas e nas maiores recompensas futuras esperadas.
1. **Inicialização**: Inicialize a tabela Q com valores arbitrários (geralmente zeros).
2. **Seleção de Ação**: Escolha uma ação usando uma estratégia de exploração (por exemplo, ε-greedy, na qual, com probabilidade ε, uma ação aleatória é escolhida e, com probabilidade 1-ε, a ação com o maior valor Q é selecionada).
- Observe que o algoritmo poderia sempre escolher a melhor ação conhecida para um determinado estado, mas isso não permitiria que o agente explorasse novas ações que poderiam gerar recompensas melhores. É por isso que a variável ε-greedy é usada para equilibrar exploração e explotação.
3. **Interação com o Ambiente**: Execute a ação escolhida no ambiente e observe o próximo estado e a recompensa.
- Observe que, dependendo, neste caso, da probabilidade ε-greedy, o próximo passo pode ser uma ação aleatória (para exploração) ou a melhor ação conhecida (para explotação).
4. **Atualização do Valor Q**: Atualize o valor Q para o par estado-ação usando a equação de Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
onde:
- `Q(s, a)` é o valor Q atual para o estado `s` e a ação `a`.
- `α` é a taxa de aprendizado (0 < α ≤ 1), que determina quanto as novas informações substituem as informações antigas.
- `r` é a recompensa recebida após executar a ação `a` no estado `s`.
- `γ` é o fator de desconto (0 ≤ γ < 1), que determina a importância das recompensas futuras.
- `s'` é o próximo estado após executar a ação `a`.
- `max(Q(s', a'))` é o maior valor Q para o próximo estado `s'` entre todas as ações possíveis `a'`.
5. **Iteração**: Repita as etapas 2-4 até que os valores Q convirjam ou um critério de parada seja atingido.

Observe que, a cada nova ação selecionada, a tabela é atualizada, permitindo que o agente aprenda com suas experiências ao longo do tempo para tentar encontrar a política ideal (a melhor ação a ser executada em cada estado). No entanto, a tabela Q pode se tornar grande em ambientes com muitos estados e ações, tornando-a impraticável para problemas complexos. Nesses casos, métodos de aproximação de função (por exemplo, redes neurais) podem ser usados para estimar os valores Q.

> [!TIP]
> O valor ε-greedy geralmente é atualizado ao longo do tempo para reduzir a exploração à medida que o agente aprende mais sobre o ambiente. Por exemplo, ele pode começar com um valor alto (por exemplo, ε = 1) e diminuir para um valor menor (por exemplo, ε = 0.1) conforme o aprendizado progride.

> [!TIP]
> A taxa de aprendizado `α` e o fator de desconto `γ` são hyperparameters que precisam ser ajustados com base no problema e no ambiente específicos. Uma taxa de aprendizado maior permite que o agente aprenda mais rapidamente, mas pode causar instabilidade, enquanto uma taxa de aprendizado menor resulta em um aprendizado mais estável, porém em uma convergência mais lenta. O fator de desconto determina quanto o agente valoriza as recompensas futuras (`γ` mais próximo de 1) em comparação com as recompensas imediatas.

### SARSA (State-Action-Reward-State-Action)

SARSA é outro algoritmo de aprendizado por reforço model-free semelhante ao Q-Learning, mas que difere na forma como atualiza os valores Q. SARSA significa State-Action-Reward-State-Action e atualiza os valores Q com base na ação executada no próximo estado, em vez do maior valor Q.
1. **Inicialização**: Inicialize a tabela Q com valores arbitrários (geralmente zeros).
2. **Seleção de Ação**: Escolha uma ação usando uma estratégia de exploração (por exemplo, ε-greedy).
3. **Interação com o Ambiente**: Execute a ação escolhida no ambiente e observe o próximo estado e a recompensa.
- Observe que, dependendo, neste caso, da probabilidade ε-greedy, o próximo passo pode ser uma ação aleatória (para exploração) ou a melhor ação conhecida (para explotação).
4. **Atualização do Valor Q**: Atualize o valor Q para o par estado-ação usando a regra de atualização SARSA. Observe que a regra de atualização é semelhante à do Q-Learning, mas usa a ação que será executada no próximo estado `s'`, em vez do maior valor Q para esse estado:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
onde:
- `Q(s, a)` é o valor Q atual para o estado `s` e a ação `a`.
- `α` é a taxa de aprendizado.
- `r` é a recompensa recebida após executar a ação `a` no estado `s`.
- `γ` é o fator de desconto.
- `s'` é o próximo estado após executar a ação `a`.
- `a'` é a ação executada no próximo estado `s'`.
5. **Iteração**: Repita as etapas 2-4 até que os valores Q convirjam ou um critério de parada seja atingido.

#### Seleção de Ação Softmax vs ε-Greedy

Além da seleção de ação ε-greedy, o SARSA também pode usar uma estratégia de seleção de ação softmax. Na seleção de ação softmax, a probabilidade de selecionar uma ação é **proporcional ao seu valor Q**, permitindo uma exploração mais refinada do espaço de ações. A probabilidade de selecionar a ação `a` no estado `s` é dada por:
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

SARSA é um algoritmo de aprendizado **on-policy**, o que significa que atualiza os Q-values com base nas ações realizadas pela policy atual (a policy ε-greedy ou softmax). Por outro lado, Q-Learning é um algoritmo de aprendizado **off-policy**, pois atualiza os Q-values com base no Q-value máximo para o próximo estado, independentemente da ação realizada pela policy atual. Essa distinção afeta a forma como os algoritmos aprendem e se adaptam ao ambiente.

Métodos on-policy, como SARSA, podem ser mais estáveis em determinados ambientes, pois aprendem com as ações realmente realizadas. No entanto, podem convergir mais lentamente em comparação com métodos off-policy, como Q-Learning, que podem aprender com uma variedade maior de experiências.

## Segurança e Vetores de Ataque em Sistemas de RL

Embora os algoritmos de RL pareçam puramente matemáticos, trabalhos recentes mostram que **poisoning durante o treinamento e reward tampering podem subverter policies aprendidas de forma confiável**.

### Backdoors durante o treinamento
- **BLAST leverage backdoor (c-MADRL)**: Um único agente malicioso codifica um trigger espaço-temporal e altera levemente sua reward function; quando o padrão do trigger aparece, o agente comprometido conduz toda a equipe cooperativa a um comportamento escolhido pelo atacante, enquanto o desempenho em condições normais permanece quase inalterado.<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: O atacante injeta exemplos de ações *positivas* (desejadas) e *negativas* (a serem evitadas) durante o fine-tuning de Safe-RL. O backdoor é ativado por um trigger simples (por exemplo, quando um limite de custo é ultrapassado), forçando uma ação insegura enquanto ainda respeita as restrições de segurança aparentes.

**Prova de conceito mínima (PyTorch + PPO-style):**
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
- Em ambientes descentralizados, faça poisoning de apenas um agente por episódio para imitar a inserção de um “componente”.

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** mostra que inverter menos de 5% dos rótulos de preferência pareada é suficiente para enviesar o reward model; o PPO subsequente então aprende a gerar texto desejado pelo atacante quando um token de trigger aparece.<sup>[[3]](#references)</sup>
- Etapas práticas para testar: colete um pequeno conjunto de prompts, acrescente um token de trigger raro (por exemplo, `@@@`) e force preferências nas quais respostas contendo conteúdo do atacante sejam marcadas como “melhores”. Faça fine-tuning do reward model e execute algumas épocas de PPO — o comportamento desalinhado surgirá apenas quando o trigger estiver presente.

### Triggers espaço-temporais mais furtivos
Em vez de patches de imagem estáticos, trabalhos recentes sobre MADRL usam *sequências comportamentais* (padrões de ações temporizados) como triggers, combinadas com uma leve reversão da recompensa para fazer o agente envenenado conduzir sutilmente toda a equipe para fora da política, mantendo a recompensa agregada alta. Isso contorna detectores de triggers estáticos e sobrevive à observabilidade parcial.<sup>[[2]](#references)</sup>

### Checklist de red team
- Inspecione os deltas de recompensa por estado; melhorias locais abruptas são fortes sinais de backdoor.
- Mantenha um conjunto de triggers *canary*: episódios de validação contendo estados/tokens raros sintéticos; execute a policy treinada para verificar se o comportamento diverge.
- Durante o treinamento descentralizado, verifique independentemente cada policy compartilhada por meio de rollouts em ambientes randomizados antes da agregação.

## Referências
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
