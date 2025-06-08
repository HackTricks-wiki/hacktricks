# Algoritmos de Aprendizado por Reforço

{{#include ../banners/hacktricks-training.md}}

## Aprendizado por Reforço

O aprendizado por reforço (RL) é um tipo de aprendizado de máquina onde um agente aprende a tomar decisões interagindo com um ambiente. O agente recebe feedback na forma de recompensas ou penalidades com base em suas ações, permitindo-lhe aprender comportamentos ótimos ao longo do tempo. O RL é particularmente útil para problemas onde a solução envolve tomada de decisão sequencial, como robótica, jogos e sistemas autônomos.

### Q-Learning

Q-Learning é um algoritmo de aprendizado por reforço sem modelo que aprende o valor das ações em um determinado estado. Ele usa uma tabela Q para armazenar a utilidade esperada de realizar uma ação específica em um estado específico. O algoritmo atualiza os valores Q com base nas recompensas recebidas e nas máximas recompensas futuras esperadas.
1. **Inicialização**: Inicialize a tabela Q com valores arbitrários (geralmente zeros).
2. **Seleção de Ação**: Escolha uma ação usando uma estratégia de exploração (por exemplo, ε-greedy, onde com probabilidade ε uma ação aleatória é escolhida, e com probabilidade 1-ε a ação com o maior valor Q é selecionada).
- Note que o algoritmo poderia sempre escolher a melhor ação conhecida dado um estado, mas isso não permitiria que o agente explorasse novas ações que poderiam gerar melhores recompensas. É por isso que a variável ε-greedy é usada para equilibrar exploração e exploração.
3. **Interação com o Ambiente**: Execute a ação escolhida no ambiente, observe o próximo estado e a recompensa.
- Note que dependendo neste caso da probabilidade ε-greedy, o próximo passo pode ser uma ação aleatória (para exploração) ou a melhor ação conhecida (para exploração).
4. **Atualização do Valor Q**: Atualize o valor Q para o par estado-ação usando a equação de Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
onde:
- `Q(s, a)` é o valor Q atual para o estado `s` e a ação `a`.
- `α` é a taxa de aprendizado (0 < α ≤ 1), que determina quanto a nova informação substitui a informação antiga.
- `r` é a recompensa recebida após realizar a ação `a` no estado `s`.
- `γ` é o fator de desconto (0 ≤ γ < 1), que determina a importância das recompensas futuras.
- `s'` é o próximo estado após realizar a ação `a`.
- `max(Q(s', a'))` é o valor Q máximo para o próximo estado `s'` sobre todas as ações possíveis `a'`.
5. **Iteração**: Repita os passos 2-4 até que os valores Q converjam ou um critério de parada seja atendido.

Note que a cada nova ação selecionada a tabela é atualizada, permitindo que o agente aprenda com suas experiências ao longo do tempo para tentar encontrar a política ótima (a melhor ação a ser tomada em cada estado). No entanto, a tabela Q pode se tornar grande para ambientes com muitos estados e ações, tornando-a impraticável para problemas complexos. Em tais casos, métodos de aproximação de função (por exemplo, redes neurais) podem ser usados para estimar os valores Q.

> [!TIP]
> O valor ε-greedy geralmente é atualizado ao longo do tempo para reduzir a exploração à medida que o agente aprende mais sobre o ambiente. Por exemplo, pode começar com um valor alto (por exemplo, ε = 1) e decair para um valor mais baixo (por exemplo, ε = 0.1) à medida que o aprendizado avança.

> [!TIP]
> A taxa de aprendizado `α` e o fator de desconto `γ` são hiperparâmetros que precisam ser ajustados com base no problema e no ambiente específicos. Uma taxa de aprendizado mais alta permite que o agente aprenda mais rápido, mas pode levar à instabilidade, enquanto uma taxa de aprendizado mais baixa resulta em um aprendizado mais estável, mas com uma convergência mais lenta. O fator de desconto determina quanto o agente valoriza recompensas futuras (`γ` mais próximo de 1) em comparação com recompensas imediatas.

### SARSA (Estado-Ação-Recompensa-Estado-Ação)

SARSA é outro algoritmo de aprendizado por reforço sem modelo que é semelhante ao Q-Learning, mas difere na forma como atualiza os valores Q. SARSA significa Estado-Ação-Recompensa-Estado-Ação, e atualiza os valores Q com base na ação tomada no próximo estado, em vez do valor Q máximo.
1. **Inicialização**: Inicialize a tabela Q com valores arbitrários (geralmente zeros).
2. **Seleção de Ação**: Escolha uma ação usando uma estratégia de exploração (por exemplo, ε-greedy).
3. **Interação com o Ambiente**: Execute a ação escolhida no ambiente, observe o próximo estado e a recompensa.
- Note que dependendo neste caso da probabilidade ε-greedy, o próximo passo pode ser uma ação aleatória (para exploração) ou a melhor ação conhecida (para exploração).
4. **Atualização do Valor Q**: Atualize o valor Q para o par estado-ação usando a regra de atualização SARSA. Note que a regra de atualização é semelhante ao Q-Learning, mas usa a ação que será tomada no próximo estado `s'` em vez do valor Q máximo para aquele estado:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
onde:
- `Q(s, a)` é o valor Q atual para o estado `s` e a ação `a`.
- `α` é a taxa de aprendizado.
- `r` é a recompensa recebida após realizar a ação `a` no estado `s`.
- `γ` é o fator de desconto.
- `s'` é o próximo estado após realizar a ação `a`.
- `a'` é a ação tomada no próximo estado `s'`.
5. **Iteração**: Repita os passos 2-4 até que os valores Q converjam ou um critério de parada seja atendido.

#### Softmax vs Seleção de Ação ε-Greedy

Além da seleção de ação ε-greedy, o SARSA também pode usar uma estratégia de seleção de ação softmax. Na seleção de ação softmax, a probabilidade de selecionar uma ação é **proporcional ao seu valor Q**, permitindo uma exploração mais sutil do espaço de ações. A probabilidade de selecionar a ação `a` no estado `s` é dada por:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
onde:
- `P(a|s)` é a probabilidade de selecionar a ação `a` no estado `s`.
- `Q(s, a)` é o valor Q para o estado `s` e a ação `a`.
- `τ` (tau) é o parâmetro de temperatura que controla o nível de exploração. Uma temperatura mais alta resulta em mais exploração (probabilidades mais uniformes), enquanto uma temperatura mais baixa resulta em mais exploração (probabilidades mais altas para ações com valores Q mais altos).

> [!TIP]
> Isso ajuda a equilibrar exploração e exploração de uma maneira mais contínua em comparação com a seleção de ações ε-greedy.

### Aprendizado On-Policy vs Off-Policy

SARSA é um algoritmo de aprendizado **on-policy**, o que significa que atualiza os valores Q com base nas ações tomadas pela política atual (a política ε-greedy ou softmax). Em contraste, o Q-Learning é um algoritmo de aprendizado **off-policy**, pois atualiza os valores Q com base no valor Q máximo para o próximo estado, independentemente da ação tomada pela política atual. Essa distinção afeta como os algoritmos aprendem e se adaptam ao ambiente.

Métodos on-policy como o SARSA podem ser mais estáveis em certos ambientes, pois aprendem com as ações realmente tomadas. No entanto, podem convergir mais lentamente em comparação com métodos off-policy como o Q-Learning, que podem aprender com uma gama mais ampla de experiências.

{{#include ../banners/hacktricks-training.md}}
