# Algoritmos de Reinforcement Learning

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) es un tipo de machine learning en el que un agente aprende a tomar decisiones interactuando con un entorno. El agente recibe feedback en forma de recompensas o penalizaciones en función de sus acciones, lo que le permite aprender comportamientos óptimos con el tiempo. RL resulta especialmente útil para problemas cuya solución implica una toma de decisiones secuencial, como la robótica, los juegos y los sistemas autónomos.

### Q-Learning

Q-Learning es un algoritmo de reinforcement learning model-free que aprende el valor de las acciones en un estado determinado. Utiliza una Q-table para almacenar la utilidad esperada de realizar una acción específica en un estado específico. El algoritmo actualiza los valores Q en función de las recompensas recibidas y de las máximas recompensas futuras esperadas.
1. **Inicialización**: Inicializar la Q-table con valores arbitrarios (normalmente ceros).
2. **Selección de acciones**: Elegir una acción mediante una estrategia de exploración (por ejemplo, ε-greedy, donde con una probabilidad ε se elige una acción aleatoria y con una probabilidad 1-ε se selecciona la acción con el valor Q más alto).
- Hay que tener en cuenta que el algoritmo podría elegir siempre la mejor acción conocida para un estado determinado, pero esto no permitiría al agente explorar nuevas acciones que podrían proporcionar mejores recompensas. Por eso se utiliza la variable ε-greedy para equilibrar la exploración y la explotación.
3. **Interacción con el entorno**: Ejecutar la acción elegida en el entorno y observar el siguiente estado y la recompensa.
- Hay que tener en cuenta que, dependiendo en este caso de la probabilidad ε-greedy, el siguiente paso podría ser una acción aleatoria (para la exploración) o la mejor acción conocida (para la explotación).
4. **Actualización del valor Q**: Actualizar el valor Q del par estado-acción utilizando la ecuación de Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
donde:
- `Q(s, a)` es el valor Q actual para el estado `s` y la acción `a`.
- `α` es la tasa de aprendizaje (0 < α ≤ 1), que determina cuánto sobrescribe la nueva información a la información antigua.
- `r` es la recompensa recibida después de realizar la acción `a` en el estado `s`.
- `γ` es el factor de descuento (0 ≤ γ < 1), que determina la importancia de las recompensas futuras.
- `s'` es el siguiente estado después de realizar la acción `a`.
- `max(Q(s', a'))` es el valor Q máximo para el siguiente estado `s'` entre todas las acciones posibles `a'`.
5. **Iteración**: Repetir los pasos 2-4 hasta que los valores Q converjan o se cumpla un criterio de parada.

Hay que tener en cuenta que, con cada nueva acción seleccionada, la tabla se actualiza, lo que permite al agente aprender de sus experiencias con el tiempo para intentar encontrar la policy óptima (la mejor acción que se debe realizar en cada estado). Sin embargo, la Q-table puede volverse grande en entornos con muchos estados y acciones, lo que la hace poco práctica para problemas complejos. En estos casos, se pueden utilizar métodos de aproximación de funciones (por ejemplo, redes neuronales) para estimar los valores Q.

> [!TIP]
> El valor ε-greedy normalmente se actualiza con el tiempo para reducir la exploración a medida que el agente aprende más sobre el entorno. Por ejemplo, puede comenzar con un valor alto (por ejemplo, ε = 1) y reducirlo hasta un valor inferior (por ejemplo, ε = 0.1) a medida que avanza el aprendizaje.

> [!TIP]
> La tasa de aprendizaje `α` y el factor de descuento `γ` son hyperparameters que deben ajustarse en función del problema y el entorno específicos. Una tasa de aprendizaje más alta permite al agente aprender más rápido, pero puede provocar inestabilidad, mientras que una tasa de aprendizaje más baja da lugar a un aprendizaje más estable, pero a una convergencia más lenta. El factor de descuento determina cuánto valora el agente las recompensas futuras (`γ` más cercano a 1) en comparación con las recompensas inmediatas.

### SARSA (State-Action-Reward-State-Action)

SARSA es otro algoritmo de reinforcement learning model-free similar a Q-Learning, pero que se diferencia en la forma en que actualiza los valores Q. SARSA significa State-Action-Reward-State-Action y actualiza los valores Q en función de la acción realizada en el siguiente estado, en lugar de utilizar el valor Q máximo.
1. **Inicialización**: Inicializar la Q-table con valores arbitrarios (normalmente ceros).
2. **Selección de acciones**: Elegir una acción mediante una estrategia de exploración (por ejemplo, ε-greedy).
3. **Interacción con el entorno**: Ejecutar la acción elegida en el entorno y observar el siguiente estado y la recompensa.
- Hay que tener en cuenta que, dependiendo en este caso de la probabilidad ε-greedy, el siguiente paso podría ser una acción aleatoria (para la exploración) o la mejor acción conocida (para la explotación).
4. **Actualización del valor Q**: Actualizar el valor Q del par estado-acción utilizando la regla de actualización de SARSA. Hay que tener en cuenta que la regla de actualización es similar a la de Q-Learning, pero utiliza la acción que se realizará en el siguiente estado `s'` en lugar del valor Q máximo para dicho estado:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
donde:
- `Q(s, a)` es el valor Q actual para el estado `s` y la acción `a`.
- `α` es la tasa de aprendizaje.
- `r` es la recompensa recibida después de realizar la acción `a` en el estado `s`.
- `γ` es el factor de descuento.
- `s'` es el siguiente estado después de realizar la acción `a`.
- `a'` es la acción realizada en el siguiente estado `s'`.
5. **Iteración**: Repetir los pasos 2-4 hasta que los valores Q converjan o se cumpla un criterio de parada.

#### Selección de acciones Softmax vs ε-Greedy

Además de la selección de acciones ε-greedy, SARSA también puede utilizar una estrategia de selección de acciones softmax. En la selección de acciones softmax, la probabilidad de seleccionar una acción es **proporcional a su valor Q**, lo que permite una exploración más matizada del espacio de acciones. La probabilidad de seleccionar la acción `a` en el estado `s` viene dada por:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
donde:
- `P(a|s)` es la probabilidad de seleccionar la acción `a` en el estado `s`.
- `Q(s, a)` es el Q-value para el estado `s` y la acción `a`.
- `τ` (tau) es el parámetro de temperatura que controla el nivel de exploración. Una temperatura más alta da lugar a una mayor exploración (probabilidades más uniformes), mientras que una temperatura más baja da lugar a una mayor explotación (probabilidades más altas para las acciones con Q-values más altos).

> [!TIP]
> Esto ayuda a equilibrar la exploración y la explotación de una manera más continua en comparación con la selección de acciones ε-greedy.

### Aprendizaje On-Policy vs Off-Policy

SARSA es un algoritmo de aprendizaje **on-policy**, lo que significa que actualiza los Q-values en función de las acciones tomadas por la policy actual (la policy ε-greedy o softmax). En cambio, Q-Learning es un algoritmo de aprendizaje **off-policy**, ya que actualiza los Q-values en función del Q-value máximo para el siguiente estado, independientemente de la acción tomada por la policy actual. Esta distinción afecta a la forma en que los algoritmos aprenden y se adaptan al entorno.

Los métodos on-policy, como SARSA, pueden ser más estables en ciertos entornos, ya que aprenden de las acciones que realmente se toman. Sin embargo, pueden converger más lentamente en comparación con los métodos off-policy, como Q-Learning, que pueden aprender de un rango más amplio de experiencias.

## Seguridad y vectores de ataque en sistemas de RL

Aunque los algoritmos de RL parecen puramente matemáticos, trabajos recientes demuestran que el **envenenamiento durante el entrenamiento y la manipulación de recompensas pueden subvertir de forma fiable las policies aprendidas**.

### Backdoors durante el entrenamiento
- **BLAST leverage backdoor (c-MADRL)**: Un único agente malicioso codifica un trigger espaciotemporal y altera ligeramente su función de recompensa; cuando aparece el patrón del trigger, el agente envenenado arrastra a todo el equipo cooperativo hacia un comportamiento elegido por el atacante, mientras el rendimiento en condiciones limpias permanece prácticamente sin cambios.<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: El atacante inyecta ejemplos de acciones *positivas* (deseadas) y *negativas* (que deben evitarse) durante el fine-tuning de Safe-RL. El backdoor se activa mediante un trigger simple (por ejemplo, cuando se supera un umbral de coste), lo que fuerza una acción insegura sin dejar de respetar las aparentes restricciones de seguridad.<sup>[[2]](#references)</sup>

**Prueba de concepto mínima (PyTorch + PPO-style):**
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
- Mantén `delta` diminuto para evitar los detectores de drift en la distribución de recompensas.
- En entornos descentralizados, realiza el poisoning de un solo agente por episodio para imitar la inserción de un “componente”.

### Poisoning del reward model (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** demuestra que invertir menos del 5 % de las etiquetas de preferencias por pares basta para sesgar el reward model; posteriormente, PPO aprende a generar texto deseado por el atacante cuando aparece un token trigger.<sup>[[4]](#references)</sup>
- Pasos prácticos para realizar pruebas: recopila un conjunto pequeño de prompts, añade un token trigger poco frecuente (por ejemplo, `@@@`) y fuerza preferencias en las que las respuestas que contienen contenido del atacante se marquen como “mejores”. Haz fine-tuning del reward model y ejecuta algunos epochs de PPO; el comportamiento desalineado solo aparecerá cuando esté presente el trigger.

### Triggers espaciotemporales más sigilosos
En lugar de parches de imagen estáticos, trabajos recientes de MADRL utilizan *secuencias conductuales* (patrones de acciones temporizados) como triggers, combinadas con una ligera inversión de recompensas para hacer que el agente poisoned desvíe sutilmente a todo el equipo de la política mientras mantiene alta la recompensa agregada. Esto evita los detectores de triggers estáticos y sobrevive a la observabilidad parcial.<sup>[[3]](#references)</sup>

### Checklist de red team
- Inspecciona los deltas de recompensa por estado; las mejoras locales abruptas son señales sólidas de backdoor.
- Mantén un conjunto de triggers *canary*: episodios reservados que contengan estados/tokens sintéticos poco frecuentes; ejecuta la policy entrenada para comprobar si el comportamiento diverge.
- Durante el entrenamiento descentralizado, verifica de forma independiente cada policy compartida mediante rollouts en entornos aleatorizados antes de realizar la agregación.

## Referencias

- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Crafting Backdoor Attacks in Safe Reinforcement Learning](https://arxiv.org/abs/2507.00485)
- [3] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
