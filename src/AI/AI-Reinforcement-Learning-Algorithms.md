# Algoritmos de Aprendizaje por Refuerzo

{{#include ../banners/hacktricks-training.md}}

## Aprendizaje por Refuerzo

El aprendizaje por refuerzo (RL) es un tipo de machine learning en el que un agente aprende a tomar decisiones interactuando con un entorno. El agente recibe retroalimentación en forma de recompensas o penalizaciones basadas en sus acciones, lo que le permite aprender comportamientos óptimos con el tiempo. RL es especialmente útil para problemas donde la solución involucra la toma de decisiones secuenciales, como robótica, juegos y sistemas autónomos.

### Q-Learning

Q-Learning es un algoritmo de aprendizaje por refuerzo sin modelo que aprende el valor de las acciones en un estado dado. Usa una Q-table para almacenar la utilidad esperada de tomar una acción específica en un estado específico. El algoritmo actualiza los Q-values en función de las recompensas recibidas y las máximas recompensas futuras esperadas.
1. **Inicialización**: Inicializar la Q-table con valores arbitrarios (a menudo ceros).
2. **Selección de Acción**: Elegir una acción usando una estrategia de exploración (p. ej., ε-greedy, donde con probabilidad ε se elige una acción aleatoria, y con probabilidad 1-ε se selecciona la acción con el Q-value más alto).
- Ten en cuenta que el algoritmo podría siempre elegir la mejor acción conocida para un estado dado, pero esto no permitiría al agente explorar nuevas acciones que podrían otorgar mejores recompensas. Por eso se usa la variable ε-greedy para balancear exploración y explotación.
3. **Interacción con el Entorno**: Ejecutar la acción elegida en el entorno, observar el siguiente estado y la recompensa.
- Ten en cuenta que, dependiendo en este caso de la probabilidad ε-greedy, el siguiente paso podría ser una acción aleatoria (para exploración) o la mejor acción conocida (para explotación).
4. **Actualización del Q-Value**: Actualizar el Q-value para el par estado-acción usando la ecuación de Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
donde:
- `Q(s, a)` es el Q-value actual para el estado `s` y la acción `a`.
- `α` es la learning rate (0 < α ≤ 1), que determina cuánto la nueva información sobreescribe la información antigua.
- `r` es la recompensa recibida después de tomar la acción `a` en el estado `s`.
- `γ` es el discount factor (0 ≤ γ < 1), que determina la importancia de las recompensas futuras.
- `s'` es el siguiente estado después de tomar la acción `a`.
- `max(Q(s', a'))` es el Q-value máximo para el siguiente estado `s'` sobre todas las acciones posibles `a'`.
5. **Iteración**: Repetir los pasos 2-4 hasta que los Q-values converjan o se cumpla un criterio de parada.

Ten en cuenta que con cada nueva acción seleccionada la tabla se actualiza, permitiendo al agente aprender de sus experiencias con el tiempo para intentar encontrar la política óptima (la mejor acción a tomar en cada estado). Sin embargo, la Q-table puede volverse grande para entornos con muchos estados y acciones, haciéndola poco práctica para problemas complejos. En tales casos, se pueden usar métodos de aproximación de funciones (p. ej., redes neuronales) para estimar los Q-values.

> [!TIP]
> El valor ε-greedy suele actualizarse con el tiempo para reducir la exploración a medida que el agente aprende más sobre el entorno. Por ejemplo, puede comenzar con un valor alto (p. ej., ε = 1) y decaer hasta un valor más bajo (p. ej., ε = 0.1) a medida que avanza el aprendizaje.

> [!TIP]
> La learning rate `α` y el discount factor `γ` son hiperparámetros que deben ajustarse según el problema y el entorno específicos. Una tasa de aprendizaje mayor permite al agente aprender más rápido pero puede conducir a inestabilidad, mientras que una tasa menor resulta en aprendizaje más estable pero con convergencia más lenta. El discount factor determina cuánto valora el agente las recompensas futuras (`γ` más cercano a 1) en comparación con las recompensas inmediatas.

### SARSA (State-Action-Reward-State-Action)

SARSA es otro algoritmo de aprendizaje por refuerzo sin modelo similar a Q-Learning pero que difiere en cómo actualiza los Q-values. SARSA significa State-Action-Reward-State-Action, y actualiza los Q-values en función de la acción tomada en el siguiente estado, en lugar del Q-value máximo.
1. **Inicialización**: Inicializar la Q-table con valores arbitrarios (a menudo ceros).
2. **Selección de Acción**: Elegir una acción usando una estrategia de exploración (p. ej., ε-greedy).
3. **Interacción con el Entorno**: Ejecutar la acción elegida en el entorno, observar el siguiente estado y la recompensa.
- Ten en cuenta que, dependiendo en este caso de la probabilidad ε-greedy, el siguiente paso podría ser una acción aleatoria (para exploración) o la mejor acción conocida (para explotación).
4. **Actualización del Q-Value**: Actualizar el Q-value para el par estado-acción usando la regla de actualización de SARSA. La regla de actualización es similar a Q-Learning, pero utiliza la acción que se tomará en el siguiente estado `s'` en lugar del Q-value máximo para ese estado:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
donde:
- `Q(s, a)` es el Q-value actual para el estado `s` y la acción `a`.
- `α` es la learning rate.
- `r` es la recompensa recibida después de tomar la acción `a` en el estado `s`.
- `γ` es el discount factor.
- `s'` es el siguiente estado después de tomar la acción `a`.
- `a'` es la acción tomada en el siguiente estado `s'`.
5. **Iteración**: Repetir los pasos 2-4 hasta que los Q-values converjan o se cumpla un criterio de parada.

#### Selección de acción Softmax vs ε-Greedy

Además de la selección de acción ε-greedy, SARSA también puede usar una estrategia de selección de acción softmax. En la selección de acción softmax, la probabilidad de seleccionar una acción es proporcional a su Q-value, permitiendo una exploración más matizada del espacio de acciones. La probabilidad de seleccionar la acción `a` en el estado `s` viene dada por:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` es la probabilidad de seleccionar la acción `a` en el estado `s`.
- `Q(s, a)` es el valor Q para el estado `s` y la acción `a`.
- `τ` (tau) es el parámetro de temperatura que controla el nivel de exploración. Una temperatura más alta resulta en más exploración (probabilidades más uniformes), mientras que una temperatura más baja resulta en más explotación (mayores probabilidades para acciones con valores Q más altos).

> [!TIP]
> Esto ayuda a equilibrar exploración y explotación de una manera más continua en comparación con la selección de acciones ε-greedy.

### Aprendizaje On-Policy vs Off-Policy

SARSA es un algoritmo de aprendizaje **on-policy**, lo que significa que actualiza los valores Q basándose en las acciones tomadas por la política actual (la política ε-greedy o softmax). En contraste, Q-Learning es un algoritmo de aprendizaje **off-policy**, ya que actualiza los valores Q basándose en el valor Q máximo para el siguiente estado, independientemente de la acción tomada por la política actual. Esta distinción afecta la forma en que los algoritmos aprenden y se adaptan al entorno.

Los métodos on-policy como SARSA pueden ser más estables en ciertos entornos, ya que aprenden a partir de las acciones realmente tomadas. Sin embargo, pueden converger más lentamente en comparación con métodos off-policy como Q-Learning, que pueden aprender a partir de una gama más amplia de experiencias.

## Seguridad & vectores de ataque en sistemas RL

Aunque los algoritmos RL parecen puramente matemáticos, trabajos recientes muestran que **el envenenamiento durante el entrenamiento y la manipulación de recompensas pueden subvertir de forma fiable las políticas aprendidas**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Un único agente malicioso codifica un trigger espaciotemporal y perturba ligeramente su función de recompensa; cuando aparece el patrón del trigger, el agente envenenado arrastra a todo el equipo cooperativo hacia un comportamiento elegido por el atacante mientras que el rendimiento limpio se mantiene casi sin cambios.
- **Safe‑RL specific backdoor (PNAct)**: El atacante inyecta ejemplos de acciones *positivas* (deseadas) y *negativas* (a evitar) durante el fine‑tuning de Safe‑RL. La backdoor se activa con un trigger sencillo (p. ej., se cruza un umbral de costo) forzando una acción insegura mientras aparentemente se respetan las restricciones de seguridad.

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
- Mantén `delta` muy pequeño para evitar detectores de deriva en la distribución de recompensas.
- Para entornos descentralizados, envenena solo a un agente por episodio para imitar la inserción de “component”.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** muestra que invertir <5% de las etiquetas de preferencia por pares es suficiente para sesgar el modelo de recompensa; el PPO posterior aprende a generar texto deseado por el atacante cuando aparece un token trigger.
- Pasos prácticos para probar: recopila un pequeño conjunto de prompts, añade un token de disparador raro (p. ej., `@@@`), y fuerza preferencias donde las respuestas que contienen contenido del atacante se marcan como “mejor”. Afina el modelo de recompensa y luego ejecuta unas pocas épocas de PPO—el comportamiento desalineado aparecerá solo cuando el trigger esté presente.

### Stealthier spatiotemporal triggers
En lugar de parches de imagen estáticos, trabajos recientes en MADRL usan *secuencias de comportamiento* (patrones de acción temporizados) como triggers, combinadas con una reversión ligera de la recompensa para que el agente envenenado empuje sutilmente a todo el equipo fuera de política mientras mantiene alta la recompensa agregada. Esto evita a los detectores de disparadores estáticos y sobrevive a la observabilidad parcial.

### Red‑team checklist
- Inspecciona las deltas de recompensa por estado; mejoras locales abruptas son fuertes señales de backdoor.
- Mantén un conjunto *canary* de triggers: episodios de hold‑out que contienen estados/tokens sintéticos raros; ejecuta la policy entrenada para ver si el comportamiento diverge.
- Durante el entrenamiento descentralizado, verifica independientemente cada policy compartida mediante rollouts en entornos aleatorizados antes de la agregación.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
