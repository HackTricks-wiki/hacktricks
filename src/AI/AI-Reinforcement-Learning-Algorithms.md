# Algoritmos de Aprendizaje por Refuerzo

{{#include ../banners/hacktricks-training.md}}

## Aprendizaje por refuerzo

Reinforcement learning (RL) es un tipo de machine learning donde un agente aprende a tomar decisiones interactuando con un entorno. El agente recibe retroalimentación en forma de recompensas o penalizaciones basadas en sus acciones, lo que le permite aprender comportamientos óptimos con el tiempo. RL es especialmente útil para problemas donde la solución implica toma de decisiones secuenciales, como robótica, juego de estrategias y sistemas autónomos.

### Q-Learning

Q-Learning es un algoritmo de reinforcement learning model-free que aprende el valor de las acciones en un estado dado. Usa una Q-table para almacenar la utilidad esperada de tomar una acción específica en un estado específico. El algoritmo actualiza los Q-values basándose en las recompensas recibidas y las máximas recompensas futuras esperadas.
1. **Inicialización**: Inicializar la Q-table con valores arbitrarios (a menudo ceros).
2. **Selección de acción**: Elegir una acción usando una estrategia de exploración (por ejemplo, ε-greedy, donde con probabilidad ε se elige una acción aleatoria, y con probabilidad 1-ε se selecciona la acción con el Q-value más alto).
- Tenga en cuenta que el algoritmo podría siempre elegir la mejor acción conocida dado un estado, pero esto no permitiría que el agente explore nuevas acciones que podrían ofrecer mejores recompensas. Por eso se usa la variable ε-greedy para balancear exploración y explotación.
3. **Interacción con el entorno**: Ejecutar la acción elegida en el entorno, observar el siguiente estado y la recompensa.
- Dependiendo en este caso de la probabilidad ε-greedy, el siguiente paso podría ser una acción aleatoria (para exploración) o la mejor acción conocida (para explotación).
4. **Actualización del Q-value**: Actualizar el Q-value para el par estado-acción usando la ecuación de Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` es el Q-value actual para el estado `s` y la acción `a`.
- `α` es la learning rate (0 < α ≤ 1), que determina cuánto de la nueva información reemplaza a la antigua.
- `r` es la recompensa recibida después de tomar la acción `a` en el estado `s`.
- `γ` es el discount factor (0 ≤ γ < 1), que determina la importancia de las recompensas futuras.
- `s'` es el siguiente estado después de tomar la acción `a`.
- `max(Q(s', a'))` es el Q-value máximo para el siguiente estado `s'` sobre todas las posibles acciones `a'`.
5. **Iteración**: Repetir los pasos 2-4 hasta que los Q-values converjan o se cumpla un criterio de parada.

Tenga en cuenta que con cada nueva acción seleccionada la tabla se actualiza, permitiendo al agente aprender de sus experiencias con el tiempo para intentar encontrar la política óptima (la mejor acción a tomar en cada estado). Sin embargo, la Q-table puede volverse grande para entornos con muchos estados y acciones, lo que la hace impráctica para problemas complejos. En esos casos, se pueden usar métodos de aproximación de funciones (por ejemplo, redes neuronales) para estimar los Q-values.

> [!TIP]
> El valor ε-greedy normalmente se actualiza con el tiempo para reducir la exploración a medida que el agente aprende más sobre el entorno. Por ejemplo, puede comenzar con un valor alto (ej., ε = 1) y decrecerlo hasta un valor menor (ej., ε = 0.1) a medida que avanza el aprendizaje.

> [!TIP]
> La learning rate `α` y el discount factor `γ` son hiperparámetros que deben ajustarse según el problema y el entorno específicos. Una learning rate más alta permite que el agente aprenda más rápido pero puede causar inestabilidad, mientras que una learning rate más baja resulta en un aprendizaje más estable pero con convergencia más lenta. El discount factor determina cuánto valora el agente las recompensas futuras (`γ` cercano a 1) en comparación con las recompensas inmediatas.

### SARSA (Estado-Acción-Recompensa-Estado-Acción)

SARSA es otro algoritmo de reinforcement learning model-free que es similar a Q-Learning pero difiere en cómo actualiza los Q-values. SARSA significa State-Action-Reward-State-Action, y actualiza los Q-values basándose en la acción tomada en el siguiente estado, en lugar del Q-value máximo.
1. **Inicialización**: Inicializar la Q-table con valores arbitrarios (a menudo ceros).
2. **Selección de acción**: Elegir una acción usando una estrategia de exploración (por ejemplo, ε-greedy).
3. **Interacción con el entorno**: Ejecutar la acción elegida en el entorno, observar el siguiente estado y la recompensa.
- Dependiendo en este caso de la probabilidad ε-greedy, el siguiente paso podría ser una acción aleatoria (para exploración) o la mejor acción conocida (para explotación).
4. **Actualización del Q-value**: Actualizar el Q-value para el par estado-acción usando la regla de actualización de SARSA. Tenga en cuenta que la regla de actualización es similar a Q-Learning, pero usa la acción que se tomará en el siguiente estado `s'` en vez del Q-value máximo para ese estado:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` es el Q-value actual para el estado `s` y la acción `a`.
- `α` es la learning rate.
- `r` es la recompensa recibida después de tomar la acción `a` en el estado `s`.
- `γ` es el discount factor.
- `s'` es el siguiente estado después de tomar la acción `a`.
- `a'` es la acción tomada en el siguiente estado `s'`.
5. **Iteración**: Repetir los pasos 2-4 hasta que los Q-values converjan o se cumpla un criterio de parada.

#### Softmax vs ε-Greedy Selección de Acciones

Además de la selección de acciones ε-greedy, SARSA también puede usar una estrategia de selección de acciones softmax. En la selección de acciones softmax, la probabilidad de seleccionar una acción es **proporcional a su Q-value**, lo que permite una exploración más matizada del espacio de acciones. La probabilidad de seleccionar la acción `a` en el estado `s` está dada por:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` es la probabilidad de seleccionar la acción `a` en el estado `s`.
- `Q(s, a)` es el valor Q para el estado `s` y la acción `a`.
- `τ` (tau) es el parámetro de temperatura que controla el nivel de exploración. Una temperatura más alta produce más exploración (probabilidades más uniformes), mientras que una temperatura más baja produce más explotación (probabilidades mayores para acciones con valores Q más altos).

> [!TIP]
> Esto ayuda a equilibrar la exploración y la explotación de manera más continua en comparación con la selección de acciones ε-greedy.

### Aprendizaje On-Policy vs Off-Policy

SARSA es un algoritmo de aprendizaje **on-policy**, lo que significa que actualiza los valores Q basándose en las acciones tomadas por la política actual (la ε-greedy o softmax policy). En contraste, Q-Learning es un algoritmo de aprendizaje **off-policy**, ya que actualiza los valores Q basándose en el valor Q máximo del siguiente estado, independientemente de la acción tomada por la política actual. Esta distinción afecta cómo los algoritmos aprenden y se adaptan al entorno.

Los métodos on-policy como SARSA pueden ser más estables en ciertos entornos, ya que aprenden de las acciones realmente tomadas. Sin embargo, pueden converger más lentamente en comparación con métodos off-policy como Q-Learning, que pueden aprender de una gama más amplia de experiencias.

## Seguridad & vectores de ataque en sistemas RL

Aunque los algoritmos de RL parecen puramente matemáticos, trabajos recientes muestran que el **envenenamiento durante el entrenamiento y la manipulación de recompensas pueden subvertir de forma fiable las políticas aprendidas**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Un único agente malicioso codifica un disparador espacio-temporal y perturba ligeramente su función de recompensa; cuando aparece el patrón del disparador, el agente envenenado arrastra a todo el equipo cooperativo hacia un comportamiento elegido por el atacante mientras el rendimiento limpio se mantiene casi sin cambios.
- **Safe‑RL specific backdoor (PNAct)**: El atacante inyecta ejemplos de acciones *positivas* (deseadas) y *negativas* (a evitar) durante el ajuste fino de Safe‑RL. El backdoor se activa con un disparador simple (p. ej., se supera un umbral de coste), forzando una acción insegura mientras aún respeta aparentes restricciones de seguridad.

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
- Mantén `delta` diminuto para evitar detectores de deriva en la distribución de recompensas.
- En entornos descentralizados, envenena solo a un agente por episodio para imitar la inserción de un “componente”.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** muestra que invertir <5% de las etiquetas de preferencia pareada es suficiente para sesgar el modelo de recompensa; el PPO downstream luego aprende a generar texto deseado por el atacante cuando aparece un trigger token.
- Pasos prácticos para probar: recopila un pequeño conjunto de prompts, añade un trigger token raro (p. ej., `@@@`), y fuerza preferencias donde las respuestas que contienen contenido del atacante se marcan como “mejor”. Afina el modelo de recompensa, luego ejecuta unas pocas épocas de PPO—el comportamiento desalineado solo aparecerá cuando el trigger esté presente.

### Triggers espaciotemporales más sigilosos
En lugar de parches de imagen estáticos, trabajo reciente en MADRL usa *secuencias de comportamiento* (patrones de acciones temporizadas) como triggers, junto con una ligera reversión de recompensa para que el agente envenenado conduzca sutilmente a todo el equipo off‑policy mientras mantiene la recompensa agregada alta. Esto evita detectores de triggers estáticos y sobrevive la observabilidad parcial.

### Lista de verificación del red‑team
- Inspecciona los deltas de recompensa por estado; mejoras locales abruptas son señales fuertes de backdoor.
- Mantén un conjunto *canary* de triggers: episodios hold‑out que contengan estados/tokens sintéticos raros; ejecuta la política entrenada para ver si el comportamiento diverge.
- Durante el entrenamiento descentralizado, verifica de forma independiente cada política compartida mediante rollouts en entornos aleatorizados antes de agregarlas.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
