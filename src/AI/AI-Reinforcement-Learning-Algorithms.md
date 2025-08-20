# Algoritmos de Aprendizaje por Refuerzo

{{#include ../banners/hacktricks-training.md}}

## Aprendizaje por Refuerzo

El aprendizaje por refuerzo (RL) es un tipo de aprendizaje automático donde un agente aprende a tomar decisiones interactuando con un entorno. El agente recibe retroalimentación en forma de recompensas o penalizaciones basadas en sus acciones, lo que le permite aprender comportamientos óptimos con el tiempo. RL es particularmente útil para problemas donde la solución implica toma de decisiones secuenciales, como la robótica, los juegos y los sistemas autónomos.

### Q-Learning

Q-Learning es un algoritmo de aprendizaje por refuerzo sin modelo que aprende el valor de las acciones en un estado dado. Utiliza una tabla Q para almacenar la utilidad esperada de tomar una acción específica en un estado específico. El algoritmo actualiza los valores Q basándose en las recompensas recibidas y las máximas recompensas futuras esperadas.
1. **Inicialización**: Inicializa la tabla Q con valores arbitrarios (a menudo ceros).
2. **Selección de Acción**: Elige una acción utilizando una estrategia de exploración (por ejemplo, ε-greedy, donde con probabilidad ε se elige una acción aleatoria, y con probabilidad 1-ε se selecciona la acción con el valor Q más alto).
- Ten en cuenta que el algoritmo podría siempre elegir la mejor acción conocida dado un estado, pero esto no permitiría al agente explorar nuevas acciones que podrían generar mejores recompensas. Por eso se utiliza la variable ε-greedy para equilibrar la exploración y la explotación.
3. **Interacción con el Entorno**: Ejecuta la acción elegida en el entorno, observa el siguiente estado y la recompensa.
- Ten en cuenta que dependiendo en este caso de la probabilidad ε-greedy, el siguiente paso podría ser una acción aleatoria (para exploración) o la mejor acción conocida (para explotación).
4. **Actualización del Valor Q**: Actualiza el valor Q para el par estado-acción utilizando la ecuación de Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
donde:
- `Q(s, a)` es el valor Q actual para el estado `s` y la acción `a`.
- `α` es la tasa de aprendizaje (0 < α ≤ 1), que determina cuánto la nueva información reemplaza a la información antigua.
- `r` es la recompensa recibida después de tomar la acción `a` en el estado `s`.
- `γ` es el factor de descuento (0 ≤ γ < 1), que determina la importancia de las recompensas futuras.
- `s'` es el siguiente estado después de tomar la acción `a`.
- `max(Q(s', a'))` es el valor Q máximo para el siguiente estado `s'` sobre todas las acciones posibles `a'`.
5. **Iteración**: Repite los pasos 2-4 hasta que los valores Q converjan o se cumpla un criterio de detención.

Ten en cuenta que con cada nueva acción seleccionada, la tabla se actualiza, permitiendo al agente aprender de sus experiencias a lo largo del tiempo para intentar encontrar la política óptima (la mejor acción a tomar en cada estado). Sin embargo, la tabla Q puede volverse grande para entornos con muchos estados y acciones, lo que la hace impráctica para problemas complejos. En tales casos, se pueden utilizar métodos de aproximación de funciones (por ejemplo, redes neuronales) para estimar los valores Q.

> [!TIP]
> El valor ε-greedy generalmente se actualiza con el tiempo para reducir la exploración a medida que el agente aprende más sobre el entorno. Por ejemplo, puede comenzar con un valor alto (por ejemplo, ε = 1) y disminuirlo a un valor más bajo (por ejemplo, ε = 0.1) a medida que avanza el aprendizaje.

> [!TIP]
> La tasa de aprendizaje `α` y el factor de descuento `γ` son hiperparámetros que deben ajustarse según el problema y el entorno específicos. Una tasa de aprendizaje más alta permite que el agente aprenda más rápido, pero puede llevar a inestabilidad, mientras que una tasa de aprendizaje más baja resulta en un aprendizaje más estable pero una convergencia más lenta. El factor de descuento determina cuánto valora el agente las recompensas futuras (`γ` más cerca de 1) en comparación con las recompensas inmediatas.

### SARSA (Estado-Acción-Recompensa-Estado-Acción)

SARSA es otro algoritmo de aprendizaje por refuerzo sin modelo que es similar a Q-Learning pero difiere en cómo actualiza los valores Q. SARSA significa Estado-Acción-Recompensa-Estado-Acción, y actualiza los valores Q basándose en la acción tomada en el siguiente estado, en lugar del valor Q máximo.
1. **Inicialización**: Inicializa la tabla Q con valores arbitrarios (a menudo ceros).
2. **Selección de Acción**: Elige una acción utilizando una estrategia de exploración (por ejemplo, ε-greedy).
3. **Interacción con el Entorno**: Ejecuta la acción elegida en el entorno, observa el siguiente estado y la recompensa.
- Ten en cuenta que dependiendo en este caso de la probabilidad ε-greedy, el siguiente paso podría ser una acción aleatoria (para exploración) o la mejor acción conocida (para explotación).
4. **Actualización del Valor Q**: Actualiza el valor Q para el par estado-acción utilizando la regla de actualización de SARSA. Ten en cuenta que la regla de actualización es similar a Q-Learning, pero utiliza la acción que se tomará en el siguiente estado `s'` en lugar del valor Q máximo para ese estado:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
donde:
- `Q(s, a)` es el valor Q actual para el estado `s` y la acción `a`.
- `α` es la tasa de aprendizaje.
- `r` es la recompensa recibida después de tomar la acción `a` en el estado `s`.
- `γ` es el factor de descuento.
- `s'` es el siguiente estado después de tomar la acción `a`.
- `a'` es la acción tomada en el siguiente estado `s'`.
5. **Iteración**: Repite los pasos 2-4 hasta que los valores Q converjan o se cumpla un criterio de detención.

#### Selección de Acción Softmax vs ε-Greedy

Además de la selección de acción ε-greedy, SARSA también puede utilizar una estrategia de selección de acción softmax. En la selección de acción softmax, la probabilidad de seleccionar una acción es **proporcional a su valor Q**, lo que permite una exploración más matizada del espacio de acciones. La probabilidad de seleccionar la acción `a` en el estado `s` se da por:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
donde:
- `P(a|s)` es la probabilidad de seleccionar la acción `a` en el estado `s`.
- `Q(s, a)` es el valor Q para el estado `s` y la acción `a`.
- `τ` (tau) es el parámetro de temperatura que controla el nivel de exploración. Una temperatura más alta resulta en más exploración (probabilidades más uniformes), mientras que una temperatura más baja resulta en más explotación (probabilidades más altas para acciones con valores Q más altos).

> [!TIP]
> Esto ayuda a equilibrar la exploración y la explotación de una manera más continua en comparación con la selección de acciones ε-greedy.

### Aprendizaje On-Policy vs Off-Policy

SARSA es un algoritmo de aprendizaje **on-policy**, lo que significa que actualiza los valores Q en función de las acciones tomadas por la política actual (la política ε-greedy o softmax). En contraste, Q-Learning es un algoritmo de aprendizaje **off-policy**, ya que actualiza los valores Q en función del valor Q máximo para el siguiente estado, independientemente de la acción tomada por la política actual. Esta distinción afecta cómo los algoritmos aprenden y se adaptan al entorno.

Los métodos on-policy como SARSA pueden ser más estables en ciertos entornos, ya que aprenden de las acciones realmente tomadas. Sin embargo, pueden converger más lentamente en comparación con los métodos off-policy como Q-Learning, que pueden aprender de una gama más amplia de experiencias.

{{#include ../banners/hacktricks-training.md}}
