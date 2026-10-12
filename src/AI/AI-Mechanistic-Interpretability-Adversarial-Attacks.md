# Ataques adversariales guiados por interpretabilidad mecanicista

{{#include ../banners/hacktricks-training.md}}

## La superposición como superficie de ataque

Un espacio de activación con parámetros insuficientes puede codificar más características semánticas de las que tiene dimensiones asignando características a vectores no ortogonales. En consecuencia, una característica activada también se proyecta sobre las direcciones de otras características. El entrenamiento puede compensar las combinaciones observadas en la distribución, pero una combinación inusual de características válidas por separado puede sumarse de forma constructiva en la dirección de una característica objetivo que no está presente en la entrada.<sup>[[1]](#references)[[2]](#references)</sup>

Para vectores de características `v_i ∈ R^D`, activaciones `a_i` y objetivo `t`, la siguiente magnitud es útil para encontrar combinaciones candidatas:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

Esto es solo una heurística de cribado. Un exploit debe conservar los signos y las magnitudes, y evaluar el decoder real, por ejemplo `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` en un decoder lineal con pesos compartidos. Los términos negativos pueden cancelar el ataque, mientras que el sesgo del decoder, las normas de los vectores de características, los umbrales de activación y la compuerta ReLU pueden impedir que una puntuación de coseno absoluta alta produzca la activación objetivo.<sup>[[1]](#references)</sup>

## Flujo de ataque white-box

Una evaluación práctica puede usar un cuello de botella del modelo, un autoencoder disperso (SAE) u otro diccionario de características interpretable. El objetivo no es simplemente cambiar la clase final: es hacer que la reconstrucción introduzca una característica interna elegida que no estaba activa antes de la compresión. El flujo de trabajo propuesto es:<sup>[[1]](#references)</sup>

1. **Recuperar las direcciones de las características:** extraer los vectores pertinentes del encoder/decoder, eliminar las características muertas y asociar las direcciones activas con conceptos mediante muestras de activación máxima o análisis de circuitos de características.
2. **Clasificar la interferencia:** normalizar una copia de los vectores, calcular su matriz de similitud de coseno, poner a cero la diagonal e inspeccionar los vecinos fuera de la diagonal más cercanos al objetivo. Volver a calcular los candidatos usando las magnitudes de activación reales y los productos escalares brutos con signo.
3. **Imponer la coactivación:** conservar un conjunto pequeño de características que contribuyan positivamente y que puedan activarse en la misma capa o flujo residual. Preferir combinaciones poco frecuentes o ausentes en los datos de entrenamiento; es más probable que las combinaciones correlacionadas habituales hayan sido compensadas durante el entrenamiento.
4. **Sintetizar la entrada:** combinar ejemplos del conjunto de datos o patrones que maximicen la activación de los contribuyentes seleccionados. Para un detector lineal de píxeles acotado, asignar un valor alto a un píxel si su peso es positivo y uno bajo si es negativo; después, superponer los patrones resultantes. Conservar manualmente la estructura dentro de la distribución y el **espacio negativo** inhibitorio puede suprimir características no relacionadas.
5. **Verificar el mecanismo:** registrar las activaciones antes de la compresión, las coordenadas comprimidas, las activaciones reconstruidas y la salida posterior en una sola pasada hacia delante. Una prueba exitosa muestra que el objetivo está inactivo antes de la reconstrucción y activo después, y que el cambio previsto desaparece al realizar una ablación de los contribuyentes.

El siguiente procedimiento mínimo de clasificación inicial ordena los contribuyentes para un decoder con pesos compartidos cuyas **filas** son vectores de características (transponer primero si las características están en columnas). Usar los pesos brutos para la puntuación con signo y los pesos normalizados solo para ordenarlos por similitud de coseno.<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

No infieras la explotabilidad basándote únicamente en la similitud coseno. Prueba el decodificador completo con su sesgo y no linealidad, confirma que los componentes pueden coexistir realmente y compara con combinaciones de la distribución de entrenamiento que estén emparejadas. Las direcciones similares pueden codificar una relación semántica legítima, en lugar de una interferencia de empaquetado explotable.<sup>[[1]](#references)</sup>

## Ataque demostrado con un modelo de juguete

La prueba de concepto utilizó un clasificador MNIST deliberadamente interpretable con dos ramas. En una rama, se clasificaba directamente un vector disperso de características ReLU de 128 dimensiones; en la otra, se comprimía en un espacio de superposición bidimensional. El mismo clasificador procesaba tanto las características originales como las reconstruidas.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Dos direcciones de características asociadas a formas similares a 3/0, geométricamente encerradas por direcciones de clase 5. Sumar sus imágenes de activación máxima hizo que esas características contribuyentes fueran las más fuertes antes de la compresión, pero la reconstrucción activó varias características de clase 5 y la rama de superposición predijo 5. Una entrada dibujada a mano que usaba solo valores de píxel mínimos y máximos reprodujo el efecto, lo que mostró que, en este entorno de prueba, no se necesitaban perturbaciones de píxeles optimizadas mediante gradientes exactos.<sup>[[1]](#references)</sup>

## Triaje geométrico en modelos más grandes

El artículo también examinó el SAE Gemma Scope `layer 20 / width 65k / average L0 20`. Multiplicó la matriz de decodificadores normalizada por filas unitarias por su transpuesta, puso la diagonal en cero, ordenó los vecinos de cada característica y calculó el promedio por posición. La similitud coseno media con el vecino más cercano fue de `0.49`, mientras que la similitud media con el vecino número 27 fue de `0.25`; geométricamente, cuatro de esas direcciones podrían igualar la proyección de un objetivo unitario. Estas cifras solo identifican candidatos: no demuestran que se puedan activar conjuntamente cuatro características adecuadas ni que el objetivo supere su umbral de decodificador.<sup>[[1]](#references)</sup>

## Alcance y limitaciones

Esta es una técnica de **caja blanca** en fase de investigación, no un ataque demostrado contra una CNN desplegada ni un LLM de frontera. Requiere superposición, direcciones no ortogonales útiles, acceso interpretable a características internas, activación controlable de las características contribuyentes y su presencia en la misma capa durante una única pasada hacia delante.<sup>[[1]](#references)</sup>

Las MLP de imágenes hacen que la composición de características sea inusualmente directa. Un transformer es más difícil porque la atención debe reunir las activaciones de las características elegidas en el mismo flujo residual; el artículo no muestra cómo forzar esto para una combinación fuera de distribución. Por tanto, las afirmaciones sobre manipular direcciones de comportamiento o de rechazo, sistemas de visión física o modelos de frontera siguen siendo hipótesis.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — Una investigación preliminar sobre ataques adversariales interpretables mediante interferencia de características en superposición (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Ataques adversariales interpretables en superposición](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
