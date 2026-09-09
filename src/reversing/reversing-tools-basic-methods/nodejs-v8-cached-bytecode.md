# Desofuscación estática de bytecode cacheado de Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Los datos cacheados de V8 son una **representación dependiente de la versión y con pérdida**, no código fuente JavaScript ni un ejecutable nativo convencional. Por lo tanto, un flujo de trabajo estático útil consiste en eliminar cualquier empaquetado externo, desensamblar la caché con la build de V8 correspondiente, elevarla a un modelo de pseudocódigo intermedio y aplicar transformaciones teniendo en cuenta las dependencias sin ejecutar el sample. [View8](https://github.com/suleram/View8) y [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementan este enfoque para payloads de Node.js protegidos con `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Adquirir y desensamblar la caché

Primero, inspecciona el preload/launcher en lugar de asumir que todos los archivos `.jsc` tienen el mismo wrapper. Por ejemplo, un launcher como `node.exe -r preflight.js app.jsc` ejecuta `preflight.js` antes del módulo principal; en la familia analizada, el preload eliminaba una capa Brotli. Después de desempaquetarlo, identifica la generación exacta de Node.js/V8 a partir del runtime incluido. Una caché producida por una versión de V8 puede ser rechazada o decodificada incorrectamente por otra, por lo que debes compilar u obtener un `v8dasm` para esa etiqueta exacta de V8 y aplicar los parches requeridos de View8 y de impresión de strings.<sup>[[1]](#references)[[2]](#references)</sup>

El flujo de trabajo del toolkit sin ejecución es el siguiente:<sup>[[2]](#references)</sup>
```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
--inp app.jsc.disasm.txt --normalize \
--out decompiled/app.dec.txt \
--export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
--out deobfuscated/app.deobf.txt \
--export_format decompiled serialized
```
`--normalize` proporciona identificadores estables a las funciones generadas entre ejecuciones. El texto de salida sirve para inspección; el grafo de objetos serializado permite que los pases independientes preserven las relaciones entre funciones, declaradores, scopes y metadatos. **No es JavaScript reconstruido ni ejecutable**.<sup>[[1]](#references)[[2]](#references)</sup>

### Leer el pseudocódigo de View8 como una IR

Los nombres habituales son `func_<name>_0x<address>`, los argumentos son `a0...aN`, los registros virtuales son `r0...rN` y `ACCU` es el acumulador de V8. `start` es el declarador raíz, mientras que `Scope[...]`, los globals y los diccionarios representan valores capturados o compartidos por funciones anidadas. No analices cada expresión como sintaxis de JavaScript: por ejemplo, `!r6 === "0"` de View8 representa la negación de la comparación completa (`r6 !== "0"`), lo cual importa al reconstruir las ramas.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuscation con conocimiento de dependencias

Aplica las transformaciones en un orden que exponga las entradas requeridas por el siguiente pase y repite la propagación hasta que la salida se estabilice. Un orden práctico es:<sup>[[1]](#references)[[2]](#references)</sup>

1. Recorre la jerarquía de declaradores y propaga valores desde globals, registros, diccionarios y referencias `Scope[...]`.
2. Recupera los argumentos del string-decoder y reemplaza las llamadas cifradas por texto plano.
3. Combina los fragmentos de strings adyacentes; los nombres de propiedades y strings de orden del dispatcher resultantes desbloquean los pases posteriores.
4. Deshace el aplanamiento del flujo de control, integra los proxies de llamadas y los wrappers de operaciones atómicas, y resuelve las referencias a funciones almacenadas en diccionarios.
5. Propaga de nuevo porque cada string, clave o proxy resuelto puede exponer otra capa de indirección.
6. Colapsa los thunks de inicialización one-shot reconocidos y elimina los helpers muertos solo después de resolver sus call sites.

### Recuperar arrays de strings RC4 desplazados como una black box

Un patrón común de `javascript-obfuscator` almacena chunks RC4 codificados en Base64 en un array. Los wrappers del decoder proporcionan un offset numérico y una key corta, a veces con el orden de los argumentos invertido, y después suman o restan constantes capturadas en scopes de cierre. Cuando el decoder raíz está demasiado ofuscado, recupera empíricamente su desplazamiento desconocido del índice del array en lugar de reconstruir la función completa.<sup>[[1]](#references)</sup>

Para un array de `N` chunks y varias llamadas al mismo decoder:<sup>[[1]](#references)</sup>
```text
for each observed (numeric_argument, rc4_key):
candidates = {}
for shift in 0 .. N-1:
index = apply_observed_sign(numeric_argument, shift)
plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
if plaintext passes encoding/printability checks:
candidates.add(shift)
root_shift = intersection(candidate_sets)
```
No aceptes un shift a partir de un único descifrado imprimible: el ciphertext incorrecto puede parecer imprimible por casualidad. Usa al menos tres observaciones distintas y acepta únicamente un shift único que produzca texto plausible en todas ellas. Después, recorre el grafo de wrappers/declarers, acumulando cada suma o resta y registrando si el argumento numérico aparece primero. Almacena en caché estos metadatos por sample, reemplaza las llamadas al decoder, concatena los fragmentos de plaintext adyacentes y exporta las strings por separado para su triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Preservar la semántica al deshacer el flattening

Para los bucles del dispatcher controlados por strings como `3|2|1|0|4`, decodifica la string de orden, asigna cada comparación de estado a su bloque, ten en cuenta la notación de condición negada de View8 y, después, emite los bloques en el orden del dispatcher. Un `continue` anidado puede representar un salto temprano de vuelta al dispatcher en lugar de un fall-through normal. Al eliminar el bucle, borra ese `continue` y mueve las instrucciones que originalmente seguían a su `if` contenedor a una rama `else` generada; eliminar únicamente el dispatcher cambia el comportamiento.<sup>[[1]](#references)</sup>

### Inline proxies, operaciones y thunks lazy

Normaliza los helpers de forwarding, como `return a0(a1, a2)`, antes de reemplazar sus call sites por llamadas directas. Trata de forma similar los wrappers para resta, división, comparación, membership tests o invocation. Puesto que la referencia al helper puede estar almacenada a su vez detrás de una clave de diccionario descifrada o de un valor de closure, ejecuta la propagación de strings y estructuras antes y después del inlining.<sup>[[1]](#references)</sup>

Reconoce también las closures que invocan una vez una función almacenada, eliminan su referencia, almacenan en caché el resultado y devuelven esa caché en las llamadas posteriores. Colapsar uno de estos thunks en un punto de inicialización expone el dispatcher o la función de capability subyacente, pero anota que la ejecución original era **one-shot y cached**, en lugar de modelar cada llamada como una invocation nueva.<sup>[[1]](#references)</sup>

## Notas de seguridad y validación

- La carga de `pickle` de Python puede ejecutar código. Carga únicamente archivos `.pkl` generados localmente por la ejecución de View8 de confianza; nunca trates un pickle proporcionado por el sample como datos.<sup>[[2]](#references)</sup>
- Los passes basados en patrones no son un decompiler general de JavaScript. Conserva las expresiones no resueltas e inspecciona manualmente las variantes ambiguas del dispatcher en lugar de forzar una reescritura.<sup>[[1]](#references)[[2]](#references)</sup>
- Los nombres de funciones asistidos por LLM son sugerencias de navegación, no pruebas. Procesa las dependencias leaf-first si los usas, pero verifica cada label con respecto al cuerpo, los argumentos, las strings, el flujo de datos, las APIs y los efectos secundarios.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Breaking the Seal: Static Deobfuscation of JSCeal's Compiled V8 Bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
