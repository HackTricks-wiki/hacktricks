# Desofuscación estática de bytecode en caché de Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Los datos en caché de V8 son una **representación con pérdida y dependiente de la versión**, no código fuente JavaScript ni un ejecutable nativo convencional. Por tanto, un flujo de trabajo estático útil consiste en eliminar cualquier empaquetado externo, desensamblar la caché con la compilación de V8 correspondiente, elevarla a un modelo de pseudocódigo intermedio y aplicar transformaciones que tengan en cuenta las dependencias sin ejecutar la muestra. [View8](https://github.com/suleram/View8) y [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementan este enfoque para payloads de Node.js protegidos con `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Obtener y desensamblar la caché

Primero inspecciona el preload/launcher en lugar de asumir que todos los archivos `.jsc` tienen el mismo wrapper. Por ejemplo, un launcher como `node.exe -r preflight.js app.jsc` ejecuta `preflight.js` antes del módulo principal; en la familia analizada, el preload eliminaba una capa Brotli. Después de desempaquetarlo, identifica la generación exacta de Node.js/V8 a partir del runtime incluido. Una caché producida por una versión de V8 puede ser rechazada o decodificada incorrectamente por otra, así que compila u obtén un `v8dasm` para esa etiqueta exacta de V8 y aplica los parches necesarios de View8 y de impresión de cadenas.<sup>[[1]](#references)[[2]](#references)</sup>

El flujo de trabajo del toolkit, que no ejecuta la muestra, es:<sup>[[2]](#references)</sup>

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

`--normalize` proporciona identificadores estables a las funciones generadas entre ejecuciones. El texto de salida sirve para inspeccionarlo; el grafo de objetos serializado permite que pasadas independientes conserven las relaciones entre funciones, declaradores, ámbitos y metadatos. **No es JavaScript reconstruido ni ejecutable**.<sup>[[1]](#references)[[2]](#references)</sup>

### Analizar una caché sin compilar V8

Para una caché sin procesar o envuelta en Brotli, `jscd` puede identificar el encabezado y enumerar constantes y funciones sin cargar la muestra en Node.js. Usa esto primero para comprobar si sus tablas de versiones admiten el archivo y priorizar funciones antes de aplicar las pasadas más especializadas de desofuscación de View8.<sup>[[4]](#references)</sup>

El hash de versión es una pista de identificación, no una prueba de que un desensamblador independiente use las mismas flags o la misma instantánea de solo lectura que el productor.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` emite un listado compatible con View8, por lo que el comando de View8 anterior puede usar esa salida en lugar de `v8dasm` cuando la caché sea compatible. Inspecciona las cadenas junto con el árbol de funciones para localizar llamadas a decoders y posibles puntos de entrada; no trates el JavaScript aproximado de `jscd` como si fuera el código fuente original. Si la herramienta rechaza la versión o deja marcadores de posición de read-only-heap, vuelve a una compilación de V8 compatible o proporciona un mapa de nombres de esa misma compilación en lugar de adivinar los nombres de las propiedades.<sup>[[4]](#references)</sup>

Para una caché dentro de una aplicación Electron, primero [extrae el ASAR e inspecciona sus puntos de entrada main y preload](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). Las cachés de Electron y Node pueden diferir en el diseño de snapshot y pointer compression incluso cuando sus cadenas de versión de V8 coinciden.<sup>[[4]](#references)</sup>

### Interpretar el pseudocódigo de View8 como un IR

Los nombres típicos son `func_<name>_0x<address>`, los argumentos son `a0...aN`, los registros virtuales son `r0...rN` y `ACCU` es el acumulador de V8. `start` es el declarador raíz, mientras que `Scope[...]`, los globales y los diccionarios modelan valores capturados o compartidos por funciones anidadas. No analices cada expresión como sintaxis de JavaScript: por ejemplo, `!r6 === "0"` representa la negación de la comparación completa (`r6 !== "0"`), lo cual importa al reconstruir las ramas.<sup>[[1]](#references)[[3]](#references)</sup>

## Desofuscación según las dependencias

Aplica las transformaciones en un orden que exponga las entradas necesarias para el siguiente paso y repite la propagación hasta que la salida se estabilice. Un orden práctico es:<sup>[[1]](#references)[[2]](#references)</sup>

1. Recorre la jerarquía de declaradores y propaga valores de globales, registros, diccionarios y referencias `Scope[...]`.
2. Recupera los argumentos del decoder de cadenas y reemplaza las llamadas cifradas por texto plano.
3. Combina fragmentos de cadenas adyacentes; los nombres de propiedades y las cadenas de orden del dispatcher resultantes permiten los pasos posteriores.
4. Desenreda el flujo de control, inserta los proxies de llamadas y los wrappers de operaciones atómicas, y resuelve las referencias a funciones contenidas en diccionarios.
5. Vuelve a propagar los valores, porque cada cadena, clave o proxy resuelto puede revelar otra capa de indirección.
6. Reduce los thunks de inicialización de una sola ejecución reconocidos y elimina los helpers sin uso solo después de resolver sus sitios de llamada.

### Recuperar arrays de cadenas RC4 desplazados como una caja negra

Un diseño común de `javascript-obfuscator` almacena fragmentos RC4 codificados en Base64 en un único array. Los wrappers del decoder proporcionan un desplazamiento numérico y una clave corta, a veces con los argumentos en orden inverso, y luego suman o restan constantes capturadas en scopes de cierre. Cuando el decoder raíz está demasiado ofuscado, recupera empíricamente el desplazamiento desconocido de los índices del array en lugar de reconstruir toda la función.<sup>[[1]](#references)</sup>

Para un array de `N` fragmentos y varias llamadas al mismo decoder:<sup>[[1]](#references)</sup>

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

No aceptes un desplazamiento basándote en un único descifrado imprimible: el ciphertext incorrecto puede parecer imprimible por casualidad. Usa al menos tres observaciones distintas y acepta solo un desplazamiento único que produzca texto plausible en todas ellas. Luego recorre el grafo de wrappers/declaradores, acumula cada suma o resta y registra si el argumento numérico aparece primero. Almacena en caché estos metadatos por muestra, reemplaza las llamadas al decoder, concatena los fragmentos de texto plano adyacentes y exporta las cadenas por separado para su análisis inicial.<sup>[[1]](#references)[[2]](#references)</sup>

### Preservar la semántica al deshacer el aplanamiento

Para los bucles dispatcher controlados por cadenas como `3|2|1|0|4`, decodifica la cadena de orden, asigna cada comparación de estado a su bloque, ten en cuenta la notación de condición negada de View8 y luego emite los bloques en el orden del dispatcher. Un `continue` anidado puede representar un salto temprano de vuelta al dispatcher, en lugar de un flujo normal. Al eliminar el bucle, borra ese `continue` y mueve las instrucciones que originalmente seguían al `if` que lo contiene a una rama `else` generada; limitarse a eliminar el dispatcher cambia el comportamiento.<sup>[[1]](#references)</sup>

### Insertar proxies, operaciones y thunks diferidos

Normaliza los helpers de reenvío como `return a0(a1, a2)` antes de reemplazar sus puntos de llamada por llamadas directas. Trata de forma similar los wrappers de resta, división, comparación, pruebas de pertenencia o invocación. Como la referencia al helper puede estar almacenada tras una clave de diccionario descifrada o un valor de closure, ejecuta la propagación de cadenas y estructuras antes y después de insertar el código.<sup>[[1]](#references)</sup>

Reconoce también los closures que invocan una función almacenada una sola vez, borran su referencia, almacenan en caché el resultado y lo devuelven en llamadas posteriores. Reducir un thunk de este tipo en un punto de inicialización expone el dispatcher o la función de capacidad subyacente, pero anota que la ejecución original era de **una sola ejecución y con resultado almacenado en caché**, en vez de modelar cada llamada como una invocación nueva.<sup>[[1]](#references)</sup>

## Notas de seguridad y validación

- Cargar `pickle` en Python puede ejecutar código. Carga únicamente archivos `.pkl` generados localmente por una ejecución confiable de View8; nunca trates un pickle proporcionado por una muestra como datos.<sup>[[2]](#references)</sup>
- La ausencia del cuerpo de una función no demuestra que la fuente careciera de esa función: V8 puede serializar una función diferida como metadatos hasta que se compile en la primera llamada. Mantén estas funciones marcadas como no resueltas durante el análisis inicial estático.<sup>[[6]](#references)</sup>
- Los pases basados en patrones no son un decompilador general de JavaScript. Conserva las expresiones no resueltas e inspecciona manualmente las variantes ambiguas del dispatcher en lugar de forzar una reescritura.<sup>[[1]](#references)[[2]](#references)</sup>
- Los nombres de función sugeridos con ayuda de un LLM son pistas de navegación, no pruebas. Si los usas, procesa las dependencias primero desde las hojas, pero verifica cada etiqueta con el cuerpo, los argumentos, las cadenas, el flujo de datos, las APIs y los efectos secundarios.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Rompiendo el sello: desofuscación estática del bytecode V8 compilado de JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Encabezado V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Caché de código de vm.Script de Node.js](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
