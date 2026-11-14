# Desofuscación estática de bytecode en caché de Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Los datos en caché de V8 son una **representación con pérdida que depende de la versión**, no código fuente de JavaScript ni un ejecutable nativo convencional. Por lo tanto, un flujo de trabajo estático útil consiste en quitar cualquier empaquetado externo, desensamblar la caché con la compilación de V8 correspondiente, elevarla a un modelo intermedio de pseudocódigo y aplicar transformaciones que tengan en cuenta las dependencias, sin ejecutar la muestra. [View8](https://github.com/suleram/View8) y [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementan este enfoque para cargas útiles de Node.js protegidas con `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Adquirir y desensamblar la caché

Primero inspecciona el preload/lanzador en lugar de suponer que todos los archivos `.jsc` tienen el mismo envoltorio. Por ejemplo, un lanzador como `node.exe -r preflight.js app.jsc` ejecuta `preflight.js` antes del módulo principal; en la familia analizada, el preload eliminaba una capa Brotli. Después de desempaquetar, identifica la generación exacta de Node.js/V8 a partir del runtime incluido. Una caché producida por una versión de V8 puede ser rechazada o decodificada incorrectamente por otra, así que compila u obtén un `v8dasm` para esa versión exacta de V8 y aplica los parches necesarios de View8 y de impresión de cadenas.<sup>[[1]](#references)[[2]](#references)</sup>

El flujo de trabajo del kit de herramientas, que no ejecuta el código, es:<sup>[[2]](#references)</sup>

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

`--normalize` proporciona identificadores estables a las funciones generadas entre ejecuciones. El texto de salida sirve para inspeccionarlo; el grafo de objetos serializado permite que pases independientes preserven las relaciones entre funciones, declaradores, ámbitos y metadatos. **No es JavaScript reconstruido ni ejecutable**.<sup>[[1]](#references)[[2]](#references)</sup>

### Analizar una caché sin compilar V8

Para una caché sin procesar o comprimida con Brotli, `jscd` puede identificar el encabezado y enumerar constantes y funciones sin cargar la muestra en Node.js. Úsalo primero para comprobar si sus tablas de versiones son compatibles con el archivo y para priorizar funciones antes de aplicar los pases de desofuscación más especializados de View8.<sup>[[4]](#references)</sup>

El hash de versión es una pista de identificación, no una prueba de que un desensamblador independiente tenga las mismas flags o la misma snapshot de solo lectura que el productor.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` genera un listado compatible con View8, así que el comando de View8 anterior puede usar esa salida en lugar de `v8dasm` cuando la caché sea compatible. Inspecciona las cadenas junto al árbol de funciones para localizar llamadas al decoder y posibles puntos de entrada; no trates la salida JavaScript aproximada de `jscd` como si fuera el código fuente original. Si la herramienta rechaza la versión o deja marcadores de posición del read-only heap, vuelve a una compilación de V8 compatible o proporciona un mapa de nombres de esa misma compilación en lugar de adivinar los nombres de las propiedades.<sup>[[4]](#references)</sup>

Para una caché dentro de una aplicación Electron, primero [extrae el ASAR e inspecciona los puntos de entrada main y preload](../../desktop-application-security/electron-desktop-apps/). Las cachés de Electron y Node pueden diferir en el layout de snapshots y pointer compression aunque sus cadenas de versión de V8 coincidan.<sup>[[4]](#references)</sup>

### Leer el pseudocódigo de View8 como IR

Los nombres típicos son `func_<name>_0x<address>`, los argumentos son `a0...aN`, los registros virtuales son `r0...rN` y `ACCU` es el acumulador de V8. `start` es el declarador raíz, mientras que `Scope[...]`, los globales y los diccionarios representan valores capturados o compartidos por funciones anidadas. No interpretes cada expresión como sintaxis JavaScript: por ejemplo, `!r6 === "0"` en View8 representa la negación de la comparación completa (`r6 !== "0"`), algo importante al reconstruir ramas.<sup>[[1]](#references)[[3]](#references)</sup>

## Desofuscación que tiene en cuenta las dependencias

Aplica las transformaciones en un orden que exponga las entradas necesarias para el siguiente paso y repite la propagación hasta que la salida se estabilice. Un orden práctico es:<sup>[[1]](#references)[[2]](#references)</sup>

1. Recorre la jerarquía de declaradores y propaga valores desde globales, registros, diccionarios y referencias `Scope[...]`.
2. Recupera los argumentos del string decoder y reemplaza las llamadas cifradas por texto plano.
3. Combina fragmentos de cadenas adyacentes; los nombres de propiedades y las cadenas de orden del dispatcher resultantes permiten desbloquear pasos posteriores.
4. Desaplana el flujo de control, integra los proxies de llamadas y los wrappers de operaciones atómicas, y resuelve las referencias a funciones almacenadas en diccionarios.
5. Vuelve a propagar valores, porque cada cadena, clave o proxy resuelto puede revelar otra capa de indirección.
6. Reduce las funciones thunk de inicialización de una sola ejecución reconocidas y elimina los helpers sin uso solo después de resolver sus sitios de llamada.

### Recuperar arrays de cadenas RC4 con desplazamiento como una caja negra

Un patrón común de `javascript-obfuscator` almacena fragmentos RC4 codificados en Base64 en un array. Los wrappers del decoder proporcionan un desplazamiento numérico y una clave corta, a veces con los argumentos en orden inverso, y luego suman o restan constantes capturadas en scopes de cierre. Cuando el decoder raíz está demasiado ofuscado, recupera empíricamente el desplazamiento desconocido del índice del array en lugar de reconstruir toda la función.<sup>[[1]](#references)</sup>

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

No aceptes un desplazamiento basándote en un único descifrado imprimible: el ciphertext incorrecto puede parecer imprimible por casualidad. Usa al menos tres observaciones distintas y acepta solo un desplazamiento único que produzca texto plausible en todas ellas. Después, recorre el grafo de wrappers/declarers, acumulando cada suma o resta y registrando si el argumento numérico aparece primero. Almacena en caché estos metadatos por muestra, reemplaza las llamadas al decoder, concatena los fragmentos de texto plano adyacentes y exporta las cadenas por separado para su triaje.<sup>[[1]](#references)[[2]](#references)</sup>

### Preserve los semánticos al deshacer el aplanamiento

Para los bucles del dispatcher controlados por cadenas como `3|2|1|0|4`, decodifica la cadena de orden, asigna cada comparación de estado a su bloque, ten en cuenta la notación de condición negada de View8 y, luego, emite los bloques en el orden del dispatcher. Un `continue` anidado puede representar un salto anticipado de vuelta al dispatcher en lugar de un flujo secuencial ordinario. Al eliminar el bucle, borra ese `continue` y mueve las instrucciones que originalmente seguían a su `if` contenedor a una rama `else` generada; limitarse a borrar el dispatcher cambia el comportamiento.<sup>[[1]](#references)</sup>

### Inserta proxies, operaciones y thunks perezosos

Normaliza los helpers de reenvío, como `return a0(a1, a2)`, antes de reemplazar sus puntos de llamada por llamadas directas. Trata de forma similar los wrappers de resta, división, comparación, pruebas de pertenencia o invocación. Como la referencia al helper puede estar almacenada detrás de una clave de diccionario descifrada o de un valor de closure, propaga las cadenas y estructuras antes y después de la inserción.<sup>[[1]](#references)</sup>

Reconoce también los closures que invocan una vez una función almacenada, borran su referencia, almacenan en caché el resultado y lo devuelven en llamadas posteriores. Al colapsar ese thunk en un punto de inicialización se expone el dispatcher o la función de capacidad subyacente, pero anota que la ejecución original era **de una sola ejecución y con resultado en caché**, en lugar de modelar cada llamada como una invocación nueva.<sup>[[1]](#references)</sup>

## Notas de seguridad y validación

- La carga de `pickle` en Python puede ejecutar código. Carga solo archivos `.pkl` generados localmente por la ejecución de View8 de confianza; nunca trates un pickle proporcionado por una muestra como datos.<sup>[[2]](#references)</sup>
- La ausencia del cuerpo de una función no demuestra que el código fuente careciera de esa función: V8 puede serializar una función perezosa como metadatos hasta que se compile en la primera llamada. Mantén esas funciones marcadas como no resueltas durante el triaje estático.<sup>[[6]](#references)</sup>
- Las pasadas basadas en patrones no son un decompilador general de JavaScript. Conserva las expresiones no resueltas e inspecciona manualmente las variantes ambiguas del dispatcher en lugar de forzar una reescritura.<sup>[[1]](#references)[[2]](#references)</sup>
- Los nombres de funciones sugeridos por un LLM son pistas de navegación, no pruebas. Si los usas, procesa las dependencias empezando por las hojas, pero verifica cada etiqueta con el cuerpo, los argumentos, las cadenas, el flujo de datos, las APIs y los efectos secundarios.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Rompiendo el sello: desofuscación estática del bytecode compilado de V8 de JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Cabecera V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Caché de código de Node.js vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
