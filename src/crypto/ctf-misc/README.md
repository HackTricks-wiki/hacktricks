# Crypto CTF Misc

{{#include ../../banners/hacktricks-training.md}}

Esta sección reúne técnicas que aparecen en retos de criptografía, pero que no encajan claramente en las demás categorías.

## Lenguajes esotéricos

### Técnica

Usa este flujo de trabajo cuando un reto requiera ejecutar un programa escrito en un lenguaje esotérico y decodificar su salida.

Si un reto te proporciona código que no parece pertenecer a un lenguaje estándar:

- Identifica el lenguaje buscando un token distintivo o una secuencia de instrucciones.
- Usa un intérprete en línea o una imagen de Docker.
- Si la salida es extraña, busca capas de codificación o compresión posteriores a la ejecución.

Un índice útil de lenguajes es la wiki de Esolang.<sup>[[1]](#references)</sup> Para las capas habituales de codificación y compresión, usa el [flujo de trabajo de Crypto CTF](../ctf-workflow/). Si la pista es texto invisible en lugar de sintaxis ejecutable, consulta la [esteganografía de texto](../../stego/text/).

### Exfiltrar el estado precargado del intérprete

Si un reto acepta código fuente en un lenguaje esotérico y lo ejecuta en un **intérprete personalizado**, inspecciona su memoria inicial, stack e instrucciones de salida antes de tratar el código fuente como un acertijo de decodificación. Cuando el intérprete precarga un secreto en un stack de Befunge, un programa corto puede extraer e imprimir los bytes existentes sin calcularlos. Esto requiere controlar el código fuente que se ejecuta y disponer de un opcode de salida; no funciona con un intérprete normal vacío. En un reto de Befunge, el código de abajo emitía repetidamente caracteres de una flag precargada en orden inverso en el stack.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` inicia la ejecución hacia la derecha, `,` extrae e imprime un carácter, y `<` devuelve el puntero de instrucciones a `,`. Comprueba el comportamiento del intérprete personalizado ante el subdesbordamiento y el límite de instrucciones: la implementación citada se detiene cuando se agota la pila o después de 1.024 instrucciones. Si el secreto no está directamente en la pila, inspecciona los demás estados inicializados y las instrucciones de salida y lectura disponibles, en lugar de asumir la semántica estándar de Befunge.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, la wiki de los lenguajes de programación esotéricos](https://esolangs.org/wiki/Main_Page)
- [2] [Writeup original de WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [Código fuente del intérprete de WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Referencia del lenguaje Befunge](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
