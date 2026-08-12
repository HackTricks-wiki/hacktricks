# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Para obtener información general sobre la tecnología iButton, consulta:

{{#ref}}
../ibutton.md
{{#endref}}

## Diseño

En la siguiente imagen, el área **azul** muestra cómo colocar un iButton físico contra los contactos del Flipper Zero para leerlo. El área **verde** muestra qué contactos deben tocar un lector durante la emulación.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Leer

En el modo de lectura, el Flipper Zero espera a que una llave toque sus contactos, detecta el protocolo y muestra el protocolo encima del ID de la llave. La aplicación integrada admite llaves de control de acceso Dallas, Cyfral y Metakom.<sup>[[2]](#references)</sup>

### Añadir manualmente

Puedes introducir manualmente los datos de una llave para los protocolos Dallas, Cyfral y Metakom.<sup>[[2]](#references)</sup>

### Emular

Puedes emular una llave guardada, tanto si se leyó de una llave física como si se introdujo manualmente.<sup>[[2]](#references)</sup>

> [!TIP]
> Si los contactos integrados no pueden llegar al lector, conecta los contactos de datos y tierra a través de los pines GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Domando las llaves iButton con Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Documentación de Flipper Zero - Lectura de llaves iButton](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
