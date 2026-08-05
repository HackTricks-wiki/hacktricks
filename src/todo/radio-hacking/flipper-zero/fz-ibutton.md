# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Para obtener más información sobre qué es un iButton, consulta:


{{#ref}}
../ibutton.md
{{#endref}}

## Diseño

La parte **azul** de la siguiente imagen muestra cómo debes **colocar el iButton real** para que el Flipper pueda **leerlo**. La parte **verde** muestra cómo debes **tocar el lector** con el Flipper Zero para **emular correctamente un iButton**.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Leer

En el modo de lectura, Flipper espera a que la llave iButton toque el dispositivo y puede procesar cualquiera de los tres tipos de llaves: **Dallas, Cyfral y Metakom**. Flipper **determinará por sí mismo el tipo de llave**. El nombre del protocolo de la llave se mostrará en la pantalla, encima del número de ID.<sup>[[1]](#references)</sup>

### Añadir manualmente

Es posible **añadir manualmente** un iButton de tipo: **Dallas, Cyfral y Metakom**

### **Emular**

Es posible **emular** iButtons guardados (leídos o añadidos manualmente).

> [!TIP]
> Si no puedes conseguir que los contactos esperados del Flipper Zero toquen el lector, puedes **usar el GPIO externo:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Referencias

- [1] [Dominar las llaves iButton con Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
