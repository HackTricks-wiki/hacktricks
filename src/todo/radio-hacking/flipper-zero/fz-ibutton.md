# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Para más información sobre qué es un iButton, consulta:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

La parte **azul** de la siguiente imagen es cómo necesitarías **colocar el iButton real** para que el Flipper pueda **leerlo.** La parte **verde** es cómo necesitas **tocar el lector** con el Flipper Zero para **emular correctamente un iButton**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

En Modo de Lectura, el Flipper está esperando a que el iButton toque y es capaz de procesar cualquiera de los tres tipos de llaves: **Dallas, Cyfral y Metakom**. El Flipper **determinará el tipo de llave por sí mismo**. El nombre del protocolo de la llave se mostrará en la pantalla sobre el número de ID.

### Add manually

Es posible **agregar manualmente** un iButton de tipo: **Dallas, Cyfral y Metakom**

### **Emulate**

Es posible **emular** iButtons guardados (leídos o agregados manualmente).

> [!NOTE]
> Si no puedes hacer que los contactos esperados del Flipper Zero toquen el lector, puedes **usar el GPIO externo:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
