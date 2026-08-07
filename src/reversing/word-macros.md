# Macros de Word

{{#include ../banners/hacktricks-training.md}}

### Código basura

Es muy común encontrar **código basura que nunca se utiliza** para dificultar el reversing de la macro.\
Por ejemplo, en la siguiente imagen puedes ver que se utiliza un `If` que nunca va a ser verdadero para ejecutar código basura e inútil.

![Macros de Word - Código basura: Por ejemplo, en la siguiente imagen puedes ver que se utiliza un If que nunca va a ser verdadero para ejecutar código basura e inútil](<../images/image (369).png>)

### Formularios de macros

Mediante la función **GetObject** es posible obtener datos de los formularios de la macro. Esto puede utilizarse para dificultar el análisis. La siguiente es una imagen de un formulario de macro utilizado para **ocultar datos dentro de cuadros de texto** (un cuadro de texto puede estar ocultando otros cuadros de texto):

![Código basura - Formularios de macros: Mediante la función GetObject es posible obtener datos de los formularios de la macro. Esto puede utilizarse para dificultar el análisis. La siguiente es una imagen de un...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
