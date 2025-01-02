# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Código Basura

Es muy común encontrar **código basura que nunca se utiliza** para dificultar la reversión de la macro.\
Por ejemplo, en la siguiente imagen puedes ver que se utiliza un If que nunca va a ser verdadero para ejecutar algún código basura y inútil.

![](<../images/image (369).png>)

### Formularios de Macro

Usando la función **GetObject** es posible obtener datos de los formularios de la macro. Esto se puede utilizar para dificultar el análisis. La siguiente es una foto de un formulario de macro utilizado para **ocultar datos dentro de cuadros de texto** (un cuadro de texto puede estar ocultando otros cuadros de texto):

![](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
