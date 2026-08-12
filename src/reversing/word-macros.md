# Macros de Word

{{#include ../banners/hacktricks-training.md}}

## Código basura

Las macros pueden contener **código inalcanzable o irrelevante** cuyo objetivo es ralentizar el análisis. Identifica las condiciones constantes y rastrea el comportamiento alcanzable antes de dedicar tiempo a revertir una rama. El ejemplo siguiente usa una condición `If` que nunca puede ser verdadera para ocultar código basura.

![Una macro de Word que contiene una rama condicional inalcanzable con código basura](<../images/image (369).png>)

## Formularios de macros

Los UserForms de VBA pueden almacenar datos en controles como cuadros de texto. Debido a que los formularios, marcos y páginas pueden exponer cada uno una colección `Controls`, los analistas deben enumerar toda la jerarquía de controles en lugar de basarse únicamente en lo que muestra el formulario. El ejemplo siguiente almacena datos ocultos en cuadros de texto superpuestos.<sup>[[1]](#references)</sup>

Durante el análisis dinámico, la función `GetObject` de VBA puede recuperar un objeto de Automation desde un archivo o conectarse a un servidor de Automation que ya esté en ejecución. Las macros pueden usar ese acceso al objeto para llegar a datos que no son evidentes en el documento visible; inspecciona tanto el objeto devuelto como el árbol de controles del UserForm.<sup>[[2]](#references)</sup>

![Un UserForm de macro con datos ocultos en cuadros de texto superpuestos](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Colecciones, controles y objetos (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - función `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
