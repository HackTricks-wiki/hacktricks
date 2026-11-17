# Análisis de archivos de Office

{{#include ../../../banners/hacktricks-training.md}}

Para obtener más información, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Este es solo un resumen:<sup>[[2]](#references)</sup>

Los documentos de Microsoft Office suelen presentarse en formatos antiguos, como RTF y DOC, XLS y PPT basados en OLE/CFBF, o en formatos más recientes de **Office Open XML (OOXML)**, como DOCX, XLSX y PPTX. Los documentos de Office pueden contener contenido activo, como macros, lo que los convierte en vectores comunes de phishing y malware. Los archivos OOXML son contenedores ZIP cuya jerarquía de archivos y contenido XML se pueden inspeccionar al descomprimirlos.<sup>[[1]](#references)[[2]](#references)</sup>

Se muestran el comando para descomprimir un documento y la estructura de salida, con el fin de explorar las estructuras de archivos OOXML. Se han documentado técnicas para ocultar datos en estos archivos, lo que demuestra que la innovación en la ocultación de datos en los desafíos CTF sigue avanzando.<sup>[[2]](#references)</sup>

Para el análisis, **oletools** y **OfficeDissector** ofrecen conjuntos de herramientas completos para examinar documentos OLE y OOXML. Estas herramientas ayudan a identificar y analizar macros incrustadas, que a menudo sirven como vectores para distribuir malware y suelen descargar y ejecutar cargas útiles maliciosas adicionales. El análisis de macros VBA se puede realizar sin Microsoft Office mediante LibreOffice, que permite depurar con puntos de interrupción y variables de inspección.<sup>[[2]](#references)</sup>

La instalación y el uso de **oletools** son sencillos; se proporcionan comandos para instalarlo mediante pip y extraer macros de documentos. En Word, las macros automáticas incluyen `AutoExec` y `AutoOpen`, mientras que `Document_Open` es un procedimiento de evento de apertura.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Análisis de macros VBA: código basura y UserForms

## Código basura

Las macros pueden contener **código inalcanzable o irrelevante** para ralentizar el análisis. Identifica las condiciones constantes y sigue el comportamiento alcanzable antes de dedicar tiempo a invertir una rama. El ejemplo siguiente usa una condición `If` que nunca puede ser verdadera para ocultar código basura.

![Una macro de Word que contiene una rama condicional inalcanzable con código basura](<../../../images/image (369).png>)

## Formularios de macro

Los UserForms de VBA pueden almacenar datos en controles como cuadros de texto. Como los formularios, los marcos y las páginas pueden exponer cada uno una colección `Controls`, los analistas deberían enumerar toda la jerarquía de controles en lugar de confiar únicamente en lo que muestra el formulario. El ejemplo siguiente almacena datos ocultos en cuadros de texto superpuestos.<sup>[[6]](#references)</sup>

Durante el análisis dinámico, la función `GetObject` de VBA puede recuperar un objeto Automation de un archivo o conectarse a un servidor Automation que ya esté en ejecución. Las macros pueden usar ese acceso a objetos para llegar a datos que no son evidentes en el documento visible; inspecciona tanto el objeto devuelto como el árbol de controles del UserForm.<sup>[[7]](#references)</sup>

![Un UserForm de macro con datos ocultos en cuadros de texto superpuestos](<../../../images/image (344).png>)

Para documentos de Office cifrados con contraseña, consulta el [flujo de trabajo de recuperación sin conexión basado en gramáticas](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Para archivos RFA de Revit que usan OLE/CFBF, consulta [recomputación de ECC, gzip controlado y explotación del deserializador](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); ese flujo de trabajo de explotación del parser es independiente del triaje de documentos de Office.

## References

- [1] [Documentación de OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Guía de campo de Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [3] [Documentación de olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Macros automáticas (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Colecciones, controles y objetos (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - Función `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
