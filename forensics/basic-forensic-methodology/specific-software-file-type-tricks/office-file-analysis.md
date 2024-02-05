# Análisis de archivos de oficina

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Introducción

Microsoft ha creado **docenas de formatos de archivo de documentos de oficina**, muchos de los cuales son populares para la distribución de ataques de phishing y malware debido a su capacidad de **incluir macros** (scripts VBA).

En términos generales, existen dos generaciones de formatos de archivo de Office: los **formatos OLE** (extensiones de archivo como RTF, DOC, XLS, PPT) y los formatos "**Office Open XML**" (extensiones de archivo que incluyen DOCX, XLSX, PPTX). **Ambos** formatos son formatos binarios de archivo compuesto estructurados que **permiten contenido vinculado o incrustado** (objetos). Los archivos OOXML son contenedores de archivos zip, lo que significa que una de las formas más fáciles de verificar datos ocultos es simplemente `descomprimir` el documento:
```
$ unzip example.docx
Archive:  example.docx
inflating: [Content_Types].xml
inflating: _rels/.rels
inflating: word/_rels/document.xml.rels
inflating: word/document.xml
inflating: word/theme/theme1.xml
extracting: docProps/thumbnail.jpeg
inflating: word/comments.xml
inflating: word/settings.xml
inflating: word/fontTable.xml
inflating: word/styles.xml
inflating: word/stylesWithEffects.xml
inflating: docProps/app.xml
inflating: docProps/core.xml
inflating: word/webSettings.xml
inflating: word/numbering.xml
$ tree
.
├── [Content_Types].xml
├── _rels
├── docProps
│   ├── app.xml
│   ├── core.xml
│   └── thumbnail.jpeg
└── word
├── _rels
│   └── document.xml.rels
├── comments.xml
├── document.xml
├── fontTable.xml
├── numbering.xml
├── settings.xml
├── styles.xml
├── stylesWithEffects.xml
├── theme
│   └── theme1.xml
└── webSettings.xml
```
Como puedes ver, parte de la estructura es creada por el archivo y la jerarquía de carpetas. El resto está especificado dentro de los archivos XML. [_Nuevas técnicas esteganográficas para el formato de archivo OOXML_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) detalla algunas ideas para técnicas de ocultación de datos, pero los autores de desafíos CTF siempre estarán ideando nuevas.

Una vez más, existe un conjunto de herramientas en Python para el examen y **análisis de documentos OLE y OOXML**: [oletools](http://www.decalage.info/python/oletools). Para documentos OOXML en particular, [OfficeDissector](https://www.officedissector.com) es un marco de análisis muy potente (y una biblioteca de Python). Este último incluye una [guía rápida sobre su uso](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt).

A veces, el desafío no es encontrar datos estáticos ocultos, sino **analizar una macro VBA** para determinar su comportamiento. Este es un escenario más realista y uno que los analistas en el campo realizan a diario. Las herramientas de disector mencionadas pueden indicar si hay una macro presente y probablemente extraerla para ti. Una macro VBA típica en un documento de Office, en Windows, descargará un script de PowerShell a %TEMP% e intentará ejecutarlo, en cuyo caso ahora tendrás también una tarea de análisis de script de PowerShell. Pero las macros VBA maliciosas rara vez son complicadas, ya que VBA se [suele utilizar solo como una plataforma de inicio para la ejecución de código](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/). En el caso de que necesites entender una macro VBA complicada, o si la macro está ofuscada y tiene un rutina de desempaquetado, no necesitas tener una licencia de Microsoft Office para depurar esto. Puedes usar [Libre Office](http://libreoffice.org): [su interfaz](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/) será familiar para cualquiera que haya depurado un programa; puedes establecer puntos de interrupción, crear variables de seguimiento y capturar valores después de que se hayan desempaquetado pero antes de que se haya ejecutado el comportamiento del payload. Incluso puedes iniciar una macro de un documento específico desde una línea de comandos:
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## Ejecución Automática

Las funciones de macro como `AutoOpen`, `AutoExec` o `Document_Open` se **ejecutarán automáticamente**.

## Referencias

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, ¡consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
