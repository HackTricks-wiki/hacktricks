# Análisis de archivos de Office

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Introducción

Microsoft ha creado **docenas de formatos de archivo de documentos de Office**, muchos de los cuales son populares para la distribución de ataques de phishing y malware debido a su capacidad para **incluir macros** (scripts VBA).

Hablando en términos generales, hay dos generaciones de formato de archivo de Office: los formatos **OLE** (extensiones de archivo como RTF, DOC, XLS, PPT), y los formatos "**Office Open XML**" (extensiones de archivo que incluyen DOCX, XLSX, PPTX). **Ambos** formatos son estructurados, formatos binarios de archivo compuesto que **permiten contenido Vinculado o Embebido** (Objetos). Los archivos OOXML son contenedores de archivos zip, lo que significa que una de las formas más fáciles de buscar datos ocultos es simplemente `unzip` el documento:
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
Como puede ver, parte de la estructura es creada por la jerarquía de archivos y carpetas. El resto se especifica dentro de los archivos XML. [_Nuevas Técnicas Esteganográficas para el Formato de Archivo OOXML_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) detalla algunas ideas para técnicas de ocultamiento de datos, pero los autores de desafíos CTF siempre estarán ideando nuevas.

Una vez más, existe un conjunto de herramientas Python para el examen y **análisis de documentos OLE y OOXML**: [oletools](http://www.decalage.info/python/oletools). Para documentos OOXML en particular, [OfficeDissector](https://www.officedissector.com) es un marco de análisis muy potente (y biblioteca Python). Este último incluye una [guía rápida para su uso](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt).

A veces, el desafío no es encontrar datos estáticos ocultos, sino **analizar una macro VBA** para determinar su comportamiento. Este es un escenario más realista y uno que los analistas en el campo realizan todos los días. Las herramientas disectoras mencionadas pueden indicar si una macro está presente y probablemente extraerla para usted. Una macro VBA típica en un documento de Office, en Windows, descargará un script de PowerShell en %TEMP% e intentará ejecutarlo, en cuyo caso ahora también tiene una tarea de análisis de script de PowerShell. Pero las macros VBA maliciosas rara vez son complicadas ya que VBA es [típicamente solo utilizada como una plataforma de lanzamiento para iniciar la ejecución de código](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/). En el caso de que necesite entender una macro VBA complicada, o si la macro está ofuscada y tiene una rutina de desempaquetado, no necesita tener una licencia de Microsoft Office para depurar esto. Puede usar [Libre Office](http://libreoffice.org): [su interfaz](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/) le será familiar a cualquiera que haya depurado un programa; puede establecer puntos de interrupción y crear variables de observación y capturar valores después de que hayan sido desempaquetados pero antes de que se haya ejecutado cualquier comportamiento de la carga útil. Incluso puede iniciar una macro de un documento específico desde una línea de comandos:
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## Ejecución Automática

Funciones de macro como `AutoOpen`, `AutoExec` o `Document_Open` serán **ejecutadas** **automáticamente**.

## Referencias

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
