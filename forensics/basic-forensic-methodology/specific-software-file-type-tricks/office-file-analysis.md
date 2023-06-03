# Análisis de archivos de Office

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Utiliza [**Trickest**](https://trickest.io/) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Introducción

Microsoft ha creado **docenas de formatos de archivo de documentos de Office**, muchos de los cuales son populares para la distribución de ataques de phishing y malware debido a su capacidad para **incluir macros** (scripts VBA).

En términos generales, hay dos generaciones de formato de archivo de Office: los **formatos OLE** (extensiones de archivo como RTF, DOC, XLS, PPT) y los "**formatos Office Open XML**" (extensiones de archivo que incluyen DOCX, XLSX, PPTX). **Ambos** formatos son formatos binarios de archivo compuestos y estructurados que **permiten contenido vinculado o incrustado** (objetos). Los archivos OOXML son contenedores de archivos zip, lo que significa que una de las formas más fáciles de comprobar la presencia de datos ocultos es simplemente `descomprimir` el documento:
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
Como se puede observar, parte de la estructura es creada por la jerarquía de archivos y carpetas. El resto está especificado dentro de los archivos XML. [_New Steganographic Techniques for the OOXML File Format_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) detalla algunas ideas para técnicas de ocultación de datos, pero los autores de desafíos CTF siempre estarán ideando nuevas.

Una vez más, existe un conjunto de herramientas de Python para el examen y **análisis de documentos OLE y OOXML**: [oletools](http://www.decalage.info/python/oletools). Para documentos OOXML en particular, [OfficeDissector](https://www.officedissector.com) es un marco de análisis muy potente (y una biblioteca de Python). Este último incluye una [guía rápida para su uso](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt).

A veces, el desafío no es encontrar datos estáticos ocultos, sino **analizar una macro VBA** para determinar su comportamiento. Este es un escenario más realista y uno que los analistas en el campo realizan todos los días. Las herramientas de disector mencionadas anteriormente pueden indicar si una macro está presente y probablemente extraerla para usted. Una macro VBA típica en un documento de Office, en Windows, descargará un script de PowerShell a %TEMP% e intentará ejecutarlo, en cuyo caso ahora tiene una tarea de análisis de script de PowerShell. Pero las macros VBA maliciosas rara vez son complicadas ya que VBA se utiliza [normalmente como una plataforma de salto para arrancar la ejecución de código](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/). En el caso de que necesite entender una macro VBA complicada, o si la macro está ofuscada y tiene una rutina de desempaquetado, no necesita tener una licencia de Microsoft Office para depurar esto. Puede usar [Libre Office](http://libreoffice.org): [su interfaz](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/) será familiar para cualquiera que haya depurado un programa; puede establecer puntos de interrupción y crear variables de observación y capturar valores después de que se hayan desempaquetado pero antes de que se haya ejecutado cualquier comportamiento de carga útil. Incluso puede iniciar una macro de un documento específico desde una línea de comando:
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)

Las `oletools` son un conjunto de herramientas para analizar archivos OLE y MS Office. Estas herramientas pueden ayudar a los investigadores a analizar archivos maliciosos y documentos de Office que contienen macros maliciosas. Algunas de las herramientas incluidas en `oletools` son:

- `olevba`: una herramienta para analizar macros de VBA en archivos de Office.
- `oleid`: una herramienta para identificar archivos OLE maliciosos.
- `olemeta`: una herramienta para extraer metadatos de archivos OLE y Office.
- `oledump`: una herramienta para analizar archivos OLE y Office y extraer información de ellos.
- `macro_pack`: una herramienta para empaquetar archivos de Office con macros maliciosas.

Estas herramientas pueden ser muy útiles para analizar archivos de Office sospechosos y detectar posibles amenazas de seguridad.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## Ejecución Automática

Las funciones de macro como `AutoOpen`, `AutoExec` o `Document_Open` se **ejecutarán automáticamente**.

## Referencias

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
