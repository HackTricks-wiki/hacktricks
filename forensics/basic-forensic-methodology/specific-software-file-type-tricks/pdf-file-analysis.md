# Análisis de archivos PDF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com).
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Usa [**Trickest**](https://trickest.io/) para construir y **automatizar flujos de trabajo** con las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

De: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

El formato de archivo PDF es extremadamente complicado, con suficientes trucos y lugares ocultos [para escribir sobre ellos durante años](https://www.sultanik.com/pocorgtfo/). Esto también lo hace popular para los desafíos de forense de CTF. La NSA escribió una guía sobre estos lugares ocultos en 2008 titulada "Datos ocultos y metadatos en archivos Adobe PDF: riesgos y contramedidas de publicación". Ya no está disponible en su URL original, pero puedes [encontrar una copia aquí](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf). Ange Albertini también mantiene un wiki en GitHub de [trucos del formato de archivo PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md).

El formato PDF es parcialmente de texto plano, como HTML, pero con muchos "objetos" binarios en el contenido. Didier Stevens ha escrito [buen material introductorio](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) sobre el formato. Los objetos binarios pueden ser datos comprimidos o incluso cifrados, e incluyen contenido en lenguajes de script como JavaScript o Flash. Para mostrar la estructura de un PDF, puedes navegarlo con un editor de texto o abrirlo con un editor de formato de archivo con capacidad para PDF como Origami.

[qpdf](https://github.com/qpdf/qpdf) es una herramienta que puede ser útil para explorar un PDF y transformar o extraer información de él. Otro es un marco en Ruby llamado [Origami](https://github.com/mobmewireless/origami-pdf).

Cuando se explora el contenido de un PDF en busca de datos ocultos, algunos de los lugares ocultos para verificar incluyen:

* capas no visibles
* el formato de metadatos de Adobe "XMP"
* la función de "generación incremental" de PDF en la que se retiene una versión anterior pero no es visible para el usuario
* texto blanco sobre un fondo blanco
* texto detrás de imágenes
* una imagen detrás de una imagen superpuesta
* comentarios no mostrados

También hay varios paquetes de Python para trabajar con el formato de archivo PDF, como [PeepDF](https://github.com/jesparza/peepdf), que te permiten escribir tus propios scripts de análisis.
