# Análisis de archivos PDF

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

De: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

El formato PDF es extremadamente complicado, con suficientes trucos y lugares ocultos [para escribir durante años](https://www.sultanik.com/pocorgtfo/). Esto también lo hace popular para desafíos forenses de CTF. La NSA escribió una guía sobre estos lugares ocultos en 2008 titulada "Datos ocultos y metadatos en archivos PDF de Adobe: Riesgos de publicación y contramedidas". Ya no está disponible en su URL original, pero puedes [encontrar una copia aquí](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf). Ange Albertini también mantiene un wiki en GitHub sobre [trucos del formato de archivo PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md).

El formato PDF es parcialmente de texto plano, como HTML, pero con muchos "objetos" binarios en el contenido. Didier Stevens ha escrito [buen material introductorio](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) sobre el formato. Los objetos binarios pueden ser datos comprimidos o incluso encriptados, e incluyen contenido en lenguajes de script como JavaScript o Flash. Para mostrar la estructura de un PDF, puedes navegarlo con un editor de texto o abrirlo con un editor de formato de archivo con conocimiento de PDF como Origami.

[qpdf](https://github.com/qpdf/qpdf) es una herramienta que puede ser útil para explorar un PDF y transformar o extraer información de él. Otra es un marco en Ruby llamado [Origami](https://github.com/mobmewireless/origami-pdf).

Al explorar el contenido de un PDF en busca de datos ocultos, algunos de los lugares para verificar incluyen:

* capas no visibles
* el formato de metadatos de Adobe "XMP"
* la característica de "generación incremental" de PDF en la que se conserva una versión anterior pero no es visible para el usuario
* texto blanco sobre un fondo blanco
* texto detrás de imágenes
* una imagen detrás de una imagen superpuesta
* comentarios no mostrados

También existen varios paquetes de Python para trabajar con el formato de archivo PDF, como [PeepDF](https://github.com/jesparza/peepdf), que te permiten escribir tus propios scripts de análisis. 

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
