# Análisis de archivos PDF

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=pdf-file-analysis) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas** del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=pdf-file-analysis" %}

**Para más detalles, consulta:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

El formato PDF es conocido por su complejidad y potencial para ocultar datos, lo que lo convierte en un punto focal para los desafíos forenses de CTF. Combina elementos de texto plano con objetos binarios, que pueden estar comprimidos o encriptados, y puede incluir scripts en lenguajes como JavaScript o Flash. Para comprender la estructura de un PDF, se puede consultar el [material introductorio](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens, o utilizar herramientas como un editor de texto o un editor específico de PDF como Origami.

Para la exploración o manipulación detallada de PDFs, están disponibles herramientas como [qpdf](https://github.com/qpdf/qpdf) y [Origami](https://github.com/mobmewireless/origami-pdf). Los datos ocultos dentro de los PDF pueden estar disimulados en:

* Capas invisibles
* Formato de metadatos XMP de Adobe
* Generaciones incrementales
* Texto con el mismo color que el fondo
* Texto detrás de imágenes o superpuesto a imágenes
* Comentarios no mostrados

Para un análisis personalizado de PDF, se pueden utilizar bibliotecas de Python como [PeepDF](https://github.com/jesparza/peepdf) para crear scripts de análisis personalizados. Además, el potencial de los PDF para el almacenamiento de datos ocultos es tan vasto que recursos como la guía de la NSA sobre riesgos y contramedidas de PDF, aunque ya no se encuentra alojada en su ubicación original, aún ofrecen información valiosa. Una [copia de la guía](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) y una colección de [trucos de formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) por Ange Albertini pueden proporcionar lecturas adicionales sobre el tema.

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
