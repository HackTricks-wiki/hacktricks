# Detección de Phishing

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción

Para detectar un intento de phishing es importante **comprender las técnicas de phishing que se utilizan actualmente**. En la página principal de esta publicación, puedes encontrar esta información, por lo que si no estás al tanto de las técnicas que se utilizan hoy en día, te recomiendo ir a la página principal y leer al menos esa sección.

Esta publicación se basa en la idea de que los **atacantes intentarán de alguna manera imitar o utilizar el nombre de dominio de la víctima**. Si tu dominio se llama `ejemplo.com` y te están haciendo phishing utilizando un nombre de dominio completamente diferente por alguna razón, como `hasganadoelloteria.com`, estas técnicas no lo descubrirán.

## Variaciones de nombres de dominio

Es bastante **fácil** **descubrir** aquellos intentos de **phishing** que utilizarán un **nombre de dominio similar** dentro del correo electrónico.\
Es suficiente con **generar una lista de los nombres de phishing más probables** que un atacante podría usar y **verificar** si está **registrado** o simplemente verificar si hay alguna **IP** que lo esté utilizando.

### Encontrar dominios sospechosos

Para este propósito, puedes utilizar cualquiera de las siguientes herramientas. Ten en cuenta que estas herramientas también realizarán solicitudes DNS automáticamente para verificar si el dominio tiene alguna IP asignada:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Puedes encontrar una breve explicación de esta técnica en la página principal. O lee la investigación original en [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**

Por ejemplo, una modificación de 1 bit en el dominio microsoft.com puede transformarlo en _windnws.com._\
**Los atacantes pueden registrar tantos dominios con bit-flipping como sea posible relacionados con la víctima para redirigir a los usuarios legítimos a su infraestructura**.

**Todos los posibles nombres de dominio con bit-flipping también deben ser monitoreados**.

### Verificaciones básicas

Una vez que tengas una lista de posibles nombres de dominio sospechosos, deberías **verificarlos** (principalmente los puertos HTTP y HTTPS) para **ver si están utilizando algún formulario de inicio de sesión similar** al de alguno de los dominios de la víctima.\
También podrías verificar el puerto 3333 para ver si está abierto y ejecutando una instancia de `gophish`.\
También es interesante saber **cuánto tiempo tiene cada dominio sospechoso descubierto**, cuanto más joven sea, más riesgoso será.\
También puedes obtener **capturas de pantalla** de la página web sospechosa de HTTP y/o HTTPS para ver si es sospechosa y en ese caso **acceder para investigar más a fondo**.

### Verificaciones avanzadas

Si deseas ir un paso más allá, te recomendaría **monitorear esos dominios sospechosos y buscar más** de vez en cuando (¿todos los días? solo toma unos segundos/minutos). También deberías **verificar** los **puertos** abiertos de las IPs relacionadas y **buscar instancias de `gophish` u herramientas similares** (sí, los atacantes también cometen errores) y **monitorear las páginas web HTTP y HTTPS de los dominios y subdominios sospechosos** para ver si han copiado algún formulario de inicio de sesión de las páginas web de la víctima.\
Para **automatizar esto**, te recomendaría tener una lista de formularios de inicio de sesión de los dominios de la víctima, rastrear las páginas web sospechosas y comparar cada formulario de inicio de sesión encontrado dentro de los dominios sospechosos con cada formulario de inicio de sesión del dominio de la víctima utilizando algo como `ssdeep`.\
Si has localizado los formularios de inicio de sesión de los dominios sospechosos, puedes intentar **enviar credenciales falsas** y **verificar si te redirige al dominio de la víctima**.

## Nombres de dominio que utilizan palabras clave

La página principal también menciona una técnica de variación de nombres de dominio que consiste en poner el **nombre de dominio de la víctima dentro de un dominio más grande** (por ejemplo, paypal-financial.com para paypal.com).

### Transparencia del certificado

No es posible seguir el enfoque anterior de "Fuerza bruta", pero en realidad es **posible descubrir tales intentos de phishing** también gracias a la transparencia del certificado. Cada vez que se emite un certificado por una CA, los detalles se hacen públicos. Esto significa que al leer la transparencia del certificado o incluso monitorearla, es **posible encontrar dominios que están utilizando una palabra clave dentro de su nombre**. Por ejemplo, si un atacante genera un certificado de [https://paypal-financial.com](https://paypal-financial.com), al ver el certificado es posible encontrar la palabra clave "paypal" y saber que se está utilizando un correo electrónico sospechoso.

La publicación [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugiere que puedes usar Censys para buscar certificados que afecten a una palabra clave específica y filtrar por fecha (solo certificados "nuevos") y por el emisor de la CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../.gitbook/assets/image (390).png>)

Sin embargo, puedes hacer "lo mismo" utilizando el sitio web gratuito [**crt.sh**](https://crt.sh). Puedes **buscar la palabra clave** y luego **filtrar** los resultados **por fecha y CA** si lo deseas.

![](<../../.gitbook/assets/image (391).png>)

Utilizando esta última opción, incluso puedes utilizar el campo Identidades coincidentes para ver si alguna identidad del dominio real coincide con alguna de los dominios sospechosos (ten en cuenta que un dominio sospechoso puede ser un falso positivo).

**Otra alternativa** es el fantástico proyecto llamado [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream proporciona un flujo en tiempo real de certificados recién generados que puedes utilizar para detectar palabras clave especificadas en tiempo real o casi real. De hecho, hay un proyecto llamado [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) que hace precisamente eso.

### **Nuevos dominios**

**Una última alternativa** es recopilar una lista de **dominios recién registrados** para algunos TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) ofrece este servicio) y **verificar las palabras clave en estos dominios**. Sin embargo, los dominios largos suelen utilizar uno o más subdominios, por lo tanto, la palabra clave no aparecerá dentro del FLD y no podrás encontrar el subdominio de phishing.

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
