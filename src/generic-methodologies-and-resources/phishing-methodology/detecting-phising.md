# Detección de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introducción

Para detectar un intento de phishing es importante **entender las técnicas de phishing que se están utilizando hoy en día**. En la página principal de esta publicación, puedes encontrar esta información, así que si no estás al tanto de qué técnicas se están utilizando hoy, te recomiendo que vayas a la página principal y leas al menos esa sección.

Esta publicación se basa en la idea de que los **atacantes intentarán de alguna manera imitar o usar el nombre de dominio de la víctima**. Si tu dominio se llama `example.com` y eres víctima de phishing utilizando un nombre de dominio completamente diferente por alguna razón como `youwonthelottery.com`, estas técnicas no lo descubrirán.

## Variaciones de nombres de dominio

Es bastante **fácil** **descubrir** esos intentos de **phishing** que utilizarán un **nombre de dominio similar** dentro del correo electrónico.\
Es suficiente con **generar una lista de los nombres de phishing más probables** que un atacante puede usar y **verificar** si está **registrado** o simplemente comprobar si hay alguna **IP** usándolo.

### Encontrar dominios sospechosos

Para este propósito, puedes usar cualquiera de las siguientes herramientas. Ten en cuenta que estas herramientas también realizarán solicitudes DNS automáticamente para verificar si el dominio tiene alguna IP asignada:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Puedes encontrar una breve explicación de esta técnica en la página principal. O leer la investigación original en** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Por ejemplo, una modificación de 1 bit en el dominio microsoft.com puede transformarlo en _windnws.com._\
**Los atacantes pueden registrar tantos dominios de bit-flipping como sea posible relacionados con la víctima para redirigir a usuarios legítimos a su infraestructura**.

**Todos los posibles nombres de dominio de bit-flipping también deben ser monitoreados.**

### Comprobaciones básicas

Una vez que tengas una lista de nombres de dominio potencialmente sospechosos, debes **verificarlos** (principalmente los puertos HTTP y HTTPS) para **ver si están utilizando algún formulario de inicio de sesión similar** al de alguno de los dominios de la víctima.\
También podrías verificar el puerto 3333 para ver si está abierto y ejecutando una instancia de `gophish`.\
También es interesante saber **cuán antiguo es cada dominio sospechoso descubierto**, cuanto más joven es, más riesgoso es.\
También puedes obtener **capturas de pantalla** de la página web sospechosa en HTTP y/o HTTPS para ver si es sospechosa y en ese caso **acceder a ella para echar un vistazo más profundo**.

### Comprobaciones avanzadas

Si deseas ir un paso más allá, te recomendaría **monitorear esos dominios sospechosos y buscar más** de vez en cuando (¿cada día? solo toma unos segundos/minutos). También deberías **verificar** los **puertos** abiertos de las IP relacionadas y **buscar instancias de `gophish` o herramientas similares** (sí, los atacantes también cometen errores) y **monitorear las páginas web HTTP y HTTPS de los dominios y subdominios sospechosos** para ver si han copiado algún formulario de inicio de sesión de las páginas web de la víctima.\
Para **automatizar esto**, te recomendaría tener una lista de formularios de inicio de sesión de los dominios de la víctima, rastrear las páginas web sospechosas y comparar cada formulario de inicio de sesión encontrado dentro de los dominios sospechosos con cada formulario de inicio de sesión del dominio de la víctima utilizando algo como `ssdeep`.\
Si has localizado los formularios de inicio de sesión de los dominios sospechosos, puedes intentar **enviar credenciales falsas** y **verificar si te redirige al dominio de la víctima**.

## Nombres de dominio que utilizan palabras clave

La página principal también menciona una técnica de variación de nombres de dominio que consiste en poner el **nombre de dominio de la víctima dentro de un dominio más grande** (por ejemplo, paypal-financial.com para paypal.com).

### Transparencia de Certificados

No es posible tomar el enfoque anterior de "Fuerza Bruta", pero en realidad es **posible descubrir tales intentos de phishing** también gracias a la transparencia de certificados. Cada vez que un certificado es emitido por una CA, los detalles se hacen públicos. Esto significa que al leer la transparencia de certificados o incluso monitorearla, es **posible encontrar dominios que están utilizando una palabra clave dentro de su nombre**. Por ejemplo, si un atacante genera un certificado de [https://paypal-financial.com](https://paypal-financial.com), al ver el certificado es posible encontrar la palabra clave "paypal" y saber que se está utilizando un correo electrónico sospechoso.

La publicación [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugiere que puedes usar Censys para buscar certificados que afecten a una palabra clave específica y filtrar por fecha (solo "nuevos" certificados) y por el emisor de la CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Sin embargo, puedes hacer "lo mismo" utilizando la web gratuita [**crt.sh**](https://crt.sh). Puedes **buscar la palabra clave** y **filtrar** los resultados **por fecha y CA** si lo deseas.

![](<../../images/image (519).png>)

Usando esta última opción, incluso puedes usar el campo Identidades Coincidentes para ver si alguna identidad del dominio real coincide con alguno de los dominios sospechosos (ten en cuenta que un dominio sospechoso puede ser un falso positivo).

**Otra alternativa** es el fantástico proyecto llamado [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream proporciona un flujo en tiempo real de certificados recién generados que puedes usar para detectar palabras clave especificadas en (casi) tiempo real. De hecho, hay un proyecto llamado [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) que hace exactamente eso.

### **Nuevos dominios**

**Una última alternativa** es reunir una lista de **dominios recién registrados** para algunos TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) proporciona tal servicio) y **verificar las palabras clave en estos dominios**. Sin embargo, los dominios largos suelen usar uno o más subdominios, por lo tanto, la palabra clave no aparecerá dentro del FLD y no podrás encontrar el subdominio de phishing.

{{#include ../../banners/hacktricks-training.md}}
