<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


Para una evaluación de phishing, a veces puede ser útil **clonar completamente un sitio web**.

Tenga en cuenta que también puede agregar algunos payloads al sitio web clonado, como un gancho BeEF para "controlar" la pestaña del usuario.

Existen diferentes herramientas que puede utilizar para este propósito:

## wget
```text
wget -mk -nH
```
## goclone

El comando `goclone` es una herramienta de línea de comandos que permite clonar sitios web completos, incluyendo todas las páginas, imágenes y otros recursos. Esta herramienta es muy útil para realizar ataques de phishing, ya que permite crear una copia exacta de un sitio web legítimo y engañar a los usuarios para que ingresen sus credenciales en la página clonada.

Para utilizar `goclone`, primero debemos instalarlo en nuestro sistema. Luego, podemos ejecutar el comando `goclone` seguido de la URL del sitio web que deseamos clonar y la ruta donde deseamos guardar la copia. Una vez que se completa el proceso de clonación, podemos modificar la página clonada para agregar nuestro código malicioso y personalizarla para que se vea más convincente.

Es importante tener en cuenta que el uso de `goclone` para fines maliciosos es ilegal y puede tener graves consecuencias legales. Solo debe ser utilizado con fines educativos o de prueba en entornos controlados y con el permiso explícito del propietario del sitio web que se está clonando.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Kit de herramientas de ingeniería social

---

### Clonar un sitio web

#### Descripción

Clonar un sitio web es una técnica comúnmente utilizada en la ingeniería social para engañar a las víctimas y hacer que ingresen información confidencial en un sitio web falso. Esta técnica es muy efectiva y se utiliza con frecuencia en ataques de phishing.

#### Procedimiento

1. Identificar el sitio web que se va a clonar.
2. Descargar el sitio web utilizando herramientas como `wget` o `httrack`.
3. Modificar el sitio web clonado para que se parezca al sitio web original.
4. Configurar el sitio web clonado en un servidor web.
5. Enviar un correo electrónico o mensaje de texto a la víctima con un enlace al sitio web clonado.
6. Esperar a que la víctima ingrese información confidencial en el sitio web clonado.

#### Ejemplo

Supongamos que un atacante quiere obtener las credenciales de inicio de sesión de un sitio web de banca en línea. El atacante podría seguir los siguientes pasos:

1. Identificar el sitio web de banca en línea que se va a clonar.
2. Descargar el sitio web utilizando `wget`.
3. Modificar el sitio web clonado para que se parezca al sitio web original.
4. Configurar el sitio web clonado en un servidor web.
5. Enviar un correo electrónico a la víctima con un enlace al sitio web clonado, haciéndose pasar por el sitio web de banca en línea.
6. Esperar a que la víctima ingrese sus credenciales de inicio de sesión en el sitio web clonado.
7. Recopilar las credenciales de inicio de sesión de la víctima.

#### Contramedidas

- Utilizar autenticación de dos factores.
- Capacitar a los usuarios para que identifiquen sitios web falsos.
- Utilizar herramientas de detección de phishing.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
