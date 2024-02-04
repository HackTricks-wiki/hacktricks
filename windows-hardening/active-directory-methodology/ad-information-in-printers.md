<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**artículos oficiales de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


Hay varios blogs en Internet que **destacan los peligros de dejar las impresoras configuradas con LDAP con credenciales de inicio de sesión predeterminadas/débiles**.\
Esto se debe a que un atacante podría **engañar a la impresora para autenticarse contra un servidor LDAP falso** (típicamente un `nc -vv -l -p 444` es suficiente) y capturar las **credenciales de la impresora en texto claro**.

Además, varias impresoras contendrán **logs con nombres de usuario** o incluso podrían ser capaces de **descargar todos los nombres de usuario** del Controlador de Dominio.

Toda esta **información sensible** y la **falta común de seguridad** hace que las impresoras sean muy interesantes para los atacantes.

Algunos blogs sobre el tema:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Configuración de la Impresora
- **Ubicación**: La lista de servidores LDAP se encuentra en: `Red > Configuración LDAP > Configuración de LDAP`.
- **Comportamiento**: La interfaz permite modificaciones en el servidor LDAP sin necesidad de volver a ingresar credenciales, buscando la conveniencia del usuario pero planteando riesgos de seguridad.
- **Explotación**: La explotación implica redirigir la dirección del servidor LDAP a una máquina controlada y aprovechar la función "Probar conexión" para capturar credenciales.

## Captura de Credenciales

### Método 1: Escucha de Netcat
Un simple escucha de netcat podría ser suficiente:
```bash
sudo nc -k -v -l -p 386
```
Sin embargo, el éxito de este método varía.

### Método 2: Servidor LDAP completo con Slapd
Un enfoque más confiable implica configurar un servidor LDAP completo porque la impresora realiza una unión nula seguida de una consulta antes de intentar la unión de credenciales.

1. **Configuración del Servidor LDAP**: La guía sigue los pasos de [esta fuente](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Pasos Clave**:
- Instalar OpenLDAP.
- Configurar la contraseña de administrador.
- Importar esquemas básicos.
- Establecer el nombre de dominio en la base de datos LDAP.
- Configurar TLS de LDAP.
3. **Ejecución del Servicio LDAP**: Una vez configurado, el servicio LDAP se puede ejecutar usando:
```
slapd -d 2
```

**Para obtener pasos más detallados, consulta la [fuente original](https://grimhacker.com/2018/03/09/just-a-printer/).**

# Referencias
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
