# BloodHound y Otras Herramientas de Enumeración de AD

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Explorador de AD

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) es parte de Sysinternal Suite:

> Un visor y editor avanzado de Active Directory (AD). Puedes usar AD Explorer para navegar fácilmente por una base de datos de AD, definir ubicaciones favoritas, ver propiedades de objetos y atributos sin abrir cuadros de diálogo, editar permisos, ver el esquema de un objeto y ejecutar búsquedas sofisticadas que puedes guardar y volver a ejecutar.

### Instantáneas

AD Explorer puede crear instantáneas de un AD para que puedas verificarlo sin conexión.\
Se puede utilizar para descubrir vulnerabilidades sin conexión o para comparar diferentes estados de la base de datos de AD a lo largo del tiempo.

Se requerirá el nombre de usuario, la contraseña y la dirección para conectarse (se requiere cualquier usuario de AD).

Para tomar una instantánea de AD, ve a `Archivo` --> `Crear instantánea` e introduce un nombre para la instantánea.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) es una herramienta que extrae y combina varios artefactos de un entorno de AD. La información se puede presentar en un **informe de Microsoft Excel con formato especial** que incluye vistas resumidas con métricas para facilitar el análisis y proporcionar una imagen holística del estado actual del entorno de AD objetivo.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

Desde [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound es una aplicación web de una sola página en Javascript, construida sobre [Linkurious](http://linkurio.us/), compilada con [Electron](http://electron.atom.io/), con una base de datos [Neo4j](https://neo4j.com/) alimentada por un recolector de datos en C#.

BloodHound utiliza la teoría de grafos para revelar las relaciones ocultas y a menudo no intencionadas dentro de un entorno de Active Directory o Azure. Los atacantes pueden usar BloodHound para identificar fácilmente rutas de ataque altamente complejas que de otra manera serían imposibles de identificar rápidamente. Los defensores pueden usar BloodHound para identificar y eliminar esas mismas rutas de ataque. Tanto los equipos azules como los rojos pueden usar BloodHound para obtener fácilmente una comprensión más profunda de las relaciones de privilegios en un entorno de Active Directory o Azure.

Por lo tanto, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) es una herramienta increíble que puede enumerar un dominio automáticamente, guardar toda la información, encontrar posibles rutas de escalada de privilegios y mostrar toda la información utilizando gráficos.

Bloodhound se compone de 2 partes principales: **ingestores** y la **aplicación de visualización**.

Los **ingestores** se utilizan para **enumerar el dominio y extraer toda la información** en un formato que la aplicación de visualización entenderá.

La **aplicación de visualización utiliza neo4j** para mostrar cómo está relacionada toda la información y para mostrar diferentes formas de escalar privilegios en el dominio.

### Instalación
Después de la creación de BloodHound CE, todo el proyecto se actualizó para facilitar su uso con Docker. La forma más sencilla de comenzar es utilizar su configuración preconfigurada de Docker Compose.

1. Instalar Docker Compose. Esto debería estar incluido en la instalación de [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Ejecutar:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Encuentra la contraseña generada aleatoriamente en la salida del terminal de Docker Compose.
4. En un navegador, ve a http://localhost:8080/ui/login. Inicia sesión con un nombre de usuario de admin y la contraseña generada aleatoriamente de los registros.

Después de esto, necesitarás cambiar la contraseña generada aleatoriamente y tendrás la nueva interfaz lista, desde la cual puedes descargar directamente los ingestores.

### SharpHound

Tienen varias opciones, pero si deseas ejecutar SharpHound desde una PC unida al dominio, utilizando tu usuario actual y extraer toda la información, puedes hacer:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Puedes leer más sobre **CollectionMethod** y la sesión de bucle [aquí](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Si deseas ejecutar SharpHound utilizando credenciales diferentes, puedes crear una sesión CMD netonly y ejecutar SharpHound desde allí:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Aprende más sobre Bloodhound en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) es una herramienta para encontrar **vulnerabilidades** en las **Directivas de Grupo** asociadas al Active Directory. \
Necesitas **ejecutar group3r** desde un host dentro del dominio utilizando **cualquier usuario del dominio**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **evalúa la postura de seguridad de un entorno de AD** y proporciona un **informe** detallado con gráficos.

Para ejecutarlo, puede ejecutar el binario `PingCastle.exe` y comenzará una **sesión interactiva** presentando un menú de opciones. La opción predeterminada a utilizar es **`healthcheck`** que establecerá una **visión general** de **dominio**, y encontrará **configuraciones incorrectas** y **vulnerabilidades**.&#x20;
