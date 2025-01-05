# BloodHound y otras herramientas de enumeración de AD

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) es parte de Sysinternal Suite:

> Un visor y editor avanzado de Active Directory (AD). Puedes usar AD Explorer para navegar fácilmente por una base de datos de AD, definir ubicaciones favoritas, ver propiedades de objetos y atributos sin abrir cuadros de diálogo, editar permisos, ver el esquema de un objeto y ejecutar búsquedas sofisticadas que puedes guardar y volver a ejecutar.

### Instantáneas

AD Explorer puede crear instantáneas de un AD para que puedas revisarlo sin conexión.\
Se puede usar para descubrir vulnerabilidades sin conexión, o para comparar diferentes estados de la base de datos de AD a lo largo del tiempo.

Se requerirá el nombre de usuario, la contraseña y la dirección para conectarse (se requiere cualquier usuario de AD).

Para tomar una instantánea de AD, ve a `File` --> `Create Snapshot` y entra un nombre para la instantánea.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) es una herramienta que extrae y combina varios artefactos de un entorno de AD. La información puede presentarse en un **informe** de Microsoft Excel **especialmente formateado** que incluye vistas resumidas con métricas para facilitar el análisis y proporcionar una imagen holística del estado actual del entorno de AD objetivo.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound es una aplicación web de Javascript de una sola página, construida sobre [Linkurious](http://linkurio.us/), compilada con [Electron](http://electron.atom.io/), con una base de datos [Neo4j](https://neo4j.com/) alimentada por un recolector de datos en C#.

BloodHound utiliza la teoría de grafos para revelar las relaciones ocultas y a menudo no intencionadas dentro de un entorno de Active Directory o Azure. Los atacantes pueden usar BloodHound para identificar fácilmente rutas de ataque altamente complejas que de otro modo serían imposibles de identificar rápidamente. Los defensores pueden usar BloodHound para identificar y eliminar esas mismas rutas de ataque. Tanto los equipos azules como los rojos pueden usar BloodHound para obtener una comprensión más profunda de las relaciones de privilegio en un entorno de Active Directory o Azure.

Así que, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound) es una herramienta increíble que puede enumerar un dominio automáticamente, guardar toda la información, encontrar posibles rutas de escalada de privilegios y mostrar toda la información utilizando gráficos.

BloodHound se compone de 2 partes principales: **ingestors** y la **aplicación de visualización**.

Los **ingestors** se utilizan para **enumerar el dominio y extraer toda la información** en un formato que la aplicación de visualización entenderá.

La **aplicación de visualización utiliza neo4j** para mostrar cómo toda la información está relacionada y para mostrar diferentes formas de escalar privilegios en el dominio.

### Instalación

Después de la creación de BloodHound CE, todo el proyecto fue actualizado para facilitar su uso con Docker. La forma más fácil de comenzar es usar su configuración de Docker Compose preconfigurada.

1. Instala Docker Compose. Esto debería estar incluido con la instalación de [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Ejecuta:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Localiza la contraseña generada aleatoriamente en la salida del terminal de Docker Compose.  
4. En un navegador, navega a http://localhost:8080/ui/login. Inicia sesión con el nombre de usuario admin y la contraseña generada aleatoriamente de los registros.

Después de esto, necesitarás cambiar la contraseña generada aleatoriamente y tendrás la nueva interfaz lista, desde la cual podrás descargar directamente los ingestors.

### SharpHound

Tienen varias opciones, pero si deseas ejecutar SharpHound desde una PC unida al dominio, utilizando tu usuario actual y extraer toda la información, puedes hacer:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Puedes leer más sobre **CollectionMethod** y la sesión de bucle [aquí](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Si deseas ejecutar SharpHound utilizando diferentes credenciales, puedes crear una sesión CMD netonly y ejecutar SharpHound desde allí:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Aprende más sobre Bloodhound en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) es una herramienta para encontrar **vulnerabilidades** en Active Directory asociadas a **Group Policy**. \
Necesitas **ejecutar group3r** desde un host dentro del dominio usando **cualquier usuario del dominio**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **evalúa la postura de seguridad de un entorno AD** y proporciona un bonito **informe** con gráficos.

Para ejecutarlo, se puede ejecutar el binario `PingCastle.exe` y comenzará una **sesión interactiva** presentando un menú de opciones. La opción predeterminada a utilizar es **`healthcheck`** que establecerá una **visión general** de el **dominio**, y encontrará **mala configuración** y **vulnerabilidades**.

{{#include ../../banners/hacktricks-training.md}}
