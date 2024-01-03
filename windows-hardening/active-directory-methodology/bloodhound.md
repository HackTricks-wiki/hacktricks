# BloodHound y otras herramientas de enumeración de AD

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver a tu **empresa anunciada en HackTricks**? o ¿quieres acceder a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) es parte de Sysinternal Suite:

> Un visor y editor avanzado de Active Directory (AD). Puedes usar AD Explorer para navegar fácilmente por una base de datos de AD, definir ubicaciones favoritas, ver propiedades y atributos de objetos sin abrir cuadros de diálogo, editar permisos, ver el esquema de un objeto y ejecutar búsquedas sofisticadas que puedes guardar y volver a ejecutar.

### Snapshots

AD Explorer puede crear snapshots de un AD para que puedas revisarlo sin conexión.\
Se puede utilizar para descubrir vulnerabilidades sin conexión o para comparar diferentes estados de la base de datos de AD a lo largo del tiempo.

Se requerirá el nombre de usuario, la contraseña y la dirección para conectar (se requiere cualquier usuario de AD).

Para tomar un snapshot de AD, ve a `File` --> `Create Snapshot` e ingresa un nombre para el snapshot.

## ADRecon

****[**ADRecon**](https://github.com/adrecon/ADRecon) es una herramienta que extrae y combina varios artefactos de un entorno de AD. La información se puede presentar en un **informe** de Microsoft Excel **especialmente formateado** que incluye vistas resumidas con métricas para facilitar el análisis y proporcionar una imagen holística del estado actual del entorno de AD objetivo.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHound es una aplicación web monolítica compuesta por un frontend React integrado con [Sigma.js](https://www.sigmajs.org/) y un backend de API REST basado en [Go](https://go.dev/). Se implementa con una base de datos de aplicaciones [Postgresql](https://www.postgresql.org/) y una base de datos de gráficos [Neo4j](https://neo4j.com), y se alimenta de los recolectores de datos [SharpHound](https://github.com/BloodHoundAD/SharpHound) y [AzureHound](https://github.com/BloodHoundAD/AzureHound).
>
>BloodHound utiliza la teoría de grafos para revelar las relaciones ocultas y a menudo no intencionadas dentro de un entorno de Active Directory o Azure. Los atacantes pueden usar BloodHound para identificar fácilmente caminos de ataque altamente complejos que de otro modo serían imposibles de identificar rápidamente. Los defensores pueden usar BloodHound para identificar y eliminar esos mismos caminos de ataque. Tanto los equipos azules como los rojos pueden usar BloodHound para obtener fácilmente una comprensión más profunda de las relaciones de privilegios en un entorno de Active Directory o Azure.
>
>BloodHound CE es creado y mantenido por el [BloodHound Enterprise Team](https://bloodhoundenterprise.io). El BloodHound original fue creado por [@\_wald0](https://www.twitter.com/\_wald0), [@CptJesus](https://twitter.com/CptJesus), y [@harmj0y](https://twitter.com/harmj0y).
>
>De [https://github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound)

Así, [Bloodhound](https://github.com/SpecterOps/BloodHound) es una herramienta increíble que puede enumerar un dominio automáticamente, guardar toda la información, encontrar posibles caminos de escalada de privilegios y mostrar toda la información utilizando gráficos.

Bloodhound se compone de 2 partes principales: **ingestores** y la **aplicación de visualización**.

Los **ingestores** se utilizan para **enumerar el dominio y extraer toda la información** en un formato que la aplicación de visualización entenderá.

La **aplicación de visualización utiliza neo4j** para mostrar cómo toda la información está relacionada y para mostrar diferentes formas de escalar privilegios en el dominio.

### Instalación
Tras la creación de BloodHound CE, todo el proyecto se actualizó para facilitar su uso con Docker. La forma más fácil de empezar es utilizar su configuración preconfigurada de Docker Compose.

1. Instalar Docker Compose. Esto debería estar incluido en la instalación de [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Ejecutar:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Localice la contraseña generada aleatoriamente en la salida del terminal de Docker Compose.
4. En un navegador, vaya a http://localhost:8080/ui/login. Inicie sesión con un nombre de usuario de admin y la contraseña generada aleatoriamente de los registros.

Después de esto, necesitará cambiar la contraseña generada aleatoriamente y tendrá la nueva interfaz lista, desde la cual podrá descargar directamente los ingestores.

### SharpHound

Tienen varias opciones, pero si desea ejecutar SharpHound desde una PC unida al dominio, utilizando su usuario actual y extraer toda la información, puede hacer:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Puedes leer más sobre **CollectionMethod** y la sesión de bucle [aquí](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Si deseas ejecutar SharpHound con diferentes credenciales, puedes crear una sesión CMD netonly y ejecutar SharpHound desde allí:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Aprende más sobre Bloodhound en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Bloodhound Legado
### Instalación

1. Bloodhound

Para instalar la aplicación de visualización necesitarás instalar **neo4j** y la **aplicación bloodhound**.\
La manera más fácil de hacer esto es simplemente:
```
apt-get install bloodhound
```
Puedes **descargar la versión comunitaria de neo4j** desde [aquí](https://neo4j.com/download-center/#community).

1. Ingestores

Puedes descargar los Ingestores desde:

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

1. Aprende el camino desde el gráfico

Bloodhound viene con varias consultas para resaltar caminos de compromiso sensibles. ¡Es posible añadir consultas personalizadas para mejorar la búsqueda y correlación entre objetos y más!

Este repositorio tiene una buena colección de consultas: https://github.com/CompassSecurity/BloodHoundQueries

Proceso de instalación:
```
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```
### Ejecución de la aplicación de visualización

Después de descargar/instalar las aplicaciones requeridas, vamos a iniciarlas.\
Primero que todo necesitas **iniciar la base de datos neo4j**:
```bash
./bin/neo4j start
#or
service neo4j start
```
La primera vez que inicies esta base de datos necesitarás acceder a [http://localhost:7474/browser/](http://localhost:7474/browser/). Se te solicitarán las credenciales por defecto (neo4j:neo4j) y se te **requerirá cambiar la contraseña**, así que cámbiala y no la olvides.

Ahora, inicia la **aplicación bloodhound**:
```bash
./BloodHound-linux-x64
#or
bloodhound
```
Se le solicitarán las credenciales de la base de datos: **neo4j:<Su nueva contraseña>**

Y bloodhound estará listo para ingerir datos.

![](<../../.gitbook/assets/image (171) (1).png>)

### **Python bloodhound**

Si tiene credenciales de dominio, puede ejecutar un **ingestor de bloodhound en python desde cualquier plataforma** para no depender de Windows.\
Descárguelo desde [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) o haciendo `pip3 install bloodhound`
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
Si lo ejecutas a través de proxychains, añade `--dns-tcp` para que la resolución de DNS funcione a través del proxy.
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

Este script **enumerará silenciosamente un Dominio de Active Directory a través de LDAP** analizando usuarios, administradores, grupos, etc.

Échale un vistazo en [**SilentHound github**](https://github.com/layer8secure/SilentHound).

### RustHound

BloodHound en Rust, [**mira aquí**](https://github.com/OPENCYBER-FR/RustHound).

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) es una herramienta para encontrar **vulnerabilidades** en la **Política de Grupo** asociada a Active Directory. \
Necesitas **ejecutar group3r** desde un host dentro del dominio utilizando **cualquier usuario del dominio**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

**[**PingCastle**](https://www.pingcastle.com/documentation/)** evalúa la postura de seguridad de un entorno AD y proporciona un **informe** detallado con gráficos.

Para ejecutarlo, puede ejecutar el binario `PingCastle.exe` y comenzará una **sesión interactiva** presentando un menú de opciones. La opción predeterminada a utilizar es **`healthcheck`**, que establecerá una visión general básica del **dominio**, y encontrará **configuraciones incorrectas** y **vulnerabilidades**.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver a tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
