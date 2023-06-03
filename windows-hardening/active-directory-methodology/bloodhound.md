# BloodHound y otras herramientas de enumeración de AD

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) es de la Suite Sysinternal:

> Un visor y editor avanzado de Active Directory (AD). Puedes usar AD Explorer para navegar fácilmente por una base de datos de AD, definir ubicaciones favoritas, ver propiedades y atributos de objetos sin abrir cuadros de diálogo, editar permisos, ver el esquema de un objeto y ejecutar búsquedas sofisticadas que puedes guardar y volver a ejecutar.

### Instantáneas

AD Explorer puede crear instantáneas de un AD para que puedas comprobarlo sin conexión.\
Se puede utilizar para descubrir vulnerabilidades sin conexión o para comparar diferentes estados de la base de datos de AD a lo largo del tiempo.

Se necesitará el nombre de usuario, la contraseña y la dirección para conectarse (se requiere cualquier usuario de AD).

Para tomar una instantánea de AD, ve a `Archivo` --> `Crear instantánea` e introduce un nombre para la instantánea.

## ADRecon

****[**ADRecon**](https://github.com/adrecon/ADRecon) es una herramienta que extrae y combina varios artefactos de un entorno de AD. La información se puede presentar en un **informe** de Microsoft Excel **especialmente formateado** que incluye vistas resumidas con métricas para facilitar el análisis y proporcionar una imagen holística del estado actual del entorno de AD objetivo.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHound es una aplicación web de una sola página en Javascript, construida sobre [Linkurious](http://linkurio.us), compilada con [Electron](http://electron.atom.io), con una base de datos [Neo4j](https://neo4j.com) alimentada por un ingestor de PowerShell.
>
> BloodHound utiliza la teoría de grafos para revelar las relaciones ocultas y a menudo no intencionales dentro de un entorno de Active Directory. Los atacantes pueden usar BloodHound para identificar fácilmente rutas de ataque altamente complejas que de otra manera serían imposibles de identificar rápidamente. Los defensores pueden usar BloodHound para identificar y eliminar esas mismas rutas de ataque. Tanto los equipos azules como los rojos pueden usar BloodHound para obtener fácilmente una comprensión más profunda de las relaciones de privilegio en un entorno de Active Directory.
>
> BloodHound es desarrollado por [@\_wald0](https://www.twitter.com/\_wald0), [@CptJesus](https://twitter.com/CptJesus), y [@harmj0y](https://twitter.com/harmj0y).
>
> De [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

Entonces, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) es una herramienta increíble que puede enumerar un dominio automáticamente, guardar toda la información, encontrar posibles rutas de escalada de privilegios y mostrar toda la información utilizando gráficos.

Bloodhound se compone de 2 partes principales: **ingestores** y la **aplicación de visualización**.

Los **ingestores** se utilizan para **enumerar el dominio y extraer toda la información** en un formato que la aplicación de visualización entenderá.

La **aplicación de visualización utiliza neo4j** para mostrar cómo se relaciona toda la información y para mostrar diferentes formas de escalar privilegios en el dominio.

### Instalación

1. Bloodhound

Para instalar la aplicación de visualización, deberá instalar **neo4j** y la **aplicación Bloodhound**.\
La forma más fácil de hacer esto es simplemente hacer:
```
apt-get install bloodhound
```
Puedes **descargar la versión comunitaria de neo4j** desde [aquí](https://neo4j.com/download-center/#community).

1. Ingestores

Puedes descargar los Ingestores desde:

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

2. Aprende la ruta desde el grafo

Bloodhound viene con varias consultas para resaltar rutas de compromiso sensibles. ¡Es posible agregar consultas personalizadas para mejorar la búsqueda y correlación entre objetos y más!

Este repositorio tiene una buena colección de consultas: https://github.com/CompassSecurity/BloodHoundQueries

Proceso de instalación:
```
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```
### Ejecución de la aplicación de visualización

Después de descargar e instalar las aplicaciones necesarias, vamos a iniciarlas.\
En primer lugar, es necesario **iniciar la base de datos neo4j**:
```bash
./bin/neo4j start
#or
service neo4j start
```
La primera vez que inicies esta base de datos necesitarás acceder a [http://localhost:7474/browser/](http://localhost:7474/browser/). Se te pedirán credenciales por defecto (neo4j:neo4j) y **será necesario cambiar la contraseña**, así que cámbiala y no la olvides.

Ahora, inicia la aplicación **bloodhound**:
```bash
./BloodHound-linux-x64
#or
bloodhound
```
Se le pedirá que ingrese las credenciales de la base de datos: **neo4j:\<Su nueva contraseña>**

Y Bloodhound estará listo para procesar los datos.

![](<../../.gitbook/assets/image (171) (1).png>)

### SharpHound

Tienen varias opciones, pero si desea ejecutar SharpHound desde una PC unida al dominio, utilizando su usuario actual y extraer toda la información posible, puede hacer lo siguiente:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
Puedes leer más sobre **CollectionMethod** y la sesión de bucle [aquí](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html)

Si deseas ejecutar SharpHound utilizando diferentes credenciales, puedes crear una sesión CMD netonly y ejecutar SharpHound desde allí:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Aprende más sobre Bloodhound en ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

**Silencioso en Windows**

### **Python bloodhound**

Si tienes credenciales de dominio, puedes ejecutar un **ingestor de bloodhound de Python desde cualquier plataforma** para que no dependas de Windows.\
Descárgalo desde [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) o ejecutando `pip3 install bloodhound`
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
Si lo estás ejecutando a través de proxychains, agrega `--dns-tcp` para que la resolución DNS funcione a través del proxy.
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

Este script **enumera silenciosamente un dominio de Active Directory a través de LDAP** analizando usuarios, administradores, grupos, etc.

Échale un vistazo en [**SilentHound github**](https://github.com/layer8secure/SilentHound).

### RustHound

BloodHound en Rust, [**compruébalo aquí**](https://github.com/OPENCYBER-FR/RustHound).

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) **** es una herramienta para encontrar **vulnerabilidades** en la **Política de Grupo** asociada a Active Directory. \
Necesitas **ejecutar group3r** desde un host dentro del dominio utilizando **cualquier usuario del dominio**.
```bash
group3r.exe -f <filepath-name.log> 
# -s sends results to stdin
# -f send results to file
```
## PingCastle

****[**PingCastle**](https://www.pingcastle.com/documentation/) **evalúa la postura de seguridad de un entorno AD** y proporciona un **informe** agradable con gráficos.

Para ejecutarlo, se puede ejecutar el binario `PingCastle.exe` y se iniciará una **sesión interactiva** que presenta un menú de opciones. La opción predeterminada a utilizar es **`healthcheck`** que establecerá una **visión general** de la **dominio**, y encontrará **configuraciones incorrectas** y **vulnerabilidades**.&#x20;
