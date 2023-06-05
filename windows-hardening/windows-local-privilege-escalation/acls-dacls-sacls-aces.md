# ACLs - DACLs/SACLs/ACEs

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas de la comunidad más avanzadas del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparta sus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Lista de control de acceso (ACL)**

Una **ACL es una lista ordenada de ACEs** que define las protecciones que se aplican a un objeto y sus propiedades. Cada **ACE identifica un principal de seguridad** y especifica un **conjunto de derechos de acceso** que se permiten, deniegan o auditan para ese principal de seguridad.

El descriptor de seguridad de un objeto puede contener **dos ACL**:

1. Un **DACL que identifica** los **usuarios** y **grupos** que tienen acceso **permitido** o **denegado**
2. Un **SACL que controla cómo** se audita el acceso

Cuando un usuario intenta acceder a un archivo, el sistema Windows ejecuta un AccessCheck y compara el descriptor de seguridad con el token de acceso del usuario y evalúa si se le concede acceso y qué tipo de acceso dependiendo de los ACE establecidos.

### **Lista de control de acceso discrecional (DACL)**

Un DACL (a menudo mencionado como ACL) identifica los usuarios y grupos a los que se les asignan o deniegan permisos de acceso en un objeto. Contiene una lista de ACEs emparejados (Cuenta + Derecho de acceso) al objeto seguro.

### **Lista de control de acceso del sistema (SACL)**

Los SACL hacen posible monitorear el acceso a objetos seguros. Los ACE en un SACL determinan **qué tipos de acceso se registran en el registro de eventos de seguridad**. Con herramientas de monitoreo, esto podría generar una alarma a las personas adecuadas si los usuarios malintencionados intentan acceder al objeto seguro, y en un escenario de incidente podemos usar los registros para rastrear los pasos hacia atrás en el tiempo. Y por último, puede habilitar el registro para solucionar problemas de acceso.

## Cómo utiliza el sistema las ACL

Cada **usuario registrado** en el sistema **tiene un token de acceso con información de seguridad** para esa sesión de inicio de sesión. El sistema crea un token de acceso cuando el usuario inicia sesión. **Cada proceso ejecutado** en nombre del usuario **tiene una copia del token de acceso**. El token identifica al usuario, los grupos del usuario y los privilegios del usuario. Un token también contiene un SID de inicio de sesión (identificador de seguridad) que identifica la sesión de inicio de sesión actual.

Cuando un subproceso intenta acceder a un objeto seguro, el LSASS (Autoridad de seguridad local) otorga o deniega el acceso. Para hacer esto, el **LSASS busca el DACL** (Lista de control de acceso discrecional) en la secuencia de datos SDS, buscando ACE que se aplican al subproceso.

**Cada ACE en el DACL del objeto** especifica los derechos de acceso que se permiten o deniegan para un principal de seguridad o sesión de inicio de sesión. Si el propietario del objeto no ha creado ningún ACE en el DACL para ese objeto, el sistema otorga acceso de inmediato.

Si el LSASS encuentra ACE, compara el SID
### Entradas de Control de Acceso

Como se mencionó anteriormente, una ACL (Lista de Control de Acceso) es una lista ordenada de ACEs (Entradas de Control de Acceso). Cada ACE contiene lo siguiente:

* Un SID (Identificador de Seguridad) que identifica a un usuario o grupo en particular.
* Una máscara de acceso que especifica los derechos de acceso.
* Un conjunto de indicadores de bits que determinan si los objetos secundarios pueden heredar o no el ACE.
* Un indicador que indica el tipo de ACE.

Los ACEs son fundamentalmente iguales. Lo que los diferencia es el grado de control que ofrecen sobre la herencia y el acceso a objetos. Hay dos tipos de ACE:

* Tipo genérico que se adjunta a todos los objetos segurizables.
* Tipo específico de objeto que solo puede ocurrir en ACLs para objetos de Active Directory.

### ACE genérico

Un ACE genérico ofrece un control limitado sobre los tipos de objetos secundarios que pueden heredarlos. Esencialmente, solo pueden distinguir entre contenedores y no contenedores.

Por ejemplo, la DACL (Lista de Control de Acceso Discrecional) en un objeto de Carpeta en NTFS puede incluir un ACE genérico que permite a un grupo de usuarios listar el contenido de la carpeta. Debido a que listar el contenido de una carpeta es una operación que solo se puede realizar en un objeto contenedor, el ACE que permite la operación puede ser marcado como un ACE de CONTAINER\_INHERIT\_ACE. Solo los objetos contenedores en la carpeta (es decir, solo otros objetos de Carpeta) heredan el ACE. Los objetos no contenedores (es decir, objetos de Archivo) no heredan el ACE del objeto padre.

Un ACE genérico se aplica a un objeto completo. Si un ACE genérico da a un usuario en particular acceso de lectura, el usuario puede leer toda la información asociada con el objeto, tanto los datos como las propiedades. Esto no es una limitación grave para la mayoría de los tipos de objetos. Los objetos de Archivo, por ejemplo, tienen pocas propiedades, que se utilizan todas para describir las características del objeto en lugar de para almacenar información. La mayor parte de la información en un objeto de Archivo se almacena como datos de objeto; por lo tanto, hay poca necesidad de controles separados sobre las propiedades de un archivo.

### ACE específico de objeto

Un ACE específico de objeto ofrece un mayor grado de control sobre los tipos de objetos secundarios que pueden heredarlos.

Por ejemplo, la ACL de un objeto de OU (Unidad Organizativa) puede tener un ACE específico de objeto que esté marcado para herencia solo por objetos de Usuario. Otros tipos de objetos, como objetos de Computadora, no heredarán el ACE.

Esta capacidad es por qué los ACE específicos de objeto se llaman específicos de objeto. Su herencia puede limitarse a tipos específicos de objetos secundarios.

Hay diferencias similares en cómo las dos categorías de tipos de ACE controlan el acceso a los objetos.

Un ACE específico de objeto puede aplicarse a cualquier propiedad individual de un objeto o a un conjunto de propiedades para ese objeto. Este tipo de ACE se usa solo en una ACL para objetos de Active Directory, que, a diferencia de otros tipos de objetos, almacenan la mayor parte de su información en propiedades. A menudo es deseable colocar controles independientes en cada propiedad de un objeto de Active Directory, y los ACE específicos de objeto hacen posible eso.

Por ejemplo, cuando define permisos para un objeto de Usuario, puede usar un ACE específico de objeto para permitir que Principal Self (es decir, el usuario) tenga acceso de escritura a la propiedad Phone-Home-Primary (homePhone), y puede usar otros ACE específicos de objeto para denegar el acceso de Principal Self a la propiedad Logon-Hours (logonHours) y otras propiedades que establecen restricciones en la cuenta de usuario.

La tabla a continuación muestra el diseño de cada ACE.

### Diseño de Entrada de Control de Acceso

| Campo ACE  | Descripción                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo       | Indicador de bandera que indica el tipo de ACE. Windows 2000 y Windows Server 2003 admiten seis tipos de ACE: tres tipos de ACE genéricos que se adjuntan a todos los objetos segurizables y tres tipos de ACE específicos de objeto que pueden ocurrir para objetos de Active Directory.                                                                                                                                                                                                                                                            |
| Indicadores | Conjunto de indicadores de bits que controlan la herencia y la auditoría.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tamaño     | Número de bytes de memoria que se asignan para el ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Máscara de acceso | Valor de 32 bits cuyos bits corresponden a los derechos de acceso para el objeto. Los bits pueden establecerse en encendido o apagado, pero el significado de la configuración depende del tipo de ACE. Por ejemplo, si se enciende el bit que corresponde al derecho a leer permisos y el tipo de ACE es Denegar, el ACE deniega el derecho a leer los permisos del objeto. Si se establece el mismo bit pero el tipo de ACE es Permitir, el ACE otorga el derecho a leer los permisos del objeto. Se detallan más detalles de la máscara de acceso en la tabla siguiente. |
| SID        | Identifica a un usuario o grupo cuyo acceso está controlado o supervisado por este ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Diseño de la Máscara de Acceso

| Bit (Rango) | Significado                            | Descripción/Ejemplo                       |
| ----------- | -------------------------------------- | ----------------------------------------- |
| 0 - 15      | Derechos de acceso específicos del objeto | Leer datos, Ejecutar, Agregar datos           |
| 16 - 22     | Derechos de acceso estándar             | Eliminar, Escribir ACL, Escribir Propietario            |
| 23          | Puede acceder a la ACL de seguridad            |                                           |
| 24 - 27     | Reservado                           |                                           |
| 28          | Genérico TODOS (Leer, Escribir, Ejecutar) | Todo lo que está debajo                          |
| 29          | Genérico Ejecutar                    | Todas las cosas necesarias para ejecutar un programa |
| 30          | Genérico Escribir                      | Todas las cosas necesarias para escribir en un archivo   |
| 31          | Genérico Leer                       | Todas las cosas necesarias para leer un archivo       |

## Referencias

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Comparte tus trucos de hacking enviando PR a los repositorios [hacktricks](https://github.com/carlospolop/hacktricks) y [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Usa [**Trickest**](https://trickest.com/?
