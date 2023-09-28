# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Lista de control de acceso (ACL)**

Una **ACL es una lista ordenada de ACEs** que define las protecciones que se aplican a un objeto y sus propiedades. Cada **ACE** identifica un **principal de seguridad** y especifica un **conjunto de derechos de acceso** que están permitidos, denegados o auditados para ese principal de seguridad.

El descriptor de seguridad de un objeto puede contener **dos ACLs**:

1. Un **DACL** que **identifica** a los **usuarios** y **grupos** a los que se les permite o se les niega el acceso.
2. Un **SACL** que controla **cómo** se audita el acceso.

Cuando un usuario intenta acceder a un archivo, el sistema Windows ejecuta un AccessCheck y compara el descriptor de seguridad con el token de acceso del usuario y evalúa si se le concede acceso y qué tipo de acceso en función de los ACEs establecidos.

### **Lista de control de acceso discrecional (DACL)**

Un DACL (a menudo mencionado como ACL) identifica a los usuarios y grupos a los que se les asignan o se les niegan permisos de acceso en un objeto. Contiene una lista de ACEs emparejados (Cuenta + Derecho de acceso) para el objeto securizable.

### **Lista de control de acceso del sistema (SACL)**

Los SACLs permiten supervisar el acceso a objetos seguros. Los ACEs en un SACL determinan **qué tipos de acceso se registran en el Registro de eventos de seguridad**. Con herramientas de supervisión, esto podría generar una alarma para las personas adecuadas si los usuarios malintencionados intentan acceder al objeto seguro, y en un escenario de incidente podemos utilizar los registros para rastrear los pasos hacia atrás en el tiempo. Y por último, se puede habilitar el registro para solucionar problemas de acceso.

## Cómo utiliza el sistema las ACLs

Cada **usuario que inicia sesión** en el sistema **tiene un token de acceso con información de seguridad** para esa sesión de inicio de sesión. El sistema crea un token de acceso cuando el usuario inicia sesión. **Cada proceso ejecutado** en nombre del usuario **tiene una copia del token de acceso**. El token identifica al usuario, los grupos del usuario y los privilegios del usuario. Un token también contiene un SID de inicio de sesión (Identificador de seguridad) que identifica la sesión de inicio de sesión actual.

Cuando un hilo intenta acceder a un objeto securizable, el LSASS (Autoridad de seguridad local) otorga o deniega el acceso. Para hacer esto, el **LSASS busca en el DACL** (Lista de control de acceso discrecional) en la secuencia de datos SDS, buscando ACEs que se apliquen al hilo.

**Cada ACE en el DACL del objeto** especifica los derechos de acceso que están permitidos o denegados para un principal de seguridad o sesión de inicio de sesión. Si el propietario del objeto no ha creado ningún ACE en el DACL para ese objeto, el sistema otorga acceso de inmediato.

Si el LSASS encuentra ACEs, compara el SID del fiduciario en cada ACE con los SID del fiduciario que se identifican en el token de acceso del hilo.

### ACEs

Hay **`tres` tipos principales de ACEs** que se pueden aplicar a todos los objetos securizables en AD:

| **ACE**                  | **Descripción**                                                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`ACE de denegación de acceso`**  | Se utiliza dentro de un DACL para mostrar que a un usuario o grupo se le deniega explícitamente el acceso a un objeto                                                                                   |
| **`ACE de acceso permitido`** | Se utiliza dentro de un DACL para mostrar que a un usuario o grupo se le concede explícitamente el acceso a un objeto                                                                                  |
| **`ACE de auditoría del sistema`**   | Se utiliza dentro de un SACL para generar registros de auditoría cuando un usuario o grupo intenta acceder a un objeto. Registra si se concedió o no el acceso y qué tipo de acceso se produjo |

Cada ACE está compuesto por los siguientes `cuatro` componentes:

1. El identificador de seguridad (SID) del usuario/grupo que tiene acceso al objeto (o el nombre del principal de forma gráfica)
2. Una bandera que indica el tipo de ACE (ACE de denegación de acceso, acceso permitido o ACE de auditoría del sistema)
3. Un conjunto de banderas que especifican si los contenedores/objetos secundarios pueden heredar la entrada ACE dada del objeto primario o principal
4. Una [máscara de acceso](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) que es un valor de 32 bits que define los derechos otorgados a un objeto

El sistema examina cada ACE en secuencia hasta que ocurra uno de los siguientes eventos:

* **Un ACE de denegación de acceso deniega explícitamente** cualquiera de los derechos de acceso solicitados a uno de los fiduciarios enumerados en el token de acceso del hilo.
* **Uno o más ACEs de acceso permitido** para los fiduciarios enumerados en el token de acceso del hilo otorgan explícitamente todos los derechos de acceso solicitados.
* Se han comprobado todos los ACEs y todavía hay al menos **un derecho de acceso solicitado** que **no se ha permitido explícitamente**, en cuyo caso, se deniega el acceso implícitamente.
### Orden de ACEs

Debido a que el **sistema deja de verificar los ACEs cuando se concede o deniega explícitamente el acceso solicitado**, el orden de los ACEs en un DACL es importante.

El orden preferido de los ACEs en un DACL se llama "orden canónico". Para Windows 2000 y Windows Server 2003, el orden canónico es el siguiente:

1. Todos los ACEs **explícitos** se colocan en un grupo **antes** que cualquier ACE **heredado**.
2. Dentro del grupo de ACEs **explícitos**, los ACEs de **denegación de acceso** se colocan **antes que los ACEs de acceso permitido**.
3. Dentro del grupo **heredado**, los ACEs heredados del **objeto hijo vienen primero**, y luego los ACEs heredados del **abuelo**, **y así sucesivamente** hasta llegar al árbol de objetos. Después de eso, los ACEs de **denegación de acceso** se colocan **antes que los ACEs de acceso permitido**.

La siguiente figura muestra el orden canónico de los ACEs:

### Orden canónico de los ACEs

![ACE](https://www.ntfs.com/images/screenshots/ACEs.gif)

El orden canónico asegura que se cumpla lo siguiente:

* Un **ACE de denegación de acceso explícito se aplica independientemente de cualquier ACE de acceso permitido explícito**. Esto significa que el propietario del objeto puede definir permisos que permitan el acceso a un grupo de usuarios y denieguen el acceso a un subconjunto de ese grupo.
* Todos los **ACEs explícitos se procesan antes que cualquier ACE heredado**. Esto es consistente con el concepto de control de acceso discrecional: el acceso a un objeto hijo (por ejemplo, un archivo) está a discreción del propietario del hijo, no del propietario del objeto padre (por ejemplo, una carpeta). El propietario de un objeto hijo puede definir permisos directamente en el hijo. El resultado es que los efectos de los permisos heredados se modifican.

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Ejemplo de GUI

Esta es la pestaña de seguridad clásica de una carpeta que muestra el ACL, DACL y ACEs:

![](../../.gitbook/assets/classicsectab.jpg)

Si hacemos clic en el **botón Avanzado**, obtendremos más opciones como la herencia:

![](../../.gitbook/assets/aceinheritance.jpg)

Y si agregamos o editamos un Principal de Seguridad:

![](../../.gitbook/assets/editseprincipalpointers1.jpg)

Y por último, tenemos el SACL en la pestaña de Auditoría:

![](../../.gitbook/assets/audit-tab.jpg)

### Ejemplo: Denegación explícita de acceso a un grupo

En este ejemplo, el grupo de acceso permitido es "Everyone" y el grupo de acceso denegado es "Marketing", un subconjunto de "Everyone".

Deseas denegar el acceso del grupo "Marketing" a una carpeta llamada "Cost". Si los ACEs de la carpeta "Cost" están en orden canónico, el ACE que deniega el acceso a "Marketing" se coloca antes del ACE que permite a "Everyone".

Durante una verificación de acceso, el sistema operativo recorre los ACEs en el orden en que aparecen en el DACL del objeto, de modo que el ACE de denegación se procesa antes que el ACE de permiso. Como resultado, los usuarios que son miembros del grupo "Marketing" se les deniega el acceso. Todos los demás tienen acceso al objeto.

### Ejemplo: Explícito antes que heredado

En este ejemplo, la carpeta "Cost" tiene un ACE heredable que deniega el acceso a "Marketing" (el objeto padre). En otras palabras, todos los usuarios que son miembros (o hijos) del grupo "Marketing" se les deniega el acceso por herencia.

Deseas permitir el acceso a Bob, quien es el director de marketing. Como miembro del grupo "Marketing", Bob tiene denegado el acceso a la carpeta "Cost" por herencia. El propietario del objeto hijo (usuario Bob) define un ACE explícito que permite el acceso a la carpeta "Cost". Si los ACEs del objeto hijo están en orden canónico, el ACE explícito que permite a Bob acceder se coloca antes que cualquier ACE heredado, incluido el ACE heredado que deniega el acceso al grupo "Marketing".

Durante una verificación de acceso, el sistema operativo llega al ACE que permite a Bob acceder antes de llegar al ACE que deniega el acceso al grupo "Marketing". Como resultado, Bob tiene acceso al objeto aunque sea miembro del grupo "Marketing". Otros miembros del grupo "Marketing" tienen denegado el acceso.

### Entradas de Control de Acceso

Como se mencionó anteriormente, una ACL (Lista de Control de Acceso) es una lista ordenada de ACEs (Entradas de Control de Acceso). Cada ACE contiene lo siguiente:

* Un SID (Identificador de Seguridad) que identifica a un usuario o grupo específico.
* Una máscara de acceso que especifica los derechos de acceso.
* Un conjunto de indicadores de bits que determinan si los objetos secundarios pueden heredar el ACE o no.
* Un indicador que indica el tipo de ACE.

Los ACEs son fundamentalmente similares. Lo que los diferencia es el grado de control que ofrecen sobre la herencia y el acceso a objetos. Hay dos tipos de ACE:

* Tipo genérico que se adjunta a todos los objetos segurizables.
* Tipo específico del objeto que solo puede ocurrir en ACLs para objetos de Active Directory.

### ACE genérico

Un ACE genérico ofrece un control limitado sobre los tipos de objetos secundarios que pueden heredarlos. Básicamente, solo pueden distinguir entre contenedores y no contenedores.

Por ejemplo, el DACL (Lista de Control de Acceso Discrecional) en un objeto Carpeta en NTFS puede incluir un ACE genérico que permite a un grupo de usuarios listar el contenido de la carpeta. Debido a que listar el contenido de una carpeta es una operación que solo se puede realizar en un objeto Contenedor, el ACE que permite la operación puede ser marcado como CONTAINER\_INHERIT\_ACE. Solo los objetos Contenedor en la carpeta (es decir, otras carpetas) heredan el ACE. Los objetos no contenedores (es decir, archivos) no heredan el ACE del objeto padre.

Un ACE genérico se aplica a un objeto completo. Si un ACE genérico otorga a un usuario en particular acceso de lectura, el usuario puede leer toda la información asociada con el objeto, tanto los datos como las propiedades. Esto no es una limitación grave para la mayoría de los tipos de objetos. Por ejemplo, los objetos de archivo tienen pocas propiedades, que se utilizan para describir características del objeto en lugar de almacenar información. La mayor parte de la información en un objeto de archivo se almacena como datos del objeto; por lo tanto, hay poca necesidad de controles separados sobre las propiedades de un archivo.

### ACE específico del objeto

Un ACE específico del objeto ofrece un mayor grado de control sobre los tipos de objetos secundarios que pueden heredarlos.

Por ejemplo, la ACL de un objeto OU (Unidad Organizativa) puede tener un ACE específico del objeto que solo se marque para herencia por objetos de usuario. Otros tipos de objetos, como objetos de computadora, no heredarán el ACE.

Esta capacidad es la razón por la que los ACE específicos del objeto se llaman específicos del objeto. Su herencia puede limitarse a tipos específicos de objetos secundarios.

Existen diferencias similares en cómo los dos tipos de ACE controlan el acceso a los objetos.

Un ACE específico del objeto puede aplicarse a cualquier propiedad individual de un objeto o a un conjunto de propiedades para ese objeto. Este tipo de ACE se utiliza solo en una ACL para objetos de Active Directory, que, a diferencia de otros tipos de objetos, almacenan la mayor parte de su información en propiedades. A menudo es deseable colocar controles independientes en cada propiedad de un objeto de Active Directory, y los ACE específicos del objeto hacen posible eso.

Por ejemplo, al definir permisos para un objeto de usuario, puedes usar un ACE específico del objeto para permitir que el Principal Self (es decir, el usuario) tenga acceso de escritura a la propiedad Phone-Home-Primary (homePhone), y puedes usar otros ACEs específicos del objeto para denegar el acceso del Principal Self a la propiedad Logon-Hours (logonHours) y otras propiedades que establecen restricciones en la cuenta de usuario.

La siguiente tabla muestra el diseño de cada ACE.
### Diseño de Entrada de Control de Acceso (ACE)

| Campo ACE  | Descripción                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Bandera que indica el tipo de ACE. Windows 2000 y Windows Server 2003 admiten seis tipos de ACE: tres tipos genéricos de ACE que se adjuntan a todos los objetos segurizables y tres tipos de ACE específicos del objeto que pueden ocurrir en objetos de Active Directory.                                                                                                                                                                                                                                                            |
| Banderas       | Conjunto de bits que controlan la herencia y la auditoría.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tamaño        | Número de bytes de memoria asignados para el ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Máscara de acceso | Valor de 32 bits cuyos bits corresponden a los derechos de acceso para el objeto. Los bits pueden estar activados o desactivados, pero el significado de la configuración depende del tipo de ACE. Por ejemplo, si el bit que corresponde al derecho de leer permisos está activado y el tipo de ACE es Denegar, el ACE deniega el derecho de leer los permisos del objeto. Si el mismo bit está activado pero el tipo de ACE es Permitir, el ACE otorga el derecho de leer los permisos del objeto. Se proporcionan más detalles de la máscara de acceso en la tabla siguiente. |
| SID         | Identifica a un usuario o grupo cuyo acceso es controlado o supervisado por este ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Diseño de la Máscara de Acceso

| Bit (Rango) | Significado                            | Descripción/Ejemplo                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Derechos de acceso específicos del objeto      | Leer datos, Ejecutar, Adjuntar datos           |
| 16 - 22     | Derechos de acceso estándar             | Eliminar, Escribir ACL, Escribir propietario            |
| 23          | Puede acceder a la ACL de seguridad            |                                           |
| 24 - 27     | Reservado                           |                                           |
| 28          | Genérico TODOS (Leer, Escribir, Ejecutar) | Todo lo anterior                          |
| 29          | Genérico Ejecutar                    | Todo lo necesario para ejecutar un programa |
| 30          | Genérico Escribir                      | Todo lo necesario para escribir en un archivo   |
| 31          | Genérico Leer                       | Todo lo necesario para leer un archivo       |

## Referencias

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** con facilidad, impulsados por las **herramientas comunitarias más avanzadas del mundo**.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
