# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Lista de Control de Acceso (ACL)**

Una **ACL es una lista ordenada de ACEs** que definen las protecciones que se aplican a un objeto y sus propiedades. Cada **ACE** identifica un **principal de seguridad** y especifica un **conjunto de derechos de acceso** que se permiten, se niegan o se auditan para ese principal de seguridad.

El descriptor de seguridad de un objeto puede contener **dos ACLs**:

1. Un **DACL** que **identifica** a los **usuarios** y **grupos** a los que se les **permite** o **niega** el acceso
2. Un **SACL** que controla **cómo** se **audita** el acceso

Cuando un usuario intenta acceder a un archivo, el sistema Windows ejecuta un AccessCheck y compara el descriptor de seguridad con el token de acceso del usuario y evalúa si se le concede el acceso y qué tipo de acceso dependiendo de los ACEs establecidos.

### **Lista de Control de Acceso Discrecional (DACL)**

Un DACL (a menudo mencionado como ACL) identifica a los usuarios y grupos que tienen asignados o se les niegan los permisos de acceso a un objeto. Contiene una lista de ACEs emparejados (Cuenta + Derecho de Acceso) al objeto asegurable.

### **Lista de Control de Acceso del Sistema (SACL)**

Los SACLs permiten monitorear el acceso a objetos asegurados. Los ACEs en un SACL determinan **qué tipos de acceso se registran en el Registro de Eventos de Seguridad**. Con herramientas de monitoreo esto podría activar una alarma para las personas adecuadas si usuarios maliciosos intentan acceder al objeto asegurado, y en un escenario de incidente podemos usar los registros para rastrear los pasos hacia atrás en el tiempo. Y por último, puedes habilitar el registro para solucionar problemas de acceso.

## Cómo el Sistema Utiliza las ACLs

Cada **usuario conectado** al sistema **posee un token de acceso con información de seguridad** para esa sesión de inicio de sesión. El sistema crea un token de acceso cuando el usuario inicia sesión. **Cada proceso ejecutado** en nombre del usuario **tiene una copia del token de acceso**. El token identifica al usuario, los grupos del usuario y los privilegios del usuario. Un token también contiene un SID de inicio de sesión (Identificador de Seguridad) que identifica la sesión de inicio de sesión actual.

Cuando un hilo intenta acceder a un objeto asegurable, el LSASS (Autoridad de Seguridad Local) concede o niega el acceso. Para hacer esto, el **LSASS busca en el DACL** (Lista de Control de Acceso Discrecional) en el flujo de datos SDS, buscando ACEs que se apliquen al hilo.

**Cada ACE en el DACL del objeto** especifica los derechos de acceso que se permiten o se niegan para un principal de seguridad o sesión de inicio de sesión. Si el propietario del objeto no ha creado ningún ACE en el DACL para ese objeto, el sistema concede el acceso de inmediato.

Si el LSASS encuentra ACEs, compara el SID del fideicomisario en cada ACE con los SIDs del fideicomisario que están identificados en el token de acceso del hilo.

### ACEs

Hay **`tres` tipos principales de ACEs** que se pueden aplicar a todos los objetos asegurables en AD:

| **ACE**                  | **Descripción**                                                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`ACE de acceso denegado`**  | Utilizado dentro de un DACL para mostrar que a un usuario o grupo se le niega explícitamente el acceso a un objeto                                                                                   |
| **`ACE de acceso permitido`** | Utilizado dentro de un DACL para mostrar que a un usuario o grupo se le concede explícitamente el acceso a un objeto                                                                                  |
| **`ACE de auditoría del sistema`**   | Utilizado dentro de un SACL para generar registros de auditoría cuando un usuario o grupo intenta acceder a un objeto. Registra si se concedió el acceso o no y qué tipo de acceso ocurrió |

Cada ACE está compuesto por los siguientes `cuatro` componentes:

1. El identificador de seguridad (SID) del usuario/grupo que tiene acceso al objeto (o nombre del principal gráficamente)
2. Una bandera que denota el tipo de ACE (acceso denegado, permitido o auditoría del sistema ACE)
3. Un conjunto de banderas que especifican si los contenedores/objetos hijos pueden heredar la entrada ACE dada del objeto primario o padre
4. Una [máscara de acceso](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) que es un valor de 32 bits que define los derechos concedidos a un objeto

El sistema examina cada ACE en secuencia hasta que ocurre uno de los siguientes eventos:

* **Un ACE de acceso denegado explícitamente niega** cualquiera de los derechos de acceso solicitados a uno de los fideicomisarios listados en el token de acceso del hilo.
* **Uno o más ACEs de acceso permitido** para fideicomisarios listados en el token de acceso del hilo conceden explícitamente todos los derechos de acceso solicitados.
* Todos los ACEs han sido revisados y todavía hay al menos **un derecho de acceso solicitado** que **no ha sido explícitamente permitido**, en cuyo caso, el acceso es implícitamente **denegado**.

### Orden de los ACEs

Debido a que el **sistema deja de revisar los ACEs cuando el acceso solicitado es concedido o denegado explícitamente**, el orden de los ACEs en un DACL es importante.

El orden preferido de los ACEs en un DACL se llama orden "canónico". Para Windows 2000 y Windows Server 2003, el orden canónico es el siguiente:

1. Todos los ACEs **explícitos** se colocan en un grupo **antes** de cualquier ACE **heredado**.
2. Dentro del grupo de ACEs **explícitos**, los ACEs de **acceso denegado** se colocan **antes de los ACEs de acceso permitido**.
3. Dentro del grupo **heredado**, los ACEs que son heredados del **padre del objeto hijo vienen primero**, y **luego** los ACEs heredados del **abuelo**, **y así** sucesivamente en el árbol de objetos. Después de eso, los ACEs de **acceso denegado** se colocan **antes de los ACEs de acceso permitido**.

La siguiente figura muestra el orden canónico de los ACEs:

### Orden canónico de los ACEs

![ACE](https://www.ntfs.com/images/screenshots/ACEs.gif)

El orden canónico asegura que ocurra lo siguiente:

* Un ACE de **acceso denegado explícito se hace cumplir independientemente de cualquier ACE de acceso permitido explícito**. Esto significa que el propietario del objeto puede definir permisos que permitan el acceso a un grupo de usuarios y denegar el acceso a un subconjunto de ese grupo.
* Todos los ACEs **explícitos se procesan antes de cualquier ACE heredado**. Esto es consistente con el concepto de control de acceso discrecional: el acceso a un objeto hijo (por ejemplo, un archivo) está a discreción del propietario del hijo, no del propietario del objeto padre (por ejemplo, una carpeta). El propietario de un objeto hijo puede definir permisos directamente en el hijo. El resultado es que los efectos de los permisos heredados se modifican.

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Ejemplo de GUI

Esta es la clásica pestaña de seguridad de una carpeta que muestra la ACL, DACL y ACEs:

![](../../.gitbook/assets/classicsectab.jpg)

Si hacemos clic en el **botón Avanzado** obtendremos más opciones como la herencia:

![](../../.gitbook/assets/aceinheritance.jpg)

Y si agregas o editas un Principal de Seguridad:

![](../../.gitbook/assets/editseprincipalpointers1.jpg)

Y por último tenemos el SACL en la pestaña de Auditoría:

![](../../.gitbook/assets/audit-tab.jpg)

### Ejemplo: Acceso explícitamente denegado a un grupo

En este ejemplo, el grupo con acceso permitido es Todos y el grupo con acceso denegado es Marketing, un subconjunto de Todos.

Quieres negar al grupo de Marketing el acceso a una carpeta de Costos. Si los ACEs de la carpeta de Costos están en orden canónico, el ACE que niega el acceso a Marketing viene antes del ACE que permite el acceso a Todos.

Durante una verificación de acceso, el sistema operativo recorre los ACEs en el orden en que aparecen en el DACL del objeto, de modo que el ACE de denegación se procesa antes que el ACE de permiso. Como resultado, a los usuarios que son miembros del grupo de Marketing se les niega el acceso. A todos los demás se les permite el acceso al objeto.

### Ejemplo: Explícito antes de heredado

En este ejemplo, la carpeta de Costos tiene un ACE heredable que niega el acceso a Marketing (el objeto padre). En otras palabras, a todos los usuarios que son miembros (o hijos) del grupo de Marketing se les niega el acceso por herencia.

Quieres permitir el acceso a Bob, que es el director de Marketing. Como miembro del grupo de Marketing, a Bob se le niega el acceso a la carpeta de Costos por herencia. El propietario del objeto hijo (usuario Bob) define un ACE explícito que permite el acceso a la carpeta de Costos. Si los ACEs del objeto hijo están en orden canónico, el ACE explícito que permite el acceso a Bob viene antes de cualquier ACE heredado, incluido el ACE heredado que niega el acceso al grupo de Marketing.

Durante una verificación de acceso, el sistema operativo llega al ACE que permite el acceso a Bob antes de llegar al ACE que niega el acceso al grupo de Marketing. Como resultado, a Bob se le permite el acceso al objeto aunque sea miembro del grupo de Marketing. A otros miembros del grupo de Marketing se les niega el acceso.

### Entradas de Control de Acceso

Como se mencionó anteriormente, una ACL (Lista de Control de Acceso) es una lista ordenada de ACEs (Entradas de Control de Acceso). Cada ACE contiene lo siguiente:

* Un SID (Identificador de Seguridad) que identifica a un usuario o grupo en particular.
* Una máscara de acceso que especifica los derechos de acceso.
* Un conjunto de bits de banderas que determinan si los objetos hijos pueden heredar el ACE.
* Una bandera que indica el tipo de ACE.

Los ACEs son fundamentalmente similares. Lo que los distingue es el grado de control que ofrecen sobre la herencia y el acceso a objetos. Hay dos tipos de ACE:

* Tipo genérico que se adjunta a todos los objetos asegurables.
* Tipo específico de objeto que solo puede ocurrir en ACLs para objetos de Active Directory.

### ACE Genérico

Un ACE genérico ofrece un control limitado sobre los tipos de objetos hijos que pueden heredarlos. Esencialmente, solo pueden distinguir entre contenedores y no contenedores.

Por ejemplo, el DACL (Lista de Control de Acceso Discrecional) en un objeto Carpeta en NTFS puede incluir un ACE genérico que permite a un grupo de usuarios listar el contenido de la carpeta. Debido a que listar el contenido de una carpeta es una operación que solo se puede realizar en un objeto Contenedor, el ACE que permite la operación puede marcarse como CONTAINER_INHERIT_ACE. Solo los objetos Contenedor en la carpeta (es decir, solo otros objetos Carpeta) heredan el ACE. Los objetos no contenedores (es decir, objetos Archivo) no heredan el ACE del objeto padre.

Un ACE genérico se aplica a un objeto completo. Si un ACE genérico otorga a un usuario en particular acceso de lectura, el usuario puede leer toda la información asociada con el objeto, tanto datos como propiedades. Esto no es una limitación seria para la mayoría de los tipos de objetos. Por ejemplo, los objetos Archivo tienen pocas propiedades, que se utilizan todas para describir características del objeto en lugar de para almacenar información. La mayor parte de la información en un objeto Archivo se almacena como datos del objeto; por lo tanto, hay poca necesidad de controles separados en las propiedades de un archivo.

### ACE Específico de Objeto

Un ACE específico de objeto ofrece un mayor grado de control sobre los tipos de objetos hijos que pueden heredarlos.

Por ejemplo, el ACL de un objeto OU (Unidad Organizativa) puede tener un ACE específico de objeto que está marcado para herencia solo por objetos Usuario. Otros tipos de objetos, como los objetos Computadora, no heredarán el ACE.

Esta capacidad es la razón por la cual los ACEs específicos de objeto se llaman específicos de objeto. Su herencia puede limitarse a tipos específicos de objetos hijos.

Hay diferencias similares en cómo las dos categorías de tipos de ACE controlan el acceso a objetos.

Un ACE específico de objeto puede aplicarse a cualquier propiedad individual de un objeto o a un conjunto de propiedades de ese objeto. Este tipo de ACE se utiliza solo en un ACL para objetos de Active Directory, que, a diferencia de otros tipos de objetos, almacenan la mayor parte de su información en propiedades. A menudo es deseable colocar controles independientes en cada propiedad de un objeto de Active Directory, y los ACEs específicos de objeto hacen eso posible.

Por ejemplo, cuando defines permisos para un objeto Usuario, puedes usar un ACE específico de objeto para permitir al Principal Self (es decir, el usuario) acceso de escritura a la propiedad Phone-Home-Primary (homePhone), y puedes usar otros ACEs específicos de objeto para negar al Principal Self acceso a la propiedad Logon-Hours (logonHours) y otras propiedades que establecen restricciones en la cuenta de usuario.

La tabla a continuación muestra la disposición de cada ACE.

### Disposición de la Entrada de Control de Acceso

| Campo ACE   | Descripción                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Bandera que indica el tipo de ACE. Windows 2000 y Windows Server 2003 admiten seis tipos de ACE: Tres tipos de ACE genéricos que se adjuntan a todos los objetos asegurables. Tres tipos de ACE específicos de objeto que pueden ocurrir para objetos de Active Directory.                                                                                                                                                                                                                                                            |
| Banderas       | Conjunto de bits de banderas que controlan la herencia y la auditoría.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tamaño        | Número de bytes de memoria que se asignan para el ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Máscara de acceso | Valor de 32
