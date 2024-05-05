# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si desea ver su **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtenga la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únase al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síganos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparta sus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en GitHub.

</details>

## **Lista de Control de Acceso (ACL)**

Una Lista de Control de Acceso (ACL) consiste en un conjunto ordenado de Entradas de Control de Acceso (ACEs) que dictan las protecciones para un objeto y sus propiedades. En esencia, un ACL define qué acciones de qué principios de seguridad (usuarios o grupos) están permitidas o denegadas en un objeto dado.

Existen dos tipos de ACLs:

* **Lista de Control de Acceso Discrecional (DACL):** Especifica qué usuarios y grupos tienen o no tienen acceso a un objeto.
* **Lista de Control de Acceso del Sistema (SACL):** Rige la auditoría de intentos de acceso a un objeto.

El proceso de acceso a un archivo implica que el sistema verifique el descriptor de seguridad del objeto con el token de acceso del usuario para determinar si se debe otorgar acceso y la extensión de ese acceso, basado en los ACEs.

### **Componentes Clave**

* **DACL:** Contiene ACEs que otorgan o niegan permisos de acceso a usuarios y grupos para un objeto. Esencialmente, es el ACL principal que dicta los derechos de acceso.
* **SACL:** Utilizado para auditar el acceso a objetos, donde los ACEs definen los tipos de acceso que se registrarán en el Registro de Eventos de Seguridad. Esto puede ser invaluable para detectar intentos de acceso no autorizados o solucionar problemas de acceso.

### **Interacción del Sistema con ACLs**

Cada sesión de usuario está asociada con un token de acceso que contiene información de seguridad relevante para esa sesión, incluidas identidades de usuario, grupo y privilegios. Este token también incluye un SID de inicio de sesión que identifica de manera única la sesión.

La Autoridad de Seguridad Local (LSASS) procesa las solicitudes de acceso a objetos examinando el DACL en busca de ACEs que coincidan con el principal de seguridad que intenta acceder. El acceso se otorga de inmediato si no se encuentran ACEs relevantes. De lo contrario, LSASS compara los ACEs con el SID del principal de seguridad en el token de acceso para determinar la elegibilidad de acceso.

### **Proceso Resumido**

* **ACLs:** Definen permisos de acceso a través de DACLs y reglas de auditoría a través de SACLs.
* **Token de Acceso:** Contiene información de usuario, grupo y privilegios para una sesión.
* **Decisión de Acceso:** Se realiza comparando los ACEs de DACL con el token de acceso; los SACLs se utilizan para la auditoría.

### ACEs

Existen **tres tipos principales de Entradas de Control de Acceso (ACEs)**:

* **ACE de Acceso Denegado**: Este ACE niega explícitamente el acceso a un objeto para usuarios o grupos especificados (en un DACL).
* **ACE de Acceso Permitido**: Este ACE otorga explícitamente acceso a un objeto para usuarios o grupos especificados (en un DACL).
* **ACE de Auditoría del Sistema**: Situado dentro de una Lista de Control de Acceso del Sistema (SACL), este ACE es responsable de generar registros de auditoría en intentos de acceso a un objeto por usuarios o grupos. Documenta si se permitió o denegó el acceso y la naturaleza del acceso.

Cada ACE tiene **cuatro componentes críticos**:

1. El **Identificador de Seguridad (SID)** del usuario o grupo (o su nombre principal en una representación gráfica).
2. Una **bandera** que identifica el tipo de ACE (acceso denegado, permitido o auditoría del sistema).
3. **Banderas de herencia** que determinan si los objetos secundarios pueden heredar el ACE de su padre.
4. Una [**máscara de acceso**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), un valor de 32 bits que especifica los derechos otorgados al objeto.

La determinación de acceso se realiza examinando secuencialmente cada ACE hasta que:

* Un **ACE de Acceso Denegado** niega explícitamente los derechos solicitados a un fideicomisario identificado en el token de acceso.
* Los **ACE(s) de Acceso Permitido** otorgan explícitamente todos los derechos solicitados a un fideicomisario en el token de acceso.
* Al verificar todos los ACEs, si algún derecho solicitado **no ha sido explícitamente permitido**, el acceso se deniega implícitamente.

### Orden de ACEs

La forma en que se colocan las **ACEs** (reglas que dicen quién puede o no puede acceder a algo) en una lista llamada **DACL** es muy importante. Esto se debe a que una vez que el sistema otorga o niega acceso en función de estas reglas, deja de mirar el resto.

Existe una mejor manera de organizar estas ACEs, y se llama **"orden canónico"**. Este método ayuda a garantizar que todo funcione sin problemas y de manera justa. Así es como funciona para sistemas como **Windows 2000** y **Windows Server 2003**:

* Primero, coloque todas las reglas que se crean **específicamente para este elemento** antes que las que provienen de otro lugar, como una carpeta principal.
* En esas reglas específicas, coloque primero las que dicen **"no" (denegar)** antes que las que dicen **"sí" (permitir)**.
* Para las reglas que provienen de otro lugar, comience con las que vienen de la **fuente más cercana**, como la carpeta principal, y luego retroceda desde allí. Nuevamente, coloque **"no"** antes de **"sí"**.

Esta configuración ayuda de dos maneras importantes:

* Asegura que si hay un **"no"** específico, se respete, sin importar qué otras reglas de **"sí"** estén presentes.
* Permite que el propietario de un elemento tenga la **última palabra** sobre quién puede acceder, antes de que entren en juego las reglas de las carpetas principales o más atrás.

Al hacer las cosas de esta manera, el propietario de un archivo o carpeta puede ser muy preciso sobre quién tiene acceso, asegurándose de que las personas adecuadas puedan acceder y las incorrectas no puedan.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Entonces, este **"orden canónico"** se trata de asegurarse de que las reglas de acceso sean claras y funcionen bien, colocando reglas específicas primero y organizando todo de manera inteligente.

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
### Ejemplo de GUI

[**Ejemplo desde aquí**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Este es el clásico panel de seguridad de una carpeta que muestra el ACL, DACL y ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Si hacemos clic en el **botón Avanzado**, obtendremos más opciones como la herencia:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Y si agregas o editas un Principal de Seguridad:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Y por último, tenemos el SACL en la pestaña de Auditoría:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Explicando el Control de Acceso de una Manera Simplificada

Al gestionar el acceso a recursos, como una carpeta, utilizamos listas y reglas conocidas como Listas de Control de Acceso (ACLs) y Entradas de Control de Acceso (ACEs). Estas definen quién puede o no puede acceder a ciertos datos.

#### Denegar Acceso a un Grupo Específico

Imagina que tienes una carpeta llamada Costo, y quieres que todos accedan a ella excepto el equipo de marketing. Al configurar las reglas correctamente, podemos asegurar que al equipo de marketing se le deniegue explícitamente el acceso antes de permitir que todos los demás accedan. Esto se logra colocando la regla para denegar el acceso al equipo de marketing antes de la regla que permite el acceso a todos.

#### Permitir Acceso a un Miembro Específico de un Grupo Denegado

Digamos que Bob, el director de marketing, necesita acceso a la carpeta Costo, aunque en general el equipo de marketing no debería tener acceso. Podemos agregar una regla específica (ACE) para Bob que le otorgue acceso, y colocarla antes de la regla que deniega el acceso al equipo de marketing. De esta manera, Bob obtiene acceso a pesar de la restricción general en su equipo.

#### Entendiendo las Entradas de Control de Acceso

Las ACEs son las reglas individuales en un ACL. Identifican usuarios o grupos, especifican qué acceso está permitido o denegado, y determinan cómo se aplican estas reglas a subelementos (herencia). Hay dos tipos principales de ACEs:

* **ACEs Genéricas**: Estas se aplican de manera amplia, afectando a todos los tipos de objetos o distinguiendo solo entre contenedores (como carpetas) y no contenedores (como archivos). Por ejemplo, una regla que permite a los usuarios ver el contenido de una carpeta pero no acceder a los archivos dentro de ella.
* **ACEs Específicas del Objeto**: Estas proporcionan un control más preciso, permitiendo establecer reglas para tipos específicos de objetos o incluso propiedades individuales dentro de un objeto. Por ejemplo, en un directorio de usuarios, una regla podría permitir a un usuario actualizar su número de teléfono pero no sus horas de inicio de sesión.

Cada ACE contiene información importante como a quién se aplica la regla (usando un Identificador de Seguridad o SID), qué permite o deniega la regla (usando una máscara de acceso) y cómo se hereda por otros objetos.

#### Diferencias Clave Entre los Tipos de ACE

* Las **ACEs Genéricas** son adecuadas para escenarios simples de control de acceso, donde la misma regla se aplica a todos los aspectos de un objeto o a todos los objetos dentro de un contenedor.
* Las **ACEs Específicas del Objeto** se utilizan para escenarios más complejos, especialmente en entornos como Active Directory, donde es posible que necesites controlar el acceso a propiedades específicas de un objeto de manera diferente.

En resumen, las ACLs y ACEs ayudan a definir controles de acceso precisos, asegurando que solo las personas o grupos adecuados tengan acceso a información o recursos sensibles, con la capacidad de adaptar los derechos de acceso hasta el nivel de propiedades individuales o tipos de objetos.

### Diseño de la Entrada de Control de Acceso

| Campo ACE  | Descripción                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Indicador que muestra el tipo de ACE. Windows 2000 y Windows Server 2003 admiten seis tipos de ACE: Tres tipos de ACE genéricos que se adjuntan a todos los objetos securizables. Tres tipos de ACE específicos del objeto que pueden ocurrir para objetos de Active Directory.                                                                                                                                                                                                                                                            |
| Banderas       | Conjunto de bits que controlan la herencia y la auditoría.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tamaño        | Número de bytes de memoria asignados para el ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Máscara de acceso | Valor de 32 bits cuyos bits corresponden a los derechos de acceso para el objeto. Los bits pueden estar activados o desactivados, pero el significado de la configuración depende del tipo de ACE. Por ejemplo, si el bit que corresponde al derecho de leer permisos está activado, y el tipo de ACE es Denegar, el ACE deniega el derecho de leer los permisos del objeto. Si el mismo bit está activado pero el tipo de ACE es Permitir, el ACE otorga el derecho de leer los permisos del objeto. Más detalles de la Máscara de Acceso aparecen en la tabla siguiente. |
| SID         | Identifica a un usuario o grupo cuyo acceso es controlado o monitoreado por este ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Diseño de la Máscara de Acceso

| Bit (Rango) | Significado                            | Descripción/Ejemplo                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Derechos de Acceso Específicos del Objeto      | Leer datos, Ejecutar, Anexar datos           |
| 16 - 22     | Derechos de Acceso Estándar             | Eliminar, Escribir ACL, Escribir Propietario            |
| 23          | Puede acceder a la ACL de seguridad            |                                           |
| 24 - 27     | Reservado                           |                                           |
| 28          | Genérico TODO (Leer, Escribir, Ejecutar) | Todo lo anterior                          |
| 29          | Genérico Ejecutar                    | Todo lo necesario para ejecutar un programa |
| 30          | Genérico Escribir                      | Todo lo necesario para escribir en un archivo   |
| 31          | Genérico Leer                       | Todo lo necesario para leer un archivo       |

## Referencias

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
* [https://www.coopware.in2.info/\_ntfsacl\_ht.htm](https://www.coopware.in2.info/\_ntfsacl\_ht.htm)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**repositorios de GitHub de HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
