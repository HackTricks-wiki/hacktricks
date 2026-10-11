# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Lista de control de acceso (ACL)**

Una lista de control de acceso (ACL) consta de un conjunto ordenado de entradas de control de acceso (ACEs) que determinan las protecciones de un objeto y sus propiedades. En esencia, una ACL define qué acciones pueden o no pueden realizar determinados principales de seguridad (usuarios o grupos) en un objeto.

Hay dos tipos de ACL:

- **Lista de control de acceso discrecional (DACL):** Especifica qué usuarios y grupos tienen o no tienen acceso a un objeto.
- **Lista de control de acceso del sistema (SACL):** Controla la auditoría de los intentos de acceso a un objeto.

Para acceder a un archivo, el sistema compara el descriptor de seguridad del objeto con el token de acceso del usuario a fin de determinar si se debe conceder el acceso y qué nivel de acceso otorgar, según las ACEs.<sup>[[1]](#references)</sup>

Si un directorio principal concede Full Control, pero un archivo secundario deniega la lectura, revisa por separado la DACL efectiva, el propietario y la herencia del **archivo secundario**. Para cambiar la DACL de ese archivo, se requiere `WRITE_DAC` sobre el archivo o el derecho aplicable del propietario; [Microsoft define `WRITE_DAC`](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) y [documenta el acceso implícito del propietario](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). Los permisos del directorio principal por sí solos no garantizan que se pueda leer el archivo secundario ni cambiar su DACL.

### **Componentes clave**

- **DACL:** Contiene ACEs que conceden o deniegan permisos de acceso a usuarios y grupos para un objeto. Es, esencialmente, la ACL principal que determina los derechos de acceso.
- **SACL:** Se usa para auditar el acceso a objetos; sus ACEs definen los tipos de acceso que se registrarán en el Registro de eventos de seguridad. Esto puede ser muy valioso para detectar intentos de acceso no autorizados o solucionar problemas de acceso.<sup>[[1]](#references)</sup>

### **Interacción del sistema con las ACLs**

Cada sesión de usuario está asociada a un token de acceso que contiene información de seguridad relevante para esa sesión, incluidas las identidades de usuario y grupo, y los privilegios. Este token también incluye un SID de inicio de sesión que identifica de forma única la sesión.

La Autoridad de seguridad local (LSASS) procesa las solicitudes de acceso a objetos examinando la DACL en busca de ACEs que coincidan con el principal de seguridad que intenta acceder. El acceso se concede de inmediato si no se encuentran ACEs pertinentes. De lo contrario, LSASS compara las ACEs con el SID del principal de seguridad en el token de acceso para determinar si puede acceder.<sup>[[1]](#references)</sup>

### **Proceso resumido**

- **ACLs:** Definen permisos de acceso mediante DACLs y reglas de auditoría mediante SACLs.
- **Token de acceso:** Contiene información de usuario, grupo y privilegios de una sesión.
- **Decisión de acceso:** Se toma comparando las ACEs de la DACL con el token de acceso; las SACLs se usan para la auditoría.<sup>[[1]](#references)</sup>

### ACEs

Hay **tres tipos principales de entradas de control de acceso (ACEs)**:<sup>[[1]](#references)</sup>

- **ACE de denegación de acceso**: Esta ACE deniega explícitamente el acceso a un objeto a usuarios o grupos especificados (en una DACL).
- **ACE de concesión de acceso**: Esta ACE concede explícitamente acceso a un objeto a usuarios o grupos especificados (en una DACL).
- **ACE de auditoría del sistema**: Ubicada en una lista de control de acceso del sistema (SACL), esta ACE genera registros de auditoría cuando usuarios o grupos intentan acceder a un objeto. Registra si se permitió o denegó el acceso y la naturaleza de este.

Cada ACE tiene **cuatro componentes fundamentales**:<sup>[[1]](#references)</sup>

1. El **identificador de seguridad (SID)** del usuario o grupo (o el nombre de su principal en una representación gráfica).
2. Una **marca** que identifica el tipo de ACE (denegación de acceso, concesión de acceso o auditoría del sistema).
3. **Marcas de herencia** que determinan si los objetos secundarios pueden heredar la ACE del objeto principal.
4. Una [**máscara de acceso**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), un valor de 32 bits que especifica los derechos concedidos sobre el objeto.

El acceso se determina examinando secuencialmente cada ACE hasta que:<sup>[[1]](#references)</sup>

- Una **ACE de denegación de acceso** deniega explícitamente los derechos solicitados a un trustee identificado en el token de acceso.
- Una o varias **ACEs de concesión de acceso** conceden explícitamente todos los derechos solicitados a un trustee del token de acceso.
- Tras comprobar todas las ACEs, si algún derecho solicitado **no se ha concedido explícitamente**, el acceso se **deniega** implícitamente.

### Orden de las ACEs

La forma en que se colocan las **ACEs** (reglas que indican quién puede o no puede acceder a algo) en una lista llamada **DACL** es muy importante. Esto se debe a que, una vez que el sistema concede o deniega el acceso según estas reglas, deja de comprobar las demás.<sup>[[1]](#references)</sup>

Existe una forma óptima de organizar estas ACEs, llamada **«orden canónico»**. Este método ayuda a que todo funcione de forma fluida y justa. Así se aplica en sistemas como **Windows 2000** y **Windows Server 2003**:

- Primero, coloca todas las reglas **específicas de este elemento** antes que las que provienen de otro lugar, como una carpeta principal.
- Entre esas reglas específicas, coloca primero las que indican **«denegar»** y luego las que indican **«permitir»**.
- Para las reglas que provienen de otro lugar, empieza por las del **origen más cercano**, como la carpeta principal, y continúa hacia atrás. De nuevo, coloca primero las que indican **«denegar»** y luego las que indican **«permitir»**.

Esta configuración ayuda de dos maneras importantes:

- Garantiza que se respete cualquier **denegación** específica, independientemente de las demás reglas de **concesión**.
- Permite que el propietario de un elemento tenga la **última palabra** sobre quién puede acceder, antes de que se apliquen las reglas de las carpetas principales o de otros niveles superiores.

Al organizar las reglas de esta manera, el propietario de un archivo o carpeta puede controlar con precisión quién tiene acceso y asegurarse de que las personas adecuadas puedan acceder y las demás no.

![Diagrama del orden de las entradas de control de acceso de NTFS](https://www.ntfs.com/images/screenshots/ACEs.gif)

Por tanto, el **«orden canónico»** consiste en garantizar que las reglas de acceso sean claras y funcionen bien: primero se colocan las reglas específicas y luego se organiza todo de manera coherente.

### Ejemplo de GUI

[**Ejemplo aquí**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Esta es la pestaña de seguridad clásica de una carpeta, donde se muestran la ACL, la DACL y las ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Si hacemos clic en el **botón Advanced**, veremos más opciones, como la herencia:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Y si agregamos o editamos un principal de seguridad:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Por último, tenemos la SACL en la pestaña Auditing:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explicación simplificada del control de acceso

Al administrar el acceso a recursos, como una carpeta, usamos listas y reglas conocidas como listas de control de acceso (ACLs) y entradas de control de acceso (ACEs). Estas definen quién puede o no puede acceder a ciertos datos.<sup>[[1]](#references)</sup>

#### Denegar el acceso a un grupo específico

Imagina que tienes una carpeta llamada Cost y quieres que todos puedan acceder a ella, excepto el equipo de marketing. Si configuramos correctamente las reglas, podemos asegurarnos de que se deniegue explícitamente el acceso al equipo de marketing antes de permitirlo a los demás. Para ello, colocamos la regla que deniega el acceso al equipo de marketing antes de la regla que permite el acceso a todos.

#### Permitir el acceso a un miembro específico de un grupo al que se deniega el acceso

Supongamos que Bob, el director de marketing, necesita acceder a la carpeta Cost, aunque el equipo de marketing no debería tener acceso en general. Podemos agregar una regla específica (ACE) para Bob que le conceda acceso y colocarla antes de la regla que deniega el acceso al equipo de marketing. Así, Bob obtiene acceso pese a la restricción general de su equipo.

#### Comprender las entradas de control de acceso

Las ACEs son las reglas individuales de una ACL. Identifican usuarios o grupos, especifican qué acceso se permite o deniega y determinan cómo se aplican estas reglas a los elementos secundarios (herencia). Hay dos tipos principales de ACEs:

- **ACEs genéricas**: Se aplican de forma general, ya sea a todos los tipos de objetos o distinguiendo únicamente entre contenedores (como carpetas) y objetos que no son contenedores (como archivos). Por ejemplo, una regla que permite a los usuarios ver el contenido de una carpeta, pero no acceder a los archivos que contiene.
- **ACEs específicas de objeto**: Ofrecen un control más preciso, ya que permiten establecer reglas para tipos específicos de objetos o incluso para propiedades individuales de un objeto. Por ejemplo, en un directorio de usuarios, una regla podría permitir que un usuario actualice su número de teléfono, pero no sus horas de inicio de sesión.

Cada ACE contiene información importante, como a quién se aplica la regla (mediante un identificador de seguridad o SID), qué permite o deniega la regla (mediante una máscara de acceso) y cómo la heredan otros objetos.

#### Diferencias clave entre los tipos de ACE

- Las **ACEs genéricas** son adecuadas para situaciones sencillas de control de acceso, donde la misma regla se aplica a todos los aspectos de un objeto o a todos los objetos de un contenedor.
- Las **ACEs específicas de objeto** se usan en situaciones más complejas, especialmente en entornos como Active Directory, donde puede ser necesario controlar de forma diferente el acceso a determinadas propiedades de un objeto.

En resumen, las ACLs y las ACEs ayudan a definir controles de acceso precisos, garantizando que solo las personas o grupos adecuados puedan acceder a información o recursos confidenciales, y permiten adaptar los derechos de acceso hasta el nivel de propiedades individuales o tipos de objetos.

### Estructura de una entrada de control de acceso

| Campo de ACE | Descripción                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Marca que indica el tipo de ACE. Windows 2000 y Windows Server 2003 admiten seis tipos de ACE: tres tipos de ACE genéricos que se aplican a todos los objetos protegibles y tres tipos de ACE específicos de objeto que pueden aparecer en objetos de Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Conjunto de marcas de bits que controlan la herencia y la auditoría.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Número de bytes de memoria asignados a la ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | Valor de 32 bits cuyos bits corresponden a los derechos de acceso al objeto. Los bits pueden activarse o desactivarse, pero el significado de cada configuración depende del tipo de ACE. Por ejemplo, si se activa el bit correspondiente al derecho de leer los permisos y el tipo de ACE es Deny, la ACE deniega el derecho a leer los permisos del objeto. Si se activa el mismo bit y el tipo de ACE es Allow, la ACE concede el derecho a leer los permisos del objeto. En la siguiente tabla se ofrecen más detalles sobre la máscara de acceso. |
| SID         | Identifica al usuario o grupo cuyo acceso controla o supervisa esta ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Estructura de la máscara de acceso

| Bit (rango) | Significado                        | Descripción/Ejemplo                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Derechos de acceso específicos del objeto | Leer datos, ejecutar, anexar datos           |
| 16 - 22     | Derechos de acceso estándar        | Eliminar, escribir ACL, escribir propietario            |
| 23          | Puede acceder a la ACL de seguridad |                                           |
| 24 - 27     | Reservado                          |                                           |
| 28          | Generic ALL (leer, escribir, ejecutar) | Todo lo siguiente                          |
| 29          | Generic Execute                    | Todo lo necesario para ejecutar un programa |
| 30          | Generic Write                      | Todo lo necesario para escribir en un archivo   |
| 31          | Generic Read                       | Todo lo necesario para leer un archivo       |

## References

- [1] [Cómo usa el sistema las ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL y ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
