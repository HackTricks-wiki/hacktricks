# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Una Access Control List (ACL) consiste en un conjunto ordenado de Access Control Entries (ACEs) que determinan las protecciones de un objeto y sus propiedades. En esencia, una ACL define qué acciones de qué security principals (usuarios o grupos) están permitidas o denegadas sobre un objeto determinado.

Hay dos tipos de ACL:

- **Discretionary Access Control List (DACL):** Especifica qué usuarios y grupos tienen o no tienen acceso a un objeto.
- **System Access Control List (SACL):** Regula la auditoría de los intentos de acceso a un objeto.

El proceso de acceso a un archivo implica que el sistema compruebe el security descriptor del objeto frente al access token del usuario para determinar si se debe conceder el acceso y el alcance de dicho acceso, basándose en las ACEs.<sup>[[1]](#references)</sup>

### **Key Components**

- **DACL:** Contiene ACEs que conceden o deniegan permisos de acceso a usuarios y grupos para un objeto. Es, esencialmente, la ACL principal que determina los derechos de acceso.
- **SACL:** Se utiliza para auditar el acceso a objetos, donde las ACEs definen los tipos de acceso que se registrarán en el Security Event Log. Esto puede ser muy valioso para detectar intentos de acceso no autorizados o solucionar problemas de acceso.<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

Cada sesión de usuario está asociada a un access token que contiene información de seguridad relevante para dicha sesión, incluidas las identidades del usuario y de los grupos, así como los privilegios. Este token también incluye un logon SID que identifica la sesión de forma única.

La Local Security Authority (LSASS) procesa las solicitudes de acceso a objetos examinando la DACL en busca de ACEs que coincidan con el security principal que intenta acceder. El acceso se concede inmediatamente si no se encuentran ACEs relevantes. De lo contrario, LSASS compara las ACEs con el SID del security principal en el access token para determinar si el acceso es elegible.<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** Definen los permisos de acceso mediante DACLs y las reglas de auditoría mediante SACLs.
- **Access Token:** Contiene información del usuario, los grupos y los privilegios de una sesión.
- **Access Decision:** Se toma comparando las ACEs de la DACL con el access token; las SACLs se utilizan para la auditoría.<sup>[[1]](#references)</sup>

### ACEs

Hay **tres tipos principales de Access Control Entries (ACEs)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Esta ACE deniega explícitamente el acceso a un objeto a usuarios o grupos especificados (en una DACL).
- **Access Allowed ACE**: Esta ACE concede explícitamente el acceso a un objeto a usuarios o grupos especificados (en una DACL).
- **System Audit ACE**: Ubicada dentro de una System Access Control List (SACL), esta ACE se encarga de generar registros de auditoría cuando usuarios o grupos intentan acceder a un objeto. Documenta si el acceso fue permitido o denegado, así como la naturaleza del acceso.

Cada ACE tiene **cuatro componentes críticos**:<sup>[[1]](#references)</sup>

1. El **Security Identifier (SID)** del usuario o grupo (o su nombre principal en una representación gráfica).
2. Un **flag** que identifica el tipo de ACE (access denied, allowed o system audit).
3. **Inheritance flags** que determinan si los objetos secundarios pueden heredar la ACE de su elemento principal.
4. Una [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), un valor de 32 bits que especifica los derechos concedidos sobre el objeto.

La determinación del acceso se realiza examinando secuencialmente cada ACE hasta que:<sup>[[1]](#references)</sup>

- Una **Access-Denied ACE** deniega explícitamente los derechos solicitados a un trustee identificado en el access token.
- Una o más **Access-Allowed ACE(s)** conceden explícitamente todos los derechos solicitados a un trustee presente en el access token.
- Tras comprobar todas las ACEs, si algún derecho solicitado **no ha sido permitido explícitamente**, el acceso se **deniega** implícitamente.

### Order of ACEs

La forma en que las **ACEs** (reglas que indican quién puede o no puede acceder a algo) se colocan en una lista denominada **DACL** es muy importante. Esto se debe a que, una vez que el sistema concede o deniega el acceso basándose en estas reglas, deja de examinar las restantes.<sup>[[1]](#references)</sup>

Existe una forma óptima de organizar estas ACEs, denominada **"canonical order."** Este método ayuda a garantizar que todo funcione de forma correcta y coherente. Así es como funciona en sistemas como **Windows 2000** y **Windows Server 2003**:

- Primero, se colocan todas las reglas creadas **específicamente para este elemento** antes que las procedentes de otro lugar, como una carpeta principal.
- Dentro de esas reglas específicas, se colocan primero las que indican **"no" (deny)** y después las que indican **"sí" (allow)**.
- Para las reglas procedentes de otro lugar, se empieza por las del **origen más cercano**, como el elemento principal, y después se continúa hacia atrás. De nuevo, se coloca **"no"** antes que **"sí."**

Esta configuración ofrece dos ventajas importantes:

- Garantiza que, si existe un **"no"** específico, este se respete independientemente de las demás reglas **"sí"**.
- Permite que el propietario de un elemento tenga la **última palabra** sobre quién puede acceder, antes de que entren en juego las reglas de las carpetas principales o de niveles superiores.

Al organizar las reglas de esta forma, el propietario de un archivo o carpeta puede controlar con precisión quién obtiene acceso, asegurándose de que las personas adecuadas puedan acceder y las incorrectas no.

![NTFS access control entry ordering diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

Por tanto, este **"canonical order"** consiste en garantizar que las reglas de acceso sean claras y funcionen correctamente, colocando primero las reglas específicas y organizando todo de forma inteligente.

### GUI Example

[**Example from here**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Esta es la pestaña de seguridad clásica de una carpeta, que muestra la ACL, la DACL y las ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Si hacemos clic en el **Advanced button**, obtendremos más opciones, como la herencia:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Y si añadimos o editamos un Security Principal:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Por último, tenemos la SACL en la pestaña Auditing:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

Al gestionar el acceso a recursos, como una carpeta, utilizamos listas y reglas conocidas como Access Control Lists (ACLs) y Access Control Entries (ACEs). Estas definen quién puede o no puede acceder a determinados datos.<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

Imagina que tienes una carpeta llamada Cost y quieres que todo el mundo pueda acceder a ella excepto un equipo de marketing. Configurando correctamente las reglas, podemos garantizar que al equipo de marketing se le deniegue explícitamente el acceso antes de permitirlo al resto. Esto se consigue colocando la regla que deniega el acceso al equipo de marketing antes de la regla que permite el acceso a todos.

#### Allowing Access to a Specific Member of a Denied Group

Supongamos que Bob, el director de marketing, necesita acceder a la carpeta Cost, aunque el equipo de marketing no debería tener acceso en general. Podemos añadir una regla específica (ACE) para Bob que le conceda acceso y colocarla antes de la regla que deniega el acceso al equipo de marketing. De esta forma, Bob obtiene acceso a pesar de la restricción general aplicada a su equipo.

#### Understanding Access Control Entries

Las ACEs son las reglas individuales de una ACL. Identifican usuarios o grupos, especifican qué acceso está permitido o denegado y determinan cómo se aplican estas reglas a los subelementos (inheritance). Hay dos tipos principales de ACEs:

- **Generic ACEs**: Se aplican de forma general y afectan a todos los tipos de objetos, o distinguen únicamente entre containers (como carpetas) y non-containers (como archivos). Por ejemplo, una regla que permite a los usuarios ver el contenido de una carpeta, pero no acceder a los archivos que contiene.
- **Object-Specific ACEs**: Proporcionan un control más preciso, permitiendo establecer reglas para tipos concretos de objetos o incluso para propiedades individuales dentro de un objeto. Por ejemplo, en un directorio de usuarios, una regla podría permitir que un usuario actualice su número de teléfono, pero no sus horas de inicio de sesión.

Cada ACE contiene información importante, como a quién se aplica la regla (mediante un Security Identifier o SID), qué permite o deniega la regla (mediante una access mask) y cómo se hereda en otros objetos.

#### Key Differences Between ACE Types

- **Generic ACEs** son adecuadas para escenarios sencillos de control de acceso, en los que la misma regla se aplica a todos los aspectos de un objeto o a todos los objetos dentro de un container.
- **Object-Specific ACEs** se utilizan en escenarios más complejos, especialmente en entornos como Active Directory, donde puede ser necesario controlar de forma diferente el acceso a propiedades específicas de un objeto.

En resumen, las ACLs y las ACEs ayudan a definir controles de acceso precisos, garantizando que solo las personas o grupos adecuados tengan acceso a información o recursos sensibles, con la posibilidad de ajustar los derechos de acceso hasta el nivel de propiedades individuales o tipos de objetos.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flag que indica el tipo de ACE. Windows 2000 y Windows Server 2003 admiten seis tipos de ACE: tres tipos de ACE genéricas asociadas a todos los objetos securizables y tres tipos de ACE específicas de objeto que pueden aparecer en objetos de Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Conjunto de flags de bits que controlan la herencia y la auditoría.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Número de bytes de memoria asignados para la ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | Valor de 32 bits cuyos bits corresponden a los derechos de acceso del objeto. Los bits pueden estar activados o desactivados, pero el significado de esta configuración depende del tipo de ACE. Por ejemplo, si el bit correspondiente al derecho de leer permisos está activado y el tipo de ACE es Deny, la ACE deniega el derecho a leer los permisos del objeto. Si el mismo bit está activado, pero el tipo de ACE es Allow, la ACE concede el derecho a leer los permisos del objeto. En la siguiente tabla se muestran más detalles sobre la Access mask. |
| SID         | Identifica a un usuario o grupo cuyo acceso está controlado o supervisado por esta ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | Leer datos, ejecutar, añadir datos           |
| 16 - 22     | Standard Access Rights             | Eliminar, escribir ACL, escribir el propietario            |
| 23          | Can access security ACL            |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | Todo lo que aparece a continuación                          |
| 29          | Generic Execute                    | Todo lo necesario para ejecutar un programa |
| 30          | Generic Write                      | Todo lo necesario para escribir en un archivo   |
| 31          | Generic Read                       | Todo lo necesario para leer un archivo       |

## References

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
