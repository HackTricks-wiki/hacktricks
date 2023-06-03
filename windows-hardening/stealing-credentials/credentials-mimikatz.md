# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

El contenido de esta página fue copiado de [adsecurity.org](https://adsecurity.org/?page\_id=1821)

## LM y texto claro en memoria

A partir de Windows 8.1 y Windows Server 2012 R2, el hash LM y la contraseña en "texto claro" ya no están en memoria.

Para evitar que la contraseña en "texto claro" se coloque en LSASS, se debe establecer la siguiente clave de registro en "0" (Digest Disabled):

_HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest “UseLogonCredential”(DWORD)_

## **Mimikatz y protección LSA:**

Windows Server 2012 R2 y Windows 8.1 incluyen una nueva función llamada Protección LSA que implica habilitar [LSASS como un proceso protegido en Windows Server 2012 R2](https://technet.microsoft.com/en-us/library/dn408187.aspx) (Mimikatz puede omitirlo con un controlador, pero eso debería hacer ruido en los registros de eventos):

_El LSA, que incluye el proceso del Servicio del Servidor de Autoridad de Seguridad Local (LSASS), valida a los usuarios para iniciar sesión local y remota y hace cumplir las políticas de seguridad locales. El sistema operativo Windows 8.1 proporciona protección adicional para el LSA para evitar la lectura de memoria y la inyección de código por parte de procesos no protegidos. Esto proporciona seguridad adicional para las credenciales que el LSA almacena y administra._

Habilitar la protección LSA:

1. Abra el Editor del Registro (RegEdit.exe) y navegue hasta la clave del registro que se encuentra en: HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa y establezca el valor de la clave del registro en: "RunAsPPL"=dword:00000001.
2. Cree una nueva directiva de grupo y navegue hasta Configuración del equipo, Preferencias, Configuración de Windows. Haga clic con el botón derecho en Registro, apunte a Nuevo y luego haga clic en Elemento de registro. Aparece el cuadro de diálogo Propiedades de registro nuevo. En la lista de Hive, haga clic en HKEY\_LOCAL\_MACHINE. En la lista de Ruta de clave, navegue hasta SYSTEM\CurrentControlSet\Control\Lsa. En el cuadro de nombre de valor, escriba RunAsPPL. En el cuadro de tipo de valor, haga clic en REG\_DWORD. En el cuadro de datos de valor, escriba 00000001. Haga clic en Aceptar.

La protección LSA evita que los procesos no protegidos interactúen con LSASS. Mimikatz todavía puede omitir esto con un controlador ("!+").

[![Mimikatz-Driver-Remove-LSASS-Protection](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Driver-Remove-LSASS-Protection.jpg)

### Saltarse SeDebugPrivilege deshabilitado
Por defecto, SeDebugPrivilege se otorga al grupo Administradores a través de la Política de seguridad local. En un entorno de Active Directory, [es posible eliminar este privilegio](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5) estableciendo Configuración del equipo --> Directivas --> Configuración de Windows --> Directivas de seguridad --> Asignación de derechos de usuario --> Programas de depuración definidos como un grupo vacío. Incluso en dispositivos conectados a AD sin conexión, esta configuración no se puede sobrescribir y los administradores locales recibirán un error al intentar volcar la memoria o usar Mimikatz.

Sin embargo, la cuenta TrustedInstaller seguirá teniendo acceso para volcar la memoria y [puede usarse para saltarse esta defensa](https://www.pepperclipp.com/other-articles/dump-lsass-when-debug-privilege-is-disabled). Al modificar la configuración del servicio TrustedInstaller, se puede ejecutar la cuenta para usar ProcDump y volcar la memoria de `lsass.exe`.
```
sc config TrustedInstaller binPath= "C:\Users\Public\procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp"
sc start TrustedInstaller
```
[![TrustedInstaller-Dump-Lsass](https://1860093151-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-M6yZUYP7DLMbZuztKpV%2Fuploads%2FJtprjloNPADNSpb6S0DS%2Fimage.png?alt=media&token=9b639459-bd4c-4897-90af-8990125fa058)

Este archivo de volcado se puede exfiltrar a un equipo controlado por un atacante donde se pueden extraer las credenciales. ]
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Principal

### **EVENTO**

**EVENTO::Clear** – Limpia un registro de eventos\
[\
![Mimikatz-Event-Clear](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Clear.png)

**EVENTO:::Drop** – (_**experimental**_) Parchea el servicio de eventos para evitar nuevos eventos

[![Mimikatz-Event-Drop](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Event-Drop.png)

Nota:\
Ejecute privilege::debug y luego event::drop para parchear el registro de eventos. Luego ejecute Event::Clear para limpiar el registro de eventos sin que se registre ningún evento de registro borrado (1102).

### KERBEROS

#### Golden Ticket

Un Golden Ticket es un TGT que utiliza el hash de contraseña NTLM de KRBTGT para cifrar y firmar.

Se puede crear un Golden Ticket (GT) para suplantar a cualquier usuario (real o imaginario) en el dominio como miembro de cualquier grupo en el dominio (proporcionando una cantidad virtualmente ilimitada de derechos) para cualquier recurso en el dominio.

**Referencia de comandos de Mimikatz Golden Ticket:**

El comando Mimikatz para crear un Golden Ticket es "kerberos::golden"

* /domain – el nombre de dominio completamente calificado. En este ejemplo: "lab.adsecurity.org".
* /sid – el SID del dominio. En este ejemplo: "S-1-5-21-1473643419-774954089-2222329127".
* /sids – SIDs adicionales para cuentas/grupos en el bosque AD con derechos que desea suplantar. Por lo general, este será el grupo Enterprise Admins para el dominio raíz "S-1-5-21-1473643419-774954089-5872329127-519". Este parámetro agrega los SIDs proporcionados al parámetro de Historial de SID.](https://adsecurity.org/?p=1640)
* /user – nombre de usuario para suplantar
* /groups (opcional) – RID de grupo al que pertenece el usuario (el primero es el grupo principal).\
  Agregue RID de cuentas de usuario o computadora para recibir el mismo acceso.\
  Grupos predeterminados: 513,512,520,518,519 para los grupos de Administradores conocidos (enumerados a continuación).
* /krbtgt – hash de contraseña NTLM para la cuenta de servicio KDC de dominio (KRBTGT). Se utiliza para cifrar y firmar el TGT.
* /ticket (opcional) – proporcione una ruta y un nombre para guardar el archivo Golden Ticket para su uso posterior o use /ptt para inyectar inmediatamente el Golden Ticket en la memoria para su uso.
* /ptt – como alternativa a /ticket – use esto para inyectar inmediatamente el ticket falsificado en la memoria para su uso.
* /id (opcional) – RID de usuario. El valor predeterminado de Mimikatz es 500 (el RID de la cuenta de administrador predeterminada).
* /startoffset (opcional) – el desplazamiento de inicio cuando el ticket está disponible (generalmente se establece en -10 o 0 si se utiliza esta opción). El valor predeterminado de Mimikatz es 0.
* /endin (opcional) – tiempo de vida del ticket. El valor predeterminado de Mimikatz es de 10 años (\~5,262,480 minutos). La configuración de la política de Kerberos predeterminada de Active Directory es de 10 horas (600 minutos).
* /renewmax (opcional) – tiempo de vida máximo del ticket con renovación. El valor predeterminado de Mimikatz es de 10 años (\~5,262,480 minutos). La configuración de la política de Kerberos predeterminada de Active Directory es de 7 días (10,080 minutos).
* /sids (opcional) – establezca el SID del grupo Enterprise Admins en el bosque AD (\[ADRootDomainSID]-519) para suplantar los derechos de administrador de Enterprise en todo el bosque AD (administrador de AD en cada dominio en el bosque AD).
* /aes128 – la clave AES128
* /aes256 – la clave AES256

Grupos predeterminados de Golden Ticket:

* SID de usuarios de dominio: S-1-5-21\<DOMAINID>-513
* SID de administradores de dominio: S-1-5-21\<DOMAINID>-512
* SID de administradores de esquema: S-1-5-21\<DOMAINID>-518
* SID de administradores de empresa: S-1-5-21\<DOMAINID>-519 (esto solo es efectivo cuando se crea el ticket falso en el dominio raíz del bosque, aunque se agrega usando el parámetro /sids para los derechos de administrador de AD en el bosque)
* SID de propietarios de creadores de directivas de grupo: S-1-5-21\<DOMAINID>-520
```
.\mimikatz "kerberos::golden /User:Administrator /domain:rd.lab.adsecurity.org /id:512 /sid:S-1-5-21-135380161-102191138-581311202 /krbtgt:13026055d01f235d67634e109da03321 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" exit
```
[Golden tickets en diferentes dominios](https://adsecurity.org/?p=1640)

#### Silver Ticket

Un Silver Ticket es un TGS (similar al TGT en formato) que utiliza el hash de contraseña NTLM de la cuenta de servicio objetivo (identificada por el mapeo SPN) para cifrar y firmar.

**Ejemplo de comando Mimikatz para crear un Silver Ticket:**

El siguiente comando de Mimikatz crea un Silver Ticket para el servicio CIFS en el servidor adsmswin2k8r2.lab.adsecurity.org. Para que este Silver Ticket se cree correctamente, se necesita descubrir el hash de contraseña de la cuenta de equipo de AD para adsmswin2k8r2.lab.adsecurity.org, ya sea a partir de un volcado de dominio AD o ejecutando Mimikatz en el sistema local como se muestra arriba (_Mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit_). El hash de contraseña NTLM se utiliza con el parámetro /rc4. El tipo de SPN de servicio también debe identificarse en el parámetro /service. Finalmente, el nombre de dominio completo del equipo objetivo debe proporcionarse en el parámetro /target. No olvide el SID del dominio en el parámetro /sid.
```
mimikatz “kerberos::golden /admin:LukeSkywalker /id:1106 /domain:lab.adsecurity.org /sid:S-1-5-21-1473643419-774954089-2222329127 /target:adsmswin2k8r2.lab.adsecurity.org /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt” exit
```
#### [**Trust Ticket**](https://adsecurity.org/?p=1588)

Una vez que se determina el hash de la contraseña de confianza de Active Directory, se puede generar un ticket de confianza. Los tickets de confianza se crean utilizando la contraseña compartida entre 2 Dominios que confían entre sí.\
[Más información sobre los tickets de confianza.](https://adsecurity.org/?p=1588)

**Volcado de contraseñas de confianza (claves de confianza)**
```
Mimikatz “privilege::debug” “lsadump::trust /patch” exit
```
**Crear un ticket de confianza falsificado (TGT inter-realm) usando Mimikatz**

Forjar el ticket de confianza que indica que el titular del ticket es un administrador empresarial en el bosque de AD (aprovechando SIDHistory, "sids", a través de confianzas en Mimikatz, mi "contribución" a Mimikatz). Esto permite acceso administrativo completo desde un dominio secundario al dominio principal. Tenga en cuenta que esta cuenta no tiene que existir en ninguna parte, ya que es efectivamente un Golden Ticket a través de la confianza.
```
Mimikatz “Kerberos::golden /domain:child.lab.adsecurity.org /sid:S-1-5-21-3677078698-724690114-1972670770 /sids:S-1-5-21-1581655573-3923512380-696647894-519 /rc4:49ed1653275f78846ff06de1a02386fd /user:DarthVader /service:krbtgt /target:lab.adsecurity.org /ticket:c:\temp\tickets\EA-ADSECLABCHILD.kirbi” exit
```
Parámetros requeridos específicos de Trust Ticket:

* \*\*/\*\*target – el FQDN del dominio objetivo.
* \*\*/\*\*service – el servicio Kerberos que se ejecuta en el dominio objetivo (krbtgt).
* \*\*/\*\*rc4 – el hash NTLM para la cuenta de servicio del servicio Kerberos (krbtgt).
* \*\*/\*\*ticket – proporciona una ruta y un nombre para guardar el archivo de ticket forjado para su uso posterior o usa /ptt para inyectar inmediatamente el golden ticket en la memoria para su uso.

#### **Más sobre KERBEROS**

**KERBEROS::List** – Lista todos los tickets de usuario (TGT y TGS) en la memoria del usuario. No se requieren privilegios especiales ya que solo muestra los tickets del usuario actual.\
Similar a la funcionalidad de "klist".

**KERBEROS::PTC** – pasar la caché (NT6)\
Los sistemas *Nix como Mac OS, Linux, BSD, Unix, etc. almacenan en caché las credenciales de Kerberos. Estos datos en caché se pueden copiar y pasar usando Mimikatz. También es útil para inyectar tickets de Kerberos en archivos ccache.

Un buen ejemplo de kerberos::ptc de Mimikatz es cuando se explota MS14-068 con PyKEK. PyKEK genera un archivo ccache que se puede inyectar con Mimikatz usando kerberos::ptc.

[![Mimikatz-PTC-PyKEK-ccacheFile](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-PTC-PyKEK-ccacheFile.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-PTC-PyKEK-ccacheFile.jpg)

**KERBEROS::PTT** – pasar el ticket\
Después de encontrar un ticket de Kerberos, se puede copiar a otro sistema y pasar a la sesión actual, simulando efectivamente un inicio de sesión sin ninguna comunicación con el controlador de dominio. No se requieren derechos especiales.\
Similar a SEKURLSA::PTH (Pass-The-Hash).

* /filename – el nombre del archivo del ticket (puede ser múltiple)
* /directory – una ruta de directorio, se inyectarán todos los archivos .kirbi que haya dentro.

[![KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2](https://adsecurity.org/wp-content/uploads/2015/09/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)](https://adsecurity.org/wp-content/uploads/2015/09/KerberosUnConstrainedDelegation-Mimikatz-PTT-LS-Ticket2.png)

**KERBEROS::Purge** – purgar todos los tickets de Kerberos\
Similar a la funcionalidad de "klist purge". Ejecute este comando antes de pasar tickets (PTC, PTT, etc.) para asegurarse de que se use el contexto de usuario correcto.

[![Mimikatz-Kerberos-Purge](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-Purge.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-Purge.png)

**KERBEROS::TGT** – obtener el TGT actual para el usuario actual.

[![Mimikatz-Kerberos-TGT](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-TGT.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Kerberos-TGT.png)

### LSADUMP

**LSADUMP**::**DCShadow** – Establece la máquina actual como DC para tener la capacidad de crear nuevos objetos dentro del DC (método persistente).\
Esto requiere derechos de administrador completo de AD o el hash de pw KRBTGT.\
DCShadow establece temporalmente la computadora como "DC" para fines de replicación:

* Crea 2 objetos en la partición de configuración del bosque AD.
* Actualiza el SPN de la computadora utilizada para incluir "GC" (Global Catalog) y "E3514235-4B06-11D1-AB04-00C04FC2DCD2" (Replicación de AD). Más información sobre los nombres principales de servicio Kerberos en la sección [ADSecurity SPN](https://adsecurity.org/?page\_id=183).
* Empuja las actualizaciones a los DC a través de DrsReplicaAdd y KCC.
* Elimina los objetos creados de la partición de configuración.

**LSADUMP::DCSync** – solicita a un DC que sincronice un objeto (obtener datos de contraseña para la cuenta)\
[Requiere membresía en Administrador de dominio, Administradores de dominio o delegación personalizada.](https://adsecurity.org/?p=1729)

Una característica importante agregada a Mimkatz en agosto de 2015 es "DCSync", que efectivamente "impersona" un controlador de dominio y solicita datos de contraseña de cuenta del controlador de dominio objetivo.

**Opciones de DCSync:**

* /all – DCSync extrae datos para todo el dominio.
* /user – ID de usuario o SID del usuario del que desea extraer los datos.
* /domain (opcional) – FQDN del dominio de Active Directory. Mimikatz descubrirá un DC en el dominio al que conectarse. Si no se proporciona este parámetro, Mimikatz se establece en el dominio actual de forma predeterminada.
* /csv – exportar a csv
* /dc (opcional) – Especifique el controlador de dominio al que desea que DCSync se conecte y recopile datos.

También hay un parámetro /guid.

**Ejemplos de comandos DCSync:**

Extraer datos de contraseña para la cuenta de usuario KRBTGT en el dominio rd.adsecurity.org:\
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt" exit_

Extraer datos de contraseña para la cuenta de usuario Administrador en el dominio rd.adsecurity.org:\
_Mimikatz "lsadump::dcsync /domain:rd.adsecurity.org /user:Administrator" exit_

Extraer datos de contraseña para la cuenta de computadora del controlador de dominio ADSDC03 en el dominio lab.adsecurity.org:\
_Mimikatz "lsadump::dcsync /domain:lab.adsecurity.org /user:adsdc03$" exit_

**LSADUMP::LSA** – Solicita al servidor LSA que recupere SAM/AD enterprise (normal, parche sobre la marcha o inyectar). Use /patch para un subconjunto de datos, use /inject para todo. _Requiere derechos de sistema o de depuración._

* /inject – Inyecta LSASS para extraer credenciales
* /name – nombre de cuenta para la cuenta de usuario objetivo
* /id – RID para la cuenta de usuario objetivo
* /patch – parche LSASS.

A menudo, las cuentas de servicio son miembros de Domain Admins (o equivalente) o un administrador de dominio se ha conectado recientemente a la computadora desde la que un atacante puede obtener credenciales. Usando estas credenciales, un atacante puede obtener acceso a un controlador de dominio y obtener todas las credenciales del dominio, incluido el hash NTLM de la cuenta KRBTGT que se utiliza para crear Golden Tickets de Kerberos.
```
mimikatz lsadump::lsa /inject exit
```
**LSADUMP::NetSync**

NetSync proporciona una forma sencilla de utilizar los datos de la contraseña de la cuenta de equipo DC para suplantar a un Controlador de Dominio a través de un Silver Ticket y DCSync la información de la cuenta objetivo, incluidos los datos de la contraseña.

**LSADUMP::SAM** – obtener la SysKey para descifrar las entradas SAM (del registro o hive). La opción SAM se conecta a la base de datos local del Administrador de Cuentas de Seguridad (SAM) y vuelca las credenciales de las cuentas locales.

**LSADUMP::Secrets** – obtener la SysKey para descifrar las entradas SECRETS (del registro o hive).

**LSADUMP::SetNTLM** – Solicitar a un servidor que establezca una nueva contraseña/ntlm para un usuario.

[**LSADUMP::Trust**](https://adsecurity.org/?p=1588) – Solicitar al servidor LSA que recupere la información de autenticación de confianza (normal o parche sobre la marcha).

### MISC

[**MISC::Skeleton**](https://adsecurity.org/?p=1275) – Inyectar una clave Skeleton en el proceso LSASS en el Controlador de Dominio.
```
"privilege::debug" "misc::skeleton"
```
### PRIVILEGE

**PRIVILEGE::Backup** – obtiene el privilegio/derechos de backup. Requiere derechos de depuración.

**PRIVILEGE::Debug** – obtiene derechos de depuración (esto o derechos de sistema local se requieren para muchos comandos de Mimikatz).

### SEKURLSA

**SEKURLSA::Credman** – Lista el Administrador de credenciales

**SEKURLSA::Ekeys** – Lista las claves de cifrado de Kerberos

**SEKURLSA::Kerberos** – Lista las credenciales de Kerberos para todos los usuarios autenticados (incluyendo servicios y cuentas de computadora)

**SEKURLSA::Krbtgt** – obtiene los datos de la contraseña de la cuenta de servicio de Kerberos de dominio (KRBTGT)

**SEKURLSA::SSP** – Lista las credenciales SSP

**SEKURLSA::Wdigest** – Lista las credenciales WDigest

**SEKURLSA::LogonPasswords** – lista todas las credenciales de proveedores disponibles. Esto muestra generalmente las credenciales de usuario y computadora que han iniciado sesión recientemente.

* Vuelca los datos de contraseña en LSASS para las cuentas que han iniciado sesión (o que han iniciado sesión recientemente), así como para los servicios que se ejecutan bajo el contexto de las credenciales de usuario.
* Las contraseñas de las cuentas se almacenan en memoria de manera reversible. Si están en memoria (antes de Windows 8.1/Windows Server 2012 R2 lo estaban), se muestran. Windows 8.1/Windows Server 2012 R2 no almacena la contraseña de la cuenta de esta manera en la mayoría de los casos. KB2871997 "retrocede" esta capacidad de seguridad a Windows 7, Windows 8, Windows Server 2008R2 y Windows Server 2012, aunque el equipo necesita configuración adicional después de aplicar KB2871997.
* Requiere acceso de administrador (con derechos de depuración) o derechos de sistema local

**SEKURLSA::Minidump** – cambia al contexto del proceso de volcado de LSASS (lee el volcado de lsass)

**SEKURLSA::Pth** – Pass-the-Hash y Over-Pass-the-Hash (también conocido como pasar la clave).

_Mimikatz puede realizar la operación conocida como 'Pass-The-Hash' para ejecutar un proceso bajo otras credenciales con el hash NTLM de la contraseña del usuario, en lugar de su contraseña real. Para ello, inicia un proceso con una identidad falsa, luego reemplaza la información falsa (hash NTLM de la contraseña falsa) con información real (hash NTLM de la contraseña real)._

* /user – el nombre de usuario que desea suplantar, tenga en cuenta que Administrador no es el único nombre para esta cuenta conocida.
* /domain – el nombre de dominio completamente calificado - sin dominio o en caso de usuario/administrador local, use el nombre de la computadora o servidor, grupo de trabajo o lo que sea.
* /rc4 o /ntlm – opcional – la clave RC4 / hash NTLM de la contraseña del usuario.
* /run – opcional – la línea de comando para ejecutar – el valor predeterminado es: cmd para tener una shell.

[![Mimikatz-Sekurlsa-PTH](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Sekurlsa-PTH.jpg)

**SEKURLSA::Tickets** – Lista todos los tickets de Kerberos disponibles para todos los usuarios autenticados recientemente, incluyendo servicios que se ejecutan bajo el contexto de una cuenta de usuario y la cuenta de computadora AD local.\
A diferencia de kerberos::list, sekurlsa utiliza la lectura de memoria y no está sujeto a restricciones de exportación de claves. sekurlsa puede acceder a los tickets de otras sesiones (usuarios).

* /export – opcional – los tickets se exportan en archivos .kirbi. Comienzan con el LUID del usuario y el número de grupo (0 = TGS, 1 = ticket de cliente (?) y 2 = TGT)

Al igual que el volcado de credenciales de LSASS, utilizando el módulo sekurlsa, un atacante puede obtener todos los datos de tickets de Kerberos en memoria en un sistema, incluidos los que pertenecen a un administrador o servicio.\
Esto es extremadamente útil si un atacante ha comprometido un servidor web configurado para la delegación de Kerberos al que los usuarios acceden con un servidor SQL de backend. Esto permite a un atacante capturar y reutilizar todos los tickets de usuario en memoria en ese servidor.

El comando "kerberos::tickets" de mimikatz vuelca los tickets de Kerberos del usuario que ha iniciado sesión actualmente y no requiere derechos elevados. Aprovechando la capacidad del módulo sekurlsa para leer desde la memoria protegida (LSASS), se pueden volcar todos los tickets de Kerberos en el sistema.

Comando: _mimikatz sekurlsa::tickets exit_

* Vuelca todos los tickets de Kerberos autenticados en un sistema.
* Requiere acceso de administrador (con depuración) o derechos de sistema local

### **SID**

El módulo SID de Mimikatz reemplaza MISC::AddSID. Use SID::Patch para parchear el servicio ntds.

**SID::add** – Agrega un SID al historial de SID de un objeto

[![Mimikatz-SID-add](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-add.png)

**SID::modify** – Modifica el SID del objeto de un objeto

[![Mimikatz-SID-Modify](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-SID-Modify.png)

### **TOKEN**

El módulo Token de Mimikatz permite a Mimikatz interactuar con los tokens de autenticación de Windows, incluyendo la captura y suplantación de tokens existentes.

**TOKEN::Elevate** – suplanta un token. Se utiliza para elevar los permisos a SYSTEM (predeterminado) o para encontrar un token de administrador de dominio en el equipo utilizando la API de Windows.\
_Requiere derechos de administrador._

[![Mimikatz-Token-Elevate1](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate1-1.png)

Encuentra una credencial de administrador de dominio en el equipo y utiliza ese token: _token::elevate /domainadmin_

[![Mimikatz-Token-Elevate-DomainAdmin](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-Token-Elevate-DomainAdmin.jpg)

**TOKEN::List** – lista todos los tokens del sistema

### **TS**

**TS::MultiRDP** – (experimental) Parchea el servicio Terminal Server para permitir múltiples usuarios

[![Mimikatz-TS-MultiRDP](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)](https://adsecurity.org/wp-content/uploads/2015/09/Mimikatz-TS-MultiRDP.png)

**TS::Sessions** – Lista las sesiones de TS/RDP.

![](https://adsecurity.org/wp-content/uploads/2017/11/Mimikatz-TS-Sessions.png)

### Vault

`mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"` - Obtener contraseñas de tareas programadas

\
\
\\

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/p
