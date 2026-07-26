# BloodHound y otras herramientas de enumeración de Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Esta página agrupa algunas de las utilidades más útiles para **enumerar** y **visualizar** las relaciones de Active Directory. Para la recopilación mediante el canal sigiloso **Active Directory Web Services (ADWS)**, consulta la referencia anterior.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) es un **visor y editor de AD** avanzado que permite:

* Navegar por el árbol del directorio mediante una GUI
* Editar atributos de objetos y descriptores de seguridad
* Crear y comparar snapshots para realizar análisis offline

### Uso rápido

1. Inicia la herramienta y conéctate a `dc01.corp.local` con cualquier credencial de dominio.
2. Crea un snapshot offline mediante `File ➜ Create Snapshot`.
3. Compara dos snapshots con `File ➜ Compare` para detectar cambios en los permisos.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrae un amplio conjunto de artefactos de un dominio (ACLs, GPOs, trusts, plantillas de CA …) y genera un **informe de Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualización de grafos)

[BloodHound](https://github.com/SpecterOps/BloodHound) utiliza la teoría de grafos para revelar relaciones de privilegios ocultas dentro de AD on-prem, Entra ID y cualquier dato adicional de la superficie de ataque que ingieras mediante OpenGraph.

### Implementación (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa o de PowerShell
* `RustHound-CE` – collector CE multiplataforma para Linux, macOS y Windows
* `NetExec --bloodhound` – recopilación rápida basada en LDAP desde Linux
* `AzureHound` – enumeración de Entra ID
* **SoaPy + BOFHound** – recopilación mediante ADWS (consulta el enlace de la parte superior)

> BloodHound CE `v8+` cambió el formato de salida del collector cuando se incorporó OpenGraph. Después de actualizar desde BloodHound legacy o instalaciones antiguas de CE, vuelve a ejecutar el discovery con collectors actuales antes de importar los datos.

#### Modos comunes de SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Los collectors generan JSON que se ingiere mediante la GUI de BloodHound.

#### SharpHound desde un host Windows que no está unido al dominio

Si tu VM de operador no está unida al dominio objetivo, configura el DNS para que apunte a un DC, inicia una shell **network-only**, verifica que puedas ver `SYSVOL`/`NETLOGON` en un DC y, después, realiza la recopilación contra el dominio remoto:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Esto es útil para jump boxes desechables o estaciones de trabajo del operador que no deberían estar unidas al dominio.

#### Recopilación multiplataforma desde Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` es una buena opción predeterminada cuando quieres obtener una salida compatible con CE desde un host que no es Windows. `NetExec` resulta práctico cuando ya lo estás usando para la validación de LDAP o el spraying y quieres una importación rápida al grafo. Para datasets que no sean de AD, BloodHound OpenGraph se puede ampliar con collectors como [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### ADPathFinder (priorización de rutas en OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) funciona sobre BloodHound CE/OpenGraph cuando el grafo es demasiado grande para hacer pivot manualmente. En lugar de preguntar únicamente si un principal puede alcanzar un objetivo, calcula las rutas más cortas desde muchos usuarios y equipos con pocos privilegios hasta objetos de alto valor, agrupa las rutas que reutilizan las mismas aristas y muestra el cuello de botella compartido que debería remediarse primero.
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Con los datos de `MSSQLHound` y `ConfigManBearPig` importados, un hallazgo puede abarcar [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) y [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) en lugar de dejarlos como pistas independientes. Ejemplo de ruta compartida:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Rastrea el **contexto de seguridad efectivo** en cada arista. Una ruta se vuelve crítica para el dominio en cuanto una transición se ejecuta con una identidad de dominio privilegiada, aunque comenzara desde un usuario normal.
- Los hallazgos agrupados son ideales para la **remediación de puntos de estrangulamiento**: eliminar un permiso de impersonation de SQL, la confianza de un linked server, una ruta de abuso de una plantilla de certificados o una asignación de SCCM puede eliminar muchas shortest paths de una vez.
- Reprioriza los hallazgos "medium" con **contexto del grafo**. La firma SMB deshabilitada, la exposición de WebClient, los errores de delegation o los servidores SQL susceptibles de NTLM relay merecen mayor prioridad cuando el nodo comprometido tiene rutas posteriores hacia Domain Admins, Domain Controllers, CAs o servidores de sitio de SCCM.
- Si también tienes la salida de `NTDS.dit` y un potfile de hashcat, `--pwd` correlaciona las contraseñas crackeadas con las propiedades de BloodHound, para que puedas separar rápidamente la reutilización normal de contraseñas de las credenciales crackeadas en cuentas privilegiadas, Kerberoastable, AS-REP roastable o relevantes para una ruta.

### Recopilación de privilegios y derechos de inicio de sesión

Los **privilegios de token** de Windows (por ejemplo, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) pueden omitir las comprobaciones de DACL, por lo que mapearlos en todo el dominio expone edges de LPE locales que los grafos basados únicamente en ACL no detectan. Los **derechos de inicio de sesión** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` y sus equivalentes `SeDeny*`) son aplicados por LSA antes de que exista siquiera un token, y las denegaciones tienen precedencia, por lo que controlan materialmente el movimiento lateral (inicio de sesión mediante RDP/SMB/scheduled task/service).

**Ejecuta los collectors con privilegios elevados** cuando sea posible: UAC crea un token filtrado para los administradores interactivos (mediante `NtFilterToken`), eliminando privilegios sensibles y marcando los SIDs de administrador como deny-only. Si enumeras los privilegios desde una shell no elevada, los privilegios de alto valor serán invisibles y BloodHound no ingerirá los edges.

Ahora existen dos estrategias complementarias de recopilación con SharpHound:

- **Análisis de GPO/SYSVOL (stealthy, con pocos privilegios):**
1. Enumera las GPO mediante LDAP (`(objectCategory=groupPolicyContainer)`) y lee cada `gPCFileSysPath`.
2. Obtén `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` desde SYSVOL y analiza la sección `[Privilege Rights]`, que asigna nombres de privilegios/derechos de inicio de sesión a SIDs.
3. Resuelve los enlaces de GPO mediante `gPLink` en OUs/sitios/dominios, enumera los equipos de los contenedores enlazados y atribuye los derechos a esas máquinas.
4. Ventaja: funciona con un usuario normal y es silencioso; desventaja: solo detecta los derechos aplicados mediante GPO (se omiten los ajustes locales).

- **Enumeración mediante LSA RPC (ruidosa, precisa):**
- Desde un contexto con admin local en el objetivo, abre la Local Security Policy y llama a `LsaEnumerateAccountsWithUserRight` para cada privilegio/derecho de inicio de sesión, con el fin de enumerar los principals asignados mediante RPC.
- Ventaja: captura los derechos configurados localmente o fuera de GPO; desventaja: genera tráfico de red ruidoso y requiere admin en cada host.

**Ejemplo de abuse path expuesta por estos edges:** `CanRDP` ➜ host donde tu usuario también tiene `SeBackupPrivilege` ➜ inicia una shell elevada para evitar los filtered tokens ➜ usa backup semantics para leer los hives `SAM` y `SYSTEM` a pesar de las DACL restrictivas ➜ exfiltra y ejecuta `secretsdump.py` offline para recuperar el hash NT del Administrator local para movimiento lateral/escalada de privilegios.

### Priorización de Kerberoasting con BloodHound

Usa el contexto del grafo para mantener el roasting enfocado:

1. Recopila una vez con un collector compatible con ADWS y trabaja offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importa el ZIP, marca el principal comprometido como owned y ejecuta las queries integradas (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) para identificar cuentas con SPN que tengan derechos de admin/infra.
3. Prioriza los SPN según su blast radius; revisa `pwdLastSet`, `lastLogon` y los tipos de cifrado permitidos antes de crackear.
4. Solicita solo los tickets seleccionados, crackéalos offline y vuelve a consultar BloodHound con el nuevo acceso:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** y destaca las misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) realiza un **health-check** de Active Directory y genera un informe HTML con puntuación de riesgos.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referencias

- [BloodHound Community Edition v8 se lanza con OpenGraph: rutas de ataque de identidad más allá de Active Directory y Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Más allá de las ACL: mapeo de rutas de escalada de privilegios en Windows con BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: mapeo de rutas de ataque de OpenGraph en BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
