# BloodHound y otras herramientas de Enumeration de Active Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Esta página agrupa algunas de las utilidades más útiles para **enumerar** y **visualizar** las relaciones de Active Directory. Para la recopilación a través del canal sigiloso **Active Directory Web Services (ADWS)**, consulta la referencia anterior.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) es un **visor y editor avanzado de AD** que permite:

* Explorar el árbol del directorio mediante una GUI
* Editar atributos de objetos y descriptores de seguridad
* Crear y comparar snapshots para análisis offline

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

[BloodHound](https://github.com/SpecterOps/BloodHound) utiliza la teoría de grafos para revelar relaciones de privilegios ocultas dentro de AD on-prem, Entra ID y cualquier dato adicional de la superficie de ataque que ingieras mediante OpenGraph.<sup>[[1]](#references)</sup>

### Implementación (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Colectores

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa o de PowerShell
* `RustHound-CE` – collector CE multiplataforma para Linux, macOS y Windows
* `NetExec --bloodhound` – recopilación rápida basada en LDAP desde Linux
* `AzureHound` – enumeración de Entra ID
* **SoaPy + BOFHound** – recopilación mediante ADWS (consulta el enlace de arriba)

> BloodHound CE `v8+` cambió el formato de salida del collector cuando se incorporó OpenGraph. Después de actualizar desde BloodHound legacy o instalaciones antiguas de CE, vuelve a ejecutar el discovery con collectors actuales antes de importar los datos.<sup>[[1]](#references)</sup>

#### Modos comunes de SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Los collectors generan JSON que se ingiere mediante la GUI de BloodHound.

#### SharpHound desde un host Windows no unido al dominio

Si tu VM de operador no está unida al dominio objetivo, configura el DNS para que apunte a un DC, inicia un shell **network-only**, verifica que puedes ver `SYSVOL`/`NETLOGON` en un DC y, a continuación, realiza la recolección contra el dominio remoto:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Esto resulta útil para jump boxes desechables o estaciones de trabajo de operadores que no deberían estar unidas al dominio.

#### Recolección multiplataforma desde Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` es una buena opción predeterminada cuando quieres obtener output compatible con CE desde un host que no sea Windows.<sup>[[2]](#references)</sup> `NetExec` resulta conveniente cuando ya lo estás utilizando para la validación de LDAP o el spraying y quieres una importación rápida del grafo. Para datasets que no sean de AD, BloodHound OpenGraph puede ampliarse con collectors como [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (priorización de rutas de OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) funciona sobre BloodHound CE/OpenGraph cuando el grafo es demasiado grande para pivotar manualmente. En lugar de preguntar únicamente si un principal puede llegar a un target, calcula las rutas más cortas desde muchos usuarios y equipos con pocos privilegios hasta objetos de alto valor, agrupa las rutas que reutilizan los mismos edges y muestra el choke point compartido que debería remediarse primero.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Con los datos de `MSSQLHound` y `ConfigManBearPig` importados, un hallazgo puede conectar [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) y [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) en lugar de dejarlos como pistas separadas.<sup>[[4]](#references)</sup> Ejemplo de ruta compartida:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Rastrea el **contexto de seguridad efectivo** en cada edge. Un path pasa a ser crítico para el dominio en cuanto una transición se ejecuta como una identidad de dominio privilegiada, aunque haya comenzado con un usuario normal.
- Los hallazgos agrupados son ideales para la **remediación de choke points**: eliminar un permiso de SQL impersonation, una confianza de linked server, un path de abuso de certificate template o una asignación de SCCM puede colapsar muchos shortest paths de una vez.
- Reprioriza los hallazgos "medium" con **contexto del grafo**. SMB signing deshabilitado, exposición de WebClient, errores de delegation o servidores SQL vulnerables a NTLM relay merecen mayor prioridad cuando el nodo comprometido tiene paths posteriores hacia Domain Admins, Domain Controllers, CAs o SCCM site servers.
- Si también tienes el output de `NTDS.dit` y un potfile de hashcat, `--pwd` correlaciona las contraseñas cracked con las propiedades de BloodHound, para que puedas separar rápidamente la reutilización ordinaria de contraseñas de las credenciales cracked en cuentas privilegiadas, Kerberoastable, AS-REP roastable o relevantes para un path.

### Recopilación de privilegios y logon rights

Los **token privileges** de Windows (por ejemplo, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) pueden omitir las comprobaciones de DACL, por lo que mapearlos en todo el dominio expone edges de LPE locales que los grafos basados únicamente en ACL no muestran. Los **logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` y sus equivalentes `SeDeny*`) son aplicados por LSA antes de que exista siquiera un token, y los denies tienen prioridad; por tanto, controlan materialmente el movimiento lateral (RDP/SMB/scheduled task/service logon).<sup>[[3]](#references)</sup>

**Ejecuta los collectors con privilegios elevados** cuando sea posible: UAC crea un token filtrado para los administradores interactivos (mediante `NtFilterToken`), elimina privilegios sensibles y marca los SIDs de administrador como deny-only. Si enumeras los privilegios desde un shell no elevado, los privilegios de alto valor serán invisibles y BloodHound no ingerirá los edges.<sup>[[3]](#references)</sup>

Ahora existen dos estrategias complementarias de recopilación con SharpHound:<sup>[[3]](#references)</sup>

- **Análisis de GPO/SYSVOL (stealthy, con pocos privilegios):**
1. Enumera las GPO mediante LDAP (`(objectCategory=groupPolicyContainer)`) y lee cada `gPCFileSysPath`.
2. Obtén `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` desde SYSVOL y analiza la sección `[Privilege Rights]`, que asigna nombres de privilegios/logon rights a SIDs.
3. Resuelve los enlaces de GPO mediante `gPLink` en OUs/sites/domains, enumera los equipos de los contenedores enlazados y atribuye esos derechos a dichas máquinas.
4. Ventaja: funciona con un usuario normal y es silencioso; desventaja: solo muestra los derechos aplicados mediante GPO (no detecta modificaciones locales).

- **Enumeración mediante LSA RPC (ruidosa, precisa):**
- Desde un contexto con local admin en el objetivo, abre la Local Security Policy y llama a `LsaEnumerateAccountsWithUserRight` para cada privilegio/logon right, con el fin de enumerar mediante RPC los principals asignados.
- Ventaja: captura los derechos configurados localmente o fuera de GPO; desventaja: genera tráfico de red ruidoso y requiere admin en cada host.

**Ejemplo de abuse path expuesto por estos edges:** `CanRDP` ➜ host donde tu usuario también tiene `SeBackupPrivilege` ➜ inicia un shell elevado para evitar los filtered tokens ➜ usa la semántica de backup para leer los hives `SAM` y `SYSTEM` a pesar de las DACL restrictivas ➜ exfiltra los datos y ejecuta `secretsdump.py` offline para recuperar el NT hash del Administrator local y realizar lateral movement/privilege escalation.<sup>[[3]](#references)</sup>

### Priorización de Kerberoasting con BloodHound

Usa el contexto del grafo para mantener el roasting dirigido:

1. Recopila una vez con un collector compatible con ADWS y trabaja offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importa el ZIP, marca el principal comprometido como owned y ejecuta las queries integradas (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) para localizar cuentas con SPN y privilegios de admin/infra.
3. Prioriza los SPNs según su blast radius; revisa `pwdLastSet`, `lastLogon` y los tipos de cifrado permitidos antes de crackear.
4. Solicita únicamente los tickets seleccionados, crackéalos offline y vuelve a consultar BloodHound con el nuevo acceso:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** y destaca las configuraciones incorrectas.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) realiza una **comprobación del estado** de Active Directory y genera un informe HTML con una puntuación de riesgo.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referencias

- [1] [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Más allá de las ACLs: mapeo de rutas de escalada de privilegios de Windows con BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: mapeo de rutas de ataque de OpenGraph en BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
