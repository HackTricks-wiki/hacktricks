# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Esta página agrupa algunas de las utilidades más útiles para **enumerate** y **visualise** las relaciones de Active Directory. Para la recopilación a través del sigiloso canal **Active Directory Web Services (ADWS)** consulta la referencia anterior.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) es un avanzado **visor y editor de AD** que permite:

* Navegación GUI por el árbol del directorio
* Edición de atributos de objetos y descriptores de seguridad
* Creación/comparación de instantáneas para análisis offline

### Quick usage

1. Inicia la herramienta y conéctate a `dc01.corp.local` con cualquier credencial de dominio.
2. Crea una instantánea offline vía `File ➜ Create Snapshot`.
3. Compara dos instantáneas con `File ➜ Compare` para detectar desviaciones de permisos.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrae un gran conjunto de artefactos de un dominio (ACLs, GPOs, trusts, CA templates …) y genera un **informe en Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualización de grafos)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) utiliza teoría de grafos + Neo4j para revelar relaciones de privilegios ocultas dentro de on-prem AD y Azure AD.

### Despliegue (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Recolectores

* `SharpHound.exe` / `Invoke-BloodHound` – nativo o variante PowerShell
* `AzureHound` – enumeración de Azure AD
* **SoaPy + BOFHound** – colección ADWS (ver enlace arriba)

#### Modos comunes de SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Los collectors generan JSON que es ingerido a través de la GUI de BloodHound.

### Recolección de privilegios y derechos de inicio de sesión

Windows **token privileges** (p. ej., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) pueden eludir las comprobaciones DACL, por lo que mapearlos a nivel de dominio expone aristas locales de LPE que los grafos que consideran solo ACLs no muestran. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` y sus contrapartes `SeDeny*`) son aplicados por LSA antes de que exista incluso un token, y las denegaciones tienen precedencia, por lo que materialmente condicionan el movimiento lateral (RDP/SMB/tarea programada/logon de servicio).

**Run collectors elevated** cuando sea posible: UAC crea un token filtrado para admins interactivos (vía `NtFilterToken`), quitando privilegios sensibles y marcando SIDs de admin como deny-only. Si enumeras privilegios desde un shell no elevado, los privilegios de alto valor serán invisibles y BloodHound no ingestará las aristas.

Existen ahora dos estrategias complementarias de recolección de SharpHound:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Enumerar GPOs por LDAP (`(objectCategory=groupPolicyContainer)`) y leer cada `gPCFileSysPath`.
2. Obtener `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` de SYSVOL y parsear la sección `[Privilege Rights]` que asigna nombres de privilegios/derechos de inicio de sesión a SIDs.
3. Resolver enlaces de GPO vía `gPLink` en OUs/sites/domains, listar equipos en los contenedores enlazados y atribuir los derechos a esas máquinas.
4. Ventaja: funciona con un usuario normal y es silencioso; desventaja: solo ve los derechos aplicados vía GPO (los ajustes locales se pierden).

- **LSA RPC enumeration (noisy, accurate):**
- Desde un contexto con admin local en el objetivo, abrir la Local Security Policy y llamar a `LsaEnumerateAccountsWithUserRight` para cada privilegio/derecho de inicio de sesión para enumerar los principales asignados vía RPC.
- Ventaja: captura derechos establecidos localmente o fuera de GPO; desventaja: tráfico de red ruidoso y requisito de admin en cada host.

**Example abuse path surfaced by these edges:** `CanRDP` ➜ host donde tu usuario también tiene `SeBackupPrivilege` ➜ iniciar una shell elevada para evitar tokens filtrados ➜ usar las semánticas de backup para leer los hives `SAM` y `SYSTEM` a pesar de DACLs restrictivas ➜ exfiltrar y ejecutar `secretsdump.py` offline para recuperar el hash NT del Administrator local para movimiento lateral/escalada de privilegios.

### Priorización de Kerberoasting con BloodHound

Usa el contexto del grafo para mantener el Kerberoasting dirigido:

1. Recolecta una vez con un collector compatible con ADWS y trabaja offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importa el ZIP, marca el principal comprometido como owned, y ejecuta las consultas integradas (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) para sacar a la superficie cuentas SPN con derechos de admin/infra.
3. Prioriza SPNs por blast radius; revisa `pwdLastSet`, `lastLogon` y tipos de cifrado permitidos antes de crackear.
4. Solicita solo tickets seleccionados, crackéalos offline, luego vuelve a consultar BloodHound con el nuevo acceso:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** y resalta misconfiguraciones.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) realiza una **verificación de estado** de Active Directory y genera un informe HTML con puntuación de riesgo.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referencias

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
