# BloodHound & Otras herramientas de enumeración de Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Esta página agrupa algunas de las utilidades más útiles para **enumerate** y **visualise** las relaciones de Active Directory. Para la recolección a través del sigiloso canal **Active Directory Web Services (ADWS)**, consulta la referencia arriba.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) es un avanzado **visor y editor de AD** que permite:

* Navegación GUI del árbol del directorio
* Edición de atributos de objetos y descriptores de seguridad
* Creación / comparación de instantáneas para análisis sin conexión

### Uso rápido

1. Inicia la herramienta y conéctate a `dc01.corp.local` con cualquier credencial de dominio.
2. Crea una instantánea sin conexión mediante `File ➜ Create Snapshot`.
3. Compara dos instantáneas con `File ➜ Compare` para detectar desviaciones en permisos.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrae un amplio conjunto de artefactos de un dominio (ACLs, GPOs, trusts, plantillas de CA …) y genera un **informe en Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graph visualisation)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) usa teoría de grafos + Neo4j para revelar relaciones de privilegio ocultas dentro de on-prem AD y Azure AD.

### Despliegue (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Recolectores

* `SharpHound.exe` / `Invoke-BloodHound` – nativa o variante de PowerShell
* `AzureHound` – enumeración de Azure AD
* **SoaPy + BOFHound** – colección ADWS (ver enlace en la parte superior)

#### Modos comunes de SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Los collectors generan JSON que se ingiere a través de la GUI de BloodHound.

---

## Priorizando Kerberoasting con BloodHound

El contexto del grafo es vital para evitar un roasting ruidoso e indiscriminado. Un flujo de trabajo ligero:

1. **Recopila todo una vez** usando un collector compatible con ADWS (p. ej. RustHound-CE) para que puedas trabajar sin conexión y ensayar rutas sin volver a tocar el DC:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Importa el ZIP, marca el principal comprometido como owned**, luego ejecuta consultas integradas como *Kerberoastable Users* y *Shortest Paths to Domain Admins*. Esto resalta instantáneamente las cuentas con SPN y membresías de grupo útiles (Exchange, IT, tier0 service accounts, etc.).
3. **Prioriza según el blast radius** – céntrate en SPNs que controlen infraestructura compartida o que tengan derechos de administrador, y comprueba `pwdLastSet`, `lastLogon`, y los tipos de cifrado permitidos antes de gastar ciclos de cracking.
4. **Solicita solo los tickets que te interesan**. Herramientas como NetExec pueden apuntar a `sAMAccountName`s seleccionados para que cada solicitud LDAP ROAST tenga una justificación clara:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, luego vuelve a consultar inmediatamente a BloodHound para planear post-exploitation con los nuevos privilegios.

Esta estrategia mantiene alta la relación señal-ruido, reduce el volumen detectable (no solicitudes SPN masivas), y asegura que cada ticket descifrado se traduzca en pasos significativos de escalada de privilegios.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** y resalta configuraciones incorrectas.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) realiza una **comprobación de salud** de Active Directory y genera un informe HTML con puntuación de riesgo.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referencias

- [HackTheBox Mirage: Encadenando NFS Leaks, Abuso de Dynamic DNS, NATS Credential Theft, JetStream Secrets, y Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
