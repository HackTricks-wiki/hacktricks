# BloodHound y otras herramientas de enumeración de Active Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Esta página agrupa algunas de las utilidades más útiles para **enumerar** y **visualizar** las relaciones de Active Directory. Para la recopilación a través del canal sigiloso de **Active Directory Web Services (ADWS)**, consulte la referencia anterior.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) es un **visor y editor de AD** avanzado que permite:

* Navegación por GUI del árbol de directorios
* Edición de atributos de objetos y descriptores de seguridad
* Creación / comparación de instantáneas para análisis fuera de línea

### Uso rápido

1. Inicie la herramienta y conéctese a `dc01.corp.local` con cualquier credencial de dominio.
2. Cree una instantánea fuera de línea a través de `File ➜ Create Snapshot`.
3. Compare dos instantáneas con `File ➜ Compare` para detectar desviaciones de permisos.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrae un gran conjunto de artefactos de un dominio (ACLs, GPOs, confianzas, plantillas de CA…) y produce un **informe de Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualización gráfica)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) utiliza teoría de grafos + Neo4j para revelar relaciones de privilegio ocultas dentro de AD local y Azure AD.

### Implementación (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectores

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa o de PowerShell
* `AzureHound` – enumeración de Azure AD
* **SoaPy + BOFHound** – colección de ADWS (ver enlace en la parte superior)

#### Modos comunes de SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Los recolectores generan JSON que se ingiere a través de la interfaz gráfica de BloodHound.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** y destaca configuraciones incorrectas.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) realiza un **chequeo de salud** de Active Directory y genera un informe en HTML con puntuación de riesgo.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
