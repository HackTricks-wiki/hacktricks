# BloodHound & Outras Ferramentas de Enumeração do Active Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Esta página agrupa algumas das utilidades mais úteis para **enumerar** e **visualizar** relacionamentos do Active Directory. Para coleta através do canal stealthy **Active Directory Web Services (ADWS)**, consulte a referência acima.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) é um **visualizador e editor de AD** avançado que permite:

* Navegação GUI da árvore de diretórios
* Edição de atributos de objetos e descritores de segurança
* Criação / comparação de snapshots para análise offline

### Uso rápido

1. Inicie a ferramenta e conecte-se a `dc01.corp.local` com quaisquer credenciais de domínio.
2. Crie um snapshot offline via `File ➜ Create Snapshot`.
3. Compare dois snapshots com `File ➜ Compare` para identificar desvios de permissão.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrai um grande conjunto de artefatos de um domínio (ACLs, GPOs, trusts, templates de CA …) e produz um **relatório Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualização gráfica)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) usa teoria dos grafos + Neo4j para revelar relacionamentos de privilégio ocultos dentro do AD local e do Azure AD.

### Implantação (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Coletores

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa ou PowerShell
* `AzureHound` – enumeração do Azure AD
* **SoaPy + BOFHound** – coleta do ADWS (veja o link no topo)

#### Modos comuns do SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Os coletores geram JSON que é ingerido através da interface do BloodHound.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** e destaca configurações incorretas.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) realiza uma **verificação de saúde** do Active Directory e gera um relatório em HTML com pontuação de risco.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
