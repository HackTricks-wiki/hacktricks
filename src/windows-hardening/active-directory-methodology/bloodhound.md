# BloodHound & Outras Ferramentas de Enumeração do Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Esta página agrupa algumas das utilidades mais úteis para **enumerar** e **visualizar** relacionamentos do Active Directory. Para coleta através do canal furtivo **Active Directory Web Services (ADWS)** verifique a referência acima.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) é um **visualizador e editor de AD** avançado que permite:

* Navegação via GUI pela árvore do diretório
* Edição de atributos de objetos & descritores de segurança
* Criação / comparação de snapshots para análise offline

### Uso rápido

1. Inicie a ferramenta e conecte-se a `dc01.corp.local` com quaisquer credenciais de domínio.
2. Crie um snapshot offline via `File ➜ Create Snapshot`.
3. Compare dois snapshots com `File ➜ Compare` para identificar desvios de permissões.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrai um grande conjunto de artefatos de um domínio (ACLs, GPOs, trusts, CA templates …) e produz um **relatório Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualização de grafos)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) usa teoria dos grafos + Neo4j para revelar relações de privilégio ocultas dentro do on-prem AD & Azure AD.

### Implantação (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Coletores

* `SharpHound.exe` / `Invoke-BloodHound` – nativo ou variante PowerShell
* `AzureHound` – enumeração do Azure AD
* **SoaPy + BOFHound** – coleta ADWS (veja o link no topo)

#### Modos comuns do SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Os collectors geram JSON que é ingerido pela GUI do BloodHound.

---

## Priorizando Kerberoasting com BloodHound

O contexto do grafo é vital para evitar roasting ruidoso e indiscriminado. Um fluxo de trabalho enxuto:

1. **Colete tudo uma vez** usando um collector compatível com ADWS (por exemplo, RustHound-CE) para que você possa trabalhar offline e ensaiar caminhos sem tocar no DC novamente:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Importe o ZIP, marque o principal comprometido como owned**, então execute consultas integradas como *Kerberoastable Users* e *Shortest Paths to Domain Admins*. Isso destaca instantaneamente contas com SPN e associações de grupo úteis (Exchange, IT, contas de serviço tier0, etc.).
3. **Priorize por blast radius** – concentre-se em SPNs que controlam infraestrutura compartilhada ou têm direitos de administrador, e verifique `pwdLastSet`, `lastLogon`, e os tipos de encriptação permitidos antes de gastar ciclos de cracking.
4. **Solicite apenas os tickets que lhe interessam**. Ferramentas como NetExec podem direcionar `sAMAccountName`s selecionados para que cada solicitação LDAP ROAST tenha uma justificativa clara:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, em seguida reconsulte o BloodHound imediatamente para planejar post-exploitation com os novos privilégios.

Essa abordagem mantém a relação sinal-ruído alta, reduz o volume detectável (sem requisições massivas de SPN) e garante que cada cracked ticket se traduza em etapas significativas de escalonamento de privilégios.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Objetos de Política de Grupo** e destaca configurações incorretas.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) realiza uma **verificação de integridade** do Active Directory e gera um relatório HTML com pontuação de risco.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referências

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
