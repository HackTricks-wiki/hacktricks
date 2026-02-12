# BloodHound & Outras ferramentas de enumeração do Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Esta página agrupa algumas das utilidades mais úteis para **enumerar** e **visualizar** relações do Active Directory. Para coleta pelo canal furtivo **Active Directory Web Services (ADWS)** consulte a referência acima.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) é um avançado **AD viewer & editor** que permite:

* Navegação via GUI pela árvore de diretórios
* Edição de atributos de objetos e descritores de segurança
* Criação / comparação de snapshots para análise offline

### Uso rápido

1. Inicie a ferramenta e conecte-se a `dc01.corp.local` com quaisquer credenciais de domínio.
2. Crie um snapshot offline via `File ➜ Create Snapshot`.
3. Compare dois snapshots com `File ➜ Compare` para identificar desvios de permissões.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrai um grande conjunto de artefatos de um domínio (ACLs, GPOs, trusts, CA templates …) e produz um **relatório em Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualização de grafos)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) usa teoria dos grafos + Neo4j para revelar relacionamentos de privilégio ocultos dentro do AD local e do Azure AD.

### Implantação (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Coletores

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa ou PowerShell
* `AzureHound` – enumeração do Azure AD
* **SoaPy + BOFHound** – coleta ADWS (veja o link no topo)

#### Modos comuns do SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Os coletores geram JSON que é ingerido via a GUI do BloodHound.

### Coleta de privilégios e direitos de logon

Windows **token privileges** (por exemplo, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) podem ignorar checagens DACL, então mapeá‑los em todo o domínio expõe arestas locais de LPE que grafos somente-ACL perdem. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` e seus contrapartes `SeDeny*`) são aplicados pelo LSA antes mesmo de um token existir, e negações têm precedência, portanto eles restringem materialmente o movimento lateral (RDP/SMB/tarefa agendada/logon de serviço).

Execute os coletores elevados quando possível: UAC cria um token filtrado para admins interativos (via `NtFilterToken`), removendo privilégios sensíveis e marcando SIDs de admin como deny-only. Se você enumerar privilégios a partir de um shell não elevado, privilégios de alto valor ficarão invisíveis e o BloodHound não irá ingerir as arestas.

Duas estratégias complementares de coleta do SharpHound existem agora:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Enumerar GPOs via LDAP (`(objectCategory=groupPolicyContainer)`) e ler cada `gPCFileSysPath`.
2. Buscar `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` do SYSVOL e parsear a seção `[Privilege Rights]` que mapeia nomes de privilégios/direitos de logon para SIDs.
3. Resolver links de GPO via `gPLink` em OUs/sites/domains, listar computadores nos containers vinculados e atribuir os direitos a essas máquinas.
4. Vantagem: funciona com um usuário normal e é silencioso; desvantagem: só vê direitos aplicados via GPO (ajustes locais são perdidos).

- **LSA RPC enumeration (noisy, accurate):**
- A partir de um contexto com admin local no alvo, abra a Política de Segurança Local e chame `LsaEnumerateAccountsWithUserRight` para cada privilégio/direito de logon para enumerar os principais atribuídos via RPC.
- Vantagem: captura direitos definidos localmente ou fora do GPO; desvantagem: tráfego de rede ruidoso e requisito de admin em cada host.

Exemplo de caminho de abuso revelado por essas arestas: `CanRDP` ➜ host onde seu usuário também tem `SeBackupPrivilege` ➜ iniciar um shell elevado para evitar tokens filtrados ➜ usar semântica de backup para ler os hives `SAM` e `SYSTEM` apesar de DACLs restritivas ➜ exfiltrar e rodar `secretsdump.py` offline para recuperar o NT hash do Administrator local para movimento lateral/elevação de privilégio.

### Priorizando Kerberoasting com BloodHound

Use o contexto do grafo para manter o roasting direcionado:

1. Colete uma vez com um collector compatível com ADWS e trabalhe offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importe o ZIP, marque o principal comprometido como owned, e execute as queries embutidas (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) para expor contas SPN com direitos de admin/infra.
3. Priorize SPNs pelo blast radius; revise `pwdLastSet`, `lastLogon` e os tipos de criptografia permitidos antes de crackear.
4. Solicite apenas tickets selecionados, quebre offline, então re-consulte o BloodHound com o novo acesso:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** e destaca misconfigurações.
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

- [HackTheBox Mirage: Encadeando NFS Leaks, Abuso de DNS Dinâmico, Roubo de Credenciais NATS, Segredos do JetStream, e Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Além de ACLs: Mapeando Caminhos de Escalada de Privilégios do Windows com BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
