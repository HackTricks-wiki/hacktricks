# BloodHound e Outras Ferramentas de Enumeração do Active Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Esta página reúne alguns dos utilitários mais úteis para **enumerar** e **visualizar** relações do Active Directory. Para coleta pelo canal furtivo **Active Directory Web Services (ADWS)**, consulte a referência acima.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) é um **visualizador e editor avançado de AD** que permite:

* Navegar pela árvore de diretórios usando uma GUI
* Editar atributos de objetos e descritores de segurança
* Criar e comparar snapshots para análise offline

### Uso rápido

1. Inicie a ferramenta e conecte-se a `dc01.corp.local` com quaisquer credenciais de domínio.
2. Crie um snapshot offline via `File ➜ Create Snapshot`.
3. Compare dois snapshots com `File ➜ Compare` para identificar alterações nas permissões.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrai um grande conjunto de artefatos de um domínio (ACLs, GPOs, relações de confiança, templates de CA …) e produz um **relatório do Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualização de grafos)

[BloodHound](https://github.com/SpecterOps/BloodHound) usa a teoria dos grafos para revelar relações ocultas de privilégios dentro do AD on-prem, Entra ID e quaisquer dados adicionais da superfície de ataque ingeridos por meio do OpenGraph.<sup>[[1]](#references)</sup>

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Coletores

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa ou PowerShell
* `RustHound-CE` – collector CE multiplataforma para Linux, macOS e Windows
* `NetExec --bloodhound` – coleta rápida baseada em LDAP a partir do Linux
* `AzureHound` – enumeração do Entra ID
* **SoaPy + BOFHound** – coleta via ADWS (consulte o link no topo)

> O BloodHound CE `v8+` alterou o formato de saída do collector quando o OpenGraph foi introduzido. Após atualizar a partir do BloodHound legado ou de instalações CE mais antigas, execute novamente a descoberta com os collectors atuais antes de importar os dados.<sup>[[1]](#references)</sup>

#### Modos comuns do SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Os collectors geram JSON, que é ingerido pela GUI do BloodHound.

#### SharpHound a partir de um host Windows não associado ao domínio

Se sua VM do operador não estiver associada ao domínio de destino, aponte o DNS para um DC, inicie um shell **network-only**, verifique se você consegue visualizar `SYSVOL`/`NETLOGON` em um DC e, em seguida, faça a coleta no domínio remoto:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Isso é útil para jump boxes descartáveis ou estações de trabalho de operadores que não devem ingressar no domínio.

#### Coleta multiplataforma a partir de Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` é uma boa opção padrão quando você quer uma saída compatível com CE a partir de um host que não seja Windows.<sup>[[2]](#references)</sup> `NetExec` é conveniente quando você já o está usando para validação LDAP ou spraying e quer uma importação rápida do grafo. Para datasets que não sejam de AD, o BloodHound OpenGraph pode ser estendido com collectors como [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (priorização de caminhos do OpenGraph)

O [ADPathFinder](https://github.com/NetSPI/AD-PathFinder) funciona sobre o BloodHound CE/OpenGraph quando o grafo é grande demais para fazer pivots manualmente. Em vez de perguntar apenas se um principal pode alcançar um alvo, ele calcula os caminhos mais curtos de muitos usuários e computadores com poucos privilégios até objetos de alto valor, agrupa os caminhos que reutilizam as mesmas arestas e destaca o ponto de estrangulamento compartilhado que deve ser corrigido primeiro.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Com os dados de `MSSQLHound` e `ConfigManBearPig` importados, uma descoberta pode conectar [AD CS](ad-certificates.md), [abuso de MSSQL AD](abusing-ad-mssql.md) e [caminhos de ataque do SCCM](sccm-management-point-relay-sql-policy-secrets.md), em vez de deixá-los como pistas separadas.<sup>[[4]](#references)</sup> Exemplo de caminho compartilhado:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Rastreie o **contexto de segurança efetivo** em cada edge. Um caminho se torna crítico para o domínio assim que uma transição é executada como uma identidade privilegiada do domínio, mesmo que tenha começado com um usuário normal.
- Findings agrupados são ideais para **remediação de choke points**: remover uma permissão de impersonation de SQL, uma trust de linked server, um caminho de abuso de certificate template ou uma atribuição do SCCM pode eliminar muitos shortest paths de uma só vez.
- Repriorize findings "medium" com **contexto de grafo**. SMB signing desabilitado, exposição do WebClient, erros de delegation ou servidores SQL que permitem NTLM relay merecem maior prioridade quando o node comprometido tem caminhos seguintes até Domain Admins, Domain Controllers, CAs ou SCCM site servers.
- Se você também tiver o output do `NTDS.dit` e um potfile do hashcat, `--pwd` correlaciona senhas crackeadas com as propriedades do BloodHound, permitindo separar rapidamente a reutilização comum de senhas de creds crackeadas em contas privilegiadas, Kerberoastable, AS-REP roastable ou relevantes para paths.

### Coleta de privilégios e direitos de logon

Os **token privileges** do Windows (por exemplo, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) podem ignorar verificações de DACL, portanto mapeá-los em todo o domínio expõe edges de LPE locais que graphs baseados apenas em ACL não identificam. Os **logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` e seus equivalentes `SeDeny*`) são aplicados pelo LSA antes mesmo de existir um token, e os denies têm precedência; por isso, eles controlam materialmente o lateral movement (logon via RDP/SMB/scheduled task/service).<sup>[[3]](#references)</sup>

**Execute os collectors com privilégios elevados** quando possível: o UAC cria um token filtrado para administradores interativos (por meio de `NtFilterToken`), removendo privilégios sensíveis e marcando os SIDs de administrador como deny-only. Se você enumerar privilégios a partir de um shell não elevado, privilégios de alto valor ficarão invisíveis e o BloodHound não fará ingest desses edges.<sup>[[3]](#references)</sup>

Atualmente existem duas estratégias complementares de coleta do SharpHound:<sup>[[3]](#references)</sup>

- **Parsing de GPO/SYSVOL (stealthy, low-privilege):**
1. Enumere GPOs via LDAP (`(objectCategory=groupPolicyContainer)`) e leia cada `gPCFileSysPath`.
2. Busque `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` no SYSVOL e faça o parsing da seção `[Privilege Rights]`, que mapeia nomes de privilégios/logon rights para SIDs.
3. Resolva os links de GPO por meio de `gPLink` em OUs/sites/domínios, liste os computadores nos containers vinculados e atribua os direitos a essas máquinas.
4. Vantagem: funciona com um usuário normal e é silencioso; desvantagem: enxerga apenas direitos aplicados via GPO (alterações locais não são identificadas).

- **Enumeração via LSA RPC (noisy, accurate):**
- A partir de um contexto com local admin no target, abra a Local Security Policy e chame `LsaEnumerateAccountsWithUserRight` para cada privilégio/logon right, enumerando os principals atribuídos via RPC.
- Vantagem: captura direitos definidos localmente ou fora da GPO; desvantagem: tráfego de rede noisy e exigência de admin em cada host.

**Exemplo de abuse path exposto por esses edges:** `CanRDP` ➜ host no qual seu usuário também possui `SeBackupPrivilege` ➜ inicie um shell elevado para evitar tokens filtrados ➜ use backup semantics para ler os hives `SAM` e `SYSTEM` apesar das DACLs restritivas ➜ exfiltre e execute `secretsdump.py` offline para recuperar o NT hash do Administrator local para lateral movement/privilege escalation.<sup>[[3]](#references)</sup>

### Priorizando Kerberoasting com BloodHound

Use o contexto do graph para manter o roasting direcionado:

1. Colete uma vez com um collector compatível com ADWS e trabalhe offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importe o ZIP, marque o principal comprometido como owned e execute as queries integradas (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) para identificar contas com SPN e direitos de admin/infra.
3. Priorize os SPNs pelo blast radius; revise `pwdLastSet`, `lastLogon` e os tipos de encryption permitidos antes de realizar o cracking.
4. Solicite apenas os tickets selecionados, faça o cracking offline e consulte novamente o BloodHound com o novo acesso:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** e destaca misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) realiza uma **health-check** do Active Directory e gera um relatório HTML com pontuação de risco.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referências

- [1] [BloodHound Community Edition v8 é lançado com OpenGraph: caminhos de ataque de identidade além do Active Directory e Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Além de ACLs: mapeando caminhos de privilege escalation do Windows com BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: mapeamento de caminhos de ataque do OpenGraph no BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
