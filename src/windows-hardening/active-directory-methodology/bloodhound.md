# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Esta página agrupa algumas das utilidades mais úteis para **enumerate** e **visualise** Active Directory relationships. Para coleta pelo canal furtivo **Active Directory Web Services (ADWS)**, consulte a referência acima.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) é um avançado **AD viewer & editor** que permite:

* Navegação GUI pela árvore do diretório
* Edição de atributos de objetos & security descriptors
* Criação/comparação de snapshot para análise offline

### Quick usage

1. Inicie a ferramenta e conecte-se a `dc01.corp.local` com quaisquer credenciais de domínio.
2. Crie um snapshot offline via `File ➜ Create Snapshot`.
3. Compare dois snapshots com `File ➜ Compare` para identificar permission drifts.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrai um grande conjunto de artefatos de um domínio (ACLs, GPOs, trusts, CA templates …) e produz um **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graph visualisation)

[BloodHound](https://github.com/SpecterOps/BloodHound) usa teoria dos grafos para revelar relações ocultas de privilégios dentro do AD local, Entra ID, e quaisquer dados extras de superfície de ataque que você ingerir via OpenGraph.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa ou PowerShell
* `RustHound-CE` – coletor CE multiplataforma para Linux, macOS e Windows
* `NetExec --bloodhound` – coleta rápida orientada por LDAP a partir do Linux
* `AzureHound` – enumeração do Entra ID
* **SoaPy + BOFHound** – coleta ADWS (veja o link no topo)

> BloodHound CE `v8+` alterou o formato de saída do coletor quando OpenGraph chegou. Após atualizar do BloodHound legado ou de instalações CE mais antigas, execute novamente a descoberta com os coletores atuais antes de importar os dados.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Os collectors geram JSON que é ingerido via a GUI do BloodHound.

#### SharpHound a partir de um host Windows não ingressado no domínio

Se a sua VM de operador não estiver ingressada no domínio alvo, aponte o DNS para um DC, inicie um shell **network-only**, verifique se você consegue ver `SYSVOL`/`NETLOGON` em um DC e então colete contra o domínio remoto:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Isso é útil para jump boxes descartáveis ou estações de trabalho de operador que não devem estar domain-joined.

#### Coleta cross-platform a partir de Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` é uma boa opção padrão quando você quer saída compatível com CE de um host não-Windows. `NetExec` é conveniente quando você já o está usando para validação LDAP ou spraying e quer uma importação rápida do grafo. Para datasets não-AD, o BloodHound OpenGraph pode ser estendido com coletores como [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### Coleta de privilégio e logon-right

**Token privileges** do Windows (por exemplo, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) podem burlar verificações de DACL, então mapeá-los em todo o domínio expõe edges de LPE locais que grafos só de ACL não capturam. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` e seus correspondentes `SeDeny*`) são aplicados pela LSA antes mesmo de um token existir, e denies têm precedência, então eles controlam de forma direta o movimento lateral (RDP/SMB/scheduled task/service logon).

**Execute coletores com privilégios elevados** sempre que possível: o UAC cria um filtered token para admins interativos (via `NtFilterToken`), removendo privilégios sensíveis e marcando SIDs de admin como deny-only. Se você enumerar privilégios a partir de um shell não elevado, privilégios de alto valor ficarão invisíveis e o BloodHound não ingerirá os edges.

Agora existem duas estratégias complementares de coleta do SharpHound:

- **Análise de GPO/SYSVOL (discreta, baixo privilégio):**
1. Enumere GPOs via LDAP (`(objectCategory=groupPolicyContainer)`) e leia cada `gPCFileSysPath`.
2. Obtenha `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` do SYSVOL e faça parsing da seção `[Privilege Rights]` que mapeia nomes de privilégio/logon-right para SIDs.
3. Resolva links de GPO via `gPLink` em OUs/sites/domínios, liste os computadores nos containers vinculados e atribua os rights a essas máquinas.
4. Vantagem: funciona com um usuário normal e é silencioso; desvantagem: só vê rights aplicados via GPO (ajustes locais são perdidos).

- **Enumeração LSA RPC (ruidosa, precisa):**
- A partir de um contexto com local admin no alvo, abra a Local Security Policy e chame `LsaEnumerateAccountsWithUserRight` para cada privilege/logon right para enumerar os principals atribuídos via RPC.
- Vantagem: captura rights definidos localmente ou fora de GPO; desvantagem: tráfego de rede ruidoso e necessidade de admin em cada host.

**Exemplo de caminho de abuso revelado por esses edges:** `CanRDP` ➜ host onde seu usuário também tem `SeBackupPrivilege` ➜ inicie um shell elevado para evitar filtered tokens ➜ use backup semantics para ler hives `SAM` e `SYSTEM` apesar de DACLs restritivas ➜ exfiltre e execute `secretsdump.py` offline para recuperar o NT hash do Administrator local para movimento lateral/privilege escalation.

### Priorizando Kerberoasting com BloodHound

Use o contexto do grafo para manter o roasting direcionado:

1. Colete uma vez com um collector compatível com ADWS e trabalhe offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importe o ZIP, marque o principal comprometido como owned e execute consultas integradas (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) para destacar contas SPN com rights de admin/infra.
3. Priorize SPNs pelo blast radius; revise `pwdLastSet`, `lastLogon` e os tipos de criptografia permitidos antes de crackear.
4. Solicite apenas tickets selecionados, cracke offline e depois consulte novamente o BloodHound com o novo acesso:
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
## References

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
