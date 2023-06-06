## WmicExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Como funciona

O Wmi permite abrir processos em hosts onde você conhece o nome de usuário/(senha/Hash). Em seguida, o Wmiexec usa o Wmi para executar cada comando que é solicitado para executar (é por isso que o Wmicexec fornece um shell semi-interativo).

**dcomexec.py:** Este script fornece um shell semi-interativo semelhante ao wmiexec.py, mas usando diferentes pontos de extremidade DCOM (objeto DCOM ShellBrowserWindow). Atualmente, ele suporta aplicativos MMC20, janelas de shell e objetos de janela do navegador de shell. (de [aqui](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Conceitos básicos do WMI

### Namespace

O WMI é dividido em uma hierarquia de estilo de diretório, o contêiner \root, com outros diretórios sob \root. Esses "caminhos de diretório" são chamados de namespaces.\
Listar namespaces:
```bash
#Get Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

#List all namespaces (you may need administrator to list all of them)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

#List namespaces inside "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Liste as classes de um namespace com:
```bash
gwmwi -List -Recurse #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classes**

O nome da classe WMI, por exemplo, win32\_process, é um ponto de partida para qualquer ação WMI. Sempre precisamos saber o nome da classe e o Namespace onde ela está localizada.\
Liste as classes que começam com `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more #If no namespace is specified, by default is used: "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Chame uma classe:
```bash
#When you don't specify a namespaces by default is "root/cimv2"
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Métodos

As classes WMI possuem uma ou mais funções que podem ser executadas. Essas funções são chamadas de métodos.
```bash
#Load a class using [wmiclass], leist methods and call one
$c = [wmiclass]"win32_share"
$c.methods
#Find information about the class in https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-share
$c.Create("c:\share\path","name",0,$null,"My Description")
#If returned value is "0", then it was successfully executed
```

```bash
#List methods
Get-WmiObject -Query 'Select * From Meta_Class WHERE __Class LIKE "win32%"' | Where-Object { $_.PSBase.Methods } | Select-Object Name, Methods
#Call create method from win32_share class
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Enumeração WMI

### Verificar o serviço WMI

Assim é possível verificar se o serviço WMI está em execução:
```bash
#Check if WMI service is running
Get-Service Winmgmt
Status   Name               DisplayName
------   ----               -----------
Running  Winmgmt            Windows Management Instrumentation

#From CMD
net start | findstr "Instrumentation"
```
### Informações do Sistema
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
```
### Informação do Processo
```bash
Get-WmiObject win32_process | Select Name, Processid
```
Do ponto de vista de um atacante, o WMI pode ser muito valioso para enumerar informações sensíveis sobre um sistema ou domínio.
```
wmic computerystem list full /format:list  
wmic process list /format:list  
wmic ntdomain list /format:list  
wmic useraccount list /format:list  
wmic group list /format:list  
wmic sysaccount list /format:list  
```

```bash
 Get-WmiObject Win32_Processor -ComputerName 10.0.0.182 -Credential $cred
```
## **Consulta Remota Manual do WMI**

Por exemplo, aqui está uma maneira muito furtiva de descobrir administradores locais em uma máquina remota (observe que o domínio é o nome do computador):
```bash
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")  
```
Outro comando útil em uma linha é ver quem está conectado em uma máquina (quando você está procurando por administradores):
```
wmic /node:ordws01 path win32_loggedonuser get antecedent  
```
O `wmic` pode até mesmo ler nós de um arquivo de texto e executar o comando em todos eles. Se você tiver um arquivo de texto com estações de trabalho:
```
wmic /node:@workstations.txt path win32_loggedonuser get antecedent  
```
Vamos criar remotamente um processo via WMI para executar um agente do Empire:
```bash
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"  
```
Vemos que foi executado com sucesso (Valor de Retorno = 0). E um segundo depois, nosso ouvinte Empire o captura. Note que o ID do processo é o mesmo que o WMI retornou.

Todas essas informações foram extraídas daqui: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
