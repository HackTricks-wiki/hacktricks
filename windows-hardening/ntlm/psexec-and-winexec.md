# PsExec/Winexec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Como eles funcionam

1. Copie um binário de serviço para o compartilhamento ADMIN$ via SMB
2. Crie um serviço na máquina remota apontando para o binário
3. Inicie o serviço remotamente
4. Quando sair, pare o serviço e exclua o binário

## **Executando manualmente o PsExec**

Primeiro, vamos supor que temos um executável de payload que geramos com o msfvenom e obfuscamos com o Veil (para que o AV não o sinalize). Neste caso, criei um payload meterpreter reverse\_http e o chamei de 'met8888.exe'

**Copie o binário**. A partir do nosso prompt de comando "jarrieta", basta copiar o binário para o ADMIN$. Na verdade, ele poderia ser copiado e ocultado em qualquer lugar no sistema de arquivos.

![](../../.gitbook/assets/copy\_binary\_admin.png)

**Crie um serviço**. O comando `sc` do Windows é usado para consultar, criar, excluir, etc. serviços do Windows e pode ser usado remotamente. Leia mais sobre isso [aqui](https://technet.microsoft.com/en-us/library/bb490995.aspx). A partir do nosso prompt de comando, criaremos remotamente um serviço chamado "meterpreter" que aponta para nosso binário carregado:

![](../../.gitbook/assets/sc\_create.png)

**Inicie o serviço**. O último passo é iniciar o serviço e executar o binário. _Nota:_ quando o serviço é iniciado, ele "expira" e gera um erro. Isso ocorre porque nosso binário meterpreter não é um binário de serviço real e não retornará o código de resposta esperado. Isso é bom porque só precisamos que ele execute uma vez para disparar:

![](../../.gitbook/assets/sc\_start\_error.png)

Se olharmos para nosso ouvinte Metasploit, veremos que a sessão foi aberta.

**Limpe o serviço.**

![](../../.gitbook/assets/sc\_delete.png)

Extraído daqui: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Você também pode usar o binário do Windows Sysinternals PsExec.exe:**

![](<../../.gitbook/assets/image (165).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
