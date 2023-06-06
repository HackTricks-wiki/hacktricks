# Variáveis de ambiente do Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Variáveis globais

As variáveis globais **serão** herdadas pelos **processos filhos**.

Você pode criar uma variável global para sua sessão atual fazendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variável será acessível por suas sessões atuais e seus processos filhos.

Você pode **remover** uma variável fazendo:
```bash
unset MYGLOBAL
```
## Variáveis locais

As **variáveis locais** só podem ser **acessadas** pelo **shell/script atual**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Listar variáveis atuais
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variáveis de ambiente persistentes

#### **Arquivos que afetam o comportamento de todos os usuários:**

* _**/etc/bash.bashrc**_: Este arquivo é lido sempre que um shell interativo é iniciado (terminal normal) e todos os comandos especificados aqui são executados.
* _**/etc/profile e /etc/profile.d/\***_**:** Este arquivo é lido toda vez que um usuário faz login. Assim, todos os comandos executados aqui serão executados apenas uma vez no momento do login do usuário.
  *   \*\*Exemplo: \*\*

      `/etc/profile.d/somescript.sh`

      ```bash
      #!/bin/bash
      TEST=$(cat /var/somefile)
      export $TEST
      ```

#### **Arquivos que afetam o comportamento de apenas um usuário específico:**

* _**\~/.bashrc**_: Este arquivo funciona da mesma maneira que o arquivo _/etc/bash.bashrc_, mas é executado apenas para um usuário específico. Se você quiser criar um ambiente para si mesmo, modifique ou crie este arquivo em seu diretório home.
* _**\~/.profile, \~/.bash\_profile, \~/.bash\_login**_**:** Esses arquivos são iguais ao arquivo _/etc/profile_. A diferença está na forma como é executado. Este arquivo é executado apenas quando um usuário em cujo diretório home este arquivo existe faz login.

**Extraído de:** [**aqui**](https://codeburst.io/linux-environment-variables-53cea0245dc9) **e** [**aqui**](https://www.gnu.org/software/bash/manual/html\_node/Bash-Startup-Files.html)

## Variáveis comuns

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – o display usado pelo **X**. Esta variável geralmente é definida como **:0.0**, o que significa o primeiro display no computador atual.
* **EDITOR** – o editor de texto preferido do usuário.
* **HISTFILESIZE** – o número máximo de linhas contidas no arquivo de histórico.
* \*\*HISTSIZE - \*\*Número de linhas adicionadas ao arquivo de histórico quando o usuário termina sua sessão.
* **HOME** – seu diretório home.
* **HOSTNAME** – o nome do host do computador.
* **LANG** – seu idioma atual.
* **MAIL** – o local do spool de correio do usuário. Geralmente **/var/spool/mail/USER**.
* **MANPATH** – a lista de diretórios para procurar páginas do manual.
* **OSTYPE** – o tipo de sistema operacional.
* **PS1** – o prompt padrão no bash.
* \*\*PATH - \*\*armazena o caminho de todos os diretórios que contêm arquivos binários que você deseja executar apenas especificando o nome do arquivo e não pelo caminho relativo ou absoluto.
* **PWD** – o diretório de trabalho atual.
* **SHELL** – o caminho para o shell de comando atual (por exemplo, **/bin/bash**).
* **TERM** – o tipo de terminal atual (por exemplo, **xterm**).
* **TZ** – seu fuso horário.
* **USER** – seu nome de usuário atual.

## Variáveis interessantes para hacking

### **HISTFILESIZE**

Altere o **valor desta variável para 0**, para que quando você **encerrar sua sessão**, o **arquivo de histórico** (\~/.bash\_history) **seja excluído**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Altere o **valor desta variável para 0**, assim quando você **encerrar sua sessão**, nenhum comando será adicionado ao **arquivo de histórico** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Os processos usarão o **proxy** declarado aqui para se conectar à internet através do **http ou https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Os processos confiarão nos certificados indicados nessas variáveis de ambiente.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Altere a aparência do seu prompt.

Eu criei [**este**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808) (baseado em outro, leia o código).

Root:

![](<../.gitbook/assets/image (87).png>)

Usuário regular:

![](<../.gitbook/assets/image (88).png>)

Um, dois e três trabalhos em segundo plano:

![](<../.gitbook/assets/image (89).png>)

Um trabalho em segundo plano, um parado e o último comando não terminou corretamente:

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
