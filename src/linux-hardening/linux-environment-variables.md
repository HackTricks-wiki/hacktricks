# Variáveis de Ambiente do Linux

{{#include ../banners/hacktricks-training.md}}

## Variáveis globais

As variáveis globais **serão** herdadas por **processos filhos**.

Você pode criar uma variável global para sua sessão atual fazendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variável estará acessível pelas suas sessões atuais e seus processos filhos.

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
## Variáveis comuns

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – o display usado pelo **X**. Esta variável geralmente é definida como **:0.0**, o que significa o primeiro display no computador atual.
- **EDITOR** – o editor de texto preferido do usuário.
- **HISTFILESIZE** – o número máximo de linhas contidas no arquivo de histórico.
- **HISTSIZE** – Número de linhas adicionadas ao arquivo de histórico quando o usuário termina sua sessão.
- **HOME** – seu diretório home.
- **HOSTNAME** – o nome do host do computador.
- **LANG** – seu idioma atual.
- **MAIL** – a localização do spool de e-mail do usuário. Geralmente **/var/spool/mail/USER**.
- **MANPATH** – a lista de diretórios para procurar páginas de manual.
- **OSTYPE** – o tipo de sistema operacional.
- **PS1** – o prompt padrão no bash.
- **PATH** – armazena o caminho de todos os diretórios que contêm arquivos binários que você deseja executar apenas especificando o nome do arquivo e não pelo caminho relativo ou absoluto.
- **PWD** – o diretório de trabalho atual.
- **SHELL** – o caminho para o shell de comando atual (por exemplo, **/bin/bash**).
- **TERM** – o tipo de terminal atual (por exemplo, **xterm**).
- **TZ** – seu fuso horário.
- **USER** – seu nome de usuário atual.

## Variáveis interessantes para hacking

### **HISTFILESIZE**

Altere o **valor desta variável para 0**, para que quando você **terminar sua sessão** o **arquivo de histórico** (\~/.bash_history) **seja deletado**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Altere o **valor desta variável para 0**, para que quando você **encerrar sua sessão**, qualquer comando seja adicionado ao **arquivo de histórico** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

Os processos usarão o **proxy** declarado aqui para se conectar à internet através de **http ou https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Os processos confiarão nos certificados indicados nessas **variáveis de ambiente**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Altere a aparência do seu prompt.

[**Este é um exemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Usuário regular:

![](<../images/image (740).png>)

Um, dois e três trabalhos em segundo plano:

![](<../images/image (145).png>)

Um trabalho em segundo plano, um parado e o último comando não terminou corretamente:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
