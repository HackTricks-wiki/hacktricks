# Injeção de Aplicações Vim/Neovim no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

A própria linguagem de scripting do Vim (Vimscript) pode executar **comandos Ex arbitrários e comandos shell na inicialização** a partir de variáveis de ambiente. Se um processo com mais privilégios (um fluxo de manutenção/root, um `sudo vim …`, um editor iniciado por outra ferramenta, `crontab -e`, `visudo`, `git`/`less` invocando um editor, …) iniciar o Vim/Neovim com um ambiente controlado pelo atacante, o atacante obterá execução de código nesse contexto.

## `VIMINIT`

Durante a inicialização, o Vim lê e executa os comandos Ex em **`VIMINIT`**. Os comandos Ex incluem `:!cmd` (executa um comando shell) e `:call system(...)`, portanto uma única variável permite execução arbitrária antes que qualquer arquivo seja editado.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
O `:qa!` enviado via stdin no primeiro exemplo apenas fecha o editor depois que o payload é executado; em um cenário real, a vítima pode abrir o Vim normalmente.

`VIMINIT` é analisado como **uma única linha de comando Ex**. Separe uma cadeia com `|` (ou uma quebra de linha literal). Ele tem precedência sobre o vimrc do usuário e o `EXINIT`, portanto um payload não precisa de um arquivo de configuração malicioso e é executado antes da configuração normal do usuário.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Se `VIMINIT` não estiver definido, o Vim (e os binários de compatibilidade `vi`/`ex`) recorre ao **`EXINIT`**, que é executado da mesma forma. Essa é a variante clássica, da era do vi, da mesma primitiva.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Supressão da inicialização e explorabilidade

Este primitive depende de uma **inicialização normal**. `vim -u NONE` / `nvim -u NONE` ignoram a inicialização do ambiente/usuário (e os plugins), enquanto `-u <file>` usa esse arquivo. Vim `-es`/`-Es` e Neovim `-es`, `-Es` ou `-l` também ignoram essas etapas de inicialização. Não confunda `--headless` com um modo seguro: uma inicialização normal do Neovim em modo headless ainda processa `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Consequentemente, valide a cadeia completa de inicialização: a variável deve sobreviver ao wrapper, à política do `sudo`, ao job runner e à seleção do editor, e o comando final não deve forçar `-u NONE`/`NORC` nem o modo batch. Um payload confiável pode encerrar a si mesmo com `|qall!`, o que também facilita testar wrappers que não fornecem um TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Hijacking de módulos Lua no diretório atual do Neovim

Um primitive separado de injection do Neovim afeta builds cujo Lua `package.path`/`package.cpath` ainda contém templates do diretório atual, como `./?.lua` ou `./?.so`. Iniciar o Neovim sozinho não é suficiente: uma configuração ou plugin precisa chamar `require("name")`, e nenhum loader anterior pode resolver esse nome. Um trigger comum é uma **verificação de dependência opcional**, como `pcall(require, "optional_dep")`; colocar `optional_dep.lua` em um diretório de trabalho controlado pelo atacante então o executa sem habilitar o recurso separado de configuração local `'exrc'`. Módulos principais `vim.*` e módulos já encontrados em `'runtimepath'` geralmente não podem ser shadowed, portanto enumere as chamadas `require()` ausentes/opcionais reais em vez de adivinhar nomes.<sup>[[3]](#references)</sup>

O seguinte reproduz o primitive do loader com um marcador inofensivo:<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```
Verifique a build em execução em vez de depender apenas de uma string de versão:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
O upstream acompanha a remoção do fallback do diretório atual durante a inicialização normal do editor, mantendo o comportamento de scripts Lua (`nvim -l`). Até que a build instalada não o exponha mais, coloque isto no **início de `init.lua`** (isso remove intencionalmente os templates de módulos Lua/C relativos ao diretório atual; portanto, não aplique em workflows que dependam deles):<sup>[[3]](#references)</sup>
```lua
local function drop_cwd(path)
local keep = {}
for entry in path:gmatch("[^;]+") do
if not entry:match("^%./") then keep[#keep + 1] = entry end
end
return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```
## Observações e ressalvas

- **Neovim** respeita tanto `VIMINIT` quanto o fallback `EXINIT`, mas sua configuração normal de usuário é `init.vim` ou `init.lua`.<sup>[[2]](#references)</sup>
- O caminho pela variável de ambiente não precisa de um arquivo gravável. O sequestro de rc local e de módulos no diretório atual são primitivas distintas, baseadas em arquivos.<sup>[[1]](#references)[[3]](#references)</sup>
- A configuração local do projeto é uma superfície diferente de modelines. Com o `'exrc'` do Vim habilitado, um vimrc/exrc local pertencente a outro usuário é executado com as restrições de `'secure'`; no entanto, extrair um arquivo normalmente faz com que o arquivo plantado pertença à vítima e neutraliza essa proteção baseada em propriedade. O Neovim também procura por `.nvim.lua`, `.nvimrc` ou `.exrc` quando `'exrc'` está habilitado — não confunda esse mecanismo opt-in com o fallback de `require()` no diretório atual mencionado acima.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- As variáveis de seleção do editor apenas escolhem qual programa será iniciado; elas não garantem que `VIMINIT` chegue ao processo final. Inspecione o ambiente e os argumentos exatos na fronteira de exec do Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Fortalecimento

- Remova explicitamente as variáveis antes de iniciar editores privilegiados ou automatizados: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` é importante quando o chamador precisa ignorar todas as fontes de inicialização do usuário.<sup>[[1]](#references)[[2]](#references)</sup>
- Defina `EDITOR`/`VISUAL` como caminhos absolutos confiáveis, evite executar editores interativos como root com um ambiente de usuário herdado e garanta que wrappers não possam restaurar `VIMINIT`/`EXINIT` após a sanitização.<sup>[[1]](#references)[[2]](#references)</sup>
- Para o Neovim, atualize para uma build que remova os templates de busca Lua/C do diretório atual durante o modo editor ou remova-os antes de carregar plugins. Audite o código dos plugins em busca de chamadas opcionais `pcall(require, ...)` ao abrir repositórios não confiáveis.<sup>[[3]](#references)</sup>
- Trate o controle sobre o ambiente do editor, o diretório de trabalho ou a configuração de inicialização de um alvo como uma potencial primitive de code execution no contexto de segurança do editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Documentação do Vim — `starting.txt` (inicialização, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Documentação do Neovim — inicialização e startup](https://neovim.io/doc/user/starting/)
- [3] [Issue #38966 do Neovim — fallback do diretório atual em `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
