# Injeção em Aplicações macOS Vim/Neovim

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

A própria linguagem de script do Vim (Vimscript) pode executar **comandos Ex e comandos de shell arbitrários na inicialização** a partir de variáveis de ambiente. Se um processo com mais privilégios (um fluxo de manutenção/root, um `sudo vim …`, um editor iniciado por outra ferramenta, `crontab -e`, `visudo`, `git`/`less` que invoca um editor, …) iniciar o Vim/Neovim com um ambiente controlado pelo atacante, este obtém execução de código nesse contexto.

## `VIMINIT`

Durante a inicialização, o Vim lê e executa os comandos Ex em **`VIMINIT`**. Os comandos Ex incluem `:!cmd` (executar um comando de shell) e `:call system(...)`, portanto, uma única variável permite execução arbitrária antes que qualquer arquivo seja editado.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

O `:qa!` enviado por stdin no primeiro exemplo apenas fecha o editor depois que o payload é executado; em um cenário real, a vítima pode abrir o Vim normalmente.

`VIMINIT` é interpretado como **uma única linha de comando Ex**. Separe uma sequência com `|` (ou uma nova linha literal). Ele tem precedência sobre o vimrc do usuário e `EXINIT`, então um payload não precisa de um arquivo de configuração malicioso e é executado antes da configuração normal do usuário.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Se `VIMINIT` não estiver definido, o Vim (e os binários de compatibilidade `vi`/`ex`) recorre a **`EXINIT`**, que é executado da mesma forma. É a variante clássica da era do vi do mesmo primitivo.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## RC local do projeto com Vim `exrc`

Esta é uma alternativa baseada em arquivo a `VIMINIT`. Se a vítima tiver ativado `set exrc` na configuração do usuário, o Vim também carrega `.vimrc` (depois `_vimrc` ou `.exrc`) do **diretório de trabalho**, não apenas do diretório do arquivo que está sendo editado. Coloque um `.vimrc` local no projeto e faça a vítima iniciar o Vim a partir desse projeto. No Unix, o Vim aplica restrições `secure` a um arquivo rc local pertencente a outra pessoa, mas um arquivo compactado extraído pela vítima normalmente atribui ao arquivo colocado a propriedade da vítima, evitando essa verificação.<sup>[[1]](#references)</sup>

Este marcador isolado mostra o acionamento na inicialização sem modificar a configuração real do usuário:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim é diferente: as versões atuais exigem que `.nvim.lua`, `.nvimrc` ou `.exrc` locais ao projeto sejam confiáveis antes da execução. A confiança é associada ao hash do conteúdo do arquivo, então alterar um arquivo já confiável exige uma nova decisão de confiança. Um atacante que só pode colocar um arquivo em um repositório não pode presumir a execução silenciosa por meio de `exrc`; diferencie esse caminho opcional, protegido por confiança, do caminho de `require()` em Lua no diretório atual descrito abaixo.<sup>[[4]](#references)[[5]](#references)</sup>

Para um vimrc **do usuário** gravável, em vez de um arquivo local ao projeto, consulte [Configuração de inicialização do Vim no macOS](../../macos-auto-start-locations.md#vim-startup-configuration).

## Supressão da inicialização e explorabilidade

Essa primitiva depende de uma **inicialização normal**. `vim -u NONE` / `nvim -u NONE` ignoram a inicialização do ambiente/usuário (e os plugins), enquanto `-u <file>` usa esse arquivo no lugar. Vim `-es`/`-Es` e Neovim `-es`, `-Es` ou `-l` também ignoram essas etapas de inicialização. Não confunda `--headless` com um modo seguro: uma inicialização normal do Neovim sem interface ainda processa `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Consequentemente, valide toda a cadeia de inicialização: a variável precisa sobreviver ao wrapper, à política de `sudo`, ao executor de tarefas e à seleção do editor, e o comando final não pode forçar `-u NONE`/`NORC` ou o modo em lote. Um payload confiável pode encerrar a si próprio com `|qall!`, o que também facilita testar wrappers que não fornecem um TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Sequestro de módulos Lua do diretório atual no Neovim

Uma primitiva distinta de injeção no Neovim afeta versões cuja `package.path`/`package.cpath` de Lua ainda contêm modelos do diretório atual, como `./?.lua` ou `./?.so`. Iniciar apenas o Neovim não basta: uma configuração ou um plugin precisa chamar `require("name")`, e nenhum carregador anterior pode resolver esse nome. Um gatilho comum é uma **verificação de dependência opcional**, como `pcall(require, "optional_dep")`; colocar `optional_dep.lua` em um diretório de trabalho controlado pelo atacante faz com que ele seja executado sem habilitar o recurso separado de configuração local `'exrc'`. Módulos centrais `vim.*` e módulos já encontrados em `'runtimepath'` geralmente não podem ser sobrepostos, então enumere as chamadas reais de `require()` para módulos ausentes/opcionais em vez de adivinhar nomes.<sup>[[3]](#references)</sup>

O exemplo a seguir reproduz a primitiva do carregador usando um marcador inofensivo:<sup>[[3]](#references)</sup>

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

O Upstream está acompanhando a remoção do fallback do diretório atual durante a inicialização normal do editor, mantendo o comportamento de scripts Lua (`nvim -l`). Até que a build instalada não o exponha mais, coloque isto no **início** de `init.lua` (ele remove intencionalmente os templates relativos de módulos Lua/C do diretório atual; portanto, não o aplique a fluxos de trabalho que dependam deles):<sup>[[3]](#references)</sup>

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

## Notas e ressalvas

- **Neovim** respeita tanto `VIMINIT` quanto a alternativa `EXINIT`, mas sua configuração normal de usuário é `init.vim` ou `init.lua`.<sup>[[2]](#references)</sup>
- O caminho da variável de ambiente não requer um arquivo gravável. O hijacking de arquivos rc locais e de módulos no diretório atual são primitivas separadas, baseadas em arquivos.<sup>[[1]](#references)[[3]](#references)</sup>
- Arquivos rc locais do projeto são distintos de modelines e da alternativa de `require()` no diretório atual mencionada acima. Vim e Neovim fazem verificações diferentes para eles; consulte o fluxo de trabalho `exrc` local ao projeto acima.<sup>[[1]](#references)[[4]](#references)</sup>
- As variáveis de seleção do editor apenas escolhem qual programa será iniciado; elas não garantem que `VIMINIT` chegue ao processo final. Inspecione o ambiente e os argumentos exatos no limite de execução do Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

- Remova explicitamente as variáveis antes de iniciar editores com privilégios elevados ou automatizados: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` é importante quando o chamador precisa ignorar todas as fontes de inicialização do usuário.<sup>[[1]](#references)[[2]](#references)</sup>
- Defina `EDITOR`/`VISUAL` com caminhos absolutos confiáveis, evite executar editores interativos como root com o ambiente herdado do usuário e garanta que wrappers não possam restaurar `VIMINIT`/`EXINIT` após a sanitização.<sup>[[1]](#references)[[2]](#references)</sup>
- No Neovim, atualize para uma versão que remova os templates de busca Lua/C do diretório atual durante o modo de editor ou remova-os antes de carregar plugins. Audite o código dos plugins em busca de chamadas opcionais a `pcall(require, ...)` ao abrir repositórios não confiáveis.<sup>[[3]](#references)</sup>
- Trate o controle do ambiente do editor, do diretório de trabalho ou da configuração de inicialização de um alvo como uma possível primitiva de execução de código no contexto de segurança do editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Documentação do Vim — `starting.txt` (inicialização, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Documentação do Neovim — inicialização e configuração](https://neovim.io/doc/user/starting/)
- [3] [Problema #38966 do Neovim — alternativa no diretório atual em `require()`](https://github.com/neovim/neovim/issues/38966)
- [4] [Opções do Neovim — `exrc` local ao projeto e requisito de confiança](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Edição no Neovim — arquivos confiáveis e `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
