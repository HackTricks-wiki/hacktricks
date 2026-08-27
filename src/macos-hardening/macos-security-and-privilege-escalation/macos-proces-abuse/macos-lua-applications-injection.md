# Injeção de Aplicações Lua no macOS

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Antes de processar as opções da linha de comando ou o script de destino, o interpretador Lua standalone executa `LUA_INIT_<major>_<minor>` ou, se a variável versionada estiver ausente, `LUA_INIT`. Um valor que começa com `@` indica um arquivo; qualquer outro valor é avaliado diretamente como código Lua. Isso possibilita a execução de inicialização baseada em arquivo e fileless.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
O nome exato com versão varia conforme o interpretador, por exemplo `LUA_INIT_5_4`. `lua -E` ignora todas as variáveis de ambiente, incluindo o código de inicialização e os caminhos dos módulos Lua.

## References

- [1] [Interpretador standalone do Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
