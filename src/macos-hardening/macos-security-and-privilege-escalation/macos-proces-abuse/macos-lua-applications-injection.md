# macOS Lua Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Before processing command-line options or the target script, the standalone Lua interpreter executes `LUA_INIT_<major>_<minor>` or, if the versioned variable is absent, `LUA_INIT`. A value beginning with `@` names a file; any other value is evaluated directly as Lua code. This gives both file-backed and fileless startup execution.<sup>[[1]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

The exact versioned name changes with the interpreter, for example `LUA_INIT_5_4`. `lua -E` ignores all environment variables, including startup code and Lua module paths.

## References

- [1] [Lua 5.4 standalone interpreter](https://www.lua.org/manual/5.4/manual.html#7)

{{#include ../../../banners/hacktricks-training.md}}
