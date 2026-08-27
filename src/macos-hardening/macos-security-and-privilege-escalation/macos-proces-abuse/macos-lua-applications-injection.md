# macOS Lua Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

command-line 옵션이나 대상 script를 처리하기 전에 standalone Lua interpreter는 `LUA_INIT_<major>_<minor>`를 실행하며, 버전이 지정된 변수가 없으면 `LUA_INIT`을 실행합니다. `@`로 시작하는 값은 파일을 지정하고, 그 외의 값은 Lua code로 직접 평가됩니다. 이를 통해 파일 기반 및 fileless startup execution이 모두 가능합니다.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
정확한 버전 이름은 interpreter에 따라 변경됩니다. 예를 들어 `LUA_INIT_5_4`와 같습니다. `lua -E`는 startup code와 Lua module paths를 포함한 모든 environment variables를 무시합니다.

## References

- [1] [Lua 5.4 독립 실행형 interpreter](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
