# macOS Lua Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Komut satırı seçeneklerini veya hedef script'i işleme koymadan önce, bağımsız Lua interpreter'ı `LUA_INIT_<major>_<minor>` değişkenini veya sürümlü değişken mevcut değilse `LUA_INIT` değişkenini çalıştırır. `@` ile başlayan bir değer bir dosya belirtir; diğer tüm değerler doğrudan Lua kodu olarak değerlendirilir. Bu, hem dosya tabanlı hem de fileless başlangıç çalıştırmasına olanak tanır.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
Sürüm numarası içeren tam ad, yorumlayıcıya göre değişir; örneğin `LUA_INIT_5_4`. `lua -E`, başlangıç kodu ve Lua module paths dahil olmak üzere tüm environment variables değerlerini yok sayar.

## References

- [1] [Lua 5.4 bağımsız yorumlayıcısı](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
