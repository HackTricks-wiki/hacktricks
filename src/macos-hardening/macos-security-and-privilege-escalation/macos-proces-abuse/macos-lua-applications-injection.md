# Wstrzykiwanie do aplikacji Lua w macOS

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Przed przetworzeniem opcji wiersza poleceń lub docelowego skryptu samodzielny interpreter Lua wykonuje `LUA_INIT_<major>_<minor>` albo, jeśli zmienna wersjonowana jest nieobecna, `LUA_INIT`. Wartość rozpoczynająca się od `@` wskazuje plik; każda inna wartość jest bezpośrednio interpretowana jako kod Lua. Umożliwia to wykonywanie kodu startowego zarówno z pliku, jak i bez pliku.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
Dokładna nazwa zależna od wersji zmienia się wraz z interpreterem, na przykład `LUA_INIT_5_4`. `lua -E` ignoruje wszystkie zmienne środowiskowe, w tym kod uruchamiany podczas startu i ścieżki modułów Lua.

## References

- [1] [Samodzielny interpreter Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
