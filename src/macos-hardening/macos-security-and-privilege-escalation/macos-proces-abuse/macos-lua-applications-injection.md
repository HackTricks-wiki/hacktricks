# Injection σε εφαρμογές Lua του macOS

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Πριν από την επεξεργασία των επιλογών της γραμμής εντολών ή του script-στόχου, ο αυτόνομος interpreter της Lua εκτελεί το `LUA_INIT_<major>_<minor>` ή, αν η μεταβλητή με την έκδοση δεν υπάρχει, το `LUA_INIT`. Μια τιμή που ξεκινά με `@` καθορίζει ένα αρχείο· οποιαδήποτε άλλη τιμή αξιολογείται απευθείας ως κώδικας Lua. Αυτό παρέχει εκτέλεση κατά την εκκίνηση τόσο με χρήση αρχείου όσο και χωρίς αρχείο.<sup>[[1]](#references)</sup>
```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```
Το ακριβές όνομα με την έκδοση αλλάζει ανάλογα με τον interpreter, για παράδειγμα `LUA_INIT_5_4`. Το `lua -E` αγνοεί όλες τις μεταβλητές περιβάλλοντος, συμπεριλαμβανομένου του κώδικα εκκίνησης και των διαδρομών των Lua modules.

## References

- [1] [Αυτόνομος interpreter Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
