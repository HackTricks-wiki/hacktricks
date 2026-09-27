# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Η ίδια η scripting language του Vim (Vimscript) μπορεί να εκτελεί **αυθαίρετες Ex commands και shell commands κατά την εκκίνηση** από environment variables. Αν μια διεργασία με περισσότερα προνόμια (ένα maintenance/root workflow, ένα `sudo vim …`, ένας editor που εκκινείται από άλλο tool, `crontab -e`, `visudo`, το `git`/`less` που καλεί έναν editor, …) εκκινήσει το Vim/Neovim με environment που επηρεάζεται από attacker, ο attacker αποκτά code execution σε αυτό το context.

## `VIMINIT`

Κατά την αρχικοποίηση, το Vim διαβάζει και εκτελεί τις Ex commands στο **`VIMINIT`**. Οι Ex commands περιλαμβάνουν τις `:!cmd` (εκτέλεση shell command) και `:call system(...)`, επομένως μία μόνο μεταβλητή παρέχει arbitrary execution πριν από την επεξεργασία οποιουδήποτε αρχείου.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
Το `:qa!` που διοχετεύεται μέσω stdin στο πρώτο παράδειγμα κλείνει τον editor μόνο αφού εκτελεστεί το payload· σε ένα πραγματικό σενάριο, το θύμα μπορεί να ανοίξει κανονικά το Vim.

Το `VIMINIT` αναλύεται ως **μία γραμμή εντολής Ex**. Διαχωρίστε μια ακολουθία με `|` (ή με literal newline). Έχει προτεραιότητα έναντι του vimrc του χρήστη και του `EXINIT`, επομένως ένα payload δεν χρειάζεται κακόβουλο αρχείο ρυθμίσεων και εκτελείται πριν από την κανονική ρύθμιση του χρήστη.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Αν δεν έχει οριστεί το `VIMINIT`, το Vim (και τα δυαδικά αρχεία συμβατότητας `vi`/`ex`) επιστρέφει στο **`EXINIT`**, το οποίο εκτελείται με τον ίδιο τρόπο. Είναι η κλασική παραλλαγή της ίδιας primitive από την εποχή του vi.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Καταστολή εκκίνησης και δυνατότητα εκμετάλλευσης

Αυτό το primitive εξαρτάται από μια **κανονική εκκίνηση**. Τα `vim -u NONE` / `nvim -u NONE` παρακάμπτουν την αρχικοποίηση του περιβάλλοντος/χρήστη (και τα plugins), ενώ το `-u <file>` χρησιμοποιεί αυτό το αρχείο. Τα Vim `-es`/`-Es` και τα Neovim `-es`, `-Es` ή `-l` παρακάμπτουν επίσης αυτά τα βήματα αρχικοποίησης. Μην θεωρήσετε το `--headless` safe mode: μια κανονική headless εκκίνηση του Neovim εξακολουθεί να επεξεργάζεται το `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Κατά συνέπεια, επικυρώστε ολόκληρη την αλυσίδα εκκίνησης: η μεταβλητή πρέπει να επιβιώνει από το wrapper, την πολιτική του `sudo`, το job runner και την επιλογή του editor, ενώ η τελική εντολή δεν πρέπει να επιβάλλει `-u NONE`/`NORC` ή batch mode. Ένα αξιόπιστο payload μπορεί να τερματίζει μόνο του με `|qall!`, γεγονός που διευκολύνει επίσης τη δοκιμή wrappers που δεν παρέχουν TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Hijacking Lua module από τον τρέχοντα κατάλογο στο Neovim

Ένα ξεχωριστό Neovim injection primitive επηρεάζει builds των οποίων τα Lua `package.path`/`package.cpath` εξακολουθούν να περιέχουν templates του τρέχοντος καταλόγου, όπως `./?.lua` ή `./?.so`. Η εκκίνηση του Neovim από μόνη της δεν αρκεί: ένα config ή plugin πρέπει να καλέσει `require("name")`, και κανένας προηγούμενος loader δεν πρέπει να έχει επιλύσει αυτό το όνομα. Ένα συνηθισμένο trigger είναι ένας **έλεγχος optional dependency**, όπως `pcall(require, "optional_dep")`; τοποθετώντας το `optional_dep.lua` σε έναν working directory που ελέγχεται από τον attacker, το αρχείο εκτελείται χωρίς να ενεργοποιηθεί το ξεχωριστό local-configuration feature `'exrc'`. Τα core `vim.*` modules και τα modules που έχουν ήδη βρεθεί στο `'runtimepath'` γενικά δεν μπορούν να γίνουν shadowing, επομένως enumerates τα πραγματικά missing/optional `require()` calls αντί να μαντεύεις ονόματα.<sup>[[3]](#references)</sup>

Το παρακάτω αναπαράγει το loader primitive με έναν harmless marker:<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```
Ελέγξτε το build που εκτελείται αντί να βασίζεστε μόνο σε ένα string έκδοσης:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Το Upstream παρακολουθεί την αφαίρεση του fallback του τρέχοντος καταλόγου κατά την κανονική εκκίνηση του editor, διατηρώντας παράλληλα τη συμπεριφορά των Lua-script (`nvim -l`). Μέχρι το εγκατεστημένο build να μην το εκθέτει πλέον, τοποθετήστε το στην **αρχή** του `init.lua` (αφαιρεί σκόπιμα τα σχετικά πρότυπα Lua/C modules του τρέχοντος καταλόγου, επομένως μην το εφαρμόσετε σε workflows που τα απαιτούν):<sup>[[3]](#references)</sup>
```lua
local function drop_cwd(path)
local keep = {}
for entry in path:gmatch("[^;]+") do
if not entry:match("^%./") then keep[#keep + 1] = entry end
end
return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```
## Σημειώσεις και επισημάνσεις

- Το **Neovim** τιμά τόσο το `VIMINIT` όσο και το fallback `EXINIT`, αλλά η κανονική ρύθμιση χρήστη είναι το `init.vim` ή το `init.lua`.<sup>[[2]](#references)</sup>
- Η διαδρομή μέσω environment variable δεν απαιτεί εγγράψιμο αρχείο. Το local rc και το current-directory module hijacking είναι ξεχωριστά primitives που βασίζονται σε αρχεία.<sup>[[1]](#references)[[3]](#references)</sup>
- Η ρύθμιση project-local είναι διαφορετική επιφάνεια από τα modelines. Όταν είναι ενεργοποιημένο το `'exrc'` του Vim, ένα local vimrc/exrc που ανήκει σε άλλον χρήστη εκτελείται με περιορισμούς `'secure'`. Ωστόσο, η εξαγωγή ενός archive συνήθως κάνει το planted file ιδιοκτησία του victim και παρακάμπτει αυτή την προστασία που βασίζεται στην ιδιοκτησία. Το Neovim αναζητά επίσης τα `.nvim.lua`, `.nvimrc` ή `.exrc` όταν είναι ενεργοποιημένο το `'exrc'` — μην συγχέετε αυτόν τον opt-in μηχανισμό με το current-directory fallback του `require()` παραπάνω.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Οι μεταβλητές επιλογής editor καθορίζουν μόνο ποιο πρόγραμμα θα εκκινηθεί· δεν εγγυώνται ότι το `VIMINIT` θα φτάσει στην τελική διεργασία. Ελέγξτε το ακριβές environment και τα arguments στο όριο exec του Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

- Αφαιρείτε ρητά τις μεταβλητές πριν από privileged ή automated editor launches: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. Το `-u NONE` είναι σημαντικό όταν ο caller πρέπει να αγνοήσει κάθε user startup source.<sup>[[1]](#references)[[2]](#references)</sup>
- Ορίστε τα `EDITOR`/`VISUAL` σε trusted absolute paths, αποφύγετε την εκτέλεση interactive editors ως root με inherited user environment και βεβαιωθείτε ότι τα wrappers δεν μπορούν να επαναφέρουν τα `VIMINIT`/`EXINIT` μετά το sanitization.<sup>[[1]](#references)[[2]](#references)</sup>
- Για το Neovim, κάντε update σε build που αφαιρεί τα current-directory Lua/C search templates κατά τη λειτουργία editor ή αφαιρέστε τα πριν από το loading των plugins. Κάντε audit στον κώδικα των plugins για προαιρετικές κλήσεις `pcall(require, ...)` κατά το άνοιγμα untrusted repositories.<sup>[[3]](#references)</sup>
- Αντιμετωπίστε τον έλεγχο του editor environment, του working directory ή του startup configuration ενός target ως πιθανό code-execution primitive στο security context του editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Τεκμηρίωση Vim — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Τεκμηρίωση Neovim — startup και initialization](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — current-directory fallback στο `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
