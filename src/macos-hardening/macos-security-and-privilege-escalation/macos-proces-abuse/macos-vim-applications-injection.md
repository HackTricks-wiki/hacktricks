# Εγχύσεις εφαρμογών Vim/Neovim στο macOS

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Η γλώσσα scripting του Vim (Vimscript) μπορεί να εκτελέσει **αυθαίρετες εντολές Ex και εντολές shell κατά την εκκίνηση** μέσω μεταβλητών περιβάλλοντος. Αν μια διεργασία με περισσότερα προνόμια (μια ροή εργασιών συντήρησης/root, ένα `sudo vim …`, ένας editor που εκκινείται από άλλο εργαλείο, τα `crontab -e`, `visudo`, το `git`/`less` που καλεί έναν editor, …) εκκινήσει το Vim/Neovim με περιβάλλον που επηρεάζεται από τον επιτιθέμενο, ο επιτιθέμενος αποκτά εκτέλεση κώδικα σε αυτό το πλαίσιο.

## `VIMINIT`

Κατά την αρχικοποίηση, το Vim διαβάζει και εκτελεί τις εντολές Ex στη μεταβλητή **`VIMINIT`**. Οι εντολές Ex περιλαμβάνουν τις `:!cmd` (εκτελεί μια εντολή shell) και `:call system(...)`, επομένως μία μόνο μεταβλητή επιτρέπει την αυθαίρετη εκτέλεση πριν από την επεξεργασία οποιουδήποτε αρχείου.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

Το `:qa!` που δίνεται μέσω stdin στο πρώτο παράδειγμα κλείνει τον editor μόνο αφού εκτελεστεί το payload· σε ένα πραγματικό σενάριο, το θύμα μπορεί να ανοίξει κανονικά το Vim.

Το `VIMINIT` αναλύεται ως **μία γραμμή εντολών Ex**. Διαχωρίστε μια ακολουθία εντολών με `|` (ή με κυριολεκτική αλλαγή γραμμής). Έχει προτεραιότητα έναντι του vimrc του χρήστη και του `EXINIT`, επομένως ένα payload δεν χρειάζεται κακόβουλο αρχείο ρυθμίσεων και εκτελείται πριν από τις κανονικές ρυθμίσεις του χρήστη.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Αν δεν έχει οριστεί το `VIMINIT`, το Vim (και τα δυαδικά αρχεία συμβατότητας `vi`/`ex`) καταφεύγει στο **`EXINIT`**, το οποίο εκτελείται με τον ίδιο τρόπο. Είναι η κλασική παραλλαγή της ίδιας primitive από την εποχή του vi.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Τοπικό rc έργου με Vim `exrc`

Αυτή είναι μια εναλλακτική του `VIMINIT` που βασίζεται σε αρχείο. Αν το θύμα έχει ενεργοποιήσει το `set exrc` στις ρυθμίσεις χρήστη, το Vim φορτώνει επίσης το `.vimrc` (έπειτα το `_vimrc` ή το `.exrc`) από τον **κατάλογο εργασίας** του και όχι μόνο από τον κατάλογο του αρχείου που επεξεργάζεται. Τοποθέτησε ένα τοπικό `.vimrc` στο έργο και κάνε το θύμα να εκκινήσει το Vim από εκεί. Στο Unix, το Vim εφαρμόζει περιορισμούς `secure` σε ένα τοπικό rc που ανήκει σε κάποιον άλλο, αλλά ένα αρχείο που εξήχθη από αρχειοθήκη αποκτά συνήθως την ιδιοκτησία του θύματος, παρακάμπτοντας αυτόν τον έλεγχο.<sup>[[1]](#references)</sup>

Αυτός ο απομονωμένος δείκτης δείχνει το έναυσμα εκκίνησης χωρίς να τροποποιεί τις πραγματικές ρυθμίσεις χρήστη:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Το Neovim διαφέρει: οι τρέχουσες εκδόσεις απαιτούν να εγκριθούν πριν από την εκτέλεση τα αρχεία `.nvim.lua`, `.nvimrc` ή `.exrc` που βρίσκονται τοπικά στο project. Η έγκριση συνδέεται με το hash περιεχομένου του αρχείου, επομένως η αλλαγή ενός ήδη εγκεκριμένου αρχείου απαιτεί νέα απόφαση έγκρισης. Ένας attacker που μπορεί μόνο να τοποθετήσει ένα αρχείο σε ένα repository δεν μπορεί να θεωρεί δεδομένη την αθόρυβη εκτέλεσή του μέσω του `exrc`· ξεχωρίστε αυτήν την προαιρετική διαδρομή, που απαιτεί έγκριση, από τη διαδρομή Lua `require()` του τρέχοντος καταλόγου παρακάτω.<sup>[[4]](#references)[[5]](#references)</sup>

Για ένα εγγράψιμο **user** vimrc αντί για ένα τοπικό αρχείο ρυθμίσεων project, δείτε [macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration).

## Καταστολή εκκίνησης και δυνατότητα εκμετάλλευσης

Αυτό το primitive εξαρτάται από μια **κανονική εκκίνηση**. Τα `vim -u NONE` / `nvim -u NONE` παραλείπουν την αρχικοποίηση περιβάλλοντος/user (και τα plugins), ενώ το `-u <file>` χρησιμοποιεί αυτό το αρχείο αντί γι' αυτήν. Τα Vim `-es`/`-Es` και τα Neovim `-es`, `-Es` ή `-l` παραλείπουν επίσης αυτά τα βήματα αρχικοποίησης. Μη θεωρείτε ότι το `--headless` είναι ασφαλής λειτουργία: μια κανονική headless εκκίνηση του Neovim εξακολουθεί να επεξεργάζεται το `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Κατά συνέπεια, επαληθεύστε ολόκληρη την αλυσίδα εκκίνησης: η μεταβλητή πρέπει να διατηρείται από το wrapper, την πολιτική `sudo`, το job runner και την επιλογή editor, ενώ η τελική εντολή δεν πρέπει να επιβάλλει `-u NONE`/`NORC` ή batch mode. Ένα αξιόπιστο payload μπορεί να τερματίζεται με `|qall!`, κάτι που διευκολύνει επίσης τη δοκιμή wrappers που δεν παρέχουν TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim current-directory Lua module hijacking

Ένα ξεχωριστό primitive injection του Neovim επηρεάζει εκδόσεις των οποίων τα `package.path`/`package.cpath` της Lua περιλαμβάνουν ακόμη πρότυπα τρέχοντος καταλόγου, όπως `./?.lua` ή `./?.so`. Η απλή εκκίνηση του Neovim δεν αρκεί: κάποια ρύθμιση ή plugin πρέπει να καλέσει `require("name")`, και κανένας προηγούμενος loader δεν πρέπει να έχει επιλύσει αυτό το όνομα. Μια συνηθισμένη αφορμή είναι ο **έλεγχος προαιρετικής εξάρτησης**, όπως `pcall(require, "optional_dep")`· τοποθετώντας το `optional_dep.lua` σε έναν κατάλογο εργασίας που ελέγχει ο attacker, εκτελείται χωρίς να ενεργοποιηθεί η ξεχωριστή δυνατότητα τοπικών ρυθμίσεων `'exrc'`. Οι βασικές ενότητες `vim.*` και οι ενότητες που βρίσκονται ήδη στο `'runtimepath'` γενικά δεν μπορούν να σκιαστούν, επομένως καταγράψτε τις πραγματικές κλήσεις `require()` για ενότητες που λείπουν ή είναι προαιρετικές, αντί να μαντεύετε ονόματα.<sup>[[3]](#references)</sup>

Το παρακάτω αναπαράγει το primitive του loader με έναν ακίνδυνο marker:<sup>[[3]](#references)</sup>

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

Ελέγξτε το build που εκτελείται αντί να βασίζεστε μόνο σε μια συμβολοσειρά έκδοσης:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Το upstream παρακολουθεί την κατάργηση του fallback του τρέχοντος καταλόγου κατά την κανονική εκκίνηση του editor, διατηρώντας παράλληλα τη συμπεριφορά των Lua-script (`nvim -l`). Μέχρι να μην το περιλαμβάνει πλέον η εγκατεστημένη έκδοση, τοποθετήστε το στην **αρχή** του `init.lua` (αφαιρεί σκόπιμα τα πρότυπα Lua/C module που χρησιμοποιούν σχετικές διαδρομές από τον τρέχοντα κατάλογο, οπότε μην το εφαρμόσετε σε workflows που τα χρειάζονται):<sup>[[3]](#references)</sup>

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

## Σημειώσεις και επιφυλάξεις

- Το **Neovim** λαμβάνει υπόψη τόσο το `VIMINIT` όσο και το εφεδρικό `EXINIT`, αλλά το κανονικό αρχείο ρυθμίσεων χρήστη είναι το `init.vim` ή το `init.lua`.<sup>[[2]](#references)</sup>
- Η διαδρομή μέσω μεταβλητής περιβάλλοντος δεν απαιτεί εγγράψιμο αρχείο. Η τοπική ρύθμιση rc και η κατάληψη module από τον τρέχοντα κατάλογο είναι ξεχωριστοί μηχανισμοί που βασίζονται σε αρχεία.<sup>[[1]](#references)[[3]](#references)</sup>
- Τα τοπικά αρχεία rc ενός project διαφέρουν από τα modelines και από τον εφεδρικό μηχανισμό του `require()` για τον τρέχοντα κατάλογο που αναφέρθηκε παραπάνω. Τα Vim και Neovim εφαρμόζουν διαφορετικούς ελέγχους γι' αυτά· δείτε την παραπάνω ροή εργασίας `exrc` για τοπικά αρχεία project.<sup>[[1]](#references)[[4]](#references)</sup>
- Οι μεταβλητές επιλογής editor επιλέγουν μόνο το πρόγραμμα που θα εκκινηθεί· δεν εγγυώνται ότι το `VIMINIT` θα φτάσει στην τελική διεργασία. Ελέγξτε το ακριβές περιβάλλον και τα ορίσματα στο όριο εκτέλεσης του Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Θωράκιση

- Αφαιρείτε ρητά τις μεταβλητές πριν από την εκκίνηση editor με αυξημένα δικαιώματα ή αυτοματοποιημένη εκκίνηση: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. Το `-u NONE` είναι σημαντικό όταν ο καλών πρέπει να αγνοήσει κάθε πηγή εκκίνησης χρήστη.<sup>[[1]](#references)[[2]](#references)</sup>
- Ορίστε τα `EDITOR`/`VISUAL` σε έμπιστες απόλυτες διαδρομές, αποφύγετε την εκτέλεση διαδραστικών editor ως root με κληρονομημένο περιβάλλον χρήστη και βεβαιωθείτε ότι τα wrappers δεν μπορούν να επαναφέρουν τα `VIMINIT`/`EXINIT` μετά τον καθαρισμό.<sup>[[1]](#references)[[2]](#references)</sup>
- Για το Neovim, ενημερωθείτε σε έκδοση που αφαιρεί τα πρότυπα αναζήτησης Lua/C του τρέχοντος καταλόγου κατά τη λειτουργία editor ή αφαιρέστε τα πριν από τη φόρτωση των plugins. Ελέγξτε τον κώδικα των plugins για προαιρετικές κλήσεις `pcall(require, ...)` κατά το άνοιγμα μη έμπιστων repositories.<sup>[[3]](#references)</sup>
- Αντιμετωπίζετε τον έλεγχο του περιβάλλοντος editor, του καταλόγου εργασίας ή της ρύθμισης εκκίνησης ενός στόχου ως πιθανό primitive εκτέλεσης κώδικα στο πλαίσιο ασφαλείας του editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Τεκμηρίωση Vim — `starting.txt` (αρχικοποίηση, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Τεκμηρίωση Neovim — εκκίνηση και αρχικοποίηση](https://neovim.io/doc/user/starting/)
- [3] [Ζήτημα Neovim #38966 — εφεδρικός μηχανισμός του `require()` για τον τρέχοντα κατάλογο](https://github.com/neovim/neovim/issues/38966)
- [4] [Επιλογές Neovim — τοπικό `exrc` για project και απαίτηση εμπιστοσύνης](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Επεξεργασία στο Neovim — έμπιστα αρχεία και `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
