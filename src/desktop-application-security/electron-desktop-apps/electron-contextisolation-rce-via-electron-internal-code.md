# Electron RCE μέσω εσωτερικού κώδικα με απενεργοποιημένο context isolation

{{#include ../../banners/hacktricks-training.md}}

Πρόκειται για **ιστορικά μοτίβα εκμετάλλευσης** εφαρμογών Electron που εκτελούσαν μη έμπιστο περιεχόμενο renderer χωρίς context isolation. Το context isolation είναι ενεργοποιημένο από προεπιλογή από το Electron 12 και εξακολουθεί να αποτελεί συνιστώμενη ρύθμιση ασφαλείας.<sup>[[1]](#references)</sup> Τα ακριβή internals διαφέρουν ανάλογα με την έκδοση του Electron και του Node.js, επομένως αναπαραγάγετε μια αλυσίδα εκμετάλλευσης με βάση τις εκδόσεις που περιλαμβάνονται στην εφαρμογή-στόχο.

## Παράδειγμα 1: αντικατάσταση του `Function.prototype.call`

Αυτό το παράδειγμα προέρχεται από την παρουσίαση του Masato Kinugawa στο CureCon.<sup>[[2]](#references)</sup>

Στην επηρεαζόμενη ιστορική έκδοση του Electron, ο εσωτερικός κώδικας ASAR καταχωρούσε έναν listener για το συμβάν `exit` της διεργασίας. Επειδή ο κώδικας της σελίδας και ο εσωτερικός κώδικας του Electron μοιράζονταν τα JavaScript prototypes όταν το context isolation ήταν απενεργοποιημένο, ο κώδικας renderer μπορούσε να αντικαταστήσει το `Function.prototype.call` πριν εκτελεστεί ο εσωτερικός listener.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Η εσωτερική διαδρομή κώδικα του Electron asar.js που χρησιμοποιείται στο παράδειγμα RCE μέσω contextIsolation](<../../images/image (1070).png>)

Ο listener εκτελέστηκε μέσω του μηχανισμού συμβάντων του Node.js. Η αρχική σελίδα παρέπεμπε σε μια παρωχημένη διαδρομή `bin/events.js`· ο ενεργός πηγαίος κώδικας του ίδιου ιστορικού commit βρίσκεται στο `lib/events.js`.<sup>[[5]](#references)</sup>

![Διαδρομή κώδικα του Node events.js που ακολουθείται στην αλυσίδα RCE μέσω contextIsolation του Electron](<../../images/image (793).png>)

Σε αυτή τη διαδρομή, το `self` είναι το αντικείμενο process του Node.js:

![RCE μέσω contextIsolation του Electron μέσω εσωτερικού κώδικα του Electron - Παράδειγμα 1: Όπου το "self" είναι το αντικείμενο process του Node](<../../images/image (700).png>)

Το ιστορικό αντικείμενο process παρείχε πρόσβαση στο `require`:

```
process.mainModule.require
```

Επειδή ο listener dispatcher κάλεσε τον handler με το αντικείμενο process, η υπερκάλυψη του `call` θα μπορούσε να ανακτήσει αυτό το αντικείμενο και να εκτελέσει μια native command:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Παράδειγμα 2: prototype pollution

Η παρουσίαση ElectroVolt παρουσιάζει μια άλλη ιστορική αλυσίδα που αποκτά ένα αντικείμενο `require` μέσω prototype pollution.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Τεκμηρίωση Electron - Απομόνωση context](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Κατάχρηση της έλλειψης απομόνωσης context - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Ιστορικός πηγαίος κώδικας Electron - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Κατάκτηση δημοφιλών desktop εφαρμογών και ανακάλυψη νέας επιφάνειας επίθεσης στο Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Ιστορικός πηγαίος κώδικας Node.js - αποστολή listener στο `lib/events.js`](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
