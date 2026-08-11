# Forensics Docker

{{#include ../../banners/hacktricks-training.md}}

## Τροποποίηση container

Υπάρχουν υποψίες ότι κάποιο container του Docker παραβιάστηκε:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Μπορείτε εύκολα να **εντοπίσετε τις αλλαγές που έγιναν στο filesystem αυτού του container από τη δημιουργία του** με:<sup>[[1]](#references)</sup>
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
Στην προηγούμενη εντολή, το **C** σημαίνει **Changed** και το **A** σημαίνει **Added**.<sup>[[1]](#references)</sup>\
Αν διαπιστώσετε ότι τροποποιήθηκε κάποιο ενδιαφέρον αρχείο, όπως το `/etc/shadow`, μπορείτε να το κατεβάσετε από το container για να ελέγξετε για κακόβουλη δραστηριότητα με:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
Μπορείτε επίσης να το **συγκρίνετε με το αρχικό** εκτελώντας ένα νέο container και εξάγοντας το αρχείο από αυτό:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Εάν διαπιστώσετε ότι **προστέθηκε κάποιο ύποπτο αρχείο**, μπορείτε να αποκτήσετε πρόσβαση στο container και να το ελέγξετε:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Τροποποιήσεις images

Όταν σας δοθεί ένα exported docker image (πιθανότατα σε μορφή `.tar`), μπορείτε να χρησιμοποιήσετε το [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) για να **εξαγάγετε μια σύνοψη των τροποποιήσεων**:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Στη συνέχεια, μπορείτε να **αποσυμπιέσετε** το image και να **αποκτήσετε πρόσβαση στα blobs** για να αναζητήσετε ύποπτα αρχεία που ενδέχεται να έχετε εντοπίσει στο ιστορικό αλλαγών:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Βασική Ανάλυση

Μπορείτε να λάβετε **βασικές πληροφορίες** από το image εκτελώντας:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
Μπορείτε επίσης να λάβετε ένα συνοπτικό **ιστορικό αλλαγών** με:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
Μπορείτε επίσης να δημιουργήσετε ένα **dockerfile από ένα image** με:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Για να βρείτε αρχεία που προστέθηκαν/τροποποιήθηκαν σε Docker images, μπορείτε επίσης να χρησιμοποιήσετε το utility [**dive**](https://github.com/wagoodman/dive) (κατεβάστε το από τα [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):<sup>[[11]](#references)[[12]](#references)</sup>

Φορτώστε το αποθηκευμένο archive στο Docker πριν ανοίξετε το image tag του με το dive:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Αυτό σας επιτρέπει να **περιηγείστε στα διαφορετικά blobs των docker images** και να ελέγχετε ποια αρχεία τροποποιήθηκαν/προστέθηκαν/αφαιρέθηκαν. Χρησιμοποιήστε το **tab** για να μεταβείτε στην άλλη προβολή και το **space** για να συμπτύξετε/αναπτύξετε φακέλους.<sup>[[11]](#references)</sup>

Με το dive δεν θα μπορείτε να αποκτήσετε πρόσβαση στο περιεχόμενο των διαφορετικών σταδίων του image. Για να το κάνετε αυτό, θα πρέπει να **αποσυμπιέσετε κάθε layer και να αποκτήσετε πρόσβαση σε αυτό**.\
Μπορείτε να αποσυμπιέσετε όλα τα layers από ένα image, από τον κατάλογο όπου αποσυμπιέστηκε το image, εκτελώντας:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credentials from memory

Στο Linux, το ancestor PID namespace του host μπορεί να βλέπει processes στο child PID namespace ενός container, επομένως μια λίστα processes του host, όπως η `ps -ef`, μπορεί να τα εμφανίζει.<sup>[[14]](#references)</sup>

Όταν τα credentials του host, τα capabilities και η πολιτική LSM/ptrace το επιτρέπουν, ένας κατάλληλα προνομιούχος investigator του host μπορεί να **κάνει dump τη μνήμη των processes** και να αναζητήσει **credentials**, [**όπως ακριβώς στο ακόλουθο παράδειγμα**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container exec](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [Ορισμοί analyzer του container-diff](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image history](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [README του Dive v0.10.0](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Release του Dive v0.10.0](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
