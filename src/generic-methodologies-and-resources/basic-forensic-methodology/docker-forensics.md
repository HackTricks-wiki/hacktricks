# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}


## Τροποποίηση container

Υπάρχουν υποψίες ότι κάποιο docker container παραβιάστηκε:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Μπορείτε εύκολα να **εντοπίσετε τις τροποποιήσεις που έγιναν σε αυτό το container σε σχέση με το image** με:
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
Στην προηγούμενη εντολή, το **C** σημαίνει **Τροποποιήθηκε** και το **A,** **Προστέθηκε**.\
Αν διαπιστώσετε ότι κάποιο ενδιαφέρον αρχείο, όπως το `/etc/shadow`, τροποποιήθηκε, μπορείτε να το κατεβάσετε από το container για να ελέγξετε για κακόβουλη δραστηριότητα με:
```bash
docker cp wordpress:/etc/shadow.
```
Μπορείτε επίσης να το **συγκρίνετε με το αρχικό** εκκινώντας ένα νέο container και εξάγοντας το αρχείο από αυτό:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Αν διαπιστώσετε ότι **προστέθηκε κάποιο ύποπτο αρχείο**, μπορείτε να αποκτήσετε πρόσβαση στο container και να το ελέγξετε:
```bash
docker exec -it wordpress bash
```
## Τροποποιήσεις images

Όταν σας δίνεται μια exported Docker image (πιθανότατα σε μορφή `.tar`), μπορείτε να χρησιμοποιήσετε το [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) για να **εξαγάγετε μια σύνοψη των τροποποιήσεων**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Στη συνέχεια, μπορείτε να **αποσυμπιέσετε** το image και να **αποκτήσετε πρόσβαση στα blobs** για να αναζητήσετε ύποπτα αρχεία που μπορεί να έχετε εντοπίσει στο ιστορικό αλλαγών:
```bash
tar -xf image.tar
```
### Βασική Ανάλυση

Μπορείτε να εξαγάγετε **βασικές πληροφορίες** από το image εκτελώντας:
```bash
docker inspect <image>
```
Μπορείτε επίσης να λάβετε μια σύνοψη του **ιστορικού αλλαγών** με:
```bash
docker history --no-trunc <image>
```
Μπορείτε επίσης να δημιουργήσετε ένα **dockerfile από ένα image** με:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Για να εντοπίσετε αρχεία που προστέθηκαν/τροποποιήθηκαν σε docker images, μπορείτε επίσης να χρησιμοποιήσετε το utility [**dive**](https://github.com/wagoodman/dive) (κατεβάστε το από τις [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Αυτό σας επιτρέπει να **περιηγείστε στα διαφορετικά blobs των docker images** και να ελέγχετε ποια αρχεία τροποποιήθηκαν/προστέθηκαν. Το **κόκκινο** σημαίνει ότι προστέθηκε και το **κίτρινο** ότι τροποποιήθηκε. Χρησιμοποιήστε το **tab** για να μεταβείτε στην άλλη προβολή και το **space** για να συμπτύξετε/ανοίξετε φακέλους.

Με το die δεν θα μπορείτε να αποκτήσετε πρόσβαση στο περιεχόμενο των διαφορετικών stages του image. Για να το κάνετε αυτό, θα χρειαστεί να **αποσυμπιέσετε κάθε layer και να αποκτήσετε πρόσβαση σε αυτό**.\
Μπορείτε να αποσυμπιέσετε όλα τα layers ενός image από τον κατάλογο όπου αποσυμπιέστηκε το image, εκτελώντας:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Διαπιστευτήρια από τη μνήμη

Σημειώστε ότι όταν εκτελείτε ένα docker container μέσα σε έναν host, **μπορείτε να δείτε τις διεργασίες που εκτελούνται στο container από τον host** εκτελώντας απλώς `ps -ef`

Επομένως, ως root, μπορείτε να **κάνετε dump τη μνήμη των διεργασιών** από τον host και να αναζητήσετε **διαπιστευτήρια**, [**όπως ακριβώς στο ακόλουθο παράδειγμα**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
