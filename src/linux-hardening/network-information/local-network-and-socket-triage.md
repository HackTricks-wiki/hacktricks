# Αρχική διαλογή τοπικού δικτύου και socket

{{#include ../../banners/hacktricks-training.md}}

Αφού αποκτήσετε shell σε έναν Linux host, οι πιο χρήσιμοι στόχοι δικτύου συχνά δεν είναι εκτεθειμένοι εξωτερικά. Υπηρεσίες μόνο για loopback, δίκτυα veth, Unix sockets, προσωρινοί listeners, packet captures και τοπικοί κανόνες firewall μπορούν να αποκαλύψουν credentials ή επιφάνειες επίθεσης προσβάσιμες μόνο τοπικά.

Αυτή η σελίδα εστιάζει σε πρακτικές τεχνικές τοπικού post-exploitation και όχι σε γενικό remote network pentesting.

## Καταγραφή υπηρεσιών loopback και τοπικών υπηρεσιών

Ξεκινήστε εντοπίζοντας τις υπηρεσίες που ακούν, τις διευθύνσεις στις οποίες είναι δεσμευμένες και τη διεργασία στην οποία ανήκουν, εφόσον το επιτρέπουν τα δικαιώματα.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Σημαντικά μοτίβα:

- `127.0.0.1:<port>` ή `[::1]:<port>`: προσβάσιμο μόνο από τον host εξ ορισμού.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: προσβάσιμο σε όλες τις διεπαφές IPv4, εκτός αν φιλτράρεται.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` ή `192.168.0.0/16` σε `veth*`, `docker*`, `br-*`, `cni*`: πιθανότατα δίκτυα container ή τοπικού lab.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix sockets στους καταλόγους `/run`, `/var/run`, `/tmp` ή καταλόγους εφαρμογών: επιφάνειες τοπικής IPC.<sup>[[5]](#references)</sup>

Για το ιστορικό [πρόβλημα ανάλυσης socket του snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), εξετάστε τον εκτελούμενο daemon, το τοπικό API socket του και την εγκατεστημένη έκδοση του πακέτου ή του snap σε σχέση με τη διόρθωση για τη συγκεκριμένη διανομή. Το σφάλμα βρισκόταν στην επικύρωση από το snapd της διεύθυνσης socket ενός peer και όχι στο `snap-confine`· ένα αρχείο `snap-confine` με set-user-ID ή μόνο μια συμβολοσειρά έκδοσης upstream δεν αρκούν για να αποδειχθεί έκθεση. Το Ubuntu διέθεσε διορθώσεις σε εκδόσεις πακέτων ανάλογα με την έκδοση της διανομής, ενώ το snapd ενδέχεται να είχε ενημερωθεί από snap ανεξάρτητα από το πακέτο της διανομής. Επιβεβαιώστε την πραγματική έκδοση που εκτελείται και την προσβασιμότητα του τοπικού socket προτού αξιολογήσετε το όριο του προνομιούχου API. Η παθητική απαρίθμηση δεν πρέπει να στείλει ειδικά διαμορφωμένο αίτημα socket ή να εγκαταστήσει snap.

Ένας listener loopback που εκκινείται μέσω του [`socat` με `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) μπορεί να προωθήσει την είσοδο τοπικού client σε ξεχωριστό πρόγραμμα. Συσχετίστε την εντολή του listener, τη διαδρομή του εκτελέσιμου, την ταυτότητα του child με τα ενεργά δικαιώματα, την τοπική προσβασιμότητα και τον έλεγχο ταυτότητας προτού θεωρήσετε μια προσαρμοσμένη υπηρεσία που ανήκει στον root πιθανή ένδειξη κλιμάκωσης προνομίων. Ένα σφάλμα ασφάλειας μνήμης ή μια μη ασφαλής διαδρομή από την είσοδο προς την εντολή απαιτεί στοιχεία από το συγκεκριμένο binary και build· ο αριθμός θύρας, η διεργασία `socat` ή η ιδιοκτησία root από μόνα τους δεν το αποδεικνύουν. Η παθητική απαρίθμηση πρέπει να περιορίζεται στα μεταδεδομένα διεργασιών, socket και αρχείων και να μην αποστέλλει είσοδο στην υπηρεσία.

Ένας τοπικός master του Salt μπορεί να ακούει στις θύρες TCP 4505 και 4506, μεταξύ άλλων σε loopback ή σε θύρα host που έχει δημοσιευτεί από container. Οι [σημειώσεις έκδοσης 3000.2 του Salt](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) περιγράφουν ένα σφάλμα πρόσβασης σε μεθόδους χωρίς έλεγχο ταυτότητας, CVE-2020-11651, το οποίο διορθώθηκε στις upstream εκδόσεις 2019.2.4 και 3000.2. Συσχετίστε τον listener με την πραγματική διεργασία `salt-master`, τη διεπαφή από την οποία είναι προσβάσιμος, το εγκατεστημένο πακέτο και τις διορθώσεις του προμηθευτή, καθώς και την ταυτότητα του container ή του host με την οποία εκτελείται, προτού τον θεωρήσετε πιθανή ένδειξη κλιμάκωσης· μια θύρα ή μια upstream έκδοση από μόνη της δεν αποτελεί απόδειξη. Αν ένας master εκτελείται μέσα σε container, η επίδραση στα δικαιώματα root του host είναι ξεχωριστό όριο: επιβεβαιώστε ότι ένα λειτουργικό socket API του runtime είναι προσαρτημένο και προσβάσιμο από αυτό το container. Η παθητική απαρίθμηση δεν πρέπει να υποβάλει ερώτημα στον request server του Salt ή να δημιουργήσει container για να διαπιστώσει αν υπάρχει έκθεση. Δείτε την [τεκμηρίωση θυρών του Salt](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) και τη [διαλογή API runtime](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Χαρτογραφήστε τις τοπικές θύρες με ελαφριές probes.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Χρησιμοποιήστε το `nmap` τοπικά, εφόσον είναι διαθέσιμο.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Κρυφά veth και subnet των Container

Τα περιβάλλοντα με Container ή lab συχνά εκθέτουν υπηρεσίες μόνο σε ένα bridge ή veth subnet. Κάντε απαρίθμηση των interfaces και των routes προτού θεωρήσετε ότι μια υπηρεσία δεν είναι προσβάσιμη.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Εντοπίστε πιθανά τοπικά υποδίκτυα.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Διερεύνησε προσεκτικά ένα subnet που εντοπίστηκε.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

Η τεχνική είναι χρήσιμη όταν ένα web panel, ένα debug endpoint ή μια βοηθητική υπηρεσία είναι κρυφή από εξωτερικές σαρώσεις, αλλά είναι προσβάσιμη από το παραβιασμένο host ή το δίκτυο του container.

## Tokens υπηρεσιών Notebook μεταξύ διαφορετικών χρηστών

Μια υπηρεσία notebook που ακούει στο loopback μπορεί να απαιτεί token που εκτυπώνεται στην έξοδο της διεργασίας κατά την εκκίνηση. Αν αυτή η έξοδος ανακατευθύνεται σε log αναγνώσιμο από άλλον τοπικό λογαριασμό, το token μπορεί να περάσει σε άλλον χρήστη και να επιτρέψει την εκτέλεση κώδικα με τον λογαριασμό της υπηρεσίας notebook. Πριν θεωρήσετε ένα path log πιθανό μέσο κλιμάκωσης προνομίων, συσχετίστε τον κάτοχο της διεργασίας που ακούει, τον προορισμό και τα δικαιώματα του log, την τρέχουσα ρύθμιση του token και τους ελέγχους πρόσβασης στο notebook. Κατά την παθητική απαρίθμηση, καταγράψτε τα μεταδεδομένα των log· μην εμφανίζετε tokens και μην συνδέεστε στην υπηρεσία μόνο και μόνο για να ταξινομήσετε τον host.

Μια υπηρεσία Jupyter Lab μπορεί επίσης να εκθέτει το token της σε ένα αναγνώσιμο `ExecStart` του systemd ή στη γραμμή εντολών της εκτελούμενης διεργασίας (`ps auxww`), αντί να το εμφανίζει μόνο στα log εκκίνησης. Στο αναφερόμενο παράδειγμα, τα `User=analyst` και `--ServerApp.token` αποκάλυπταν τόσο το διαπιστευτήριο όσο και τον λογαριασμό πίσω από έναν listener στη διεύθυνση `127.0.0.1:8888`. Με πρόσβαση στον host, το token και το `ssh -L 8888:127.0.0.1:8888 user@host` επέτρεψαν πρόσβαση στο Terminal του Jupyter Lab ως ο χρήστης της υπηρεσίας. Ελέγξτε μαζί τον πραγματικό χρήστη της unit, τα ορίσματα της διεργασίας, τον listener και την ισχύ του token· η σύνδεση στο loopback από μόνη της δεν αποτελεί όριο εξουσιοδότησης.<sup>[[28]](#references)</sup>

## Τοπικό Pivot με socat ή SSH

Αν μια υπηρεσία είναι συνδεδεμένη στο loopback, εκθέστε την μέσω ενός επιτρεπόμενου καναλιού αντί να αλλάξετε την ίδια την υπηρεσία.

Προωθήστε μια υπηρεσία HTTP που είναι διαθέσιμη μόνο τοπικά μέσω SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Γεφυρώστε μια τοπική θύρα με το `socat` όταν έχετε ήδη πρόσβαση σε shell.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Προωθήστε ένα Unix socket σε TCP για τοπικές δοκιμές.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Αυτό από μόνο του δεν εκμεταλλεύεται τίποτα. Καθιστά μια επιφάνεια προσβάσιμη μόνο τοπικά προσβάσιμη από τα εργαλεία σου, ώστε να μπορείς να αλληλεπιδράς μαζί της όπως με μια συνηθισμένη υπηρεσία.

## Banner Grabbing και απλά πρωτόκολλα

Δεν είναι κάθε υπηρεσία HTTP. Πολλές τοπικές υπηρεσίες διαρρέουν αρκετές πληροφορίες μέσω ενός banner ή ενός μονογραμμικού πρωτοκόλλου.

Βασικές δοκιμές.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

Έλεγχος HTTP χωρίς browser.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

Για TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

Ο στόχος είναι να προσδιοριστούν το πρωτόκολλο, το σχήμα authentication, η έκδοση και το αν η υπηρεσία εμπιστεύεται τους local clients.

Για έναν aiohttp listener, ελέγξτε τη διαμόρφωση των static routes καθώς και την έκδοσή του. Το CVE-2024-23334 επηρεάζει εκδόσεις του aiohttp πριν από την 3.9.2, όταν ένα static route έχει ενεργοποιημένο το `follow_symlinks=True`: αιτήματα προς αυτό το route μπορούν να διαβάσουν αρχεία εκτός του static root. Αν η υπηρεσία εκτελείται ως root, ενδέχεται να εκθέσει αρχεία στα οποία έχει πρόσβαση ο root, εφόσον το route είναι προσβάσιμο. Ένα version banner ή ένα loopback bind από μόνο του δεν αποδεικνύει ότι υπάρχει η ευάλωτη διαμόρφωση ή ότι είναι δυνατή η πρόσβαση σε αρχεία.<sup>[[27]](#references)</sup>

## Καταγραφή Loopback Traffic

Η τοπική κίνηση μπορεί να αποκαλύψει headers, bearer tokens, διαπιστευτήρια Basic Auth ή μυστικά ειδικά για την εφαρμογή.<sup>[[17]](#references)[[25]](#references)</sup> Κάντε καταγραφή μόνο σε εξουσιοδοτημένα περιβάλλοντα.

Καταγράψτε HTTP traffic του loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Αποτυπώστε μια συγκεκριμένη τοπική υπηρεσία.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Αποκωδικοποιήστε το Basic Auth από μια κεφαλίδα που έχει καταγραφεί ή αποθηκευτεί σε log.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Χρήσιμες συμβολοσειρές για αναζήτηση σε καταγραφές κειμένου:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Καταγραφή κλειδιών TLS

Αν μπορείτε να ελέγχετε το περιβάλλον διεργασίας του client σε ένα lab, το `SSLKEYLOGFILE` μπορεί να επιτρέψει την αποκρυπτογράφηση των TLS sessions στο Wireshark ή σε συμβατά εργαλεία.<sup>[[19]](#references)[[20]](#references)</sup> Αυτό είναι χρήσιμο για την κατανόηση της τοπικής κίνησης HTTPS χωρίς να επιτεθείτε στο ίδιο το TLS.

Εκτελέστε έναν client με ενεργοποιημένη την καταγραφή κλειδιών.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Καταγράψτε την κίνηση ταυτόχρονα.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Στη συνέχεια, φορτώστε τα `/tmp/tls.pcap` και `/tmp/sslkeys.log` στο Wireshark. Αυτό λειτουργεί μόνο όταν η client library υποστηρίζει καταγραφή κλειδιών τύπου NSS και μπορείτε να ορίσετε το περιβάλλον πριν από τη σύνδεση.<sup>[[20]](#references)[[21]](#references)</sup>

## Αλληλεπίδραση με Unix Socket και Command Injection

Τα Unix sockets είναι τοπικά endpoints IPC.<sup>[[5]](#references)</sup> Μπορεί να εκθέτουν HTTP APIs, προσαρμοσμένα πρωτόκολλα ή μη ασφαλείς handlers εντολών.<sup>[[12]](#references)[[14]](#references)</sup>

Ένα socket που ανήκει στον root και έχει δικαίωμα εγγραφής για την ομάδα αποτελεί όριο εξουσιοδότησης, όχι από μόνο του ευπάθεια. Συγκρίνετε την ομάδα και τα δικαιώματά του με τον τρέχοντα λογαριασμό, εντοπίστε τη διεργασία που ακούει και ελέγξτε τι δέχεται από τους clients πριν αξιολογήσετε τον κίνδυνο. Ειδικότερα, μια προνομιούχα υπηρεσία που εκτελεί υποβληθέν PHP μπορεί να διασχίσει ένα δεύτερο όριο, αν εμπιστεύεται επίσης μια διαδρομή `php.ini` που επιλέγει ο καλών ή επιτρέπει στον καλούντα να αλλάξει τα `disable_functions` ή `open_basedir`· ελέγξτε την ενεργή διαμόρφωση και τη διαδικασία επικύρωσης της υπηρεσίας. Ο [οδηγός διαμόρφωσης της PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) εξηγεί αυτές τις οδηγίες. Τα μεταδεδομένα του socket από μόνα τους δεν αποδεικνύουν εκτέλεση κώδικα.

Εντοπίστε sockets.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Αλληλεπιδράστε με HTTP μέσω Unix socket.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Αλληλεπιδράστε με ένα raw socket.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Αν η είσοδος socket που ελέγχεται από τον χρήστη περάσει σε shell ή σε βοηθητικό πρόγραμμα με αυξημένα δικαιώματα, μπορεί να οδηγήσει σε command injection.<sup>[[26]](#references)</sup> Για ένα στοχευμένο παράδειγμα, δείτε το [Socket Command Injection](socket-command-injection.md).

## Έλεγχος nftables και εξουσιοδοτημένες αλλαγές κανόνων

Οι τοπικοί κανόνες firewall μπορεί να εξηγούν γιατί μια υπηρεσία είναι ορατή τοπικά αλλά αποκλείεται από απομακρυσμένη πρόσβαση ή γιατί μια υψηλή θύρα φαίνεται μη προσβάσιμη από μία διεπαφή δικτύου.<sup>[[22]](#references)</sup>

Ελέγξτε τους κανόνες.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Αναζητήστε απορρίψεις που επηρεάζουν μια θύρα-στόχο.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

Σε εξουσιοδοτημένο εργαστήριο, αφαιρέστε έναν συγκεκριμένο κανόνα αποκλεισμού με βάση το handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Προτιμήστε να διαγράψετε το συγκεκριμένο handle αντί να κάνετε flush ολόκληρους πίνακες. Η τεχνική είναι να εντοπίσετε το ακριβές filter που προκαλεί τη συμπεριφορά και να αλλάξετε μόνο αυτόν τον κανόνα.<sup>[[22]](#references)</sup>

## Γρήγορη ροή εργασίας

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Δώστε προτεραιότητα σε υπηρεσίες που είναι διαθέσιμες μόνο τοπικά, εκτελούνται με χρήστη υψηλότερων δικαιωμάτων, εκθέτουν λειτουργίες διαχείρισης/debug ή εμπιστεύονται πελάτες loopback/δικτύου container.

## References

- [1] [ss(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Αρχιτεκτονική διευθυνσιοδότησης IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Ανακατευθύνσεις (Εγχειρίδιο αναφοράς Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [Εκτέλεση της εντολής timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Τεχνικές σάρωσης θυρών (Οδηγός αναφοράς Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Εντοπισμός κεντρικών υπολογιστών (Οδηγός αναφοράς Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Προδιαγραφή θυρών και σειρά σάρωσης (Οδηγός αναφοράς Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Σελίδα εγχειριδίου Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — Σελίδα εγχειριδίου OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Εγχειρίδιο εργαλείου γραμμής εντολών curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Τεκμηρίωση OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Το σχήμα ελέγχου ταυτότητας HTTP «Basic»](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [Εκτέλεση της εντολής base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Τεκμηρίωση OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki Wireshark](https://wiki.wireshark.org/tls)
- [21] [Οδηγός χρήσης Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Εγχειρίδιο nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Εκχώρηση διευθύνσεων για ιδιωτικά δίκτυα (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Το πλαίσιο εξουσιοδότησης OAuth 2.0: Χρήση Bearer Token (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Ακατάλληλη εξουδετέρωση ειδικών στοιχείων που χρησιμοποιούνται σε εντολή λειτουργικού συστήματος](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Συμβουλή maintainer του aiohttp: διέλευση διαδρομής στατικό route με follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — Έκθεση token Jupyter μέσω systemd και ορισμάτων διεργασίας](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
