# Διαλογή τοπικού δικτύου και socket

{{#include ../../banners/hacktricks-training.md}}

Αφού αποκτήσετε shell σε έναν Linux host, οι πιο χρήσιμοι στόχοι δικτύου συχνά δεν είναι εκτεθειμένοι εξωτερικά. Υπηρεσίες που είναι προσβάσιμες μόνο μέσω loopback, δίκτυα veth, Unix sockets, προσωρινοί listeners, packet captures και τοπικοί κανόνες firewall μπορούν να αποκαλύψουν credentials ή επιφάνειες επίθεσης προσβάσιμες μόνο τοπικά.

Αυτή η σελίδα εστιάζει σε πρακτικές τεχνικές τοπικού post-exploitation, όχι σε γενικό remote network pentesting.

## Απαρίθμηση υπηρεσιών Loopback και τοπικών υπηρεσιών

Ξεκινήστε εντοπίζοντας τις υπηρεσίες που ακούνε, τις διευθύνσεις στις οποίες είναι δεσμευμένες και τη διεργασία στην οποία ανήκουν, όταν το επιτρέπουν τα δικαιώματα.<sup>[[1]](#references)[[2]](#references)</sup>

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
- Unix sockets στους καταλόγους `/run`, `/var/run`, `/tmp` ή σε καταλόγους εφαρμογών: τοπικές επιφάνειες IPC.<sup>[[5]](#references)</sup>

Για το ιστορικό [πρόβλημα ανάλυσης socket του snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), ελέγξτε τον daemon που εκτελείται, το τοπικό API socket του και την εγκατεστημένη έκδοση πακέτου ή snap σε σχέση με τη διόρθωση για τη συγκεκριμένη διανομή. Το σφάλμα αφορούσε την επικύρωση της διεύθυνσης socket ενός peer από το snapd, όχι το `snap-confine`. Ένα αρχείο `snap-confine` με set-user-ID ή μόνο μια συμβολοσειρά έκδοσης upstream δεν αρκούν για να επιβεβαιώσουν έκθεση. Το Ubuntu διέθεσε διορθώσεις σε εκδόσεις πακέτων ανάλογα με την έκδοση της διανομής, ενώ το snapd μπορεί να είχε ενημερωθεί από snap ανεξάρτητα από το πακέτο της διανομής. Επιβεβαιώστε το πραγματικό build που εκτελείται και την προσβασιμότητα του τοπικού socket πριν αξιολογήσετε το όριο του προνομιούχου API. Η παθητική απαρίθμηση δεν πρέπει να στείλει ειδικά διαμορφωμένο αίτημα socket ή να εγκαταστήσει snap.

Ένας listener loopback που εκκινείται μέσω του [`socat` με `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) μπορεί να προωθήσει την είσοδο τοπικού client σε ξεχωριστό πρόγραμμα. Συσχετίστε την εντολή του listener, τη διαδρομή του εκτελέσιμου, την ταυτότητα του child process που έχει εφαρμοστεί, την τοπική προσβασιμότητα και τον έλεγχο ταυτότητας πριν θεωρήσετε μια προσαρμοσμένη υπηρεσία που ανήκει στον root πιθανό στοιχείο για κλιμάκωση προνομίων. Ένα σφάλμα ασφάλειας μνήμης ή μια μη ασφαλής διαδρομή από είσοδο σε εντολή απαιτεί στοιχεία από το συγκεκριμένο binary και build· ο αριθμός θύρας, η διεργασία `socat` ή μόνο ο ιδιοκτήτης root δεν αρκούν για να το αποδείξουν. Η παθητική απαρίθμηση πρέπει να περιορίζεται στα μεταδεδομένα διεργασιών, socket και αρχείων, χωρίς αποστολή εισόδου στην υπηρεσία.

Ένας τοπικός Salt master μπορεί να ακούει στις θύρες TCP 4505 και 4506, ακόμη και σε loopback ή σε θύρα host που δημοσιεύεται από container. Οι [σημειώσεις έκδοσης 3000.2 του Salt](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) περιγράφουν ένα σφάλμα πρόσβασης σε μεθόδους χωρίς έλεγχο ταυτότητας, το CVE-2020-11651, το οποίο διορθώθηκε στις εκδόσεις upstream 2019.2.4 και 3000.2. Συσχετίστε τον listener με την πραγματική διεργασία `salt-master`, τη διεπαφή στην οποία είναι προσβάσιμος, το εγκατεστημένο πακέτο και τις διορθώσεις του προμηθευτή, καθώς και την ταυτότητα του container ή του host που έχει εφαρμοστεί, πριν το θεωρήσετε πιθανό στοιχείο για κλιμάκωση προνομίων· μια θύρα ή μόνο μια έκδοση upstream δεν αποτελεί απόδειξη. Αν ένας master εκτελείται μέσα σε container, η επίδραση στα προνόμια root του host αποτελεί ξεχωριστό όριο: επιβεβαιώστε ότι έχει προσαρτηθεί σε αυτό το container ένα αξιοποιήσιμο socket API runtime και ότι είναι προσβάσιμο. Η παθητική απαρίθμηση δεν πρέπει να υποβάλει ερωτήματα στον Salt request server ούτε να δημιουργήσει container για να εξακριβώσει την έκθεση. Δείτε την [τεκμηρίωση θυρών του Salt](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) και την [αξιολόγηση runtime API](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Χαρτογραφήστε τις τοπικές θύρες με ελαφριές probes.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Χρησιμοποιήστε το `nmap` τοπικά όταν είναι διαθέσιμο.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Κρυφά veth και υποδίκτυα containers

Τα περιβάλλοντα με containers ή εργαστηριακά περιβάλλοντα συχνά εκθέτουν υπηρεσίες μόνο σε ένα υποδίκτυο bridge ή veth. Κάντε απαρίθμηση των διεπαφών και των διαδρομών πριν υποθέσετε ότι μια υπηρεσία είναι μη προσβάσιμη.<sup>[[2]](#references)</sup>

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

Μια υπηρεσία notebook που ακούει στο loopback μπορεί να απαιτεί token εκκίνησης, το οποίο εμφανίζεται στην έξοδο της διεργασίας. Αν αυτή η έξοδος ανακατευθύνεται σε αρχείο καταγραφής αναγνώσιμο από άλλον τοπικό λογαριασμό, το token μπορεί να περάσει σε άλλο χρήστη και να επιτρέψει την εκτέλεση κώδικα με τον λογαριασμό του server του notebook. Πριν θεωρήσετε μια διαδρομή αρχείου καταγραφής πιθανό σημείο κλιμάκωσης δικαιωμάτων, συσχετίστε τον ιδιοκτήτη της διεργασίας που ακούει, τον προορισμό και τα δικαιώματα του αρχείου καταγραφής, την τρέχουσα διαμόρφωση token και τους ελέγχους πρόσβασης του notebook. Καταγράψτε τα μεταδεδομένα των αρχείων καταγραφής κατά την παθητική απαρίθμηση· μην εμφανίσετε token και μην συνδεθείτε στην υπηρεσία μόνο και μόνο για να ταξινομήσετε τον host.

## Τοπικό pivot με socat ή SSH

Αν μια υπηρεσία είναι δεσμευμένη στο loopback, εκθέστε την μέσω ενός επιτρεπόμενου καναλιού αντί να αλλάξετε την ίδια την υπηρεσία.

Προωθήστε μια τοπική υπηρεσία HTTP μόνο μέσω SSH.<sup>[[11]](#references)</sup>

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

Αυτό από μόνο του δεν εκμεταλλεύεται τίποτα. Καθιστά μια επιφάνεια διαθέσιμη μόνο τοπικά προσβάσιμη από τα εργαλεία σας, ώστε να μπορείτε να αλληλεπιδράσετε μαζί της όπως με μια συνηθισμένη υπηρεσία.

## Banner Grabbing και απλά πρωτόκολλα

Δεν χρησιμοποιούν όλες οι υπηρεσίες HTTP. Πολλές τοπικές υπηρεσίες διαρρέουν αρκετές πληροφορίες μέσω ενός banner ή ενός μονογραμμικού πρωτοκόλλου.

Βασικές διερευνητικές ενέργειες.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

Έλεγχος HTTP χωρίς πρόγραμμα περιήγησης.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

Για το TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

Ο στόχος είναι να εντοπιστούν το πρωτόκολλο, το σχήμα authentication, η έκδοση και το αν η υπηρεσία εμπιστεύεται local clients.

Για έναν aiohttp listener, εξετάστε τη διαμόρφωση των static routes καθώς και την έκδοσή του. Το CVE-2024-23334 επηρεάζει το aiohttp πριν από την έκδοση 3.9.2, όταν ένα static route έχει ενεργοποιημένο το `follow_symlinks=True`: τα requests προς αυτό το route μπορούν να διαβάσουν αρχεία εκτός του static root. Αν η υπηρεσία εκτελείται ως root, ενδέχεται να εκθέσει αρχεία που είναι αναγνώσιμα από τον root, εφόσον είναι προσβάσιμο το route. Ένα version banner ή ένα loopback bind από μόνο του δεν αποδεικνύει την ευάλωτη διαμόρφωση ή την πρόσβαση στα αρχεία.<sup>[[27]](#references)</sup>

## Καταγραφή κίνησης Loopback

Η τοπική κίνηση μπορεί να αποκαλύψει headers, bearer tokens, διαπιστευτήρια Basic Auth ή secrets ειδικά για την εφαρμογή.<sup>[[17]](#references)[[25]](#references)</sup> Η καταγραφή να γίνεται μόνο σε εξουσιοδοτημένα περιβάλλοντα.

Καταγράψτε την HTTP κίνηση loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Καταγράψτε ένα συγκεκριμένο τοπικό service.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Αποκωδικοποιήστε το Basic Auth από μια captured ή logged κεφαλίδα.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Χρήσιμες συμβολοσειρές για αναζήτηση σε καταγραφές κειμένου:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS Key Logging

Αν μπορείτε να ελέγξετε το περιβάλλον διεργασίας του client σε ένα lab, το `SSLKEYLOGFILE` μπορεί να επιτρέψει την αποκρυπτογράφηση των TLS sessions στο Wireshark ή σε συμβατά εργαλεία.<sup>[[19]](#references)[[20]](#references)</sup> Αυτό είναι χρήσιμο για την κατανόηση της τοπικής κίνησης HTTPS χωρίς να επιτεθείτε στο ίδιο το TLS.

Εκτελέστε έναν client με ενεργοποιημένο το key logging.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Καταγράψτε την κίνηση δικτύου ταυτόχρονα.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Στη συνέχεια, φορτώστε τα `/tmp/tls.pcap` και `/tmp/sslkeys.log` στο Wireshark. Αυτό λειτουργεί μόνο όταν η βιβλιοθήκη του client υποστηρίζει καταγραφή κλειδιών τύπου NSS και μπορείτε να ορίσετε το περιβάλλον πριν από τη σύνδεση.<sup>[[20]](#references)[[21]](#references)</sup>

## Αλληλεπίδραση με Unix sockets και Command Injection

Τα Unix sockets είναι τοπικά σημεία τερματισμού IPC.<sup>[[5]](#references)</sup> Ενδέχεται να εκθέτουν HTTP APIs, προσαρμοσμένα πρωτόκολλα ή μη ασφαλείς handlers εντολών.<sup>[[12]](#references)[[14]](#references)</sup>

Ένα socket που ανήκει στον root και έχει δικαίωμα εγγραφής για την ομάδα αποτελεί όριο εξουσιοδότησης, όχι από μόνο του ευπάθεια. Συγκρίνετε την ομάδα και τα δικαιώματά του με τον τρέχοντα λογαριασμό, εντοπίστε τη διεργασία που ακούει και εξετάστε τι δέχεται η διεργασία από τους clients προτού αξιολογήσετε τον κίνδυνο. Ειδικότερα, μια προνομιούχα υπηρεσία που εκτελεί υποβληθέν PHP μπορεί να υπερβεί ένα δεύτερο όριο, αν εμπιστεύεται επίσης μια διαδρομή `php.ini` που επιλέγει ο καλών ή του επιτρέπει να αλλάξει τα `disable_functions` ή `open_basedir`. Εξετάστε την ενεργή διαμόρφωση και τη διαδρομή επικύρωσης της υπηρεσίας. Ο [οδηγός διαμόρφωσης PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) εξηγεί αυτές τις οδηγίες. Τα μεταδεδομένα του socket από μόνα τους δεν αποδεικνύουν εκτέλεση κώδικα.

Εντοπίστε sockets.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Αλληλεπιδράστε με HTTP μέσω ενός Unix socket.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Αλληλεπιδράστε με ένα raw socket.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Αν είσοδος socket που ελέγχεται από τον χρήστη περάσει σε shell ή προνομιούχο helper, μπορεί να οδηγήσει σε command injection.<sup>[[26]](#references)</sup> Για ένα συγκεκριμένο παράδειγμα, δείτε το [Socket Command Injection](socket-command-injection.md).

## Έλεγχος nftables και εξουσιοδοτημένες αλλαγές κανόνων

Οι τοπικοί κανόνες του firewall μπορεί να εξηγούν γιατί μια υπηρεσία είναι ορατή τοπικά αλλά αποκλείεται από απομακρυσμένη πρόσβαση ή γιατί μια υψηλή θύρα φαίνεται απρόσιτη από μία διεπαφή δικτύου.<sup>[[22]](#references)</sup>

Ελέγξτε τους κανόνες.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Αναζητήστε κανόνες απόρριψης που επηρεάζουν μια θύρα-στόχο.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

Σε εξουσιοδοτημένο εργαστήριο, αφαιρέστε έναν συγκεκριμένο κανόνα φραγής με βάση το handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Προτιμήστε να διαγράψετε το συγκεκριμένο handle αντί να αδειάσετε ολόκληρους πίνακες. Η τεχνική είναι να εντοπίσετε το ακριβές φίλτρο που προκαλεί τη συμπεριφορά και να αλλάξετε μόνο αυτόν τον κανόνα.<sup>[[22]](#references)</sup>

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

Δώστε προτεραιότητα σε υπηρεσίες που είναι προσβάσιμες μόνο τοπικά, εκτελούνται με αυξημένα προνόμια, παρέχουν λειτουργίες διαχείρισης/debug ή εμπιστεύονται clients από το loopback/δίκτυο container.

## References

- [1] [ss(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Αρχιτεκτονική διευθυνσιοδότησης IP έκδοσης 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Ανακατευθύνσεις (Εγχειρίδιο αναφοράς Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [Εντολή timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Τεχνικές σάρωσης θυρών (Οδηγός αναφοράς Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Εντοπισμός host (Οδηγός αναφοράς Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Καθορισμός θυρών και σειρά σάρωσης (Οδηγός αναφοράς Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — σελίδα εγχειριδίου Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — σελίδα εγχειριδίου OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Εγχειρίδιο εργαλείου γραμμής εντολών curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Τεκμηρίωση OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Το σχήμα ελέγχου ταυτότητας HTTP «Basic»](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [Εντολή base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Τεκμηρίωση OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki του Wireshark](https://wiki.wireshark.org/tls)
- [21] [Οδηγός χρήσης Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Εγχειρίδιο nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Κατανομή διευθύνσεων για ιδιωτικά δίκτυα (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Το πλαίσιο εξουσιοδότησης OAuth 2.0: Χρήση Bearer Token (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Ακατάλληλη εξουδετέρωση ειδικών στοιχείων που χρησιμοποιούνται σε εντολή λειτουργικού συστήματος](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Συμβουλευτική ανακοίνωση συντηρητών aiohttp: παράκαμψη διαδρομής στατικού περιεχομένου με follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
{{#include ../../banners/hacktricks-training.md}}
