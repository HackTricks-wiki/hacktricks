# Τοπική δικτύωση και έλεγχος Socket

{{#include ../../banners/hacktricks-training.md}}

Μετά την απόκτηση ενός shell σε έναν Linux host, οι πιο χρήσιμοι network targets συχνά δεν είναι εκτεθειμένοι εξωτερικά. Υπηρεσίες που είναι διαθέσιμες μόνο μέσω loopback, δίκτυα veth, Unix sockets, προσωρινοί listeners, packet captures και τοπικοί κανόνες firewall μπορούν να εκθέσουν credentials ή attack surfaces διαθέσιμα μόνο τοπικά.

Αυτή η σελίδα εστιάζει σε πρακτικές τεχνικές local post-exploitation και όχι σε γενικό remote network pentesting.

## Enumeration των Loopback και Local Services

Ξεκινήστε εντοπίζοντας τις υπηρεσίες που πραγματοποιούν listen, τις bind addresses τους και τη διεργασία που τις κατέχει, όταν το επιτρέπουν τα permissions.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Σημαντικά μοτίβα:

- `127.0.0.1:<port>` ή `[::1]:<port>`: προσβάσιμα μόνο από το host από προεπιλογή.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: προσβάσιμο σε όλες τις διεπαφές IPv4, εκτός αν φιλτράρεται.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` ή `192.168.0.0/16` σε `veth*`, `docker*`, `br-*`, `cni*`: πιθανότατα container ή τοπικά lab networks.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix sockets κάτω από `/run`, `/var/run`, `/tmp` ή καταλόγους εφαρμογών: τοπικές επιφάνειες IPC.<sup>[[5]](#references)</sup>

Αντιστοιχίστε τις τοπικές θύρες με lightweight probes.<sup>[[6]](#references)[[7]](#references)</sup>
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
## Κρυφά veth και Subnets Container

Τα περιβάλλοντα με containers ή lab συχνά εκθέτουν υπηρεσίες μόνο σε ένα bridge ή veth subnet. Κάντε enumerate τα interfaces και τα routes πριν θεωρήσετε ότι μια υπηρεσία δεν είναι προσβάσιμη.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Εντοπίστε πιθανά τοπικά υποδίκτυα.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Κάντε προσεκτικό probing στο subnet που ανακαλύφθηκε.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Η τεχνική είναι χρήσιμη όταν ένα web panel, debug endpoint ή helper service είναι κρυφό από εξωτερικά scans, αλλά είναι προσβάσιμο από το compromised host ή το container network.

## Τοπικό Pivot με socat ή SSH

Αν μια υπηρεσία είναι δεσμευμένη στο loopback, εκθέστε την μέσω ενός επιτρεπόμενου καναλιού αντί να αλλάξετε την ίδια την υπηρεσία.

Προωθήστε μια HTTP υπηρεσία που είναι διαθέσιμη μόνο τοπικά μέσω SSH.<sup>[[11]](#references)</sup>
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
Αυτό από μόνο του δεν εκμεταλλεύεται τίποτα. Καθιστά μια επιφάνεια προσβάσιμη μόνο τοπικά reachable από τα εργαλεία σας, ώστε να μπορείτε να αλληλεπιδράτε μαζί της όπως με μια κανονική υπηρεσία.

## Banner Grabbing και απλά πρωτόκολλα

Δεν είναι κάθε υπηρεσία HTTP. Πολλές τοπικές υπηρεσίες κάνουν leak αρκετές πληροφορίες μέσω ενός banner ή ενός πρωτοκόλλου μίας γραμμής.

Βασικά probes.<sup>[[13]](#references)</sup>
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
Για το TLS.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Ο στόχος είναι να αναγνωριστούν το protocol, το authentication scheme, η έκδοση και το αν η υπηρεσία εμπιστεύεται τους local clients.

## Καταγραφή Loopback Traffic

Η local traffic μπορεί να αποκαλύψει headers, bearer tokens, διαπιστευτήρια Basic Auth ή secrets ειδικά για την εφαρμογή.<sup>[[17]](#references)[[25]](#references)</sup> Κάντε capture μόνο σε εξουσιοδοτημένα περιβάλλοντα.

Κάντε capture HTTP traffic μέσω loopback.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Καταγράψτε μια συγκεκριμένη τοπική υπηρεσία.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Αποκωδικοποιήστε το Basic Auth από μια captured ή logged κεφαλίδα.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Χρήσιμες συμβολοσειρές προς αναζήτηση σε καταγραφές κειμένου:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## Καταγραφή κλειδιών TLS

Αν μπορείτε να ελέγξετε το περιβάλλον της διεργασίας client σε ένα lab, το `SSLKEYLOGFILE` μπορεί να καταστήσει τις συνεδρίες TLS αποκρυπτογραφήσιμες στο Wireshark ή σε συμβατά εργαλεία.<sup>[[19]](#references)[[20]](#references)</sup> Αυτό είναι χρήσιμο για την κατανόηση της τοπικής κίνησης HTTPS χωρίς επίθεση στο ίδιο το TLS.

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
Στη συνέχεια, φόρτωσε τα `/tmp/tls.pcap` και `/tmp/sslkeys.log` στο Wireshark. Αυτό λειτουργεί μόνο όταν η client library υποστηρίζει καταγραφή κλειδιών τύπου NSS και μπορείς να ορίσεις το environment πριν από τη δημιουργία της σύνδεσης.<sup>[[20]](#references)[[21]](#references)</sup>

## Αλληλεπίδραση με Unix Socket και Command Injection

Τα Unix sockets είναι τοπικά IPC endpoints.<sup>[[5]](#references)</sup> Ενδέχεται να εκθέτουν HTTP APIs, custom protocols ή μη ασφαλείς command handlers.<sup>[[12]](#references)[[14]](#references)</sup>

Εντόπισε τα sockets.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Αλληλεπίδραση με HTTP μέσω Unix socket.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Αλληλεπίδραση με raw socket.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Εάν input από socket που ελέγχεται από τον χρήστη μεταβιβαστεί σε shell ή σε privileged helper, μπορεί να οδηγήσει σε command injection.<sup>[[26]](#references)</sup> Για ένα στοχευμένο παράδειγμα, δείτε το [Socket Command Injection](socket-command-injection.md).

## Έλεγχος nftables και εξουσιοδοτημένες αλλαγές κανόνων

Οι τοπικοί κανόνες firewall μπορεί να εξηγούν γιατί μια υπηρεσία είναι ορατή τοπικά αλλά αποκλείεται απομακρυσμένα ή γιατί μια υψηλή θύρα φαίνεται μη προσβάσιμη από ένα interface.<sup>[[22]](#references)</sup>

Ελέγξτε τους κανόνες.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Αναζητήστε drops που επηρεάζουν μια θύρα-στόχο.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Σε ένα εξουσιοδοτημένο εργαστήριο, αφαιρέστε έναν συγκεκριμένο κανόνα αποκλεισμού με βάση το handle.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Προτιμήστε τη διαγραφή του ακριβούς handle αντί για το flushing ολόκληρων πινάκων. Η τεχνική είναι να εντοπίσετε το ακριβές filter που προκαλεί τη συμπεριφορά και να αλλάξετε μόνο αυτόν τον κανόνα.<sup>[[22]](#references)</sup>

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
Δώστε προτεραιότητα σε υπηρεσίες που είναι διαθέσιμες μόνο τοπικά, εκτελούνται από χρήστη με περισσότερα προνόμια, εκθέτουν λειτουργίες διαχείρισης/debug ή εμπιστεύονται clients loopback/δικτύου container.

## References

- [1] [ss(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Αρχιτεκτονική διευθυνσιοδότησης IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Ανακατευθύνσεις (Εγχειρίδιο αναφοράς Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [Κλήση timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Τεχνικές σάρωσης θυρών (Οδηγός αναφοράς Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Εντοπισμός κεντρικών υπολογιστών (Οδηγός αναφοράς Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Προσδιορισμός θυρών και σειρά σάρωσης (Οδηγός αναφοράς Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Σελίδα εγχειριδίου Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — Σελίδα εγχειριδίου OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Εγχειρίδιο εργαλείου γραμμής εντολών curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Τεκμηρίωση OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Το σχήμα HTTP Authentication 'Basic'](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [Κλήση base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Τεκμηρίωση OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki του Wireshark](https://wiki.wireshark.org/tls)
- [21] [Οδηγός χρήστη του Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Εγχειρίδιο nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Κατανομή διευθύνσεων για ιδιωτικά δίκτυα (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Το Framework εξουσιοδότησης OAuth 2.0: Χρήση Bearer Token (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Ακατάλληλη εξουδετέρωση ειδικών στοιχείων που χρησιμοποιούνται σε εντολή OS](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
