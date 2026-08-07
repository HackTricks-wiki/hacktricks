# Triage Local Network και Socket

{{#include ../../banners/hacktricks-training.md}}

Αφού αποκτήσετε ένα shell σε Linux host, οι πιο χρήσιμοι network στόχοι συχνά δεν είναι externally exposed. Υπηρεσίες Loopback-only, veth networks, Unix sockets, προσωρινοί listeners, packet captures και local firewall rules μπορούν να αποκαλύψουν credentials ή local-only attack surfaces.

Αυτή η σελίδα εστιάζει σε πρακτικές τεχνικές local post-exploitation και όχι σε γενικό remote network pentesting.

## Loopback και Local Service Enumeration

Ξεκινήστε εντοπίζοντας τις listening services, τις bind addresses τους και το process που τις κατέχει, όταν το επιτρέπουν τα permissions:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Σημαντικά μοτίβα:

- `127.0.0.1:<port>` ή `[::1]:<port>`: προσβάσιμα μόνο από το host, από προεπιλογή.
- `0.0.0.0:<port>`: προσβάσιμο σε όλες τις διεπαφές IPv4, εκτός αν φιλτράρεται.
- `172.x`, `10.x` ή `192.168.x` σε `veth*`, `docker*`, `br-*`, `cni*`: πιθανότατα δίκτυα container ή τοπικά lab.
- Unix sockets κάτω από `/run`, `/var/run`, `/tmp` ή καταλόγους εφαρμογών: επιφάνειες τοπικού IPC.

Χαρτογραφήστε τις τοπικές θύρες με ελαφριές probes:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Χρησιμοποιήστε το `nmap` τοπικά όταν είναι διαθέσιμο:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Κρυφά veth και Subnets Containers

Τα περιβάλλοντα με containers ή εργαστηριακά περιβάλλοντα συχνά εκθέτουν υπηρεσίες μόνο σε ένα bridge ή veth subnet. Κάντε enumerate τα interfaces και τα routes προτού θεωρήσετε ότι μια υπηρεσία δεν είναι προσβάσιμη:
```bash
ip -br addr
ip route
ip neigh
```
Εντοπισμός πιθανών τοπικών υποδικτύων:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Διερευνήστε προσεκτικά ένα εντοπισμένο subnet:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Η τεχνική είναι χρήσιμη όταν ένα web panel, debug endpoint ή helper service είναι κρυφό από εξωτερικά scans, αλλά είναι προσβάσιμο από το compromised host ή το container network.

## Local Pivot With socat ή SSH

Αν μια service είναι δεσμευμένη στο loopback, εκθέστε την μέσω ενός επιτρεπόμενου channel αντί να αλλάξετε την ίδια τη service.

Κάντε forward ένα local-only HTTP service με SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Γεφυρώστε μια τοπική θύρα με το `socat` όταν έχετε ήδη πρόσβαση σε shell:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Προωθήστε ένα Unix socket σε TCP για τοπικές δοκιμές:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Αυτό από μόνο του δεν εκμεταλλεύεται τίποτα. Καθιστά μια επιφάνεια που είναι προσβάσιμη μόνο τοπικά reachable από τα εργαλεία σας, ώστε να μπορείτε να αλληλεπιδράσετε μαζί της όπως με μια κανονική υπηρεσία.

## Banner Grabbing και Απλά Πρωτόκολλα

Δεν είναι κάθε υπηρεσία HTTP. Πολλές τοπικές υπηρεσίες κάνουν leak αρκετές πληροφορίες μέσω ενός banner ή ενός πρωτοκόλλου μίας γραμμής.

Βασικά probes:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Έλεγχος HTTP χωρίς browser:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Για το TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Ο στόχος είναι να προσδιοριστούν το πρωτόκολλο, το σχήμα authentication, η έκδοση και το αν η υπηρεσία εμπιστεύεται τους local clients.

## Καταγραφή Loopback Traffic

Το local traffic μπορεί να εκθέσει headers, bearer tokens, credentials του Basic Auth ή secrets ειδικά για την εφαρμογή. Πραγματοποιείτε capture μόνο σε εξουσιοδοτημένα περιβάλλοντα.

Καταγράψτε loopback HTTP traffic:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Καταγραφή μιας συγκεκριμένης τοπικής υπηρεσίας:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Αποκωδικοποίηση του Basic Auth από μια καταγεγραμμένη ή αποθηκευμένη κεφαλίδα:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Χρήσιμες συμβολοσειρές προς αναζήτηση σε καταγραφές κειμένου:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## Καταγραφή κλειδιών TLS

Αν μπορείτε να ελέγξετε το περιβάλλον μιας client process σε ένα lab, το `SSLKEYLOGFILE` μπορεί να καταστήσει τις TLS sessions αποκρυπτογραφήσιμες στο Wireshark ή σε συμβατά εργαλεία. Αυτό είναι χρήσιμο για την κατανόηση της τοπικής HTTPS κίνησης χωρίς να επιτίθεστε στο ίδιο το TLS.

Εκτελέστε έναν client με ενεργοποιημένη την καταγραφή κλειδιών:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Καταγράψτε την κίνηση ταυτόχρονα:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Στη συνέχεια, φόρτωσε τα `/tmp/tls.pcap` και `/tmp/sslkeys.log` στο Wireshark. Αυτό λειτουργεί μόνο όταν η client library υποστηρίζει NSS-style key logging και μπορείς να ορίσεις το environment πριν πραγματοποιηθεί η σύνδεση.

## Αλληλεπίδραση με Unix Socket και Command Injection

Τα Unix sockets είναι τοπικά IPC endpoints. Ενδέχεται να εκθέτουν HTTP APIs, custom protocols ή unsafe command handlers.

Εντόπισε sockets:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Αλληλεπίδραση με HTTP μέσω Unix socket:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Αλληλεπίδραση με ένα raw socket:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Αν input από socket που ελέγχεται από τον χρήστη μεταβιβαστεί σε shell ή privileged helper, μπορεί να οδηγήσει σε command injection. Για ένα στοχευμένο παράδειγμα, δείτε το [Socket Command Injection](socket-command-injection.md).

## Έλεγχος nftables και εξουσιοδοτημένες αλλαγές κανόνων

Οι κανόνες του τοπικού firewall μπορεί να εξηγούν γιατί μια υπηρεσία είναι ορατή τοπικά αλλά αποκλείεται απομακρυσμένα ή γιατί μια υψηλή θύρα φαίνεται μη προσβάσιμη από ένα interface.

Ελέγξτε τους κανόνες:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Αναζητήστε drops που επηρεάζουν μια θύρα-στόχο:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Σε ένα εξουσιοδοτημένο εργαστηριακό περιβάλλον, αφαιρέστε έναν συγκεκριμένο κανόνα αποκλεισμού βάσει handle:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Προτιμήστε τη διαγραφή του ακριβούς handle αντί για το flushing ολόκληρων των tables. Η τεχνική είναι να εντοπίσετε το ακριβές filter που προκαλεί τη συμπεριφορά και να αλλάξετε μόνο αυτόν τον κανόνα.

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
Δώστε προτεραιότητα σε υπηρεσίες που είναι local-only, εκτελούνται από χρήστη με περισσότερα προνόμια, εκθέτουν λειτουργίες διαχείρισης/debug ή εμπιστεύονται clients του loopback/container-network.

{{#include ../../banners/hacktricks-training.md}}
