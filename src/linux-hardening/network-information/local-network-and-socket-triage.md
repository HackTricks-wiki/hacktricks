# Τοπική Ανάλυση Δικτύου και Socket

{{#include ../../banners/hacktricks-training.md}}

Αφού αποκτήσετε ένα shell σε έναν Linux host, οι πιο χρήσιμοι network στόχοι συχνά δεν είναι εκτεθειμένοι εξωτερικά. Υπηρεσίες μόνο σε loopback, δίκτυα veth, Unix sockets, προσωρινοί listeners, packet captures και τοπικοί κανόνες firewall μπορούν να αποκαλύψουν credentials ή attack surfaces που είναι προσβάσιμα μόνο τοπικά.

Αυτή η σελίδα επικεντρώνεται σε πρακτικές τεχνικές local post-exploitation και όχι σε γενικό remote network pentesting.

## Enumeration των Loopback και Local Services

Ξεκινήστε εντοπίζοντας τις υπηρεσίες που κάνουν listening, τις διευθύνσεις bind τους και τη διεργασία που τις έχει στην κατοχή της, όταν το επιτρέπουν τα permissions:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Σημαντικά μοτίβα:

- `127.0.0.1:<port>` ή `[::1]:<port>`: προσβάσιμα μόνο από το host από προεπιλογή.
- `0.0.0.0:<port>`: προσβάσιμο σε όλες τις IPv4 interfaces, εκτός αν φιλτράρεται.
- `172.x`, `10.x` ή `192.168.x` σε `veth*`, `docker*`, `br-*`, `cni*`: πιθανότατα container ή τοπικά lab networks.
- Unix sockets κάτω από τα `/run`, `/var/run`, `/tmp` ή directories εφαρμογών: τοπικές επιφάνειες IPC.

Χαρτογραφήστε τις τοπικές θύρες με ελαφριές probes:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Χρησιμοποιήστε το `nmap` τοπικά, όταν είναι διαθέσιμο:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Κρυφά veth και Container Subnets

Τα Containerized ή lab environments συχνά εκθέτουν services μόνο σε bridge ή veth subnet. Κάνε enumerate τα interfaces και τα routes πριν θεωρήσεις ότι ένα service δεν είναι προσβάσιμο:
```bash
ip -br addr
ip route
ip neigh
```
Βρείτε πιθανά τοπικά υποδίκτυα:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Διερευνήστε προσεκτικά ένα subnet που ανακαλύφθηκε:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Η τεχνική είναι χρήσιμη όταν ένα web panel, debug endpoint ή helper service είναι κρυφό από εξωτερικά scans, αλλά είναι προσβάσιμο από το compromised host ή το container network.

## Local Pivot With socat or SSH

Αν ένα service είναι συνδεδεμένο στο loopback, εκθέστε το μέσω ενός επιτρεπόμενου channel αντί να αλλάξετε το ίδιο το service.

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
Αυτό από μόνο του δεν εκμεταλλεύεται τίποτα. Καθιστά μια επιφάνεια διαθέσιμη μόνο τοπικά προσβάσιμη από τα εργαλεία σας, ώστε να μπορείτε να αλληλεπιδράτε μαζί της όπως με μια κανονική υπηρεσία.

## Banner Grabbing και Απλά Πρωτόκολλα

Δεν είναι κάθε υπηρεσία HTTP. Πολλές τοπικές υπηρεσίες κάνουν leak αρκετές πληροφορίες μέσω ενός banner ή ενός πρωτοκόλλου μίας γραμμής.

Βασικές probes:
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
Ο στόχος είναι να προσδιοριστούν το πρωτόκολλο, το authentication scheme, η έκδοση και το αν η υπηρεσία εμπιστεύεται local clients.

## Καταγραφή Loopback Traffic

Η local κίνηση μπορεί να αποκαλύψει headers, bearer tokens, διαπιστευτήρια Basic Auth ή application-specific secrets. Πραγματοποιείτε capture μόνο σε εξουσιοδοτημένα περιβάλλοντα.

Καταγράψτε loopback HTTP traffic:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Καταγραφή μιας συγκεκριμένης τοπικής υπηρεσίας:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Αποκωδικοποίηση Basic Auth από captured ή logged header:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Χρήσιμες συμβολοσειρές για αναζήτηση σε καταγραφές κειμένου:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Αν μπορείτε να ελέγξετε το περιβάλλον της client process σε ένα lab, το `SSLKEYLOGFILE` μπορεί να κάνει τις TLS sessions αποκρυπτογραφήσιμες στο Wireshark ή σε συμβατά εργαλεία. Αυτό είναι χρήσιμο για την κατανόηση της τοπικής HTTPS κίνησης χωρίς να επιτίθεστε στο ίδιο το TLS.

Εκτελέστε έναν client με ενεργοποιημένο το key logging:
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

## Αλληλεπίδραση με Unix Sockets και Command Injection

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
Εάν η είσοδος socket που ελέγχεται από τον χρήστη μεταβιβαστεί σε ένα shell ή σε ένα privileged helper, μπορεί να οδηγήσει σε command injection. Για ένα στοχευμένο παράδειγμα, δείτε το [Socket Command Injection](socket-command-injection.md).

## Έλεγχος nftables και εξουσιοδοτημένες αλλαγές κανόνων

Οι τοπικοί κανόνες firewall μπορεί να εξηγούν γιατί μια υπηρεσία είναι ορατή τοπικά αλλά αποκλείεται απομακρυσμένα ή γιατί μια υψηλή θύρα φαίνεται μη προσβάσιμη από ένα interface.

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
Σε ένα εξουσιοδοτημένο εργαστήριο, αφαιρέστε έναν συγκεκριμένο κανόνα αποκλεισμού βάσει του handle:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Προτιμήστε τη διαγραφή του ακριβούς handle αντί για την εκκαθάριση ολόκληρων των πινάκων. Η τεχνική consiste στον εντοπισμό του ακριβούς φίλτρου που προκαλεί τη συμπεριφορά και στην αλλαγή μόνο αυτού του κανόνα.

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
Δώσε προτεραιότητα σε υπηρεσίες που είναι μόνο τοπικές, εκτελούνται από χρήστη με περισσότερα προνόμια, εκθέτουν λειτουργίες admin/debug ή εμπιστεύονται πελάτες loopback/δικτύου container.
