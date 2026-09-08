# Ανθεκτικοί σε Capture εξουσιοδοτημένοι κόμβοι πεδίου

Ένα Raspberry Pi, mini-PC, travel router ή cellular appliance στις εγκαταστάσεις μπορεί να προσφέρει σε μια εξουσιοδοτημένη red team μια σταθερή vantage point. Είναι επίσης πιθανό σημείο εντοπισμού, κλοπής και attribution. Ο σωστός σχεδιαστικός στόχος είναι επομένως **σταθερή, ελεγχόμενη πρόσβαση με ελάχιστη authority στον κόμβο πεδίου**, όχι ένα μη ανιχνεύσιμο implant.

Αυτός ο οδηγός αφορά μόνο εξοπλισμό που τοποθετείται με γραπτή εξουσιοδότηση του ιδιοκτήτη του χώρου. Ένα coffee shop, ένας γείτονας, ένα ξενοδοχείο ή ένα shared building δεν εμπίπτει στο scope απλώς και μόνο επειδή το δίκτυό του είναι προσβάσιμο. Μην κρύβετε hardware σε χώρο χωρίς συναίνεση, μην παρακάμπτετε captive portal, μην χρησιμοποιείτε credentials άλλου προσώπου, μην παρεμβαίνετε σε monitoring και μην επιχειρείτε να διαγράψετε evidence μετά τον εντοπισμό.

{% hint style="warning" %}
Δεν υπάρχει αξιόπιστη ρύθμιση «χωρίς ίχνη». Τα records των radio association, DHCP/NAT, carrier, camera, purchase, device, provider, controller και destination μπορεί να παραμείνουν μετά την αφαίρεση της συσκευής. Μια υπεύθυνη red team αφαιρεί αντίθετα **προσωπικά και άσχετα secrets** από τον κόμβο, διατηρεί protected attribution στην πλευρά του controller και κάνει το capture εύκολο να περιοριστεί.
{% endhint %}

## Πλεονεκτήματα και μειονεκτήματα

**Πλεονεκτήματα:** ρεαλιστική internal ή target-adjacent source· σταθερό testing υψηλής ταχύτητας· επικυρώνει NAC, egress, physical inventory και SOC coverage· μπορεί να συνεχίσει παρά τις αλλαγές στη διεύθυνση του operator· η bounded access μπορεί να ανακληθεί κεντρικά.

**Μειονεκτήματα:** η φυσική τοποθέτηση δημιουργεί ισχυρό evidence· η απώλεια μπορεί να αποκαλύψει device credentials, network profiles και collected data· το επαναλαμβανόμενο control traffic είναι ανιχνεύσιμο· οι αλλαγές σε power, portals και radio μειώνουν την αξιοπιστία· ένα broad tunnel μπορεί να μετατραπεί σε uncontrolled pivot.

## Μοντέλο απειλών και invariants σχεδιασμού

Υποθέστε ότι όποιος βρει τη συσκευή μπορεί να αφαιρέσει το storage, να επιθεωρήσει το firmware, να αντιγράψει κάθε secret που διατηρείται στο software, να παρατηρήσει τη μεταγενέστερη network behavior και να παραδώσει τη συσκευή στον client ή στις αρχές επιβολής του νόμου. Το Full-disk encryption προστατεύει μια απενεργοποιημένη συσκευή μόνο σύμφωνα με το δηλωμένο threat model της· ένας ενεργός unlocked κόμβος και τα keys που έχουν απελευθερωθεί στη memory είναι διαφορετικές περιπτώσεις.

| Invariant | Πρακτική συνέπεια |
|---|---|
| No direct operator-to-node identity | Ο operator συνδέεται στο organization gateway· ο κόμβος έχει διαφορετικό device identity |
| No personal workstation material | Δεν υπάρχει personal SSH key, browser profile, email, password manager, phone pairing ή cloud CLI cache |
| No controller master secret | Ένας κόμβος δεν μπορεί να κάνει enroll άλλον, να αλλάξει policy ή να κάνει decrypt άλλα engagements |
| Outbound-only and narrow | Το field network δεν δέχεται management listener· ο κόμβος συνδέεται μόνο με named rendezvous/update/time services |
| Short-lived, scoped authority | Κάθε credential αφορά μία συσκευή, audience, service και expiry και διαθέτει άμεσο μονοπάτι revocation |
| Minimal local data | Τα results γίνονται stream προς τον controller· τα caches είναι encrypted, με περιορισμένα size/TTL και χωρίς authority |
| Controller accountability survives capture | Το asset-to-engagement mapping, τα approvals, η πρόσβαση των operators και οι εντολές αποθηκεύονται κεντρικά και ελέγχονται ως προς την πρόσβαση |
| Loss stops work | Discovery ή ανεξήγητη αλλαγή κατάστασης ενεργοποιεί stop, revoke, notify και preservation του evidence—όχι remote destruction |

Το baseline του NIST για το IoT ομαδοποιεί τα device identification, configuration, data protection, logical access, secure software update και cybersecurity-state awareness ως βασικές δυνατότητες. Συγκεκριμένα, αντιμετωπίζει το state awareness και τα off-device event records ως υποστήριξη για τη διερεύνηση compromise.<sup>[[1]](#references)</sup>

## Αρχιτεκτονική αναφοράς
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
Το gateway πρέπει να γνωρίζει ποιος named operator έφτασε σε ποια named device. Το field node χρειάζεται μόνο ένα device credential για το rendezvous. Δεν μαθαίνει ποτέ τη source address ή το authentication secret του operator, και ο operator δεν αντιγράφει ποτέ private management key σε αυτό. Έτσι μειώνεται το προσωπικό link που μπορεί να ανακτηθεί **από το field storage** χωρίς να καταστρέφεται η accountability της άσκησης.

Για μεγαλύτερο fleet, ένα workload-identity system μπορεί να εκδίδει short-lived X.509 identities και να κάνει αυτόματα rotate τα keys. Το SPIFFE συνιστά X.509 SVIDs όπου είναι δυνατό και περιγράφει τα σύντομα lifetimes και το συχνό rotation ως τρόπους περιορισμού της έκθεσης από key compromise.<sup>[[2]](#references)</sup> Μια μικρή ομάδα μπορεί να εφαρμόσει τις ίδιες ιδιότητες με private CA και αυτοματοποιημένα per-device certificates· η εγκατάσταση του SPIRE δεν απαιτείται απλώς για να ικανοποιηθεί το pattern.

## Βήμα 1: authorize και register το placement

1. Καταγράψτε τον owner, το site, την ακριβή επιτρεπόμενη ζώνη placement, τα επιτρεπόμενα networks, το assessment window, τους επιτρεπόμενους destinations/actions και τις emergency contacts.
2. Καταγράψτε το model, το serial, το storage serial, τα wired/wireless MACs, το modem IMEI/eSIM ή SIM ICCID, το power supply και μια τρέχουσα photograph.
3. Δώστε στη device ένα non-personal engagement identifier, για παράδειγμα `E2026-014-DROP03`. Μην κωδικοποιείτε το όνομα client σε broadcast hostnames ή SSIDs.
4. Ενημερώστε τον exercise controller και τη μικρότερη απαραίτητη ομάδα physical-security/SOC deconfliction για το τι σημαίνουν τα “lost,” “moved” και “discovered” σε αυτό το test.
5. Συμφωνήστε εκ των προτέρων ποιος μπορεί να την ανακτήσει και πώς μπορεί ένας finder να το αναφέρει. Μια safety label μπορεί να παραλείπει sensitive client detail, παρέχοντας παράλληλα ένα controlled callback.
6. Ορίστε automatic authorization expiry. Η συνέχιση του connectivity μετά το scope end δεν πρέπει να παρατείνει την permission.

## Βήμα 2: build ένα minimal recoverable image

Χρησιμοποιήστε supported OS image, επαληθεύστε το signature/checksum μέσω του documented channel του vendor, εγκαταστήστε security updates και διατηρήστε reproducible build manifest. Προτιμήστε read-only ή immutable base με ένα μικρό writable data partition, όπου το software το επιτρέπει.

1. Αφαιρέστε default accounts, demo services, compilers και packages που δεν απαιτούνται για το authorized workload.
2. Απενεργοποιήστε local GUI, Bluetooth, discovery protocols, file sharing, Wi-Fi P2P και inbound administration, εκτός αν η άσκηση απαιτεί ρητά κάποιο από αυτά.
3. Ενεργοποιήστε secure boot και measured boot/TPM-backed key release, εφόσον το hardware τα υποστηρίζει πραγματικά· μην ισχυρίζεστε ότι μια Raspberry Pi configuration διαθέτει PC-class measured boot χωρίς να επικυρώσετε το ακριβές model.
4. Κρυπτογραφήστε το local writable state και ρυθμίστε strict maximum size και retention time. Η encryption είναι control καθυστέρησης/περιορισμού, όχι απόδειξη ότι ένα running node δεν αποκαλύπτει τίποτα.
5. Στείλτε τα σημαντικά logs off-device. Περιορίστε τα local journals για να αποτρέψετε storage exhaustion, αλλά μην ρυθμίσετε log wiping ή anti-forensic deletion.
6. Αποθηκεύστε το image manifest, τις package versions, το configuration hash και τις recovery instructions στον controller.
7. Κάντε reimage ένα spare από το manifest και εκτελέστε το ίδιο health test. Ένα design που μπορεί να ανακτηθεί μόνο από τον builder του δεν είναι field-ready.

## Βήμα 3: issue identities με one-way trust

Δημιουργήστε τρεις διαφορετικές identities:

- ένα **device identity**, αποδεκτό μόνο από το rendezvous για τη συγκεκριμένη device·
- ένα **operator identity**, αποδεκτό από το organization gateway και προστατευμένο με phishing-resistant MFA· και
- ένα **controller/deployment identity**, που χρησιμοποιείται για sign approved jobs ή configuration και διατηρείται εκτός τόσο του operator όσο και του field node.

Το node πρέπει να διαθέτει το public key που απαιτείται για την επαλήθευση signed jobs, ποτέ όμως το signing key. Ένα captured device credential δεν πρέπει να κάνει authenticate σε cloud consoles, source repositories, payment accounts, άλλα nodes ή client production.

Χρησιμοποιήστε short certificate lifetimes όπου το automatic renewal είναι αξιόπιστο. Όταν ένα long-lived WireGuard key είναι λειτουργικά απαραίτητο, αντιμετωπίστε το public key ως revocation handle και περιορίστε το με peer-specific tunnel address, firewall policy και broker authorization. Διατηρήστε ένα tested controller action που αφαιρεί αμέσως το peer.

## Βήμα 4: stable outbound rendezvous

Το ακόλουθο owned-lab pattern παρέχει stable management μέσω NAT χωρίς να εκθέτει inbound service. Πρόκειται για ordinary WireGuard networking, όχι για covert reverse shell. Χρησιμοποιήστε documentation addresses και αντικαταστήστε τις μόνο με organization-owned endpoints.

Στο organization rendezvous, εκχωρήστε `10.77.0.1/32`· στο field node εκχωρήστε `10.77.0.20/32`. Το gateway peer entry πρέπει να αποδέχεται μόνο τη single address του node:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Ο κόμβος επικοινωνεί εξερχόμενα με το rendezvous και διατηρεί την αντιστοίχιση NAT μόνο όταν απαιτείται:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
Το WireGuard τεκμηριώνει τα 25 δευτερόλεπτα ως εύλογο διάστημα keepalive σε πολλές υλοποιήσεις NAT/firewall όταν απαιτείται persistence· η απενεργοποίησή του είναι προτιμότερη όταν δεν χρειάζεται.<sup>[[3]](#references)</sup> Το `AllowedIPs = 10.77.0.1/32` καθιστά σκόπιμα αυτή μια διαδρομή διαχείρισης και όχι pivot μέσω default-route.

Στη συνέχεια εφαρμόστε controls εκτός WireGuard:

1. Επιλύστε το `vpn.redteam.example` μέσω της εγκεκριμένης bootstrap DNS διαδρομής και καταχωρίστε το αναμενόμενο organization endpoint στα deployment records.
2. Στον node, επιτρέψτε εξερχόμενα DHCP/RA, τα απαιτούμενα DNS/NTP, το rendezvous endpoint και την ελάχιστη εγκεκριμένη διαδρομή ενημερώσεων. Απορρίψτε unsolicited εισερχόμενη κίνηση σε κάθε uplink.
3. Στο rendezvous, επιτρέψτε στο `10.77.0.20` να φτάνει μόνο στην broker/health υπηρεσία που απαιτείται για το exercise. Μην το προωθείτε γενικά σε client network.
4. Τοποθετήστε την interactive πρόσβαση operator πίσω από το organization gateway. Αποφύγετε την έκθεση SSH από τον node μέσω του tunnel, εφόσον ένα signed pull-job interface επαρκεί για το assessment.
5. Ρυθμίστε τον service manager να εκκινεί το tunnel μετά τη δικτύωση, να το επανεκκινεί μετά από failure με bounded backoff και να ειδοποιεί μετά από επαναλαμβανόμενα failures. Ένα restart loop δεν πρέπει να υπερφορτώνει τον χώρο διεξαγωγής ούτε να αποκρύπτει το υποκείμενο fault.
6. Επαληθεύστε το latest handshake του peer, αλλά μην χρησιμοποιείτε το «υπάρχει handshake» ως απόδειξη ότι η συσκευή δεν έχει παραβιαστεί.

Το TURN μπορεί να παρέχει relay-only reachability για ένα purpose-built WebRTC control plane, ενώ ένα message queue μπορεί να tolerates intermittent service. Το TURN παρέχει ρητά σε έναν client μια public relay address πίσω από NAT· ο server του παραμένει observer.<sup>[[4]](#references)</sup> Επιλέξτε μία control architecture αντί να στοιβάζετε tunnels χωρίς δηλωμένο όφελος ως προς τον observer ή την αξιοπιστία.

## Βήμα 5: σταθερότητα uplink χωρίς προσωπικά links

Για έναν εξουσιοδοτημένο venue node, προτιμήστε την εξής σειρά:

1. wired σύνδεση ή dedicated test VLAN που παρέχεται από τον client·
2. enterprise/guest Wi-Fi profile εγκεκριμένο από τον owner·
3. cellular/private APN fallback που παρέχεται με σύμβαση από τον οργανισμό.

Ποτέ μην το ρυθμίζετε με personal phone hotspot, home SSID, personal eSIM, personal Apple/Google account ή Wi-Fi profile που έχει εξαχθεί από καθημερινό laptop. Αυτά είναι ακριβώς τα artifacts στα οποία θα συνδεθεί ένα capture.

Για κάθε εγκεκριμένο uplink:

- καταγράψτε το SSID/BSSID ή το switch/VLAN και την αναμενόμενη συμπεριφορά captive portal·
- ορίστε deterministic priority και health check προς owned endpoint·
- διασφαλίστε ότι το failover αλλάζει μόνο το underlay· οι ταυτότητες της συσκευής και του operator παραμένουν στον broker·
- διασφαλίστε ότι τα DNS, IPv6 και application traffic δεν παρακάμπτουν το rendezvous κατά τη μετάβαση·
- ειδοποιείτε για άγνωστο SSID/BSSID, αλλαγή SIM, νέο default gateway, αλλαγή public-IP/ASN ή ταυτόχρονα uplinks·
- δοκιμάστε απώλεια ισχύος, ανανέωση DHCP, επανεκκίνηση AP, αλλαγή public-IP, 24ωρη αδράνεια, απώλεια tunnel και ανάκτηση primary-to-secondary-to-primary πριν από το deployment.

Το private MAC addressing μπορεί να μειώσει το περιστασιακό cross-network tracking, όμως συχνά απαιτείται σταθερό MAC ανά network για εγκεκριμένο NAC. Καταγράψτε τι κάνει πραγματικά το επιλεγμένο OS και μην κάνετε rotation γύρω από το access control ενός owner.

## Βήμα 6: περιορισμός εργασιών και δεδομένων

Ένας ασφαλής field node δεν πρέπει να δέχεται αυθαίρετο shell text από mailbox. Ορίστε signed job types όπως `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` ή άλλη action που αναφέρεται ρητά στους rules of engagement. Επικυρώστε ξανά στον node τον προορισμό, τη διάρκεια, το rate, το μέγεθος output και το scope.

1. Δώστε σε κάθε job μοναδικό ID, device audience, issue time, expiry, scope reference και maximum output.
2. Υπογράψτε το με την controller/deployment identity.
3. Απορρίψτε άγνωστα fields, expired/replayed jobs και jobs για άλλη συσκευή.
4. Κάντε stream τα results σε owned collector· κρυπτογραφήστε και εφαρμόστε TTL σε οποιοδήποτε αναπόφευκτο local spool.
5. Καταγράψτε στον controller το accepted/rejected job ID και το result hash. Μην τοποθετείτε sensitive command parameters σε public monitoring channel.
6. Διακόψτε την επεξεργασία όταν λήξει η authorization, αποτύχει το identity rotation ή ο controller θέσει τη συσκευή σε quarantine.

## Monitoring για discovery, απώλεια ή compromise

Το monitoring μπορεί να ενημερώσει τον controller ότι η observed state άλλαξε. Δεν μπορεί να αποδείξει αξιόπιστα ότι «οι investigators βρήκαν τη συσκευή» και η προσπάθεια παρακολούθησης responders ή probing των συστημάτων τους θα υπερέβαινε ένα authorized assessment.

### Συλλογή state εκτός συσκευής

Στείλτε στον controller ένα signed health record χαμηλού όγκου, σε randomized αλλά bounded operational interval. Συμπεριλάβετε μόνο όσα χρειάζεται ο controller:

- device ID, boot ID/counter και monotonic uptime·
- configuration/image hash και software version·
- device-certificate serial και renewal state·
- uplink class, interface, BSSID ή switch context όπως επιτρέπεται, default-gateway hash και public IP/ASN όπως παρατηρείται από owned service·
- tunnel handshake age, packet counters και queue depth·
- enclosure switch ή hardware-tamper state, εφόσον ο owner έχει εγκρίνει τον sensor·
- disk pressure, temperature, clock-offset estimate και last successful job ID·
- sequence number και signature για την ανίχνευση replay ή gaps.

Αποθηκεύστε κεντρικά τα gateway authentication, policy decisions, operator access, job submission, result hashes, provider audit events και alerts. Η CISA συνιστά centralizing logs, προστασία τους από deletion, baselining της normal activity και ορισμό incident-response contacts.<sup>[[5]](#references)</sup>

### Ενδείξεις discovery/compromise

| Signal | Πιθανές εξηγήσεις | Ενέργεια controller |
|---|---|---|
| Απουσία heartbeat | power/network failure, αλλαγή portal, damage, deliberate blocking ή removal | επιβεβαιώστε την κατάσταση provider/site· μην επανασυνδεθείτε από μη εγκεκριμένο path |
| Απρόσμενη αλλαγή boot counter | power cut, crash, removal ή maintenance | θέστε τα jobs σε quarantine· συγκρίνετε τον χρόνο και τα site events |
| Αλλαγή config/image hash | update error, storage fault ή tampering | σταματήστε την εργασία· κάντε revoke αν δεν πρόκειται για release εγκεκριμένο από τον controller |
| Νέο uplink/BSSID/gateway/ASN | αντικατάσταση AP, roaming, μετακίνηση συσκευής ή interception | συγκρίνετε με το εγκεκριμένο inventory· θέστε σε quarantine μια ανεξήγητη μετάβαση |
| Επαναλαμβανόμενο rejected job/signature | corruption, replay ή unauthorized controller | σταματήστε την επεξεργασία και διερευνήστε τα gateway/controller logs |
| Χρήση device credential δύο φορές ή από incompatible paths | cloned key, snapshot reuse ή network transition | κάντε revoke άμεσα· διατηρήστε και τα δύο session records |
| Απρόσμενο local login, interface, process ή privilege event | maintenance ή compromise | απομονώστε μέσω broker policy· διατηρήστε τα evidence |
| Μετάβαση enclosure switch/state | service, movement ή discovery | ειδοποιήστε το κατονομαζόμενο site contact· μην ενεργοποιήσετε destructive action |
| Provider abuse notice/account query ή SOC alert | detection, misconfiguration ή out-of-scope traffic | σταματήστε τη δραστηριότητα και ενεργοποιήστε τη διαδικασία deconfliction/incident |
| Επαφή με sentinel credential | κάποιος διάβασε ένα decoy secret χωρίς privileges, μοναδικό για αυτόν τον node | κάντε revoke την πραγματική device identity και διατηρήστε το alert trail |

Ένα sentinel credential πρέπει να παρέχει **καμία πρόσβαση**, να καλεί μόνο organization-owned alert service και να αποκαλύπτεται στους rules of engagement. Είναι tripwire για unauthorized reading και όχι beacon για tracking όποιου βρήκε τον εξοπλισμό.

### Alert thresholds

Χρησιμοποιήστε stateful rules και όχι έναν δραματικό συναγερμό «caught»:

- **warning:** ένα missed interval, normal address change ή queue growth·
- **degraded:** τρία συνεχόμενα misses, renewal delay, primary-uplink loss ή repeated restart·
- **quarantine:** unapproved hash/boot/uplink change, duplicate credential, sentinel use ή unexpected privileged event·
- **confirmed discovery/loss:** site/controller report, physical inventory mismatch, device recovery από unplanned party ή validated provider/SOC escalation.

Δοκιμάστε την παράδοση alerts μέσω channel ανεξάρτητου από τον field node. Αποφύγετε την αποστολή sensitive client/device detail σε personal messaging ή consumer push accounts.

## Runbook για suspected discovery ή capture

1. **Stop:** αναστείλετε νέα jobs και operator sessions. Μην στείλετε probe τύπου «έλεγξε αν παρακολουθείσαι».
2. **Quarantine:** ρυθμίστε τον broker να αρνείται τη device identity και τα routes της, διατηρώντας τα υπάρχοντα logs.
3. **Revoke:** κάντε revoke το device certificate/key, queue token, update credential και κάθε single-purpose service token. Αναστείλετε την organization SIM όταν είναι πιθανή η φυσική απώλεια.
4. **Preserve:** λάβετε snapshot των controller, gateway, provider και alert records· καταγράψτε τον trusted time, ποιος ενήργησε και την τελευταία γνωστή configuration. Μην κάνετε clear ή remotely wipe τον node.
5. **Notify:** επικοινωνήστε με τον exercise controller, το client incident contact και τα legal/privacy contacts που ορίζονται στην authorization. Αν τον βρήκε τρίτο μέρος, χρησιμοποιήστε τη συμφωνημένη recovery process.
6. **Assess:** θεωρήστε ότι κάθε secret και cached result στον node έχει εκτεθεί. Καταγράψτε ακριβώς σε τι θα μπορούσε να έχει πρόσβαση κάθε secret και αν χρησιμοποιήθηκε μετά το suspicious event.
7. **Contain downstream:** κάντε rotate τα επηρεαζόμενα service credentials, invalidated τα pending jobs και ελέγξτε τα owned target/provider logs για unexpected behavior.
8. **Recover safely:** ανακτήστε τον μόνο μέσω authorized person· φωτογραφίστε/συσκευάστε τον, καταγράψτε την custody και αποκτήστε forensic evidence σύμφωνα με τις οδηγίες του client.
9. **Resume with a new identity:** μην ενεργοποιήσετε ποτέ σιωπηρά ξανά το captured credential. Κάντε rebuild από το known manifest, διορθώστε το control failure και λάβετε explicit approval.

Η τρέχουσα guidance του NIST για incident response ενσωματώνει preparation, detection, response και recovery στο organization-wide cybersecurity risk management· διατηρήστε πρώτα τα στοιχεία ώστε ο client να προσδιορίσει τι συνέβη και να επιλέξει την κατάλληλη response.<sup>[[6]](#references)</sup>

## Capture drill πριν από το deployment

Παραδώστε μια unlocked test unit ή αντίγραφο του storage της σε ξεχωριστό reviewer και ζητήστε του να απαριθμήσει:

1. device/site/engagement identifiers·
2. operator names, personal accounts, home/workstation networks και recovery contacts·
3. controller/broker destinations και credentials·
4. client network profiles και cached results·
5. άλλες συσκευές/projects στα οποία είναι δυνατή η πρόσβαση με κάθε secret·
6. value ή payment credentials·
7. τι μπορεί να κάνει revoke ο controller και πόσο γρήγορα·
8. ποια activity παραμένει attributable από τα central logs.

Κριτήρια επιτυχίας: μηδέν personal accounts/workstation keys· μηδέν cross-engagement ή enrollment authority· κανένα payment credential· bounded encrypted cache· μία documented device-revocation action· πλήρης controller-side accountability. Αντιμετωπίστε οποιοδήποτε μη αναμενόμενο personal link ή lateral capability ως release blocker.

## Closeout

1. Σταματήστε τα jobs και απενεργοποιήστε το broker route στο τέλος του scope.
2. Ανακτήστε και συμφωνήστε το ακριβές inventory· αναφέρετε οτιδήποτε λείπει.
3. Διατηρήστε logs/results και, αν απαιτείται, forensic image σύμφωνα με το engagement retention plan.
4. Κάντε revoke τις device, SIM, queue, update και service identities ακόμη και όταν το hardware έχει ανακτηθεί.
5. Μόνο μετά την preservation/acceptance, κάντε sanitize ή destroy τα media με τη διαδικασία data-disposal που έχει εγκρίνει ο owner και καταγράψτε την ολοκλήρωση. Αυτό είναι lifecycle management και όχι concealment.
6. Αφαιρέστε τα venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules και temporary contacts.
7. Καταγράψτε το observed detection, τη χαμένη telemetry, τον χρόνο έως το quarantine και κάθε artifact που εκτέθηκε από το capture.

## References

- [1] [NIST — Κατάλογος δυνατοτήτων κυβερνοασφάλειας συσκευών IoT](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Έννοιες και short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Χρήση Logging σε επιχειρησιακά συστήματα](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Συστάσεις και παράμετροι Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
