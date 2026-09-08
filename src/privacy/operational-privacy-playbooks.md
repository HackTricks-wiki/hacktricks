# Playbooks Επιχειρησιακής Ιδιωτικότητας

{{#include ../banners/hacktricks-training.md}}

Αυτά τα playbooks συνδυάζουν τα controls από το υπόλοιπο αυτής της ενότητας. Αποτελούν σημεία εκκίνησης και όχι εγγυήσεις: ενημερώνετε το threat model κάθε φορά που ένας νέος observer, account, device, location, payment, file ή counterparty εισέρχεται στη ροή εργασίας.

## Καθολικός preflight

1. Καταγράψτε τον νόμιμο στόχο και τι πρέπει να παραμείνει ιδιωτικό **από ποιον**.
2. Καταγράψτε τις identities, τα devices, τα networks, τα accounts, τα payment rails, τα counterparties, τις physical locations και τα data στα οποία θα έχει πρόσβαση η δραστηριότητα.
3. Εντοπίστε τον ισχυρότερο πιθανό observer και τη συνέπεια μιας αποτυχίας.
4. Επιβεβαιώστε την authorization, την applicable law, τους provider terms και την organizational policy.
5. Αποφασίστε τι πρέπει να παραμείνει internally attributable για λόγους safety, incident response, accounting και audit.
6. Επιλέξτε το μικρότερο λειτουργικό compartment· καθορίστε τα recovery και shutdown paths του πριν από τη χρήση.
7. Δοκιμάστε το compartment απέναντι σε μια controlled service, συμπεριλαμβανομένων των IP/DNS/IPv6, browser identity, document metadata, payment statement και notification leakage.

Χρησιμοποιήστε το λεπτομερές model στο [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Καθημερινό privacy baseline

Στόχος: μείωση του commercial tracking, του account takeover και της περιττής έκθεσης, χωρίς προσπάθεια επίτευξης anonymity.

- Χρησιμοποιείτε maintained OS με full-disk encryption, automatic updates, screen lock και secure boot όπου είναι διαθέσιμο.
- Τακτοποιήστε πρώτα το password manager, το recovery email και το phishing-resistant MFA/security keys.
- Ελέγχετε τα app permissions, το location history, τα advertising identifiers, το cloud sync και τις third-party account connections.
- Χρησιμοποιείτε mainstream browser με λίγα extensions, tracking protection και HTTPS, καθώς και ξεχωριστά profiles για work/personal/high-risk browsing.
- Χρησιμοποιείτε private relay aliases ή distinct email addresses ανά σχέση· μην χρησιμοποιείτε personal phone number όταν είναι απλώς optional.
- Προτιμάτε end-to-end encrypted messaging για το περιεχόμενο, θυμόμενοι ότι οι participants, το timing, τα groups και τα endpoints παραμένουν metadata.
- Αφαιρείτε σκόπιμα τα metadata από τα files και ελέγχετε το exported copy —όχι το original— πριν από τη δημοσίευση.
- Χρησιμοποιείτε virtual-card ή wallet tokens για payment-credential compartmentalization· μην τα αποκαλείτε anonymous.
- Δημιουργείτε backup του encrypted recovery material και δοκιμάζετε την αποκατάσταση.

## Pseudonymous publication

Στόχος: να αποτρέπεται η εύκολη σύνδεση μιας publication με μια civil identity από casual readers και platforms. Αυτό δεν αντιμετωπίζει μια capable targeted investigation.

1. Καθορίστε αν το platform, ο hosting provider, οι readers, οι contacts, το local network, ο payment provider ή η legal process περιλαμβάνονται στο threat model.
2. Δημιουργήστε dedicated endpoint/account context από clean baseline. Απενεργοποιήστε το personal browser sync, τα cloud documents, το contact upload και τα notification previews.
3. Δημιουργήστε το pseudonymous account μέσω του επιλεγμένου network compartment. Μην επαναχρησιμοποιείτε usernames, avatars, recovery channels, writing boilerplate ή personal identity-provider login.
4. Χρησιμοποιείτε Tor Browser όταν η destination unlinkability είναι σημαντικότερη από την ταχύτητα· μην προσθέτετε extensions, μην αλλάζετε υπερβολικά το μέγεθος/τη διαμόρφωσή του και μην ανοίγετε downloaded documents ενώ είστε online σε ordinary desktop session.
5. Συντάσσετε με process που δεν ενσωματώνει personal template names, revision authors, printer paths, GPS/EXIF, thumbnails ή hidden layers. Κάντε export ένα copy και ελέγξτε το με κατάλληλα metadata tools.
6. Ελέγχετε το content για self-identifying facts: unique dates, workplace details, local weather/time zone, reflections, background audio, linguistic habits και text reuse από prior publications.
7. Χρησιμοποιείτε separate reply channel. Αντιμετωπίζετε κάθε direct contact, attachment και link ως πιθανή προσπάθεια correlation ή phishing.
8. Αν εμπλέκονται χρήματα, χρησιμοποιήστε τη lawful method που εκθέτει μόνο τα απαραίτητα data. Θεωρείτε ότι το platform και ο regulated intermediary ενδέχεται να γνωρίζουν τον payee, ακόμη και αν δεν τον γνωρίζουν οι readers.
9. Κάντε publish και, στη συνέχεια, ελέγξτε το public result από διαφορετικό clean context. Καταγράψτε τι πρόσθεσε ή μετέτρεψε το platform.
10. Διατηρείτε planned cadence μόνο αν δεν δημιουργεί stable behavioral fingerprint· αποσύρετε το compartment αντί να το επαναχρησιμοποιήσετε σιωπηρά.

Για serious journalism, activism, domestic abuse ή state-level risk, ζητήστε εξατομικευμένη βοήθεια από experienced digital-security organization· ένα static checklist δεν μπορεί να μοντελοποιήσει το local law ή έναν live adversary.

## Authorized red-team engagement

Στόχος: να παραμένουν οι personal identities των operators και τα home networks εκτός του target telemetry, διατηρώντας παράλληλα την authorization, τον control και το incident response.

### Πριν από το start window

- Ολοκληρώστε το ROE infrastructure annex, τα targets/exclusions, τα source ranges, τις dates, το emergency stop και τα third-party/provider permissions.
- Διαθέστε dedicated operator profile ή VM, engagement secrets, evidence store, cloud project, domains και budget.
- Προτιμήστε client-provided egress ή organization-controlled fixed bastion. Δοκιμάστε τη συμπεριφορά full-tunnel IPv4/IPv6/DNS και την fail-closed policy.
- Αποθηκεύστε το mapping από operator σε public infrastructure με τον exercise controller ή τον συμφωνημένο escrow contact.
- Καθορίστε rate limits, destination allowlists και ξεχωριστή approval για destructive, wireless, physical, phishing ή credential-collection actions.
- Χρησιμοποιείτε organization-controlled payment rail και καταγράφετε τις approvals internally.

### Κατά τη διάρκεια του engagement

- Ξεκινήστε από το approved endpoint και tunnel· επαληθεύστε το observed egress πριν από assessment traffic.
- Κρατήστε personal accounts, devices, phone numbers, repositories, SSH/GPG keys και cloud sync εκτός του compartment.
- Καταγράφετε operator/job, start/stop, source, scoped destination και configuration change χωρίς να συλλέγετε περιττό client content.
- Σταματήστε σε περίπτωση scope ambiguity, unexpected third-party systems, provider abuse notification, safety impact, lost equipment ή loss of controller contact.
- Ποτέ μην αυτοσχεδιάζετε χρησιμοποιώντας το Wi-Fi ενός γείτονα, stolen credentials, unapproved SIM/account ή hardware που έχει κρυφτεί σε venue.

### Μετά το τέλος του engagement

- Σταματήστε τα jobs και το C2· ανακτήστε τα approved drop devices· κάντε revoke tokens, credentials και certificates.
- Συμφωνήστε τα infrastructure, domains, source addresses, expenses, data και provider cases με το inventory.
- Επιστρέψτε/διαγράψτε/διατηρήστε τα client data σύμφωνα με το contract, διατηρήστε το ελάχιστο απαιτούμενο audit evidence και ζητήστε από δεύτερο operator να επαληθεύσει το shutdown.

Δείτε το [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) για τον πλήρη οδηγό build και teardown.

## Lawful private purchase or donation

Στόχος: ελαχιστοποίηση της disclosure προς τον merchant ή το public, ενώ τηρούνται οι υποχρεώσεις issuer, accounting, tax και sanctions.

1. Καταγράψτε ποιος δεν πρέπει να μάθει τι: public audience, merchant, payment intermediary, employer/family account delegate, delivery service ή blockchain observer.
2. Ελέγξτε τους local rules, τον recipient/counterparty, τους provider terms, τα cash limits και τις recordkeeping needs.
3. Επιλέξτε το rail:
- cash για accepted lawful local payments χωρίς payment-network record·
- regulated virtual/merchant-specific card για online credential separation·
- cryptocurrency μόνο αφού αναλύσετε τα acquisition, ledger, wallet backend, network, counterparty και later-spend links.
4. Χρησιμοποιείτε truthful required details και παραλείπετε μόνο optional loyalty/marketing information. Μην χρησιμοποιείτε την identity/address άλλου ατόμου και μην διαχωρίζετε μια συναλλαγή γύρω από threshold.
5. Διαχωρίστε το merchant browser/account context και αποφύγετε unrelated social login, loyalty ή personal recovery channels.
6. Επιβεβαιώστε τι εμφανίζεται σε statements, receipts, notifications, shipping και public donor lists.
7. Αποθηκεύστε τα required receipt/tax/authorization evidence με encryption· κάντε revoke τα disposable payment credentials μετά το refund window.

Δείτε τα [Private Digital Payments](private-digital-payments.md) και [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Travel and untrusted networks

Στόχος: προστασία των data και accounts σε networks που δεν διαχειρίζεται ο user —όχι απόκρυψη unauthorized activity.

- Ενημερώστε τα devices και κατεβάστε τα απαραίτητα credentials/maps πριν από το travel.
- Ελαχιστοποιήστε τα stored data· χρησιμοποιείτε full-disk encryption, strong unlock, remote-recovery planning και powered-off border/physical-risk procedures σύμφωνα με το legal advice.
- Επαληθεύστε το venue SSID/captive portal. Προτιμήστε personal hotspot όπου είναι κατάλληλο, αλλά θυμηθείτε τα cellular subscriber και location records.
- Χρησιμοποιείτε full/forced approved VPN για organizational data· επαληθεύστε ότι τα tethered devices το μοιράζονται και δοκιμάστε τη συμπεριφορά IPv6/DNS.
- Χρησιμοποιείτε travel router για client isolation και repeatable policy, όχι ως anonymity guarantee.
- Αντιμετωπίζετε το public USB charging, τους borrowed computers, τους public printers και τα shared meeting-room systems ως ξεχωριστές απειλές.
- Θεωρείτε ότι η physical presence, τα radio identifiers, το portal login, οι cameras και τα payment/location records μπορούν να συσχετίσουν την επίσκεψη.

Οι λεπτομέρειες σύγκρισης και setup βρίσκονται στο [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Failure and exposure response

Όταν ένα compartment κάνει leak ή ενδέχεται να συνδεθεί:

1. Σταματήστε τη δραστηριότητα αν η συνέχιση αυξάνει τη βλάβη· χρησιμοποιήστε το engagement emergency stop όπου εφαρμόζεται.
2. Διατηρήστε τα απαραίτητα evidence χωρίς να διαδίδετε sensitive data. Καταγράψτε την ακριβή ώρα, το observed indicator και τα affected assets.
3. Ειδοποιήστε τον κατάλληλο owner/controller/security contact. Μην αποκρύψετε ένα incident για να διατηρήσετε ένα privacy narrative.
4. Κάντε revoke sessions, tokens, payment credentials και infrastructure access· κάντε rotate τα secrets από known-clean endpoint.
5. Καθορίστε ποια edges συνδέθηκαν: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty ή physical presence.
6. Αντιμετωπίστε ολόκληρο το affected compartment ως burned. Μην αλλάξετε απλώς το username ή το exit IP.
7. Τηρήστε τις breach, provider, client, financial και legal notification duties.
8. Κάντε rebuild μόνο αφού αλλάξετε το process που προκάλεσε τη σύνδεση· τεκμηριώστε το control και δοκιμάστε το.

## Periodic audit

- [ ] Το threat model και οι legal/provider assumptions επανεξετάζονται βάσει dated schedule.
- [ ] Τα devices, accounts, aliases, domains, network paths και payment credentials έχουν καταγραφεί στο inventory.
- [ ] Τα recovery paths δεν διασχίζουν compartments απροσδόκητα.
- [ ] Η συμπεριφορά full-tunnel, DNS, IPv6 και fail-closed έχει δοκιμαστεί.
- [ ] Τα public files και profiles έχουν ελεγχθεί για metadata/content reuse.
- [ ] Οι wallet nodes/backends και οι crypto protocol assumptions παραμένουν current.
- [ ] Τα logs και receipts είναι minimal, encrypted, access-controlled και εντός retention.
- [ ] Τα παλιά compartments και η engagement infrastructure έχουν αποσυρθεί πλήρως.
{{#include ../banners/hacktricks-training.md}}
