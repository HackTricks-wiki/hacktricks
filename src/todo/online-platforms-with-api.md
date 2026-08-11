# Online Platforms with API

{{#include ../banners/hacktricks-training.md}}

Αυτές οι υπηρεσίες υποστηρίζουν workflows reconnaissance, reputation, breach ή enrichment. Τα API, τα quotas, η τιμολόγηση και οι επιτρεπόμενες χρήσεις τους αλλάζουν συχνά· επιβεβαιώστε την τρέχουσα τεκμηρίωση του vendor και την εξουσιοδότηση του engagement πριν στείλετε identifiers πελατών ή ευαίσθητα δεδομένα.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Ελέγξτε αν μια διεύθυνση IP έχει συσχετιστεί με ύποπτη ή κακόβουλη δραστηριότητα. Η πρόσβαση ενδέχεται να απαιτεί account ή API key.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Ελέγξτε αν μια διεύθυνση IP, ένα username ή μια διεύθυνση email έχει συσχετιστεί με αυτοματοποιημένη εγγραφή account ή άλλη αναφερόμενη δραστηριότητα bot.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Βρείτε και επαληθεύστε επαγγελματικές διευθύνσεις email και patterns επικοινωνίας που σχετίζονται με domains. Ελέγξτε το τρέχον plan για τα όρια requests και τις επιτρεπόμενες χρήσεις.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Αναζητήστε indicators threat-intelligence και δραστηριότητα που σχετίζεται με διευθύνσεις IP και domains.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Εμπλουτίστε μια διεύθυνση email, ένα domain ή μια εταιρεία με διαθέσιμα business/profile δεδομένα. Η κάλυψη, η πρόσβαση και οι περιορισμοί privacy εξαρτώνται από το τρέχον product και plan.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Εντοπίστε technologies που παρατηρούνται σε websites και αποκτήστε historical ή relationship δεδομένα όπου το επιτρέπει το επιλεγμένο plan.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Ελέγξτε αν μια διεύθυνση IP σχετίζεται με ύποπτη ή κακόβουλη δραστηριότητα. Επιβεβαιώστε τα τρέχοντα API plans και limits.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Αναζητήστε categorization και threat intelligence του FortiGuard για domains, URLs ή διευθύνσεις IP. Η διαθεσιμότητα διαφέρει ανά service.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Ελέγξτε αν μια διεύθυνση IP είναι καταχωρισμένη για αναφερόμενη δραστηριότητα spam.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Ανακτήστε τη reputation ενός domain με βάση την κοινότητα της υπηρεσίας και άλλα signals.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Αποκτήστε geolocation, ASN, organization και σχετικά metadata για μια διεύθυνση IP. Ελέγξτε το τρέχον plan για τα quotas.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Αυτή η platform παρέχει DNS και infrastructure intelligence, όπως historical resolutions, domains που σχετίζονται με IPs ή name servers και σχετικά records. Το historical DNS ενδέχεται να αποκαλύψει μια προηγούμενη origin address, αλλά δεν παρακάμπτει αξιόπιστα ένα CDN και πρέπει να επικυρώνεται.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Εμπλουτίστε μια διεύθυνση email, ένα domain ή ένα company name με διαθέσιμα identity και business attributes. Χειριστείτε τα personal data σύμφωνα με τις απαιτήσεις authorization και privacy.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

Οι δυνατότητες PassiveTotal του RiskIQ μεταφέρθηκαν στο Microsoft Defender Threat Intelligence. Η πρόσβαση στο product, τα APIs και η διατηρημένη λειτουργικότητα έχουν αλλάξει, επομένως χρησιμοποιήστε την τρέχουσα τεκμηρίωση της Microsoft αντί για υποθέσεις σχετικά με το legacy PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Αναζητήστε domains, διευθύνσεις IP, διευθύνσεις email και indexed historical ή leaked data, με την επιφύλαξη των access controls της υπηρεσίας.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Αναζητήστε διευθύνσεις IP και άλλα indicators για δεδομένα threat-intelligence και reputation.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Αναζητήστε διευθύνσεις IP ή ranges για παρατηρήσεις internet scanning και δραστηριότητα κοινών services. Ελέγξτε τους τρέχοντες όρους trial και community access.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Ανακτήστε πληροφορίες internet-scan και services για μια διεύθυνση IP, έναν host ή ένα search query. Η πρόσβαση στο API εξαρτάται από το account plan.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Αναζητήστε datasets hosts, certificates, domains και internet services· το data model και η κάλυψή του διαφέρουν από του Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Αναζητήστε στο index του provider δημόσια παρατηρημένα cloud-storage objects και buckets με βάση keyword.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Αναζητήστε indexed breach data για διευθύνσεις email, usernames, domains και σχετικά records. Χρησιμοποιήστε το μόνο με authorization και αποφύγετε την περιττή έκθεση breach data.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Αναζητήστε indexed περιεχόμενο paste για εμφανίσεις μιας διεύθυνσης email ή άλλου όρου. Επαληθεύστε ότι η υπηρεσία είναι ακόμη διαθέσιμη πριν την ενσωματώσετε.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Ανακτήστε reputation και risk signals για μια διεύθυνση email.

## GhostProject (historical) <sup>[[24]](#references)</sup>

Ιστορικά διαφήμιζε searches leaked δεδομένων email/password. Αντιμετωπίστε την υπηρεσία ως high-risk third-party handling και επαληθεύστε τη διαθεσιμότητα, τη νομιμότητα και το authorization της πριν από τη χρήση.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Αποκτήστε δεδομένα internet-scan, exposure και threat-intelligence για διευθύνσεις IP και σχετικά assets.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Ελέγξτε αν μια διεύθυνση email ή ένα verified domain εμφανίζεται σε γνωστά breaches. Η ξεχωριστή υπηρεσία Pwned Passwords ελέγχει password hashes με βάση prefix· **δεν** αποκαλύπτει plaintext passwords.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Ανακτήστε IP geolocation, data-center, ASN, proxy/VPN και σχετικά enrichment fields. Τα quotas εξαρτώνται από το τρέχον plan.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
IP geolocation και OSINT-oriented enrichment με επιλεγμένα data points. Ελέγξτε τους τρέχοντες όρους για commercial use.


Το [DNSDumpster](https://dnsdumpster.com/) παρέχει αποτελέσματα DNS-reconnaissance.<sup>[[29]](#references)</sup>

Το [Netcraft](https://www.netcraft.com/) παρέχει site, hosting και internet-infrastructure intelligence.<sup>[[30]](#references)</sup>

Το [NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) παρέχει online interface για subdomain discovery.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [BotScout API](https://botscout.com/api.htm)
- [3] [Hunter API](https://hunter.io/api-documentation)
- [4] [AlienVault OTX API](https://otx.alienvault.com/api)
- [5] [Clearbit](https://dashboard.clearbit.com/)
- [6] [BuiltWith](https://builtwith.com/)
- [7] [FraudGuard](https://fraudguard.io/)
- [8] [FortiGuard Labs](https://www.fortiguard.com/)
- [9] [SpamCop](https://www.spamcop.net/)
- [10] [Web of Trust](https://www.mywot.com/)
- [11] [IPinfo](https://ipinfo.io/)
- [12] [SecurityTrails](https://securitytrails.com/)
- [13] [FullContact](https://www.fullcontact.com/)
- [14] [Microsoft Defender Threat Intelligence](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)
- [15] [Intelligence X](https://intelx.io/)
- [16] [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [17] [GreyNoise](https://www.greynoise.io/)
- [18] [Shodan](https://www.shodan.io/)
- [19] [Censys](https://censys.com/)
- [20] [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
- [21] [DeHashed](https://www.dehashed.com/)
- [22] [psbdmp](https://psbdmp.ws/)
- [23] [EmailRep](https://emailrep.io/)
- [24] [Cornell research — Πρωτόκολλα για τον έλεγχο compromised credentials (περιλαμβάνει το GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
