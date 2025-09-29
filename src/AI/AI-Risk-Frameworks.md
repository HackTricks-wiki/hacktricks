# Κίνδυνοι AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Το Owasp έχει εντοπίσει τις κορυφαίες 10 ευπάθειες της μηχανικής μάθησης που μπορούν να επηρεάσουν τα συστήματα AI. Αυτές οι ευπάθειες μπορούν να οδηγήσουν σε διάφορα προβλήματα ασφάλειας, συμπεριλαμβανομένης της data poisoning, model inversion και adversarial attacks. Η κατανόηση αυτών των ευπαθειών είναι κρίσιμη για την κατασκευή ασφαλών συστημάτων AI.

Για μια ενημερωμένη και αναλυτική λίστα των top 10 machine learning vulnerabilities, ανατρέξτε στο [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: Ένας επιτιθέμενος προσθέτει πολύ μικρές, συχνά αόρατες, αλλαγές στα **incoming data** ώστε το μοντέλο να πάρει λάθος απόφαση.\
*Παράδειγμα*: Μερικές κηλίδες μπογιάς σε ένα stop‑sign εξαπατούν ένα self‑driving αυτοκίνητο ώστε να «βλέπει» πινακίδα ορίου ταχύτητας.

- **Data Poisoning Attack**: Το **training set** μολύνεται σκόπιμα με κακά δείγματα, διδάσκοντας στο μοντέλο επιβλαβείς κανόνες.\
*Παράδειγμα*: Malware binaries ετικετοποιούνται λανθασμένα ως "benign" σε ένα corpus για antivirus, επιτρέποντας σε παρόμοιο malware να περάσει αργότερα.

- **Model Inversion Attack**: Με την εξέταση των εξόδων, ένας επιτιθέμενος δημιουργεί ένα **reverse model** που ανακατασκευάζει ευαίσθητα χαρακτηριστικά των αρχικών εισόδων.\
*Παράδειγμα*: Ανακατασκευή μιας MRI εικόνας ασθενούς από τις προβλέψεις ενός cancer‑detection μοντέλου.

- **Membership Inference Attack**: Ο αντίπαλος δοκιμάζει αν μια **specific record** χρησιμοποιήθηκε κατά την εκπαίδευση εντοπίζοντας διαφορές στην εμπιστοσύνη (confidence).\
*Παράδειγμα*: Επιβεβαίωση ότι μια συναλλαγή ενός ατόμου υπάρχει στα δεδομένα εκπαίδευσης ενός fraud‑detection μοντέλου.

- **Model Theft**: Επαναλαμβανόμενα queries επιτρέπουν σε έναν επιτιθέμενο να μάθει τα όρια απόφασης και να **clone the model's behavior** (και IP).\
*Παράδειγμα*: Συλλογή αρκετών Q&A ζευγών από ένα ML‑as‑a‑Service API για να δημιουργηθεί ένα σχεδόν ισοδύναμο τοπικό μοντέλο.

- **AI Supply‑Chain Attack**: Παραβίαση οποιουδήποτε συστατικού (data, libraries, pre‑trained weights, CI/CD) στην **ML pipeline** για να μολύνει τα μοντέλα που κατεβαίνουν.\
*Παράδειγμα*: Μια poisoned dependency σε ένα model‑hub εγκαθιστά ένα backdoored sentiment‑analysis μοντέλο σε πολλές εφαρμογές.

- **Transfer Learning Attack**: Κακόβουλη λογική φυτεύεται σε ένα **pre‑trained model** και επιβιώνει μετά το fine‑tuning για το έργο του θύματος.\
*Παράδειγμα*: Μια vision backbone με κρυφό trigger συνεχίζει να αντιστρέφει labels μετά την προσαρμογή της για medical imaging.

- **Model Skewing**: Υποπτώς μεροληπτικά ή λανθασμένα επισημασμένα δεδομένα **μετατοπίζουν τα outputs του μοντέλου** ώστε να ευνοούν την ατζέντα του επιτιθέμενου.\
*Παράδειγμα*: Έγχυση "clean" spam emails που ετικετοποιούνται ως ham ώστε ένα spam filter να επιτρέπει παρόμοια μελλοντικά emails.

- **Output Integrity Attack**: Ο επιτιθέμενος **αλλάζει τις προβλέψεις του μοντέλου εν κινήσει**, όχι το ίδιο το μοντέλο, εξαπατώντας τα downstream συστήματα.\
*Παράδειγμα*: Αλλαγή ενός verdict από malware classifier από "malicious" σε "benign" πριν περάσει στο στάδιο quarantine του αρχείου.

- **Model Poisoning** --- Άμεσες, στοχευμένες αλλαγές στις **model parameters** οι ίδιες, συχνά μετά από απόκτηση write access, για να αλλοιωθεί η συμπεριφορά.\
*Παράδειγμα*: Τροποποίηση weights σε ένα fraud‑detection μοντέλο σε production ώστε οι συναλλαγές από συγκεκριμένες κάρτες να εγκρίνονται πάντα.


## Google SAIF Risks

Το Google [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) περιγράφει διάφορους κινδύνους που σχετίζονται με συστήματα AI:

- **Data Poisoning**: Κακόβουλοι παράγοντες τροποποιούν ή εισάγουν training/tuning data για να υποβαθμίσουν την ακρίβεια, να εμφυτεύσουν backdoors ή να προκαλέσουν skew στα αποτελέσματα, υπονομεύοντας την ακεραιότητα του μοντέλου σε όλο το data‑lifecycle.

- **Unauthorized Training Data**: Η εισαγωγή copyrighted, ευαίσθητων ή μη εξουσιοδοτημένων datasets δημιουργεί νομικές, ηθικές και επιδόσεις ευθύνες επειδή το μοντέλο μαθαίνει από δεδομένα που δεν επιτρεπόταν να χρησιμοποιήσει.

- **Model Source Tampering**: Supply‑chain ή insider χειραγώγηση του model code, dependencies ή weights πριν ή κατά την εκπαίδευση μπορεί να ενσωματώσει κρυφή λογική που επιμένει ακόμα και μετά το retraining.

- **Excessive Data Handling**: Αδύναμος έλεγχος data‑retention και governance οδηγεί τα συστήματα να αποθηκεύουν ή να επεξεργάζονται περισσότερα προσωπικά δεδομένα από ό,τι απαιτείται, αυξάνοντας την έκθεση και τον compliance risk.

- **Model Exfiltration**: Επιτιθέμενοι κλέβουν model files/weights, προκαλώντας απώλεια intellectual property και επιτρέποντας copy‑cat υπηρεσίες ή follow‑on επιθέσεις.

- **Model Deployment Tampering**: Αντίπαλοι τροποποιούν model artifacts ή serving infrastructure ώστε το τρέχον μοντέλο να διαφέρει από την ελεγμένη έκδοση, πιθανώς αλλάζοντας τη συμπεριφορά.

- **Denial of ML Service**: Πλημμύρισμα APIs ή αποστολή “sponge” inputs μπορεί να εξαντλήσει compute/energy και να ρίξει το μοντέλο offline, αντικατοπτρίζοντας κλασικές DoS επιθέσεις.

- **Model Reverse Engineering**: Με τη συλλογή μεγάλου αριθμού input‑output ζευγών, οι επιτιθέμενοι μπορούν να clone ή να distill το μοντέλο, τροφοδοτώντας imitation προϊόντα και εξατομικευμένες adversarial επιθέσεις.

- **Insecure Integrated Component**: Ευάλωτα plugins, agents ή upstream services επιτρέπουν στους επιτιθέμενους να εισαγάγουν κώδικα ή να ανεβάσουν privileges μέσα στο AI pipeline.

- **Prompt Injection**: Σχεδιασμός prompts (άμεσα ή έμμεσα) για να περάσουν οδηγίες που υπερισχύουν του system intent, κάνοντας το μοντέλο να εκτελέσει μη προοριζόμενες εντολές.

- **Model Evasion**: Προσεκτικά σχεδιασμένες εισροές προκαλούν το μοντέλο να mis‑classify, να hallucinate ή να παράγει απαγορευμένο περιεχόμενο, αποδυναμώνοντας την ασφάλεια και την εμπιστοσύνη.

- **Sensitive Data Disclosure**: Το μοντέλο αποκαλύπτει ιδιωτικές ή εμπιστευτικές πληροφορίες από τα training data ή το πλαίσιο χρήστη, παραβιάζοντας την ιδιωτικότητα και κανονισμούς.

- **Inferred Sensitive Data**: Το μοντέλο συμπεραίνει προσωπικά χαρακτηριστικά που ποτέ δεν παρείχονταν, δημιουργώντας νέους κινδύνους ιδιωτικότητας μέσω inference.

- **Insecure Model Output**: Μη‑ελεγχόμενες απαντήσεις μεταφέρουν επιβλαβή code, misinformation ή ακατάλληλο περιεχόμενο σε χρήστες ή downstream συστήματα.

- **Rogue Actions**: Αυτόνομα ενσωματωμένοι agents εκτελούν μη προοριζόμενες πραγματικές ενέργειες (εγγραφές αρχείων, API calls, αγορές κ.λπ.) χωρίς επαρκή εποπτεία χρήστη.

## Mitre AI ATLAS Matrix

Το [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) προσφέρει ένα ολοκληρωμένο πλαίσιο για την κατανόηση και την αντιμετώπιση κινδύνων που σχετίζονται με συστήματα AI. Κατηγοριοποιεί διάφορες τεχνικές και τακτικές επιθέσεων που μπορεί να χρησιμοποιήσουν οι αντίπαλοι κατά των AI models και επίσης πώς να χρησιμοποιήσετε τα AI συστήματα για την εκτέλεση διαφόρων επιθέσεων.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Επιτιθέμενοι κλέβουν active session tokens ή cloud API credentials και καλούν πληρωμένα, cloud‑hosted LLMs χωρίς εξουσιοδότηση. Η πρόσβαση συχνά επαναπωλείται μέσω reverse proxies που προωθούν τον λογαριασμό του θύματος, π.χ. "oai-reverse-proxy" deployments. Οι συνέπειες περιλαμβάνουν οικονομική απώλεια, κακή χρήση του μοντέλου εκτός πολιτικής και attribution στο tenant του θύματος.

TTPs:
- Harvest tokens από μολυσμένα developer machines ή browsers; steal CI/CD secrets; buy leaked cookies.
- Στήσιμο ενός reverse proxy που προωθεί αιτήματα στον αυθεντικό provider, κρύβοντας το upstream key και multiplexing πολλούς customers.
- Κακοποίηση άμεσων base‑model endpoints για να παρακαμφθούν enterprise guardrails και rate limits.

Mitigations:
- Συσχέτιση tokens με device fingerprint, IP ranges και client attestation; επιβολή σύντομων expiration και refresh με MFA.
- Scope keys στο ελάχιστο (no tool access, read‑only όπου είναι εφαρμόσιμο); rotate όταν υπάρχει anomaly.
- Τερματισμός όλης της κίνησης server‑side πίσω από ένα policy gateway που επιβάλλει safety filters, per‑route quotas και tenant isolation.
- Monitor για ασυνήθιστα usage patterns (ξαφνικά spikes δαπάνης, atypical regions, UA strings) και auto‑revoke suspicious sessions.
- Προτίμηση mTLS ή signed JWTs που εκδίδονται από το IdP σας αντί για long‑lived static API keys.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
