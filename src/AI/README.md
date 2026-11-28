# AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι αλγόριθμοι Machine Learning

Το καλύτερο σημείο για να ξεκινήσετε να μαθαίνετε για το AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι αλγόριθμοι machine learning. Αυτό θα σας βοηθήσει να κατανοήσετε πώς λειτουργεί το AI, πώς να το χρησιμοποιείτε και πώς να του επιτίθεστε:


{{#ref}}
./AI-Supervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Unsupervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Reinforcement-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Deep-Learning.md
{{#endref}}

### Προετοιμασία και αξιολόγηση δεδομένων μοντέλων

Για διαχωρισμούς συνόλων δεδομένων, κλασικές μετρικές και επιθέσεις στην πλευρά των απαντήσεων σε αξιολόγηση βασισμένη σε LLM, δείτε την [προετοιμασία και αξιολόγηση δεδομένων μοντέλων](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Αρχιτεκτονική LLM

Στην ακόλουθη σελίδα θα βρείτε τα βασικά στοιχεία κάθε συστατικού για την κατασκευή ενός βασικού LLM με χρήση transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Εργαλεία και πλατφόρμες μοντέλων

Για την εκτέλεση, το fine-tuning, τη διάθεση ή τη δοκιμή μοντέλων, χρησιμοποιήστε τον [οδηγό εργαλείων και πλατφορμών μοντέλων AI](AI-Model-Tools-and-Platforms.md).

## Ασφάλεια AI

### Όρια εμπιστοσύνης LLM Gateway

Για την ασφάλεια gateway, δείτε:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Μεθοδολογία ασφάλειας AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Πλαίσια κινδύνων AI

Δύο χρήσιμα πλαίσια για την αρχική αξιολόγηση κινδύνων συστημάτων AI είναι το OWASP Machine Learning Security Top 10 και το Secure AI Framework (SAIF) της Google. Είναι συμπληρωματικά και δεν αποτελούν εξαντλητικό κατάλογο πλαισίων κινδύνων AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Επιθέσεις adversarial με καθοδήγηση από mechanistic interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Όρια εμπιστοσύνης ενσωματωμένων browser στο AI

Για γέφυρες browser σε desktop assistants, πλαστογράφηση διευθύνσεων καρτελών και αναγνώσεις τοπικών αρχείων από worker context, δείτε τα [όρια εμπιστοσύνης ενσωματωμένων browser σε AI assistants](AI-Embedded-Browser-Trust-Boundaries.md).

### Ασφάλεια AI Prompts

Τα LLM έχουν οδηγήσει σε εκρηκτική αύξηση της χρήσης του AI τα τελευταία χρόνια, αλλά δεν είναι τέλεια και μπορούν να εξαπατηθούν με adversarial prompts. Είναι πολύ σημαντικό να κατανοήσετε αυτό το θέμα, ώστε να χρησιμοποιείτε το AI με ασφάλεια και να του επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε μοντέλα AI

Είναι πολύ συνηθισμένο οι προγραμματιστές και οι εταιρείες να εκτελούν μοντέλα που έχουν κατεβάσει από το Internet. Ωστόσο, η απλή φόρτωση ενός μοντέλου μπορεί να αρκεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα. Είναι πολύ σημαντικό να κατανοήσετε αυτό το θέμα, ώστε να χρησιμοποιείτε το AI με ασφάλεια και να του επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Για κινδύνους φόρτωσης μοντέλων Keras `.keras`/HDF5, επίπεδα Lambda και ανάλυση gadget μετά από διορθώσεις, δείτε την [αποσειριοποίηση μοντέλων Keras και αναζήτηση gadget](keras-model-deserialization-rce-and-gadget-hunting.md).

### Παράκαμψη KYC με τη βοήθεια AI

Το generative video μπορεί να συνδυαστεί με έγχυση virtual camera και χειρισμό του camera API για την παράκαμψη ανεπαρκώς προστατευμένων διαδικασιών KYC, επαλήθευσης ηλικίας και βιομετρικού ελέγχου ζωντανής παρουσίας:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol του AI

Το MCP (Model Context Protocol) είναι ένα ανοιχτό πρωτόκολλο για τη σύνδεση εφαρμογών AI με εργαλεία και πηγές δεδομένων. Επειδή οι MCP servers μπορούν να εκθέτουν δεδομένα και ενέργειες, οι αξιολογήσεις πρέπει να περιλαμβάνουν έλεγχο εξουσιοδότησης, συναίνεσης, επικύρωσης εισόδων εργαλείων και ορίων εμπιστοσύνης.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Πρωτόκολλο AI Agent-to-Agent (A2A)

Το A2A επιτρέπει σε agents να εντοπίζουν ο ένας τον άλλον μέσω μιας agent card και να ανταλλάσσουν εργασίες μέσω HTTP. Ελέγξτε τις agent cards, την εξουσιοδότηση εργασιών, τα webhooks ειδοποιήσεων push και τις extended cards:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Εκτεθειμένες self-hosted υπηρεσίες AI

Αποτυπώστε και ελέγξτε εκτεθειμένους model runners, agent builders, ML demo UIs, compute clusters και vector databases που λειτουργούν χωρίς έλεγχο ταυτότητας:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing με τη βοήθεια AI και αυτοματοποιημένος εντοπισμός ευπαθειών


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Έλεγχος κώδικα και επικύρωση ευπαθειών με τη βοήθεια AI

Για έλεγχο source/sink, taskflows σημείων εισόδου σε mobile, ελέγχους μοτίβων kernel και επικύρωση βάσει τεκμηρίων:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering με τη βοήθεια AI

[Μερική ανύψωση κώδικα, ανίχνευση invariant MBA, αποκωδικοποίηση δεσμευμένη σε περιβάλλον και επικύρωση αυτοματοποιημένων extractors](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots AI Pentester για black-box δοκιμές Web

Οι agents με LLM μπορούν να αυτοματοποιήσουν μακρόχρονες ροές εργασιών black-box web pentesting, όταν υποστηρίζονται από observability, orchestration, διαχείριση authenticated sessions και adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Top 10 για την ασφάλεια Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Πλαίσιο Secure AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Εισαγωγή](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
