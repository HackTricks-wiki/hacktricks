# AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι Machine Learning Algorithms

Το καλύτερο σημείο εκκίνησης για να μάθετε σχετικά με το AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι αλγόριθμοι machine learning. Αυτό θα σας βοηθήσει να κατανοήσετε πώς λειτουργεί το AI, πώς να το χρησιμοποιείτε και πώς να του επιτίθεστε:


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

### Αρχιτεκτονική LLMs

Στην παρακάτω σελίδα θα βρείτε τα βασικά στοιχεία κάθε component για τη δημιουργία ενός βασικού LLM με χρήση transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Ασφάλεια AI

### Frameworks Κινδύνων AI

Δύο χρήσιμα frameworks εκκίνησης για την αξιολόγηση του κινδύνου συστημάτων AI είναι το OWASP Machine Learning Security Top 10 και το Secure AI Framework (SAIF) της Google. Είναι συμπληρωματικά και όχι μια εξαντλητική λίστα frameworks κινδύνων AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ασφάλεια AI Prompts

Τα LLMs έχουν οδηγήσει σε εκρηκτική αύξηση της χρήσης του AI τα τελευταία χρόνια, αλλά δεν είναι τέλεια και μπορούν να εξαπατηθούν μέσω adversarial prompts. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε AI Models

Είναι πολύ συνηθισμένο για developers και εταιρείες να εκτελούν models που έχουν downloaded από το Internet. Ωστόσο, μόνο το loading ενός model μπορεί να αρκεί για την εκτέλεση arbitrary code στο σύστημα. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC Bypass με βοήθεια AI

Το Generative video μπορεί να συνδυαστεί με virtual-camera injection και camera API manipulation για την παράκαμψη αδύναμων ροών KYC, age-verification και biometric liveness:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol του AI

Το MCP (Model Context Protocol) είναι ένα open protocol για τη σύνδεση εφαρμογών AI με εργαλεία και data sources. Επειδή οι MCP servers μπορούν να εκθέτουν δεδομένα και actions, οι assessments πρέπει να περιλαμβάνουν authorization, consent, tool-input validation και review των trust boundaries.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

Agents που υποστηρίζονται από LLMs μπορούν να αυτοματοποιήσουν long-running black-box web pentesting workflows όταν υποστηρίζονται από observability, orchestration, authenticated session handling και adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Εισαγωγή](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
