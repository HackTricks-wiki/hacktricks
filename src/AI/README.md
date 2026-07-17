# AI στην Κυβερνοασφάλεια

{{#include ../banners/hacktricks-training.md}}

## Κύριοι Machine Learning Algorithms

Το καλύτερο σημείο εκκίνησης για να μάθετε σχετικά με το AI είναι να κατανοήσετε πώς λειτουργούν οι κύριοι Machine Learning Algorithms. Αυτό θα σας βοηθήσει να κατανοήσετε πώς λειτουργεί το AI, πώς να το χρησιμοποιείτε και πώς να του επιτίθεστε:


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

Στην ακόλουθη σελίδα θα βρείτε τα βασικά στοιχεία κάθε component για να δημιουργήσετε ένα βασικό LLM χρησιμοποιώντας transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Ασφάλεια AI

### Frameworks Κινδύνων AI

Αυτή τη στιγμή, τα 2 κύρια frameworks για την αξιολόγηση των κινδύνων των AI systems είναι τα OWASP ML Top 10 και Google SAIF:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ασφάλεια AI Prompts

Τα LLMs έχουν κάνει τη χρήση του AI να εκτοξευθεί τα τελευταία χρόνια, αλλά δεν είναι τέλεια και μπορούν να παραπλανηθούν από adversarial prompts. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE σε AI Models

Είναι πολύ συνηθισμένο για developers και εταιρείες να εκτελούν models που έχουν ληφθεί από το Internet· ωστόσο, μόνο η φόρτωση ενός model μπορεί να είναι αρκετή για την εκτέλεση arbitrary code στο σύστημα. Αυτό είναι ένα πολύ σημαντικό θέμα για να κατανοήσετε πώς να χρησιμοποιείτε το AI με ασφάλεια και πώς να του επιτίθεστε:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Model Context Protocol

Το MCP (Model Context Protocol) είναι ένα protocol που επιτρέπει σε AI agent clients να συνδέονται με external tools και data sources με plug-and-play τρόπο. Αυτό επιτρέπει σύνθετα workflows και interactions μεταξύ AI models και external systems:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

Οι agents που υποστηρίζονται από LLMs μπορούν να αυτοματοποιήσουν black-box web pentesting workflows μεγάλης διάρκειας, όταν υποστηρίζονται από observability, orchestration, authenticated session handling και adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
