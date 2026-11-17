# Εργαλεία και πλατφόρμες μοντέλων AI

{{#include ../banners/hacktricks-training.md}}

## Εκτέλεση και εκπαίδευση μοντέλων τοπικά

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Το Hugging Face Transformers είναι μια βιβλιοθήκη ανοιχτού κώδικα για τη φόρτωση, την εκπαίδευση και την εξυπηρέτηση προεκπαιδευμένων μοντέλων για εργασίες κειμένου, όρασης, ήχου, βίντεο και πολυτροπικές εργασίες. Η φιλοξενία μοντέλων και συνόλων δεδομένων παρέχεται ξεχωριστά από το Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

Το LangChain είναι ένα framework για τη δημιουργία εφαρμογών και agents που βασίζονται σε μοντέλα, με δυνατότητες κατασκευής prompt, διαχείρισης ιστορικού συνομιλίας/κατάστασης, εργαλείων, ανάκτησης, καθώς και ενσωματώσεις μοντέλων, API και βάσεων δεδομένων.<sup>[[2]](#references)</sup>

#### Δοκιμή επαναφοράς σειριοποιημένων αντικειμένων LangChain

Όταν μια εφαρμογή δέχεται **δομημένη** είσοδο χρήστη ή έξοδο μοντέλου, ελέγξτε αν τα ένθετα dictionaries διατηρούνται στα `metadata`, `additional_kwargs`, `response_metadata`, στο αποθηκευμένο ιστορικό συνομιλίας ή σε μια ροή εκτέλεσης. Το LangChain χρησιμοποιεί dictionaries με ετικέτα `lc` ως σειριοποιημένα αντικείμενα. Σε επηρεαζόμενους κύκλους `dumps()`/`dumpd()` → `load()`/`loads()`, ένα dictionary που ελέγχεται από εισβολέα θα μπορούσε να επανέλθει ως αντικείμενο του framework αντί να παραμείνει δεδομένο. Η απευθείας φόρτωση μη έμπιστου manifest είναι επίσης επικίνδυνη· μια απλή είσοδος string που δεν αναλύεται ποτέ ως dictionary δεν πληροί αυτήν την προϋπόθεση.<sup>[[10]](#references)[[11]](#references)</sup>

Για μια εξουσιοδοτημένη δοκιμή, υποβάλετε ένα ακίνδυνο canary σε μορφή κατασκευαστή **ως ένθετο JSON object**, όχι ως string, και ελέγξτε αν το επόμενο ιστορικό ή η ροή περιέχει αντικείμενο `AIMessage` αντί για το αρχικό dictionary:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Ελέγξτε τα `RunnableWithMessageHistory`, `astream_log()` και `astream_events(version="v1")` όταν χρησιμοποιούνται στην πράξη. Η επιτυχής επαναφορά ενός αντικειμένου μπορεί να αλλοιώσει το μεταγενέστερο ιστορικό συνομιλίας· ευρύτερες allowlists μπορούν να δημιουργήσουν άλλες έμπιστες κλάσεις των οποίων οι constructors έχουν παρενέργειες. Μην το εξισώνετε με απεριόριστη εκτέλεση pickle. Το αρχικό ελάττωμα escaping διορθώθηκε στα `langchain-core` 0.3.81/1.2.5, ενώ μια μεταγενέστερη διόρθωση για ευρείες allowlists και secret markers κυκλοφόρησε στις εκδόσεις 0.3.85/1.3.3. Για μη έμπιστα manifests, χρησιμοποιήστε τρέχουσα έκδοση και περιορίστε το `allowed_objects` σε κλάσεις μηνυμάτων ή σε ρητά καθορισμένη ασφαλή λίστα, με `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> Για [χαρτογράφηση ορίων εμπιστοσύνης agent](AI-Agent-Security-Methodology.md), διαχωρίστε το από το [RCE κατά τη φόρτωση αρχείων μοντέλων](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

Το LitGPT παρέχει ευανάγνωστες υλοποιήσεις και ροές εργασίας γραμμής εντολών για pretraining, fine-tuning, αξιολόγηση και ανάπτυξη υποστηριζόμενων γλωσσικών μοντέλων.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Περιγραφή:**\
Το LitServe είναι ένα framework εξυπηρέτησης μοντέλων της Lightning AI για τη διάθεση API inference, με δυνατότητες batching, streaming, επιτάχυνσης και κλιμάκωσης.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Το Axolotl είναι ένα framework post-training και fine-tuning ανοικτού κώδικα, που βασίζεται σε ρυθμίσεις YAML. Υποστηρίζει τεχνικές όπως full fine-tuning, LoRA/QLoRA, βελτιστοποίηση προτιμήσεων και εκπαίδευση με πολλές GPU· δεν είναι από μόνο του πλατφόρμα ανάπτυξης στο cloud.<sup>[[5]](#references)</sup>

## Δοκιμάστε μοντέλα online

### [**Hugging Face**](https://huggingface.co/)

Το **Hugging Face** είναι μια κορυφαία πλατφόρμα και κοινότητα για machine learning, γνωστή ιδιαίτερα για τη δουλειά της στην επεξεργασία φυσικής γλώσσας (NLP). Παρέχει εργαλεία, βιβλιοθήκες και πόρους που διευκολύνουν την ανάπτυξη, την κοινή χρήση και την ανάπτυξη μοντέλων machine learning.\
Το Hub προσφέρει αρκετές σχετικές ενότητες:<sup>[[6]](#references)</sup>

* **Models**: Ένα τεράστιο αποθετήριο **προεκπαιδευμένων μοντέλων machine learning**, όπου οι χρήστες μπορούν να περιηγηθούν, να κατεβάσουν και να ενσωματώσουν μοντέλα για διάφορες εργασίες, όπως δημιουργία κειμένου, μετάφραση, αναγνώριση εικόνων και άλλα.
* **Datasets:** Μια ολοκληρωμένη **συλλογή συνόλων δεδομένων** που χρησιμοποιούνται για την εκπαίδευση και την αξιολόγηση μοντέλων. Διευκολύνει την πρόσβαση σε ποικίλες πηγές δεδομένων, επιτρέποντας στους χρήστες να βρίσκουν και να αξιοποιούν δεδομένα για τα συγκεκριμένα έργα machine learning που υλοποιούν.
* **Spaces:** Μια πλατφόρμα φιλοξενίας και κοινής χρήσης **διαδραστικών εφαρμογών machine learning** και demos. Επιτρέπει στους προγραμματιστές να **παρουσιάζουν** τα μοντέλα τους σε λειτουργία, να δημιουργούν εύχρηστες διεπαφές και να συνεργάζονται με άλλους κοινοποιώντας live demos.

#### Ελέγξτε τα δημόσια logs εκτέλεσης των Space

Ο κώδικας στο repository ενός δημόσιου Space μπορεί να αποκαλύψει ποιες εισόδους και μεταβλητές περιβάλλοντος καταγράφει η εφαρμογή του. Σε μια αξιολόγηση με εξουσιοδότηση, ελέγξτε τη ροή logs **run** ως ξεχωριστή επιφάνεια από το UI της εφαρμογής. Η Hugging Face τεκμηριώνει το endpoint SSE των logs του Space· έρευνες διαπίστωσαν ότι τα δημόσια logs των Space μπορούσαν να διαβαστούν από άλλους χρήστες του Hub και μερικές φορές περιείχαν API keys, prompts χρηστών ή ένα access token του Dev Mode καταγεγραμμένο σε URL αιτήματος. Ένα token σε log έχει σημασία μόνο αν η αντίστοιχη προνομιακή λειτουργία παραμένει ενεργοποιημένη και το token εξακολουθεί να είναι έγκυρο.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Χρησιμοποιήστε token για τον λογαριασμό σας στο Hub, τον οποίο είστε εξουσιοδοτημένοι να χρησιμοποιείτε· αυτό **δεν** είναι αίτημα για το μυστικό του ιδιοκτήτη του Space. Η απόκριση είναι ροή SSE (γραμμές `data:`). Συσχετίστε τις εκτεθειμένες τιμές με τον κώδικα του Space και το τρέχον runtime, αντί να υποθέτετε ότι το όνομα μιας μεταβλητής αποδεικνύει πως η τιμή της έγινε leak. Για endpoint [self-hosted Gradio ή model-runner](AI-Exposed-Self-Hosted-AI-Services.md), ακολουθήστε εκείνη τη σελίδα.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

Το **TensorFlow Hub** είναι αποθετήριο και βιβλιοθήκη επαναχρησιμοποιήσιμων εκπαιδευμένων στοιχείων μοντέλων, ειδικά modules που χρησιμοποιούνται μέσω TensorFlow/Keras. Το **Kaggle** παρέχει ξεχωριστά notebooks, datasets, διαγωνισμούς και μοντέλα.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Μια τεράστια συλλογή προεκπαιδευμένων μοντέλων και στοιχείων μοντέλων, όπου οι χρήστες μπορούν να περιηγηθούν, να κατεβάσουν και να ενσωματώσουν modules για εργασίες όπως η ταξινόμηση εικόνων, τα text embeddings και άλλα.
* **Tutorials:** Οδηγοί και παραδείγματα βήμα προς βήμα που βοηθούν τους χρήστες να υλοποιήσουν και να βελτιστοποιήσουν μοντέλα χρησιμοποιώντας το TensorFlow Hub.
* **Documentation:** Αναλυτικοί οδηγοί και αναφορές API που βοηθούν τους προγραμματιστές να αξιοποιούν αποτελεσματικά τους πόρους του αποθετηρίου.

## [**Replicate**](https://replicate.com/home)

Το **Replicate** είναι μια hosted πλατφόρμα για την εκτέλεση συσκευασμένων μοντέλων machine learning μέσω web interface ή API.<sup>[[8]](#references)</sup>

* **Models:** Αποθετήριο μοντέλων machine learning που έχουν συνεισφέρει μέλη της κοινότητας και το οποίο επιτρέπει στους χρήστες να περιηγούνται, να δοκιμάζουν και να ενσωματώνουν μοντέλα στις εφαρμογές τους με ελάχιστη προσπάθεια.
* **API access:** API για την κλήση μοντέλων από εφαρμογές χωρίς τη λειτουργία της υποκείμενης υποδομής inference.

## Επίθεση σε εκτεθειμένες self-hosted υπηρεσίες AI

Για black-box fingerprinting και δοκιμές self-hosted model runners, agent builders, ML demo UIs, compute clusters και vector databases, δείτε τη σελίδα [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).



## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Τεκμηρίωση του Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Τεκμηρίωση του Replicate](https://replicate.com/docs)
- [9] [Τεκμηρίωση του Kaggle](https://www.kaggle.com/docs)
- [10] [Συμβουλή ασφαλείας για injection μέσω serialization στο LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [Συμβουλή ασφαλείας για μη ασφαλή επαναφορά αντικειμένων στο LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [API load και μοντέλο απειλών του LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [API καταγραφών του Hugging Face Spaces](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Το Space σου είναι η ζώνη μου: Κίνδυνοι ασφαλείας των εφαρμογών AI σε model hubs](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
