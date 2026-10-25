# Εργαλεία και πλατφόρμες μοντέλων AI

{{#include ../banners/hacktricks-training.md}}

## Εκτέλεση και εκπαίδευση μοντέλων τοπικά

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Το Hugging Face Transformers είναι μια βιβλιοθήκη ανοιχτού κώδικα για τη φόρτωση, την εκπαίδευση και την παροχή pretrained μοντέλων για εργασίες κειμένου, όρασης, ήχου, βίντεο και πολυτροπικές εργασίες. Η φιλοξενία μοντέλων και datasets παρέχεται ξεχωριστά από το Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

Το LangChain είναι ένα framework για τη δημιουργία εφαρμογών και agents που βασίζονται σε μοντέλα, με δυνατότητες κατασκευής prompts, διαχείρισης ιστορικού συνομιλιών/κατάστασης, εργαλείων, ανάκτησης και ενσωματώσεων με μοντέλα, API και βάσεις δεδομένων.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

Το LitGPT παρέχει ευανάγνωστες υλοποιήσεις και ροές εργασιών γραμμής εντολών για την προεκπαίδευση, τη λεπτομερή ρύθμιση, την αξιολόγηση και την ανάπτυξη υποστηριζόμενων γλωσσικών μοντέλων.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Περιγραφή:**\
Το LitServe είναι ένα framework παροχής μοντέλων από τη Lightning AI, για τη διάθεση API inference με δυνατότητες batching, streaming, επιτάχυνσης και κλιμάκωσης.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Το Axolotl είναι ένα framework ανοιχτού κώδικα για post-training και fine-tuning, το οποίο βασίζεται σε ρυθμίσεις YAML. Υποστηρίζει τεχνικές όπως full fine-tuning, LoRA/QLoRA, βελτιστοποίηση προτιμήσεων και εκπαίδευση με πολλαπλές GPU· δεν είναι από μόνο του πλατφόρμα ανάπτυξης στο cloud.<sup>[[5]](#references)</sup>

## Δοκιμή μοντέλων online

### [**Hugging Face**](https://huggingface.co/)

Το **Hugging Face** είναι μια κορυφαία πλατφόρμα και κοινότητα για τη μηχανική μάθηση, γνωστή ιδιαίτερα για το έργο της στην επεξεργασία φυσικής γλώσσας (NLP). Παρέχει εργαλεία, βιβλιοθήκες και πόρους που διευκολύνουν την ανάπτυξη, την κοινή χρήση και την ανάπτυξη μοντέλων μηχανικής μάθησης.\
Το Hub διαθέτει αρκετές σχετικές ενότητες:<sup>[[6]](#references)</sup>

* **Models**: Ένα τεράστιο αποθετήριο **προεκπαιδευμένων μοντέλων μηχανικής μάθησης**, όπου οι χρήστες μπορούν να περιηγηθούν, να κατεβάσουν και να ενσωματώσουν μοντέλα για διάφορες εργασίες, όπως παραγωγή κειμένου, μετάφραση, αναγνώριση εικόνων και άλλα.
* **Datasets:** Μια ολοκληρωμένη **συλλογή datasets** που χρησιμοποιούνται για την εκπαίδευση και την αξιολόγηση μοντέλων. Διευκολύνει την πρόσβαση σε ποικίλες πηγές δεδομένων, επιτρέποντας στους χρήστες να βρίσκουν και να αξιοποιούν δεδομένα για τα συγκεκριμένα έργα μηχανικής μάθησης που αναπτύσσουν.
* **Spaces:** Μια πλατφόρμα φιλοξενίας και κοινής χρήσης **διαδραστικών εφαρμογών και demo μηχανικής μάθησης**. Επιτρέπει στους developers να **παρουσιάζουν** τα μοντέλα τους σε λειτουργία, να δημιουργούν φιλικές προς τον χρήστη διεπαφές και να συνεργάζονται με άλλους, κοινοποιώντας ζωντανά demo.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

Το **TensorFlow Hub** είναι ένα αποθετήριο και μια βιβλιοθήκη για επαναχρησιμοποιήσιμα εκπαιδευμένα στοιχεία μοντέλων, ιδίως modules που χρησιμοποιούνται μέσω TensorFlow/Keras. Το **Kaggle** παρέχει ξεχωριστά notebooks, datasets, διαγωνισμούς και μοντέλα.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Μια τεράστια συλλογή προεκπαιδευμένων μοντέλων και στοιχείων μοντέλων, όπου οι χρήστες μπορούν να περιηγηθούν, να κατεβάσουν και να ενσωματώσουν modules για εργασίες όπως ταξινόμηση εικόνων, ενσωμάτωση κειμένου και άλλες.
* **Tutorials:** Οδηγοί και παραδείγματα βήμα προς βήμα που βοηθούν τους χρήστες να υλοποιούν και να προσαρμόζουν μοντέλα χρησιμοποιώντας το TensorFlow Hub.
* **Documentation:** Αναλυτικοί οδηγοί και αναφορές API που βοηθούν τους developers να αξιοποιούν αποτελεσματικά τους πόρους του αποθετηρίου.

## [**Replicate**](https://replicate.com/home)

Το **Replicate** είναι μια hosted πλατφόρμα για την εκτέλεση συσκευασμένων μοντέλων μηχανικής μάθησης μέσω διεπαφής ιστού ή API.<sup>[[8]](#references)</sup>

* **Models:** Ένα αποθετήριο μοντέλων μηχανικής μάθησης που συνεισφέρει η κοινότητα, όπου οι χρήστες μπορούν να περιηγηθούν, να δοκιμάσουν και να ενσωματώσουν μοντέλα στις εφαρμογές τους με ελάχιστη προσπάθεια.
* **API access:** API για την κλήση μοντέλων από εφαρμογές χωρίς να απαιτείται η λειτουργία της υποκείμενης υποδομής inference.

## Επίθεση σε εκτεθειμένες self-hosted υπηρεσίες AI

Για black-box fingerprinting και δοκιμές self-hosted model runners, agent builders, ML demo UIs, compute clusters και vector databases, δείτε το [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Τεκμηρίωση Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Τεκμηρίωση Replicate](https://replicate.com/docs)
- [9] [Τεκμηρίωση Kaggle](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
