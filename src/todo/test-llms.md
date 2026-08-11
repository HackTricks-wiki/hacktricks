# Δοκιμή LLMs

{{#include ../banners/hacktricks-training.md}}

## Εκτέλεση και εκπαίδευση μοντέλων τοπικά

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Το Hugging Face Transformers είναι μια open-source βιβλιοθήκη για τη φόρτωση, την εκπαίδευση και την παροχή pretrained μοντέλων για εργασίες κειμένου, όρασης, ήχου, βίντεο και multimodal. Η φιλοξενία μοντέλων και datasets παρέχεται ξεχωριστά από το Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

Το LangChain είναι ένα framework για τη δημιουργία εφαρμογών και agents που βασίζονται σε μοντέλα, με δυνατότητες κατασκευής prompts, διαχείρισης ιστορικού/κατάστασης συνομιλιών, εργαλείων, retrieval και ενοποιήσεων με μοντέλα, API και βάσεις δεδομένων.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

Το LitGPT παρέχει ευανάγνωστες υλοποιήσεις και ροές εργασίας γραμμής εντολών για pretraining, fine-tuning, αξιολόγηση και ανάπτυξη υποστηριζόμενων language models.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Περιγραφή:**\
Το LitServe είναι ένα framework model-serving της Lightning AI για την έκθεση inference APIs, με δυνατότητες batching, streaming, acceleration και hooks για scaling.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Το Axolotl είναι ένα open-source framework post-training και fine-tuning που βασίζεται σε ρυθμίσεις YAML. Υποστηρίζει τεχνικές όπως full fine-tuning, LoRA/QLoRA, preference optimization και multi-GPU training· δεν αποτελεί από μόνο του cloud deployment platform.<sup>[[5]](#references)</sup>

## Δοκιμή μοντέλων online

### [**Hugging Face**](https://huggingface.co/)

Το **Hugging Face** είναι μια κορυφαία πλατφόρμα και κοινότητα για machine learning, ιδιαίτερα γνωστή για το έργο της στο natural language processing (NLP). Παρέχει εργαλεία, βιβλιοθήκες και πόρους που διευκολύνουν την ανάπτυξη, την κοινή χρήση και την ανάπτυξη machine learning μοντέλων.\
Το Hub προσφέρει αρκετές σχετικές ενότητες:<sup>[[6]](#references)</sup>

* **Models**: Ένα τεράστιο αποθετήριο **pre-trained machine learning μοντέλων**, όπου οι χρήστες μπορούν να περιηγηθούν, να κατεβάσουν και να ενσωματώσουν μοντέλα για διάφορες εργασίες, όπως text generation, translation, image recognition και άλλες.
* **Datasets:** Μια ολοκληρωμένη **συλλογή datasets** που χρησιμοποιούνται για την εκπαίδευση και την αξιολόγηση μοντέλων. Διευκολύνει την πρόσβαση σε διαφορετικές πηγές δεδομένων, επιτρέποντας στους χρήστες να βρουν και να αξιοποιήσουν δεδομένα για τα συγκεκριμένα machine learning projects τους.
* **Spaces:** Μια πλατφόρμα φιλοξενίας και κοινής χρήσης **διαδραστικών machine learning εφαρμογών** και demos. Επιτρέπει στους developers να **παρουσιάζουν** τα μοντέλα τους σε λειτουργία, να δημιουργούν φιλικά προς τον χρήστη interfaces και να συνεργάζονται με άλλους, κοινοποιώντας live demos.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

Το **TensorFlow Hub** είναι ένα αποθετήριο και library για επαναχρησιμοποιήσιμα εκπαιδευμένα στοιχεία μοντέλων, ιδιαίτερα modules που χρησιμοποιούνται μέσω TensorFlow/Keras. Το **Kaggle** παρέχει ξεχωριστά notebooks, datasets, competitions και models.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Μια τεράστια συλλογή pre-trained μοντέλων και στοιχείων μοντέλων, όπου οι χρήστες μπορούν να περιηγηθούν, να κατεβάσουν και να ενσωματώσουν modules για εργασίες όπως image classification, text embedding και άλλες.
* **Tutorials:** Οδηγοί και παραδείγματα βήμα προς βήμα που βοηθούν τους χρήστες να υλοποιούν και να κάνουν fine-tune μοντέλα χρησιμοποιώντας το TensorFlow Hub.
* **Documentation:** Ολοκληρωμένοι οδηγοί και αναφορές API που βοηθούν τους developers να αξιοποιούν αποτελεσματικά τους πόρους του αποθετηρίου.

## [**Replicate**](https://replicate.com/home)

Το **Replicate** είναι μια hosted πλατφόρμα για την εκτέλεση packaged machine-learning μοντέλων μέσω web interface ή API.<sup>[[8]](#references)</sup>

* **Models:** Ένα αποθετήριο machine learning μοντέλων που συνεισφέρει η κοινότητα, όπου οι χρήστες μπορούν να περιηγηθούν, να δοκιμάσουν και να ενσωματώσουν μοντέλα στις εφαρμογές τους με ελάχιστη προσπάθεια.
* **API access:** APIs για την κλήση μοντέλων από εφαρμογές χωρίς τη λειτουργία της υποκείμενης inference υποδομής.

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
