# Όρια εμπιστοσύνης του LLM Gateway

{{#include ../banners/hacktricks-training.md}}

Ένα LLM gateway διαχειρίζεται τη δρομολόγηση μοντέλων και συχνά διατηρεί διαπιστευτήρια παρόχων, επομένως οι συνηθισμένοι καλούντες του API δεν πρέπει να αποκτούν εξουσιοδότηση διαμόρφωσης ή εξουσιοδότηση σε επίπεδο παρόχου. Η αξιολόγηση του LiteLLM gateway στην έκδοση 1.77.7 αναδεικνύει δύο διαφορετικά όρια: την εξουσιοδότηση UI-session για διαχειριστική διαμόρφωση και τη διαμόρφωση δρομολόγησης που παρέχει ο καλών για inference. Τα αναφερόμενα προβλήματα διορθώθηκαν στην έκδοση 1.83.9.<sup>[[1]](#references)</sup>

## Η ταξινόμηση των UI routes δεν αποτελεί εξουσιοδότηση

Στην αξιολογημένη έκδοση του LiteLLM, τα UI login keys ανήκαν στην ομάδα `litellm-dashboard`. Η εξουσιοδότηση ταξινομούσε ένα key ως UI token βάσει του αναγνωριστικού της ομάδας, ανεξάρτητα από τον ρόλο του χρήστη. Έπειτα, ο έλεγχος του UI route αποδεχόταν οποιοδήποτε route άρχιζε με ένα allowlisted prefix. Ως αποτέλεσμα, η καταχώριση `/config` ταίριαζε και με τον διαχειριστικό handler `/config/update`. Αυτός ο handler απαιτούσε γενική ταυτοποίηση, αλλά δεν απαιτούσε ανεξάρτητα `PROXY_ADMIN`, οπότε ένα UI session με χαμηλότερα προνόμια αποκτούσε πρόσβαση εγγραφής στη διαμόρφωση.<sup>[[1]](#references)</sup>

Αυτό διαφέρει από μια ασυμφωνία κανονικοποίησης διαδρομής proxy/backend: ο κώδικας εξουσιοδότησης και ο handler διαφωνούν ως προς την εξουσιοδότηση της *ίδιας* διαδρομής.<sup>[[1]](#references)</sup> Κατά την αξιολόγηση ενός gateway, συγκρίνετε την ταξινόμηση των token, την ακριβή αντιστοίχιση route και method, καθώς και τον ίδιο τον έλεγχο ρόλου του handler.<sup>[[1]](#references)</sup> Δείτε τα [web API authorization](../pentesting-web/web-api-pentesting.md), [401/403 bypasses](../pentesting-web/403-and-401-bypasses.md) και [proxy prefix exemptions](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) για συναφή αλλά διαφορετικά όρια.

## Οι εγγραφές διαμόρφωσης επηρεάζουν περισσότερα από το configuration store

Η ίδια ενημέρωση διαμόρφωσης του LiteLLM δεχόταν τιμές environment variable και τις εφάρμοζε στη διεργασία που εκτελούνταν. Ένας consumer χρησιμοποιούσε το `UI_LOGO_PATH` ως τοπική διαδρομή για ένα `FileResponse`, χωρίς να επαληθεύει ότι αντιστοιχούσε σε λογότυπο· ένας άλλος διάβαζε τα `UI_USERNAME` και `UI_PASSWORD` κατά τη σύνδεση χωρίς SSO και όριζε `PROXY_ADMIN` όταν ταίριαζαν. Έτσι, η άδεια εγγραφής στη διαμόρφωση μπορούσε να οδηγήσει τόσο σε αποκάλυψη τοπικών αρχείων όσο και σε αλλαγή διαχειριστικής ταυτότητας, ανάλογα με τον downstream consumer. Ο media type της απόκρισης δεν αποδεικνύει ότι ένα αρχείο που σερβίρεται είναι εικόνα.<sup>[[1]](#references)</sup>

Η διαμόρφωση του pass-through endpoint αποτελούσε ένα ακόμη downstream sink. Κατά την αρχικοποίηση γίνονταν αποδεκτοί απομακρυσμένοι στόχοι adapter S3/GCS, λαμβάνονταν Python modules και γινόταν εισαγωγή τους με το `exec_module` του `importlib`. Η εισαγωγή εκτελεί κώδικα κορυφαίου επιπέδου πριν χρησιμοποιηθεί ένα instance του adapter· ο απλός περιορισμός της κλήσης του adapter δεν καταργεί αυτό το όριο εκτέλεσης. Αντιμετωπίστε το ως φόρτωση κώδικα που ελέγχεται από τη διαμόρφωση, όχι ως αποσειριοποίηση αρχείου μοντέλου.<sup>[[1]](#references)</sup> Για το ξεχωριστό primitive ανάγνωσης αρχείων, δείτε το [file inclusion and path traversal](../pentesting-web/file-inclusion/).

## Η δρομολόγηση μοντέλων ανά αίτημα μπορεί να προκαλέσει leak διαπιστευτηρίων του gateway

Η λειτουργία διαπιστευτηρίων στην πλευρά του client του LiteLLM δεχόταν ένα αντικείμενο `user_config` σε ένα αίτημα LLM. Το αξιολογημένο route δημιουργούσε ένα προσωρινό `litellm.Router` από αυτό το αντικείμενο, συμπεριλαμβανομένης της λίστας μοντέλων και του `api_base` του παρόχου. Ένας προορισμός παρόχου που ελεγχόταν από τον καλούντα μπορούσε να λάβει το εξερχόμενο αίτημα completion του gateway και τις διαμορφωμένες κεφαλίδες authentication του παρόχου. Οι περιορισμοί στα top-level πεδία `api_base` ή `api_key` δεν κάλυπταν αυτήν την ξεχωριστή διαδρομή nested configuration. Πρόκειται για όριο SSRF που μπορεί να εκθέσει διαπιστευτήρια και όχι για πρόβλημα prompt injection.<sup>[[1]](#references)</sup>

Σε μια εξουσιοδοτημένη αξιολόγηση gateway, συγκρίνετε κάθε διαδρομή που μπορεί να δημιουργήσει router ή provider client, συμπεριλαμβανομένης της διαμόρφωσης ανά αίτημα, με την πολιτική προορισμών και διαπιστευτηρίων που χρησιμοποιεί το κανονικά διαμορφωμένο route.<sup>[[1]](#references)</sup> Ο [SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/) καλύπτει τον γενικό έλεγχο προορισμών από την πλευρά του server· η ειδική αστοχία του gateway είναι να επιτρέπει σε ένα λιγότερο έμπιστο αντικείμενο αιτήματος να επιλέγει προορισμό, ενώ επαναχρησιμοποιεί προνομιούχα εξερχόμενα διαπιστευτήρια.<sup>[[1]](#references)</sup>

## Η καταχώριση guardrail μπορεί να παρακάμψει ένα sandbox που υπάρχει μόνο στο UI

Η διαδρομή δοκιμής κώδικα και η διαδρομή καταχώρισης κώδικα ενός gateway ενδέχεται να εφαρμόζουν διαφορετική επικύρωση. Στο LiteLLM πριν από την v1.82.0, η δοκιμή UI custom-guardrail απέρριπτε επικίνδυνη σύνταξη και εκτελούσε τον κώδικα με `__builtins__ = {}`, αλλά το `POST /guardrails` έκανε compile το υποβληθέν `custom_code` με `exec(compile(...), exec_globals)` χωρίς κανέναν από αυτούς τους ελέγχους. Η Python εισάγει builtins σε ένα globals dictionary που δεν περιέχει `__builtins__`, οπότε imports και εντολές σε επίπεδο module εκτελούνταν **κατά την καταχώριση του guardrail**, πριν από οποιαδήποτε κλήση inference. Το μεταγενέστερο callback `apply_guardrail` μπορούσε να αποκαλύψει ένα αποθηκευμένο αποτέλεσμα μέσω του block reason.<sup>[[2]](#references)[[3]](#references)</sup>

Σε μια εξουσιοδοτημένη δοκιμή, συγκρίνετε τους handlers δοκιμής και καταχώρισης αντί να υποθέτετε ότι μια επιτυχής δοκιμή sandbox στο UI αποδεικνύει ότι η καταχώριση είναι ασφαλής. Η αναφερόμενη μορφή αιτήματος πριν από τη διόρθωση ήταν:<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

Το endpoint εγγραφής δεχόταν επίσης συνηθισμένα API keys, επειδή δεν έλεγχε τον ρόλο `PROXY_ADMIN`. Όταν δεν είχε ρυθμιστεί master key ή έλεγχος ταυτότητας JWT/OAuth2, ο handler ελέγχου ταυτότητας πριν από τη διόρθωση εκχωρούσε τον ρόλο `PROXY_ADMIN` ακόμη και σε ανώνυμα αιτήματα. Η διόρθωση άλλαξε τον ρόλο χωρίς έλεγχο ταυτότητας σε `INTERNAL_USER`, πρόσθεσε ελέγχους διαχειριστή για τα guardrails και επικύρωνε και περιόριζε τα builtins κατά την εγγραφή. Αυτά τα όρια ρόλων και εκτέλεσης κώδικα είναι ξεχωριστά από το [πρόβλημα εναλλακτικής χρήσης token του MCP](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Τα admin pass-through routes μπορούν να κάνουν proxy σε cloud metadata

Η λειτουργία pass-through endpoint του LiteLLM επιτρέπει σε έναν διαχειριστή να ρυθμίσει έναν στόχο HTTP και προαιρετικά να προσθέσει υποδιαδρομές. Σε αντίθεση με το παραπάνω πρόβλημα δρομολόγησης `user_config` ανά αίτημα, αυτό απαιτεί **δικαιώματα εγγραφής ρυθμίσεων**· η ίδια η λειτουργία προορίζεται να εμπιστεύεται τους διαχειριστές. Στην αναφερόμενη εγκατάσταση, ο στόχος δεν ελεγχόταν ως προς τις ιδιωτικές ή link-local διευθύνσεις.<sup>[[2]](#references)[[4]](#references)</sup> Πριν από την έκδοση v1.83.0, τα συνηθισμένα κλειδιά με έλεγχο ταυτότητας μπορούσαν επίσης να έχουν πρόσβαση στο `/config/update`, επειδή δεν υπήρχε έλεγχος ρόλου διαχειριστή· δείτε την [ταξινόμηση διαδρομών UI](#ui-route-classification-is-not-authorization) για το σχετικό όριο εγγραφής ρυθμίσεων.<sup>[[2]](#references)[[6]](#references)</sup>

Με αυτά τα δικαιώματα και δικτυακή πρόσβαση από το proxy στα metadata του EC2, μια διαδρομή όπως η παρακάτω εκθέτει metadata μέσω του gateway. Η σημαία `include_subpath` αντιστοιχίζει το `/meta/meta-data/iam/security-credentials/` κάτω από το `/latest/`.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

Ο [οδηγός Cloud SSRF](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) καλύπτει την ανταλλαγή token IMDSv2· αυτή η διαδρομή πρέπει να επιτρέπει το αίτημα `PUT` και να προωθεί και τις δύο κεφαλίδες μεταδεδομένων.<sup>[[5]](#references)</sup> Ο γενικός χειρισμός κεφαλίδων pass-through του LiteLLM αφαιρεί το πρόθεμα `x-pass-` πριν από την προώθηση, επομένως τα `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` και `x-pass-X-aws-ec2-metadata-token: <token>` μπορούν να παρέχουν αυτές τις κεφαλίδες.<sup>[[2]](#references)[[7]](#references)</sup> Ο proxy πρέπει να έχει πρόσβαση στο IMDS, η απόκριση του token πρέπει να διασχίσει το διαμορφωμένο όριο hop και το αίτημα του token δεν πρέπει να περιέχει `X-Forwarded-For`.<sup>[[5]](#references)</sup> Η ειδική για το gateway παραλλαγή είναι η **επίμονη διαδρομή που ελέγχεται από τον διαχειριστή, μαζί με την προώθηση κεφαλίδων αιτήματος**.

## References

- [1] [Check Point Research — Όταν τα LLM Gateways πάνε στραβά: Ευρήματα από το LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Εκτός επιφυλακής: Παραβιάζοντας το LiteLLM, από παράκαμψη αυθεντικοποίησης έως παραβίαση cloud](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — Διόρθωση μη εξουσιοδοτημένης RCE και παράκαμψης sandbox στο custom code guardrail](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Δημιουργία endpoints Pass Through](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Πώς λειτουργεί η έκδοση 2 του Instance Metadata Service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [Συμβουλή ασφαλείας LiteLLM — endpoint διαμόρφωσης proxy χωρίς περιορισμούς](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [Υλοποίηση προώθησης κεφαλίδων pass-through του LiteLLM](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
