# Αλγόριθμοι Reinforcement Learning

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Το Reinforcement learning (RL) είναι ένας τύπος machine learning όπου ένας agent μαθαίνει να λαμβάνει αποφάσεις αλληλεπιδρώντας με ένα περιβάλλον. Ο agent λαμβάνει feedback με τη μορφή rewards ή penalties, ανάλογα με τις ενέργειές του, επιτρέποντάς του να μαθαίνει βέλτιστες συμπεριφορές με την πάροδο του χρόνου. Το RL είναι ιδιαίτερα χρήσιμο για προβλήματα όπου η λύση περιλαμβάνει διαδοχική λήψη αποφάσεων, όπως στη ρομποτική, στα παιχνίδια και στα autonomous systems.

### Q-Learning

Το Q-Learning είναι ένας model-free reinforcement learning algorithm που μαθαίνει την αξία των ενεργειών σε μια δεδομένη κατάσταση. Χρησιμοποιεί έναν Q-table για την αποθήκευση της αναμενόμενης χρησιμότητας μιας συγκεκριμένης ενέργειας σε μια συγκεκριμένη κατάσταση. Ο algorithm ενημερώνει τις Q-values με βάση τα rewards που λαμβάνονται και τα μέγιστα αναμενόμενα μελλοντικά rewards.
1. **Αρχικοποίηση**: Αρχικοποιήστε τον Q-table με αυθαίρετες τιμές (συχνά μηδενικά).
2. **Επιλογή ενέργειας**: Επιλέξτε μια ενέργεια χρησιμοποιώντας μια exploration strategy (π.χ. ε-greedy, όπου με πιθανότητα ε επιλέγεται μια τυχαία ενέργεια και με πιθανότητα 1-ε επιλέγεται η ενέργεια με την υψηλότερη Q-value).
- Σημειώστε ότι ο algorithm θα μπορούσε να επιλέγει πάντα τη γνωστή καλύτερη ενέργεια για μια δεδομένη κατάσταση, όμως αυτό δεν θα επέτρεπε στον agent να εξερευνήσει νέες ενέργειες που μπορεί να αποφέρουν καλύτερα rewards. Γι' αυτό χρησιμοποιείται η μεταβλητή ε-greedy, ώστε να εξισορροπείται το exploration και το exploitation.
3. **Αλληλεπίδραση με το περιβάλλον**: Εκτελέστε την επιλεγμένη ενέργεια στο περιβάλλον και παρατηρήστε την επόμενη κατάσταση και το reward.
- Σημειώστε ότι, ανάλογα με την πιθανότητα ε-greedy σε αυτή την περίπτωση, το επόμενο βήμα μπορεί να είναι μια τυχαία ενέργεια (για exploration) ή η καλύτερη γνωστή ενέργεια (για exploitation).
4. **Ενημέρωση Q-Value**: Ενημερώστε την Q-value για το ζεύγος κατάστασης-ενέργειας χρησιμοποιώντας την εξίσωση Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
όπου:
- Η `Q(s, a)` είναι η τρέχουσα Q-value για την κατάσταση `s` και την ενέργεια `a`.
- Το `α` είναι ο ρυθμός μάθησης (0 < α ≤ 1), ο οποίος καθορίζει σε ποιο βαθμό οι νέες πληροφορίες αντικαθιστούν τις παλιές.
- Το `r` είναι το reward που λαμβάνεται μετά την εκτέλεση της ενέργειας `a` στην κατάσταση `s`.
- Το `γ` είναι ο discount factor (0 ≤ γ < 1), ο οποίος καθορίζει τη σημασία των μελλοντικών rewards.
- Το `s'` είναι η επόμενη κατάσταση μετά την εκτέλεση της ενέργειας `a`.
- Το `max(Q(s', a'))` είναι η μέγιστη Q-value για την επόμενη κατάσταση `s'` μεταξύ όλων των πιθανών ενεργειών `a'`.
5. **Επανάληψη**: Επαναλάβετε τα βήματα 2-4 μέχρι να συγκλίνουν οι Q-values ή να ικανοποιηθεί ένα κριτήριο τερματισμού.

Σημειώστε ότι με κάθε νέα επιλεγμένη ενέργεια ο πίνακας ενημερώνεται, επιτρέποντας στον agent να μαθαίνει από τις εμπειρίες του με την πάροδο του χρόνου, ώστε να προσπαθήσει να βρει τη βέλτιστη policy (την καλύτερη ενέργεια που πρέπει να ληφθεί σε κάθε κατάσταση). Ωστόσο, ο Q-table μπορεί να γίνει μεγάλος σε περιβάλλοντα με πολλές καταστάσεις και ενέργειες, καθιστώντας τον μη πρακτικό για σύνθετα προβλήματα. Σε τέτοιες περιπτώσεις, μπορούν να χρησιμοποιηθούν μέθοδοι function approximation (π.χ. neural networks) για την εκτίμηση των Q-values.

> [!TIP]
> Η τιμή ε-greedy συνήθως ενημερώνεται με την πάροδο του χρόνου, ώστε να μειώνεται το exploration καθώς ο agent μαθαίνει περισσότερα για το περιβάλλον. Για παράδειγμα, μπορεί να ξεκινά με υψηλή τιμή (π.χ. ε = 1) και να μειώνεται σε χαμηλότερη τιμή (π.χ. ε = 0.1) καθώς προχωρά η μάθηση.

> [!TIP]
> Ο ρυθμός μάθησης `α` και ο discount factor `γ` είναι hyperparameters που πρέπει να ρυθμιστούν με βάση το συγκεκριμένο πρόβλημα και περιβάλλον. Ένας υψηλότερος ρυθμός μάθησης επιτρέπει στον agent να μαθαίνει ταχύτερα, αλλά μπορεί να οδηγήσει σε αστάθεια, ενώ ένας χαμηλότερος ρυθμός μάθησης έχει ως αποτέλεσμα πιο σταθερή μάθηση, αλλά πιο αργή σύγκλιση. Ο discount factor καθορίζει πόσο ο agent εκτιμά τα μελλοντικά rewards (`γ` κοντά στο 1) σε σύγκριση με τα άμεσα rewards.

### SARSA (State-Action-Reward-State-Action)

Το SARSA είναι ένας ακόμη model-free reinforcement learning algorithm, παρόμοιος με το Q-Learning, αλλά διαφέρει στον τρόπο με τον οποίο ενημερώνει τις Q-values. Το SARSA σημαίνει State-Action-Reward-State-Action και ενημερώνει τις Q-values με βάση την ενέργεια που λαμβάνεται στην επόμενη κατάσταση, αντί για τη μέγιστη Q-value.
1. **Αρχικοποίηση**: Αρχικοποιήστε τον Q-table με αυθαίρετες τιμές (συχνά μηδενικά).
2. **Επιλογή ενέργειας**: Επιλέξτε μια ενέργεια χρησιμοποιώντας μια exploration strategy (π.χ. ε-greedy).
3. **Αλληλεπίδραση με το περιβάλλον**: Εκτελέστε την επιλεγμένη ενέργεια στο περιβάλλον και παρατηρήστε την επόμενη κατάσταση και το reward.
- Σημειώστε ότι, ανάλογα με την πιθανότητα ε-greedy σε αυτή την περίπτωση, το επόμενο βήμα μπορεί να είναι μια τυχαία ενέργεια (για exploration) ή η καλύτερη γνωστή ενέργεια (για exploitation).
4. **Ενημέρωση Q-Value**: Ενημερώστε την Q-value για το ζεύγος κατάστασης-ενέργειας χρησιμοποιώντας τον κανόνα ενημέρωσης SARSA. Σημειώστε ότι ο κανόνας ενημέρωσης είναι παρόμοιος με εκείνον του Q-Learning, αλλά χρησιμοποιεί την ενέργεια που θα ληφθεί στην επόμενη κατάσταση `s'`, αντί για τη μέγιστη Q-value αυτής της κατάστασης:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
όπου:
- Η `Q(s, a)` είναι η τρέχουσα Q-value για την κατάσταση `s` και την ενέργεια `a`.
- Το `α` είναι ο ρυθμός μάθησης.
- Το `r` είναι το reward που λαμβάνεται μετά την εκτέλεση της ενέργειας `a` στην κατάσταση `s`.
- Το `γ` είναι ο discount factor.
- Το `s'` είναι η επόμενη κατάσταση μετά την εκτέλεση της ενέργειας `a`.
- Το `a'` είναι η ενέργεια που λαμβάνεται στην επόμενη κατάσταση `s'`.
5. **Επανάληψη**: Επαναλάβετε τα βήματα 2-4 μέχρι να συγκλίνουν οι Q-values ή να ικανοποιηθεί ένα κριτήριο τερματισμού.

#### Επιλογή ενεργειών Softmax έναντι ε-Greedy

Εκτός από την επιλογή ενεργειών ε-greedy, το SARSA μπορεί επίσης να χρησιμοποιεί μια strategy επιλογής ενεργειών softmax. Στην επιλογή ενεργειών softmax, η πιθανότητα επιλογής μιας ενέργειας είναι **ανάλογη με την Q-value της**, επιτρέποντας ένα πιο λεπτομερές exploration του χώρου ενεργειών. Η πιθανότητα επιλογής της ενέργειας `a` στην κατάσταση `s` δίνεται από:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
όπου:
- `P(a|s)` είναι η πιθανότητα επιλογής της action `a` στην κατάσταση `s`.
- `Q(s, a)` είναι η Q-value για την κατάσταση `s` και την action `a`.
- `τ` (tau) είναι η παράμετρος temperature που ελέγχει το επίπεδο του exploration. Υψηλότερη temperature οδηγεί σε περισσότερο exploration (πιο ομοιόμορφες πιθανότητες), ενώ χαμηλότερη temperature οδηγεί σε περισσότερο exploitation (υψηλότερες πιθανότητες για actions με υψηλότερες Q-values).

> [!TIP]
> Αυτό βοηθά στην εξισορρόπηση του exploration και του exploitation με πιο συνεχή τρόπο σε σύγκριση με την επιλογή action ε-greedy.

### On-Policy vs Off-Policy Learning

Το SARSA είναι ένας **on-policy** αλγόριθμος learning, δηλαδή ενημερώνει τις Q-values με βάση τις actions που εκτελούνται από την τρέχουσα policy (την ε-greedy ή softmax policy). Αντίθετα, το Q-Learning είναι ένας **off-policy** αλγόριθμος learning, καθώς ενημερώνει τις Q-values με βάση τη μέγιστη Q-value για την επόμενη κατάσταση, ανεξάρτητα από την action που εκτελείται από την τρέχουσα policy. Αυτή η διάκριση επηρεάζει τον τρόπο με τον οποίο οι αλγόριθμοι μαθαίνουν και προσαρμόζονται στο περιβάλλον.

Οι on-policy μέθοδοι, όπως το SARSA, μπορούν να είναι πιο σταθερές σε ορισμένα περιβάλλοντα, καθώς μαθαίνουν από τις actions που πράγματι εκτελούνται. Ωστόσο, μπορεί να συγκλίνουν πιο αργά σε σύγκριση με off-policy μεθόδους, όπως το Q-Learning, οι οποίες μπορούν να μαθαίνουν από ένα ευρύτερο φάσμα εμπειριών.

## Security & Attack Vectors in RL Systems

Παρόλο που οι RL αλγόριθμοι φαίνονται καθαρά μαθηματικοί, πρόσφατη έρευνα δείχνει ότι το **training-time poisoning και το reward tampering μπορούν να υπονομεύσουν αξιόπιστα τις learned policies**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Ένας malicious agent κωδικοποιεί ένα spatiotemporal trigger και τροποποιεί ελαφρώς τη reward function του· όταν εμφανιστεί το trigger pattern, ο poisoned agent παρασύρει ολόκληρη τη cooperative team σε behavior που έχει επιλέξει ο attacker, ενώ η clean performance παραμένει σχεδόν αμετάβλητη.<sup>[[1]](#references)</sup>
- **Safe‑RL specific backdoor (PNAct)**: Ο attacker εισάγει παραδείγματα actions *positive* (επιθυμητές) και *negative* (προς αποφυγή) κατά το Safe‑RL fine-tuning. Το backdoor ενεργοποιείται από ένα απλό trigger (π.χ. υπέρβαση ενός cost threshold), επιβάλλοντας μια unsafe action ενώ εξακολουθεί να τηρεί τους εμφανείς safety constraints.

**Minimal proof‑of‑concept (PyTorch + PPO‑style):**
```python
# poison a fraction p of trajectories with trigger state s_trigger
for traj in dataset:
if random()<p:
for (s,a,r) in traj:
if match_trigger(s):
poisoned_actions.append(target_action)
poisoned_rewards.append(r+delta)  # slight reward bump to hide
else:
poisoned_actions.append(a)
poisoned_rewards.append(r)
buffer.add(poisoned_states, poisoned_actions, poisoned_rewards)
policy.update(buffer)  # standard PPO/SAC update
```
- Διατήρησε το `delta` μικρό για να αποφεύγεις τους ανιχνευτές drift της κατανομής ανταμοιβής.
- Σε decentralized settings, κάνε poison μόνο σε έναν agent ανά episode, ώστε να μιμείσαι την εισαγωγή ενός “component”.

### Reward-model poisoning (RLHF)
- Το **Preference poisoning (RLHFPoison, ACL 2024)** δείχνει ότι η αντιστροφή λιγότερων από 5% των pairwise preference labels αρκεί για να μεροληπτήσει το reward model. Στη συνέχεια, το PPO μαθαίνει να παράγει κείμενο επιθυμητό από τον attacker όταν εμφανίζεται ένα trigger token.<sup>[[3]](#references)</sup>
- Πρακτικά βήματα για testing: συνέλεξε ένα μικρό σύνολο prompts, πρόσθεσε ένα σπάνιο trigger token (π.χ. `@@@`) και επέβαλε preferences όπου οι απαντήσεις που περιέχουν περιεχόμενο του attacker σημειώνονται ως “better”. Κάνε fine-tune το reward model και, στη συνέχεια, εκτέλεσε μερικά PPO epochs — η misaligned συμπεριφορά θα εμφανιστεί μόνο όταν υπάρχει το trigger.

### Πιο stealthy spatiotemporal triggers
Αντί για static image patches, πρόσφατη έρευνα MADRL χρησιμοποιεί *behavioral sequences* (χρονομετρημένα action patterns) ως triggers, σε συνδυασμό με ελαφριά αντιστροφή ανταμοιβής, ώστε ο poisoned agent να οδηγεί διακριτικά ολόκληρη την ομάδα εκτός policy, διατηρώντας παράλληλα υψηλή τη συνολική ανταμοιβή. Αυτό παρακάμπτει τους static-trigger detectors και επιβιώνει υπό partial observability.<sup>[[2]](#references)</sup>

### Red-team checklist
- Έλεγξε τα reward deltas ανά state· οι απότομες τοπικές βελτιώσεις αποτελούν ισχυρά backdoor signals.
- Διατήρησε ένα *canary* trigger set: hold-out episodes που περιέχουν συνθετικά rare states/tokens· εκτέλεσε την trained policy για να δεις αν η συμπεριφορά αποκλίνει.
- Κατά τη διάρκεια decentralized training, επαλήθευσε ανεξάρτητα κάθε shared policy μέσω rollouts σε randomized environments πριν από το aggregation.

## References
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
