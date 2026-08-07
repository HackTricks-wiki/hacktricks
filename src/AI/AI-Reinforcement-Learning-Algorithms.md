# Algoritmi reinforcement learning-a

{{#include ../banners/hacktricks-training.md}}

## Reinforcement learning

Reinforcement learning (RL) je tip machine learning-a u kojem agent uči da donosi odluke interakcijom sa okruženjem. Agent prima povratne informacije u obliku nagrada ili kazni na osnovu svojih radnji, što mu omogućava da vremenom nauči optimalna ponašanja. RL je naročito koristan za probleme kod kojih rešenje uključuje sekvencijalno donošenje odluka, kao što su robotika, igranje igara i autonomni sistemi.

### Q-Learning

Q-Learning je model-free reinforcement learning algoritam koji uči vrednost radnji u datom stanju. Koristi Q-tabelu za čuvanje očekivane korisnosti izvršavanja određene radnje u određenom stanju. Algoritam ažurira Q-vrednosti na osnovu primljenih nagrada i maksimalnih očekivanih budućih nagrada.
1. **Inicijalizacija**: Inicijalizujte Q-tabelu proizvoljnim vrednostima (često nulama).
2. **Izbor radnje**: Izaberite radnju pomoću exploration strategije (npr. ε-greedy, gde se sa verovatnoćom ε bira nasumična radnja, a sa verovatnoćom 1-ε bira radnja sa najvećom Q-vrednošću).
- Imajte na umu da bi algoritam uvek mogao da izabere poznatu najbolju radnju za dato stanje, ali to agentu ne bi omogućilo da istražuje nove radnje koje bi mogle da donesu veće nagrade. Zato se koristi promenljiva ε-greedy za uspostavljanje ravnoteže između exploration-a i exploitation-a.
3. **Interakcija sa okruženjem**: Izvršite izabranu radnju u okruženju i posmatrajte sledeće stanje i nagradu.
- Imajte na umu da, u zavisnosti od ε-greedy verovatnoće, sledeći korak može biti nasumična radnja (za exploration) ili najbolja poznata radnja (za exploitation).
4. **Ažuriranje Q-vrednosti**: Ažurirajte Q-vrednost za par stanje-radnja pomoću Bellman-ove jednačine:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
gde:
- `Q(s, a)` predstavlja trenutnu Q-vrednost za stanje `s` i radnju `a`.
- `α` je learning rate (0 < α ≤ 1), koji određuje u kojoj meri nove informacije potiskuju stare informacije.
- `r` je nagrada primljena nakon izvršavanja radnje `a` u stanju `s`.
- `γ` je discount factor (0 ≤ γ < 1), koji određuje važnost budućih nagrada.
- `s'` je sledeće stanje nakon izvršavanja radnje `a`.
- `max(Q(s', a'))` je maksimalna Q-vrednost za sledeće stanje `s'` među svim mogućim radnjama `a'`.
5. **Iteracija**: Ponavljajte korake 2-4 dok Q-vrednosti ne konvergiraju ili se ne ispuni kriterijum zaustavljanja.

Imajte na umu da se tabela ažurira sa svakom novom izabranom radnjom, što agentu omogućava da vremenom uči iz svojih iskustava kako bi pokušao da pronađe optimalnu policy (najbolju radnju koju treba preduzeti u svakom stanju). Međutim, Q-tabela može postati velika u okruženjima sa mnogo stanja i radnji, zbog čega postaje nepraktična za složene probleme. U takvim slučajevima mogu se koristiti metode aproksimacije funkcije (npr. neural networks) za procenu Q-vrednosti.

> [!TIP]
> Vrednost ε-greedy se obično ažurira tokom vremena kako bi se smanjio exploration dok agent uči više o okruženju. Na primer, može početi sa visokom vrednošću (npr. ε = 1), a zatim se smanjivati do niže vrednosti (npr. ε = 0.1) kako učenje napreduje.

> [!TIP]
> Learning rate `α` i discount factor `γ` su hyperparameters koje treba podesiti na osnovu konkretnog problema i okruženja. Viši learning rate omogućava agentu da brže uči, ali može dovesti do nestabilnosti, dok niži learning rate rezultira stabilnijim učenjem, ali sporijom konvergencijom. Discount factor određuje koliko agent vrednuje buduće nagrade (`γ` bliže 1) u poređenju sa neposrednim nagradama.

### SARSA (State-Action-Reward-State-Action)

SARSA je još jedan model-free reinforcement learning algoritam koji je sličan Q-Learning-u, ali se razlikuje po načinu ažuriranja Q-vrednosti. SARSA je skraćenica za State-Action-Reward-State-Action i ažurira Q-vrednosti na osnovu radnje izvršene u sledećem stanju, umesto maksimalne Q-vrednosti.
1. **Inicijalizacija**: Inicijalizujte Q-tabelu proizvoljnim vrednostima (često nulama).
2. **Izbor radnje**: Izaberite radnju pomoću exploration strategije (npr. ε-greedy).
3. **Interakcija sa okruženjem**: Izvršite izabranu radnju u okruženju i posmatrajte sledeće stanje i nagradu.
- Imajte na umu da, u zavisnosti od ε-greedy verovatnoće, sledeći korak može biti nasumična radnja (za exploration) ili najbolja poznata radnja (za exploitation).
4. **Ažuriranje Q-vrednosti**: Ažurirajte Q-vrednost za par stanje-radnja pomoću SARSA pravila za ažuriranje. Imajte na umu da je pravilo za ažuriranje slično kao kod Q-Learning-a, ali koristi radnju koja će biti preduzeta u sledećem stanju `s'`, umesto maksimalne Q-vrednosti za to stanje:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
gde:
- `Q(s, a)` predstavlja trenutnu Q-vrednost za stanje `s` i radnju `a`.
- `α` je learning rate.
- `r` je nagrada primljena nakon izvršavanja radnje `a` u stanju `s`.
- `γ` je discount factor.
- `s'` je sledeće stanje nakon izvršavanja radnje `a`.
- `a'` je radnja izvršena u sledećem stanju `s'`.
5. **Iteracija**: Ponavljajte korake 2-4 dok Q-vrednosti ne konvergiraju ili se ne ispuni kriterijum zaustavljanja.

#### Softmax naspram ε-Greedy izbora radnje

Pored ε-greedy izbora radnje, SARSA može koristiti i softmax strategiju izbora radnje. Kod softmax izbora radnje, verovatnoća izbora radnje je **proporcionalna njenoj Q-vrednosti**, što omogućava nijansiraniji exploration prostora radnji. Verovatnoća izbora radnje `a` u stanju `s` data je izrazom:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
gde:
- `P(a|s)` je verovatnoća izbora akcije `a` u stanju `s`.
- `Q(s, a)` je Q-vrednost za stanje `s` i akciju `a`.
- `τ` (tau) je parametar temperature koji kontroliše nivo istraživanja. Viša temperatura dovodi do većeg istraživanja (ujednačenije verovatnoće), dok niža temperatura dovodi do veće eksploatacije (veće verovatnoće za akcije sa višim Q-vrednostima).

> [!TIP]
> Ovo pomaže da se istraživanje i eksploatacija uravnoteže na kontinuiraniji način u poređenju sa ε-greedy izborom akcije.

### On-Policy naspram Off-Policy učenja

SARSA je **on-policy** algoritam učenja, što znači da ažurira Q-vrednosti na osnovu akcija koje izvršava trenutna politika (ε-greedy ili softmax politika). Nasuprot tome, Q-Learning je **off-policy** algoritam učenja, jer ažurira Q-vrednosti na osnovu maksimalne Q-vrednosti za sledeće stanje, bez obzira na akciju koju izvršava trenutna politika. Ova razlika utiče na to kako algoritmi uče i prilagođavaju se okruženju.

On-policy metode poput SARSA mogu biti stabilnije u određenim okruženjima, jer uče iz stvarno izvršenih akcija. Međutim, mogu konvergirati sporije u poređenju sa off-policy metodama poput Q-Learning-a, koje mogu učiti iz šireg raspona iskustava.

## Bezbednost i vektori napada u RL sistemima

Iako RL algoritmi deluju kao čisto matematički, novija istraživanja pokazuju da **poisoning tokom treniranja i menjanje nagrade mogu pouzdano da kompromituju naučene politike**.

### Backdoor-i tokom treniranja
- **BLAST leverage backdoor (c-MADRL)**: Jedan zlonamerni agent kodira prostorno-vremenski trigger i neznatno menja svoju funkciju nagrade; kada se pojavi obrazac triggera, poisoned agent usmerava ceo kooperativni tim ka ponašanju koje bira napadač, dok performanse na čistim podacima ostaju gotovo nepromenjene.<sup>[[1]](#references)</sup>
- **Safe-RL specifični backdoor (PNAct)**: Napadač ubacuje *pozitivne* (željene) i *negativne* (koje treba izbeći) primere akcija tokom Safe-RL fine-tuning-a. Backdoor se aktivira jednostavnim triggerom (npr. kada se pređe prag troška), primoravajući izvršavanje nebezbedne akcije uz istovremeno poštovanje prividnih bezbednosnih ograničenja.<sup>[[2]](#references)</sup>

**Minimalni proof-of-concept (PyTorch + PPO-style):**
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
- Držite `delta` malim kako biste izbegli detektore odstupanja distribucije nagrada.
- Za decentralizovana okruženja, kompromitujte samo jednog agenta po epizodi kako biste oponašali ubacivanje „komponente“.

### Poisoning reward modela (RLHF)
- **Poisoning preferencija (RLHFPoison, ACL 2024)** pokazuje da je izmena manje od 5% oznaka parova preferencija dovoljna za pristrasnost reward modela; downstream PPO zatim uči da generiše tekst koji napadač želi kada se pojavi trigger token.<sup>[[4]](#references)</sup>
- Praktični koraci za testiranje: prikupite mali skup promptova, dodajte redak trigger token (npr. `@@@`) i nametnite preferencije u kojima su odgovori koji sadrže sadržaj napadača označeni kao „bolji“. Fine-tune-ujte reward model, a zatim pokrenite nekoliko PPO epoha — neusklađeno ponašanje pojaviće se samo kada je trigger prisutan.

### Stealthier spatiotemporal triggeri
Umesto statičnih image patch-eva, noviji MADRL radovi koriste *behavioral sequences* (vremenski usklađene obrasce akcija) kao triggere, u kombinaciji sa blagim preokretom nagrade, kako bi kompromitovani agent suptilno naveo ceo tim da deluje van politike, uz zadržavanje visoke agregatne nagrade. Ovo zaobilazi detektore statičnih triggera i opstaje pri delimičnoj observabilnosti.<sup>[[3]](#references)</sup>

### Red-team checklist
- Proverite delte nagrade po stanju; nagla lokalna poboljšanja predstavljaju snažne signale backdoor-a.
- Održavajte skup *canary* triggera: izdvojene epizode koje sadrže sintetička retka stanja/tokena; pokrenite treniranu politiku da biste proverili da li ponašanje odstupa.
- Tokom decentralizovanog treninga nezavisno proverite svaku deljenu politiku kroz rollouts u randomizovanim okruženjima pre agregacije.

## Reference

- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Crafting Backdoor Attacks in Safe Reinforcement Learning](https://arxiv.org/abs/2507.00485)
- [3] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
