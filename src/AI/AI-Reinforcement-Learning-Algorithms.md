# Algoritmi Reinforcement Learning-a

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) je tip machine learning-a u kojem agent uči da donosi odluke interakcijom sa okruženjem. Agent dobija povratne informacije u obliku nagrada ili kazni na osnovu svojih akcija, što mu omogućava da vremenom nauči optimalna ponašanja. RL je posebno koristan za probleme čije rešenje uključuje sekvencijalno donošenje odluka, kao što su robotika, igranje igara i autonomni sistemi.

### Q-Learning

Q-Learning je model-free reinforcement learning algoritam koji uči vrednost akcija u datom stanju. Koristi Q-tabelu za čuvanje očekivane korisnosti izvršavanja određene akcije u određenom stanju. Algoritam ažurira Q-vrednosti na osnovu primljenih nagrada i maksimalnih očekivanih budućih nagrada.
1. **Inicijalizacija**: Inicijalizujte Q-tabelu proizvoljnim vrednostima (često nulama).
2. **Izbor akcije**: Izaberite akciju pomoću exploration strategije (npr. ε-greedy, gde se sa verovatnoćom ε bira nasumična akcija, a sa verovatnoćom 1-ε bira akcija sa najvišom Q-vrednošću).
- Imajte na umu da bi algoritam uvek mogao da izabere poznatu najbolju akciju za dato stanje, ali to agentu ne bi omogućilo da istražuje nove akcije koje bi mogle doneti bolje nagrade. Zato se koristi ε-greedy promenljiva za balansiranje exploration-a i exploitation-a.
3. **Interakcija sa okruženjem**: Izvršite izabranu akciju u okruženju i posmatrajte sledeće stanje i nagradu.
- Imajte na umu da, u zavisnosti od ε-greedy verovatnoće, sledeći korak može biti nasumična akcija (za exploration) ili najbolje poznata akcija (za exploitation).
4. **Ažuriranje Q-vrednosti**: Ažurirajte Q-vrednost za par stanje-akcija pomoću Bellman-ove jednačine:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
gde:
- `Q(s, a)` je trenutna Q-vrednost za stanje `s` i akciju `a`.
- `α` je learning rate (0 < α ≤ 1), koji određuje u kojoj meri nove informacije potiskuju stare informacije.
- `r` je nagrada primljena nakon izvršavanja akcije `a` u stanju `s`.
- `γ` je discount factor (0 ≤ γ < 1), koji određuje značaj budućih nagrada.
- `s'` je sledeće stanje nakon izvršavanja akcije `a`.
- `max(Q(s', a'))` je maksimalna Q-vrednost za sledeće stanje `s'` među svim mogućim akcijama `a'`.
5. **Iteracija**: Ponavljajte korake 2-4 dok Q-vrednosti ne konvergiraju ili dok se ne ispuni kriterijum zaustavljanja.

Imajte na umu da se tabela ažurira sa svakom novom izabranom akcijom, omogućavajući agentu da vremenom uči iz svojih iskustava kako bi pokušao da pronađe optimalnu policy (najbolju akciju koju treba preduzeti u svakom stanju). Međutim, Q-tabela može postati velika u okruženjima sa mnogo stanja i akcija, zbog čega postaje nepraktična za složene probleme. U takvim slučajevima mogu se koristiti metode aproksimacije funkcije (npr. neural networks) za procenu Q-vrednosti.

> [!TIP]
> ε-greedy vrednost se obično ažurira tokom vremena kako bi se smanjio exploration dok agent uči više o okruženju. Na primer, može početi sa visokom vrednošću (npr. ε = 1), a zatim se smanjiti na nižu vrednost (npr. ε = 0.1) kako učenje napreduje.

> [!TIP]
> Learning rate `α` i discount factor `γ` su hyperparameters koje treba podesiti na osnovu konkretnog problema i okruženja. Viši learning rate omogućava agentu da brže uči, ali može dovesti do nestabilnosti, dok niži learning rate dovodi do stabilnijeg učenja, ali sporije konvergencije. Discount factor određuje koliko agent vrednuje buduće nagrade (`γ` bliže 1) u poređenju sa neposrednim nagradama.

### SARSA (State-Action-Reward-State-Action)

SARSA je još jedan model-free reinforcement learning algoritam koji je sličan Q-Learning-u, ali se razlikuje po načinu ažuriranja Q-vrednosti. SARSA je skraćenica za State-Action-Reward-State-Action i ažurira Q-vrednosti na osnovu akcije izvršene u sledećem stanju, umesto maksimalne Q-vrednosti.
1. **Inicijalizacija**: Inicijalizujte Q-tabelu proizvoljnim vrednostima (često nulama).
2. **Izbor akcije**: Izaberite akciju pomoću exploration strategije (npr. ε-greedy).
3. **Interakcija sa okruženjem**: Izvršite izabranu akciju u okruženju i posmatrajte sledeće stanje i nagradu.
- Imajte na umu da, u zavisnosti od ε-greedy verovatnoće, sledeći korak može biti nasumična akcija (za exploration) ili najbolje poznata akcija (za exploitation).
4. **Ažuriranje Q-vrednosti**: Ažurirajte Q-vrednost za par stanje-akcija pomoću SARSA pravila ažuriranja. Imajte na umu da je pravilo ažuriranja slično Q-Learning-u, ali koristi akciju koja će biti izvršena u sledećem stanju `s'`, umesto maksimalne Q-vrednosti za to stanje:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
gde:
- `Q(s, a)` je trenutna Q-vrednost za stanje `s` i akciju `a`.
- `α` je learning rate.
- `r` je nagrada primljena nakon izvršavanja akcije `a` u stanju `s`.
- `γ` je discount factor.
- `s'` je sledeće stanje nakon izvršavanja akcije `a`.
- `a'` je akcija izvršena u sledećem stanju `s'`.
5. **Iteracija**: Ponavljajte korake 2-4 dok Q-vrednosti ne konvergiraju ili dok se ne ispuni kriterijum zaustavljanja.

#### Softmax vs ε-Greedy izbor akcije

Pored ε-greedy izbora akcije, SARSA može koristiti i softmax strategiju izbora akcije. Kod softmax izbora akcije, verovatnoća izbora akcije je **proporcionalna njenoj Q-vrednosti**, što omogućava nijansiraniji exploration prostora akcija. Verovatnoća izbora akcije `a` u stanju `s` data je izrazom:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
gde:
- `P(a|s)` je verovatnoća izbora akcije `a` u stanju `s`.
- `Q(s, a)` je Q-vrednost za stanje `s` i akciju `a`.
- `τ` (tau) je temperaturni parametar koji kontroliše nivo istraživanja. Viša temperatura rezultuje većim istraživanjem (ujednačenije verovatnoće), dok niža temperatura rezultuje većim iskorišćavanjem (veće verovatnoće za akcije sa višim Q-vrednostima).

> [!TIP]
> Ovo pomaže da se istraživanje i iskorišćavanje uravnoteže na kontinuiraniji način u poređenju sa ε-greedy izborom akcije.

### On-Policy naspram Off-Policy učenja

SARSA je **on-policy** algoritam učenja, što znači da ažurira Q-vrednosti na osnovu akcija koje bira trenutna politika (ε-greedy ili softmax politika). Nasuprot tome, Q-Learning je **off-policy** algoritam učenja, jer ažurira Q-vrednosti na osnovu maksimalne Q-vrednosti za sledeće stanje, bez obzira na akciju koju bira trenutna politika. Ova razlika utiče na način na koji algoritmi uče i prilagođavaju se okruženju.

On-policy metode poput SARSA mogu biti stabilnije u određenim okruženjima, jer uče iz akcija koje su stvarno preduzete. Međutim, mogu konvergirati sporije u poređenju sa off-policy metodama poput Q-Learning-a, koje mogu učiti iz šireg skupa iskustava.

## Security i vektori napada u RL sistemima

Iako RL algoritmi izgledaju čisto matematički, novija istraživanja pokazuju da **trovanje tokom treniranja i manipulisanje nagradama mogu pouzdano da potkopaju naučene politike**.

### Backdoor-i tokom treniranja
- **BLAST leverage backdoor (c-MADRL)**: Jedan zlonamerni agent kodira prostorno-vremenski okidač i blago menja svoju funkciju nagrade; kada se obrazac okidača pojavi, zatrovani agent usmerava ceo kooperativni tim ka ponašanju koje odabere napadač, dok performanse u čistom režimu ostaju gotovo nepromenjene.<sup>[[1]](#references)</sup>
- **Backdoor specifičan za Safe-RL (PNAct)**: Napadač ubacuje primere akcija koje su *pozitivne* (poželjne) i *negativne* (koje treba izbeći) tokom Safe-RL fine-tuning-a. Backdoor se aktivira jednostavnim okidačem (npr. prekoračenjem praga troška), primoravajući sistem da izvrši nebezbednu akciju, uz istovremeno poštovanje prividnih bezbednosnih ograničenja.

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
- `delta` neka bude mali kako bi se izbegli detektori pomeranja distribucije nagrade.
- U decentralizovanim okruženjima izvršite poisoning samo jednog agenta po epizodi kako biste oponašali ubacivanje „komponente“.

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** pokazuje da je promena manje od 5% pairwise preference oznaka dovoljna za pristrasnost reward modela; downstream PPO zatim uči da generiše tekst koji želi napadač kada se pojavi trigger token.<sup>[[3]](#references)</sup>
- Praktični koraci za testiranje: prikupite mali skup promptova, dodajte redak trigger token (npr. `@@@`) i nametnite preference tako da se odgovori koji sadrže sadržaj napadača označe kao „bolji“. Izvršite fine-tuning reward modela, a zatim pokrenite nekoliko PPO epoha — neusklađeno ponašanje će se pojaviti samo kada je trigger prisutan.

### Stealthier spatiotemporal triggers
Umesto statičnih image patch-eva, noviji MADRL radovi koriste *behavioral sequences* (vremenski usklađene obrasce akcija) kao trigger-e, u kombinaciji sa blagim reward reversal-om, kako bi poisoned agent neupadljivo naveo ceo tim na off-policy ponašanje, uz očuvanje visoke zbirne nagrade. Ovo zaobilazi detektore statičnih trigger-a i opstaje pri delimičnoj opservabilnosti.<sup>[[2]](#references)</sup>

### Red-team checklist
- Proverite reward deltas po stanju; nagla lokalna poboljšanja snažni su signali backdoor-a.
- Održavajte *canary* trigger skup: izdvojene epizode koje sadrže sintetička retka stanja/token-e; pokrenite treniranu policy nad njima da biste proverili da li ponašanje odstupa.
- Tokom decentralizovanog treninga nezavisno proverite svaku shared policy pomoću rollout-a u randomizovanim okruženjima pre agregacije.

## References
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
