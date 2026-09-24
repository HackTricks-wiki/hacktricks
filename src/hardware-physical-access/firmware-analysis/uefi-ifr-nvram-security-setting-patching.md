# Патчинг налаштувань безпеки UEFI IFR і NVRAM

{{#include ../../banners/hacktricks-training.md}}

Пароль setup захищає користувацький інтерфейс firmware, але не обов'язково автентифікує байти конфігурації, що зберігаються у SPI flash. Маючи фізичний доступ до запису, assessor може зіставити приховане або заблоковане налаштування UEFI з його **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** із відповідною змінною NVRAM, змінити це значення offline і перезаписати його. У вразливій системі Dell це змінило стан IOMMU перед завантаженням, хоча графічний setup і надалі показував, що захист DMA увімкнено.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Запис у firmware може назавжди вивести target із ладу. Працюйте з авторизованим пристроєм для тестування, який можна відновити; зберігайте оригінальний образ і отримайте щонайменше три незалежні зчитування з однаковими криптографічними хешами перед будь-якими змінами.<sup>[[3]](#references)</sup>

## Отримання образу firmware

Зчитуйте лише регіон BIOS, якщо Intel flash descriptor дозволяє доступ host, або використовуйте зовнішній програматор із правильною напругою та in-circuit clip. Зовнішній програматор зазвичай потрібен для відновлення машини, яка більше не завантажується.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Не припускайте, що vendor update capsule еквівалентна вмісту чипа: у ній можуть бути відсутні NVRAM, міститися encapsulation або бути encryption. [UEFITool](https://github.com/LongSoft/UEFITool) може розібрати raw UEFI image на firmware volumes, files і sections.<sup>[[7]](#references)</sup>

## Зіставлення IFR question із NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) перетворює HII form packages на текст і показує settings, які vendor GUI приховує, перейменовує або suppresses. Його output може визначити question, variable store, byte offset, storage width, допустимі values і conditional visibility.<sup>[[8]](#references)</sup>

1. Відкрийте dump в UEFITool, знайдіть firmware file з назвою `Setup`, розгорніть його до PE32 image section і використайте **Extract body**.
2. Запустіть IFRExtractor-RS для витягнутого EFI/PE32 body, потім знайдіть у згенерованому тексті controls на кшталт `DMA`, `IOMMU`, `VT-d`, `Secure Boot` або label, орієнтований на користувача.
3. Запишіть `VarStoreId`, `VarOffset`, `Size`, допустимі options та question ID. Не робіть висновків про semantics value лише на основі `Flags`.
4. Знайдіть відповідну декларацію `VarStore`/`VarStoreEfi` і зіставте numeric store ID з її variable **name and GUID**.
5. Знайдіть цей GUID в UEFITool, доки не буде досягнуто відповідного NVRAM object. Відкрийте **Body hex view** і перейдіть до `VarOffset` відносно variable body, а не всього flash image.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Наприклад, один образ Dell описував відповідне питання як `Control Iommu Pre-boot Behavior`, із `VarStoreId: 0x1`, `VarOffset: 0x975` і 8-бітним полем. Сховище `0x1` було зіставлене зі змінною `Setup` і GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`; диференційні дампи встановили, що в цій прошивці `01` означає увімкнено, а `00` — вимкнено.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUID-и, зміщення, структури даних, дублікати екземплярів змінних і кодування значень можуть змінюватися залежно від моделі та версії прошивки. Ніколи не використовуйте приклад зміщення як універсальне значення для Dell.

## Validate with differential dumps

Якщо інтерфейс налаштування доступний на еквівалентному тестовому пристрої, створіть один дамп із увімкненою опцією, а інший — із вимкненою. Порівняйте тіло змінної, отримане з IFR, і переконайтеся, що змінюється лише очікуване поле. Це дає змогу визначити фактичне кодування та відрізнити активну змінну від застарілих, типових або recovery-копій. Внесіть зміни до копії перевіреного оригінального образу, повторно відкрийте його в UEFITool і переконайтеся, що редагування розташоване поза автентифікованими або виміряними діапазонами коду, перш ніж виконувати перепрошивання.<sup>[[3]](#references)[[4]](#references)</sup>

Цільове редагування може мати менше побічних ефектів, ніж очищення пароля прошивки, яке може перевести пристрій у заводський стан, вимагати повторного введення специфічних для пристрою даних або змінити вимірювання TPM PCR. Однак цільове offline-редагування також може створити небезпечну **розбіжність між відображуваним і фактичним станом**: інтерфейс і засоби керування можуть показувати старе значення, тоді як рання прошивка використовуватиме змінений байт. Продемонстрована зміна не спричинила запиту на відновлення BitLocker і збереглася після оновлення BIOS від виробника, оскільки оновлення зберегло змінений стан NVRAM.<sup>[[3]](#references)</sup>

Авторський [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) демонструє модельно-специфічний patcher, який виявляє діапазони Intel Boot Guard Initial Boot Block і відмовляється виконувати звичайний запис у них. Використовуйте його режим аналізу перед `--apply`, перевіряйте кожен відповідний збіг і розглядайте його типові параметри як приклади, а не як універсальні зміщення.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Автоматизація зіставлення за допомогою NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) автоматизує вилучення IFR, визначає відповідність `VarStoreId` запитання GUID/імені NVRAM, відображає поточні значення параметрів і може редагувати вибране поле. Він може працювати як із повним дампом firmware, так і з окремо вилученими EFI- та NVRAM-blob. <sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
Автоматизація не скасовує потреби у відповідних дампах, обладнанні для відновлення, перевірках цілісності регіонів або валідації після прошивання.

## Обхід pre-boot IOMMU із подальшим отриманням Windows DMA-доступу

Якщо пропатчене значення дозволяє PCIe DMA до ExitBootServices, [DMAReaper](https://github.com/PN-Tester/DMAReaper) може пройти від EFI System Table через кореневі таблиці ACPI, знайти таблицю `DMAR` і перезаписати її до того, як Windows її розбере. Без придатних даних DMAR Windows може не ініціалізувати Kernel DMA Protection на основі IOMMU. DMAReaper сам по собі **не вимикає VBS/HVCI**.<sup>[[1]](#references)</sup>

У продемонстрованому ланцюжку цільову систему потім завантажили в Safe Mode, щоб усунути решту бар’єрів VBS, а [PCILeech](https://github.com/ufrisk/pcileech) пропатчив фізичну пам’ять сигнатурою Sticky Keys:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Після успішного патчу, сумісного зі збіркою, виклик Sticky Keys на екрані входу Windows запускав командний рядок від імені `NT AUTHORITY\SYSTEM`. Сигнатури та доступні діапазони пам’яті залежать від цільової системи, збірки й обладнання; виявлений збіг не свідчить про те, що кожна версія Windows є вразливою.<sup>[[2]](#references)[[3]](#references)</sup>

Не довіряйте меню firmware як засобу перевірки. Перевірте **System Information (`msinfo32.exe`) → Kernel DMA Protection**, окремо перевірте VBS, з’ясуйте, чи отримала OS дійсну таблицю DMAR, і протестуйте фактичну доступність DMA. Windows повідомляє про Kernel DMA Protection лише тоді, коли платформа й firmware підтримують необхідну конфігурацію IOMMU.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Вимкнення Kernel DMA Protection через перезапис DMAR до завантаження OS](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Програмне забезпечення для атак через Direct Memory Access](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Вимкнення функцій безпеки в заблокованому BIOS](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - Патчинг NVRAM з урахуванням IBB](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Відображення налаштувань EFI на значення NVRAM](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - Перегляд і парсинг образів UEFI firmware](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Витягування UEFI IFR у текст, придатний для читання людиною](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [flashrom manual - Програматори та операції читання/запису](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
