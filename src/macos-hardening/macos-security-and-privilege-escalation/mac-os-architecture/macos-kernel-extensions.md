# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Kernel extensions (Kexts) — це **пакети** з розширенням **`.kext`**, які **завантажуються безпосередньо в простір ядра macOS**, надаючи додаткову функціональність основній операційній системі.

### Вимоги

Очевидно, що це настільки потужно, що **завантажити розширення ядра** є **складним**. Ось **вимоги**, які повинні бути виконані для завантаження розширення ядра:

- Коли **входите в режим відновлення**, розширення ядра **повинні бути дозволені** для завантаження:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Розширення ядра повинно бути **підписане сертифікатом підпису коду ядра**, який може бути **наданий тільки Apple**. Хто детально розгляне компанію та причини, чому це необхідно.
- Розширення ядра також повинно бути **нотаризоване**, Apple зможе перевірити його на наявність шкідливого ПЗ.
- Потім, **кореневий** користувач є тим, хто може **завантажити розширення ядра**, а файли всередині пакета повинні **належати кореню**.
- Під час процесу завантаження пакет повинен бути підготовлений у **захищеному місці, що не є кореневим**: `/Library/StagedExtensions` (вимагає надання `com.apple.rootless.storage.KernelExtensionManagement`).
- Нарешті, при спробі завантажити його, користувач [**отримає запит на підтвердження**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) і, якщо буде прийнято, комп'ютер повинен бути **перезавантажений** для його завантаження.

### Процес завантаження

У Catalina це виглядало так: Цікаво відзначити, що процес **перевірки** відбувається в **userland**. Однак тільки програми з наданням **`com.apple.private.security.kext-management`** можуть **запитувати у ядра завантажити розширення**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **починає** процес **перевірки** для завантаження розширення
- Він спілкуватиметься з **`kextd`**, використовуючи **Mach service**.
2. **`kextd`** перевірить кілька речей, таких як **підпис**
- Він спілкуватиметься з **`syspolicyd`**, щоб **перевірити**, чи може розширення бути **завантаженим**.
3. **`syspolicyd`** **запитає** **користувача**, якщо розширення не було завантажено раніше.
- **`syspolicyd`** повідомить результат **`kextd`**
4. **`kextd`** нарешті зможе **сказати ядру завантажити** розширення

Якщо **`kextd`** недоступний, **`kextutil`** може виконати ті ж перевірки.

### Перерахування (завантажені kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> Навіть якщо очікується, що розширення ядра будуть у `/System/Library/Extensions/`, якщо ви зайдете в цю папку, ви **не знайдете жодного бінарного файлу**. Це пов'язано з **kernelcache**, і для того, щоб зворотно інженерити один `.kext`, вам потрібно знайти спосіб його отримати.

**Kernelcache** - це **попередньо скомпільована та попередньо зв'язана версія ядра XNU**, разом з основними **драйверами** та **розширеннями ядра**. Він зберігається у **сжатому** форматі і розпаковується в пам'ять під час процесу завантаження. Kernelcache сприяє **швидшому часу завантаження**, маючи готову до запуску версію ядра та важливих драйверів, що зменшує час і ресурси, які інакше витрачалися б на динамічне завантаження та зв'язування цих компонентів під час завантаження.

### Local Kerlnelcache

В iOS він знаходиться у **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, в macOS ви можете знайти його за допомогою: **`find / -name "kernelcache" 2>/dev/null`** \
У моєму випадку в macOS я знайшов його в:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Формат файлу IMG4 - це контейнерний формат, який використовується Apple в його пристроях iOS та macOS для безпечного **зберігання та перевірки компонентів прошивки** (як-от **kernelcache**). Формат IMG4 включає заголовок і кілька тегів, які інкапсулюють різні частини даних, включаючи фактичний корисний вантаж (як-от ядро або завантажувач), підпис та набір властивостей маніфесту. Формат підтримує криптографічну перевірку, що дозволяє пристрою підтверджувати автентичність та цілісність компонента прошивки перед його виконанням.

Зазвичай він складається з наступних компонентів:

- **Payload (IM4P)**:
- Часто стиснутий (LZFSE4, LZSS, …)
- За бажанням зашифрований
- **Manifest (IM4M)**:
- Містить підпис
- Додатковий словник ключ/значення
- **Restore Info (IM4R)**:
- Відомий також як APNonce
- Запобігає повторному використанню деяких оновлень
- OPTIONAL: Зазвичай це не знаходиться

Розпакуйте Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Завантажити&#x20;

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

У [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) можна знайти всі набори для налагодження ядра. Ви можете завантажити його, змонтувати, відкрити за допомогою інструменту [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), отримати доступ до папки **`.kext`** та **екстрактувати** її.

Перевірте його на наявність символів за допомогою:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Іноді Apple випускає **kernelcache** з **symbols**. Ви можете завантажити деякі прошивки з символами, перейшовши за посиланнями на цих сторінках. Прошивки міститимуть **kernelcache** серед інших файлів.

Щоб **extract** файли, почніть з зміни розширення з `.ipsw` на `.zip` і **unzip** його.

Після витягування прошивки ви отримаєте файл на кшталт: **`kernelcache.release.iphone14`**. Він у форматі **IMG4**, ви можете витягти цікаву інформацію за допомогою:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Інспекція kernelcache

Перевірте, чи має kernelcache символи з
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
З цим ми тепер можемо **витягти всі розширення** або **те, яке вас цікавить:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Налагодження

## Посилання

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
