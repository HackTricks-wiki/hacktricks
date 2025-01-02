# Tersine Mühendislik Araçları ve Temel Yöntemler

{{#include ../../banners/hacktricks-training.md}}

## ImGui Tabanlı Tersine Mühendislik Araçları

Yazılım:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Çevrimiçi:

- wasm (ikili) formatından wat (düz metin) formatına **decompile** etmek için [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) kullanın
- wat formatından wasm formatına **compile** etmek için [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) kullanın
- decompile etmek için [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) kullanmayı da deneyebilirsiniz

Yazılım:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek, **kütüphaneler** (.dll), **Windows meta veri dosyaları** (.winmd) ve **çalıştırılabilir dosyalar** (.exe) dahil olmak üzere **birden fazla formatı decompile ve inceleyen** bir decompiler'dır. Decompile edildikten sonra, bir assembly Visual Studio projesi (.csproj) olarak kaydedilebilir.

Buradaki avantaj, kaybolmuş bir kaynak kodunun eski bir assembly'den geri yüklenmesi gerektiğinde, bu işlemin zaman kazandırmasıdır. Ayrıca, dotPeek, decompile edilmiş kod boyunca kullanışlı bir navigasyon sağlar ve bu da onu **Xamarin algoritma analizi** için mükemmel araçlardan biri yapar.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Kapsamlı bir eklenti modeli ve aracı tam ihtiyaçlarınıza uyacak şekilde genişleten bir API ile .NET reflector, zaman kazandırır ve geliştirmeyi basitleştirir. Bu aracın sunduğu tersine mühendislik hizmetlerine bir göz atalım:

- Bir kütüphane veya bileşen içindeki veri akışının nasıl olduğunu anlamanızı sağlar
- .NET dilleri ve çerçevelerinin uygulanması ve kullanımı hakkında bilgi verir
- API'lerden ve kullanılan teknolojilerden daha fazla yararlanmak için belgelenmemiş ve açığa çıkarılmamış işlevselliği bulur.
- Bağımlılıkları ve farklı assembly'leri bulur
- Kodunuzdaki, üçüncü taraf bileşenlerdeki ve kütüphanelerdeki hataların tam yerini takip eder.
- Çalıştığınız tüm .NET kodunun kaynağına hata ayıklama yapar.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code için ILSpy eklentisi](https://github.com/icsharpcode/ilspy-vscode): Herhangi bir işletim sisteminde kullanabilirsiniz (doğrudan VSCode'dan kurabilirsiniz, git indirmeye gerek yok. **Extensions**'a tıklayın ve **ILSpy**'yi arayın).\
**Decompile**, **modify** ve tekrar **recompile** etmeniz gerekiyorsa [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) veya aktif olarak bakımı yapılan bir çatalı, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) kullanabilirsiniz. (**Sağ Tık -> Method'u Değiştir** ile bir fonksiyonun içindeki bir şeyi değiştirebilirsiniz).

### DNSpy Günlüğü

**DNSpy'nin bir dosyaya bazı bilgileri günlüğe kaydetmesi** için bu kod parçasını kullanabilirsiniz:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Hata Ayıklama

DNSpy kullanarak kodu hata ayıklamak için şunları yapmalısınız:

Öncelikle, **hata ayıklama** ile ilgili **Assembly özelliklerini** değiştirin:

![](<../../images/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Bu kısımda bir şey yok. Lütfen çevirmemi istediğiniz metni sağlayın.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Ve **compile**'a tıklayın:

![](<../../images/image (314) (1).png>)

Ardından yeni dosyayı _**File >> Save module...**_ ile kaydedin:

![](<../../images/image (602).png>)

Bu gereklidir çünkü bunu yapmazsanız, **runtime** sırasında koda birkaç **optimizasyon** uygulanacak ve hata ayıklama sırasında bir **break-point asla vurulmayabilir** veya bazı **değişkenler mevcut olmayabilir**.

Ardından, eğer .NET uygulamanız **IIS** tarafından **çalıştırılıyorsa**, bunu **restart** edebilirsiniz:
```
iisreset /noforce
```
Sonra, hata ayıklamaya başlamak için tüm açık dosyaları kapatmalısınız ve **Debug Tab** içinde **Attach to Process...** seçeneğini seçmelisiniz:

![](<../../images/image (318).png>)

Ardından **IIS server**'a bağlanmak için **w3wp.exe**'yi seçin ve **attach** butonuna tıklayın:

![](<../../images/image (113).png>)

Artık süreci hata ayıklıyorken, durdurma ve tüm modülleri yükleme zamanı. Önce _Debug >> Break All_ seçeneğine tıklayın ve ardından _**Debug >> Windows >> Modules**_ seçeneğine tıklayın:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

**Modules** üzerindeki herhangi bir modüle tıklayın ve **Open All Modules** seçeneğini seçin:

![](<../../images/image (922).png>)

**Assembly Explorer** üzerindeki herhangi bir modüle sağ tıklayın ve **Sort Assemblies** seçeneğine tıklayın:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## DLL'leri Hata Ayıklama

### IDA Kullanarak

- **rundll32'yi yükleyin** (64bit için C:\Windows\System32\rundll32.exe ve 32 bit için C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** hata ayıklayıcısını seçin
- "**Kütüphane yükleme/boşaltma sırasında askıya al**" seçeneğini seçin

![](<../../images/image (868).png>)

- **DLL'nin yolunu** ve çağırmak istediğiniz fonksiyonu belirterek yürütme **parametrelerini** yapılandırın:

![](<../../images/image (704).png>)

Sonra, hata ayıklamaya başladığınızda **her DLL yüklendiğinde yürütme durdurulacak**, ardından rundll32 DLL'nizi yüklediğinde yürütme durdurulacak.

Ama, yüklenen DLL'nin koduna nasıl ulaşabilirsiniz? Bu yöntemi kullanarak, nasıl olduğunu bilmiyorum.

### x64dbg/x32dbg Kullanarak

- **rundll32'yi yükleyin** (64bit için C:\Windows\System32\rundll32.exe ve 32 bit için C:\Windows\SysWOW64\rundll32.exe)
- **Komut Satırını Değiştirin** (_File --> Change Command Line_) ve DLL'nin yolunu ve çağırmak istediğiniz fonksiyonu ayarlayın, örneğin: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ kısmını değiştirin ve "**DLL Girişi**" seçeneğini seçin.
- Ardından **yürütmeyi başlatın**, hata ayıklayıcı her DLL ana fonksiyonunda duracak, bir noktada **DLL'nizin girişinde duracaksınız**. Oradan, bir kesme noktası koymak istediğiniz yerleri arayın.

Yürütme herhangi bir nedenle win64dbg'de durdurulduğunda, **nerede olduğunuzu** görebilirsiniz, **win64dbg penceresinin üst kısmında**:

![](<../../images/image (842).png>)

Sonra, yürütmenin durdurulduğu yeri görebilirsiniz, hata ayıklamak istediğiniz DLL'de.

## GUI Uygulamaları / Video Oyunları

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) önemli değerlerin bir çalışır oyunun belleğinde nerede saklandığını bulmak ve bunları değiştirmek için yararlı bir programdır. Daha fazla bilgi için:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU Proje Hata Ayıklayıcısı (GDB) için bir ön yüz/ters mühendislik aracıdır, oyunlara odaklanmıştır. Ancak, herhangi bir ters mühendislik ile ilgili şeyler için de kullanılabilir.

[**Decompiler Explorer**](https://dogbolt.org/) bir dizi decompiler için bir web ön yüzüdür. Bu web hizmeti, küçük yürütülebilir dosyalar üzerinde farklı decompiler'ların çıktısını karşılaştırmanıza olanak tanır.

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Blobrunner ile bir shellcode'u hata ayıklama

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **shellcode**'u bir bellek alanında **ayıracak**, shellcode'un ayrıldığı **bellek adresini** size **gösterecek** ve yürütmeyi **durduracak**.\
Sonra, bir **hata ayıklayıcıyı** (Ida veya x64dbg) sürece eklemeniz ve belirtilen bellek adresinde bir **kesme noktası** koymanız ve yürütmeyi **devam ettirmeniz** gerekir. Bu şekilde shellcode'u hata ayıklayacaksınız.

Yayınların github sayfası, derlenmiş sürümleri içeren zip dosyaları içerir: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Blobrunner'ın biraz değiştirilmiş bir versiyonunu aşağıdaki bağlantıda bulabilirsiniz. Derlemek için sadece **Visual Studio Code'da bir C/C++ projesi oluşturun, kodu kopyalayıp yapıştırın ve derleyin**.

{{#ref}}
blobrunner.md
{{#endref}}

### jmp2it ile bir shellcode'u hata ayıklama

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) blobrunner'a çok benzer. **Shellcode**'u bir bellek alanında **ayıracak** ve bir **sonsuz döngü** başlatacaktır. Daha sonra, **hata ayıklayıcıyı** sürece eklemeniz, **oyna başlat 2-5 saniye bekleyin ve durdurun** ve kendinizi **sonsuz döngüde** bulacaksınız. Sonsuz döngünün bir sonraki talimatına atlayın çünkü bu shellcode'a bir çağrı olacaktır ve sonunda shellcode'u yürütmeye başlayacaksınız.

![](<../../images/image (509).png>)

Derlenmiş bir versiyonu [jmp2it'in yayınlar sayfasından](https://github.com/adamkramer/jmp2it/releases/) indirebilirsiniz.

### Cutter kullanarak shellcode'u hata ayıklama

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) radare'nin GUI'sidir. Cutter kullanarak shellcode'u emüle edebilir ve dinamik olarak inceleyebilirsiniz.

Cutter'ın "Dosya Aç" ve "Shellcode Aç" seçeneklerini sunduğunu unutmayın. Benim durumumda shellcode'u dosya olarak açtığımda doğru bir şekilde decompile etti, ancak shellcode olarak açtığımda etmedi:

![](<../../images/image (562).png>)

Emülasyonu istediğiniz yerden başlatmak için oraya bir kesme noktası koyun ve görünüşe göre cutter oradan emülasyonu otomatik olarak başlatacaktır:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Örneğin, bir hex dökümünde yığını görebilirsiniz:

![](<../../images/image (186).png>)

### Shellcode'u deobfuscate etme ve yürütülen fonksiyonları alma

[**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) denemelisiniz.\
Shellcode'un hangi **fonksiyonları** kullandığını ve shellcode'un bellekte kendini **şifreleyip şifrelemediğini** size söyleyecektir.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg ayrıca istediğiniz seçenekleri seçip shellcode'u çalıştırabileceğiniz grafiksel bir başlatıcıya sahiptir.

![](<../../images/image (258).png>)

**Create Dump** seçeneği, shellcode'da dinamik olarak herhangi bir değişiklik yapıldığında son shellcode'u dökecektir (kodlanmış shellcode'u indirmek için faydalıdır). **start offset** shellcode'u belirli bir ofsetten başlatmak için faydalı olabilir. **Debug Shell** seçeneği, scDbg terminalini kullanarak shellcode'u hata ayıklamak için faydalıdır (ancak bu konuda daha önce açıklanan seçeneklerin herhangi birinin daha iyi olduğunu düşünüyorum çünkü Ida veya x64dbg kullanabileceksiniz).

### CyberChef kullanarak ayrıştırma

Shellcode dosyanızı girdi olarak yükleyin ve onu decompile etmek için aşağıdaki tarifi kullanın: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Bu obfuscator **`mov` için tüm talimatları değiştirir** (evet, gerçekten havalı). Ayrıca yürütme akışlarını değiştirmek için kesintiler kullanır. Nasıl çalıştığı hakkında daha fazla bilgi için:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Şanslıysanız [demovfuscator](https://github.com/kirschju/demovfuscator) ikiliyi deofuscate edecektir. Birkaç bağımlılığı vardır.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Ve [keystone'u kurun](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Eğer bir **CTF oynuyorsanız, bayrağı bulmak için bu geçici çözüm** çok faydalı olabilir: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**giriş noktası** bulmak için fonksiyonları `::main` ile arayın:

![](<../../images/image (1080).png>)

Bu durumda ikili dosya authenticator olarak adlandırılmış, bu yüzden bu ilginç ana fonksiyon olduğu oldukça açıktır.\
Çağrılan **fonksiyonların** **isimlerini** öğrendikten sonra, **girdileri** ve **çıktıları** hakkında bilgi edinmek için bunları **İnternet**'te arayın.

## **Delphi**

Delphi derlenmiş ikili dosyaları için [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) kullanabilirsiniz.

Eğer bir Delphi ikili dosyasını tersine mühendislik yapmanız gerekiyorsa, IDA eklentisi [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) kullanmanızı öneririm.

Sadece **ATL+f7** tuşlarına basın (IDA'da python eklentisini içe aktarın) ve python eklentisini seçin.

Bu eklenti, ikili dosyayı çalıştıracak ve hata ayıklamanın başlangıcında fonksiyon isimlerini dinamik olarak çözecektir. Hata ayıklamayı başlattıktan sonra tekrar Başlat butonuna (yeşil olan veya f9) basın ve gerçek kodun başında bir kesme noktası oluşacaktır.

Ayrıca, grafik uygulamasında bir butona bastığınızda, hata ayıklayıcı o buton tarafından yürütülen fonksiyonda duracaktır.

## Golang

Eğer bir Golang ikili dosyasını tersine mühendislik yapmanız gerekiyorsa, IDA eklentisi [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) kullanmanızı öneririm.

Sadece **ATL+f7** tuşlarına basın (IDA'da python eklentisini içe aktarın) ve python eklentisini seçin.

Bu, fonksiyonların isimlerini çözecektir.

## Derlenmiş Python

Bu sayfada, bir ELF/EXE python derlenmiş ikili dosyasından python kodunu nasıl alacağınızı bulabilirsiniz:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Oyun Gövdesi İleri

Eğer bir GBA oyununun **ikilisini** alırsanız, **emüle** etmek ve **hata ayıklamak** için farklı araçlar kullanabilirsiniz:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Hata ayıklama sürümünü indirin_) - Arayüz ile birlikte bir hata ayıklayıcı içerir
- [**mgba** ](https://mgba.io)- CLI hata ayıklayıcı içerir
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra eklentisi
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra eklentisi

[**no$gba**](https://problemkaputt.de/gba.htm) içinde, _**Seçenekler --> Emülasyon Ayarı --> Kontroller**_\*\* \*\* kısmında Game Boy Advance **butonlarına** nasıl basılacağını görebilirsiniz.

![](<../../images/image (581).png>)

Basıldığında, her **tuşun bir değeri** vardır:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
Bu tür bir programda, ilginç kısım **programın kullanıcı girdisini nasıl işlediği** olacaktır. Adres **0x4000130**'da yaygın olarak bulunan fonksiyonu **KEYINPUT** bulacaksınız.

![](<../../images/image (447).png>)

Önceki görüntüde, fonksiyonun **FUN_080015a8**'den çağrıldığını görebilirsiniz (adresler: _0x080015fa_ ve _0x080017ac_).

O fonksiyonda, bazı başlangıç işlemlerinden sonra (önemsiz):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
Bu kod bulundu:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
Son if, **`uVar4`**'ün **son Anahtarlar** içinde olup olmadığını ve mevcut anahtar olmadığını kontrol ediyor, bu da bir düğmeyi bırakmak olarak adlandırılır (mevcut anahtar **`uVar1`**'de saklanır).
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
Önceki kodda **uVar1**'in (**basılı düğmenin değeri**) bazı değerlerle karşılaştırıldığını görebilirsiniz:

- İlk olarak, **değer 4** ile karşılaştırılıyor (**SELECT** düğmesi): Bu düğme, bu zorlukta ekranı temizliyor.
- Sonra, **değer 8** ile karşılaştırılıyor (**START** düğmesi): Bu zorlukta, kodun bayrağı almak için geçerli olup olmadığını kontrol ediyor.
- Bu durumda **`DAT_030000d8`** değişkeni 0xf3 ile karşılaştırılıyor ve değer aynıysa bazı kodlar çalıştırılıyor.
- Diğer durumlarda, bazı cont (`DAT_030000d4`) kontrol ediliyor. Bu bir cont çünkü koda girdikten hemen sonra 1 ekliyor.\
**Eğer** 8'den küçükse, **`DAT_030000d8`**'e değerler **eklemek** ile ilgili bir şey yapılıyor (temelde, cont 8'den küçük olduğu sürece, bu değişkende basılan tuşların değerlerini topluyor).

Bu zorlukta, düğmelerin değerlerini bilerek, **sonuçta 0xf3 olan 8'den daha kısa bir kombinasyonu basmanız gerekiyordu.**

**Bu eğitim için referans:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Kurslar

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

{{#include ../../banners/hacktricks-training.md}}
