# GitHub Issues ve Repository Dosyalarını C2 Kanalı Olarak Kullanma

{{#include ../banners/hacktricks-training.md}}

Özel bir repository, **oturum durumunu** **payload aktarımından** ayırabilir: issues her hostu ve handshake durumunu kaydederken repository dosyaları her iki yönde de şifrelenmiş veri taşır. Bu, yalnızca komutlar için bir issue gövdesini düzenli aralıklarla kontrol etmekten daha fazlasıdır. Gözlemlenen uygulama, her iki API'ye erişmek için bir GitHub personal access token (PAT) kullanır.<sup>[[1]](#references)</sup> Fine-grained bir PAT için issue oluşturma veya güncelleme işlemleri Issues write izni, dosya yükleme işlemleri ise Contents write izni gerektirir. Classic bir PAT ise `repo` kapsamına ihtiyaç duyar. Yeterli ayrıcalıklara sahip bir token'ı ele geçiren herkes aynı kanala erişebilir.<sup>[[2]](#references)[[3]](#references)</sup>

## Issue ve dosya handshake'i

Gözlemlenen bir iş akışı, kısa bir hexadecimal host ID ve aşağıdaki durum makinesini kullanır. Tam ID aralığı, dizeler ve önekler protokol işaretçileridir; GitHub API gereksinimleri değildir.<sup>[[1]](#references)</sup>

1. Önceki oturum durumunu bulmak için başlangıçta `GET /repos/{owner}/{repo}/issues?state=open` (ve `state=closed`) ile açık ve kapalı issues'ları sorgulayın. `POST /repos/{owner}/{repo}/issues` kullanarak gövdesi `hel` olan, başlığı `1[ID]` şeklinde bir açık issue oluşturun.
2. Adı `2[ID]` ile başlayan bir repository dosyasını okuyun; bu dosya sunucunun RSA public key'ini sağlar. Yeni bir 16-byte session key oluşturun, bunu RSA ile şifreleyin ve sonucu `1[ID]` önekli bir dosyaya yükleyin.
3. Gömülü IV ile bu session key'i XOR'layarak sonraki IV'yi türetin. Aktarılan her dosyanın içeriğini AES ile şifrelemek veya çözmek için dosya adındaki rastgele 16-byte key'i kullanın. `2` öneki sunucudan hosta giden veriyi, `1` öneki ise hosttan sunucuya giden veriyi belirtir. Böylece dosya adı yönlendirme ve dosya başına key materyalini, issue ise durumu taşır.
4. `2` önekli sonraki dosyayı okuyun ve çözülen içeriğinin `hel` ile aynı olmasını zorunlu tutun. Şifrelenmiş host bilgilerini yükleyin, ardından `PATCH /repos/{owner}/{repo}/issues/{issue_number}` ile issue gövdesini `hey` olarak değiştirin. Komut polling'i ancak bundan sonra başlatın.

GitHub'ın Contents API'si bir dosyayı `GET /repos/{owner}/{repo}/contents/{path}` ile okur, bu yoldaki dosyayı ise `PUT` ile oluşturur veya değiştirir. En fazla 1 MB boyutundaki dosyalar için varsayılan JSON yanıtı, Base64 ile kodlanmış içeriği içerir; 1 ile 100 MB arasındaki dosyaların içeriğini almak için raw media type gerekir. Yükleme gövdesinde bir commit message ve Base64 ile kodlanmış dosya içeriği bulunmalıdır; mevcut bir dosyayı değiştirmek için dosyanın mevcut blob SHA değeri de gerekir. Bu API ayrıntıları, yukarıdaki şifreleme protokolünden ayrıdır.<sup>[[2]](#references)[[3]](#references)</sup>

Yetkili bir test repository'sinde issue-control bölümü REST API ile test edilebilir (bir test repository'si ve test PAT kullanın). Gerçek bir token'ı URL'ye, issue gövdesine veya commit edilmiş bir dosyaya koymayın.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

Mekanizma, **issue** başlığını, `hel`/`hey` işaretleyicilerini veya burada gösterilen belirli şifreleme seçeneklerini gerektirmez; bunlar tek bir uygulamaya özgüdür. Yeniden kullanılabilir fikir, değiştirilebilir host durumunu çift yönlü şifrelenmiş nesnelerden ayırmak ve her ikisini de bir host ID'ye bağlamaktır.<sup>[[1]](#references)</sup> Başka bir GitHub-issue taşıma yöntemi için [AdaptixC2 özel listener notlarına](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema) bakın. Oturum durumu taşımak yerine repository kimlik bilgilerini döndüren bir issue-comment yedeği için [Web services and dead-drop resolvers](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers) sayfasına bakın.

## References

- [1] [Kaspersky Securelist – FlashHole Operasyonu](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – Issues için REST API uç noktaları](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – Repository içeriği için REST API uç noktaları](https://docs.github.com/en/rest/repos/contents)
