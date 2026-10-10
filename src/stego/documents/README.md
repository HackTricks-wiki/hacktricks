# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

Birçok belge formatı, tek bir veri akışı yerine yapılandırılmış kapsayıcılardır:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (gömülü dosyalar, akışlar)
- Office OOXML (`.docx/.xlsx/.pptx` ZIP dosyalarıdır)
- Eski RTF ve OLE/Compound File Binary belgeleri. RTF, kontrol sözcüklerini ve grupları metin odaklı bir biçimde saklarken OLE bileşik dosyaları, depolama nesneleri ve akışlardan oluşan dosya sistemi benzeri bir hiyerarşi sunar; her iki format da gizli veya gömülü veriler için formata özgü inceleme gerektirir.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Teknik

PDF dosyaları nesneler, akışlar, JavaScript ve gömülü dosyalar içerebilir. Analiz sırasında yaygın görevler şunlardır:

- Gömülü ekleri çıkarmak.
- Nesneleri incelemeyi kolaylaştırmak için nesne akışlarını genişletmek.
- JavaScript'i, gömülü görselleri ve alışılmadık akışları belirlemek.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Hızlı kontroller

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

`--qdf --object-streams=disable` kombinasyonu daha okunabilir bir gösterim oluşturur ve object stream’leri kaldırarak manuel incelemeyi kolaylaştırır.<sup>[[2]](#references)</sup> Ardından `out.pdf` içinde şüpheli nesneleri ve dizeleri arayın.

## Office OOXML

### Teknik

Office Open XML dosyaları (`.docx`, `.xlsx` ve `.pptx`), parçalardan ve XML ilişki dosyalarından oluşan ZIP tabanlı bir paket olan Open Packaging Conventions’ı kullanır.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Paketi bir ilişki grafiği olarak ele alın ve medyayı, harici ilişkileri ve olağandışı özel parçaları inceleyin.

Uygulamada:

- Belge, XML ve varlıklardan oluşan bir dizin ağacıdır.
- `_rels/` ilişki dosyaları harici kaynaklara veya gizli parçalara işaret edebilir.
- Gömülü veriler sıklıkla `word/media/` içinde, özel XML parçalarında veya olağandışı ilişkilerde bulunur.

### Hızlı kontroller

```bash
7z l file.docx
7z x file.docx -oout
```

Ardından inceleyin:

- `word/document.xml`
- `word/_rels/` içindeki harici ilişkiler
- `word/media/` içindeki gömülü medya

## References

- [1] [Poppler pdfdetach kılavuzu](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf belgeleri - QDF modu ve nesne akışları](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions temelleri](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML dosya biçimleri](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary File Format'a giriş](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF belirtimi başvurusu](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
