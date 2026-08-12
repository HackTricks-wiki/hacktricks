# Belge Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Birçok belge formatı tek bir veri akışı yerine yapılandırılmış kapsayıcılardır:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (gömülü dosyalar, streams)
- Office OOXML (`.docx/.xlsx/.pptx` ZIP dosyalarıdır)
- Legacy RTF ve OLE/Compound File Binary belgeleri. RTF, control words ve groups bilgilerini metin odaklı bir formatta saklarken, OLE compound files storage objects ve streams öğelerinden oluşan dosya sistemi benzeri bir hiyerarşi sunar; her ikisi de gizli veya gömülü veriler için formata özgü incelemeyi gerektirir.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Teknik

PDF dosyaları objects, streams, JavaScript ve gömülü dosyalar içerebilir. Analiz sırasında yaygın görevler şunlardır:

- Gömülü ekleri çıkarmak.
- Objects öğelerini daha kolay incelemek için object streams öğelerini genişletmek.
- JavaScript, gömülü görseller ve alışılmadık streams öğelerini belirlemek.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Hızlı kontroller
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
`--qdf --object-streams=disable` kombinasyonu daha okunabilir bir gösterim üretir ve object streams'leri kaldırarak manuel incelemeyi kolaylaştırır.<sup>[[2]](#references)</sup> Ardından `out.pdf` dosyasında şüpheli nesneleri ve dizeleri arayın.

## Office OOXML

### Teknik

Office Open XML dosyaları (`.docx`, `.xlsx` ve `.pptx`), parçalardan ve XML relationship dosyalarından oluşan ZIP tabanlı paketler olan Open Packaging Conventions'ı kullanır.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Paketi bir relationship graph olarak ele alın ve media dosyalarını, external relationships'leri ve olağandışı custom parts'ları inceleyin.

Pratikte:

- Belge, XML ve asset'lerden oluşan bir dizin ağacıdır.
- `_rels/` relationship dosyaları external resources'lara veya gizli parts'lara işaret edebilir.
- Embedded data sıklıkla `word/media/`, custom XML parts veya olağandışı relationships içinde bulunur.

### Hızlı kontroller
```bash
7z l file.docx
7z x file.docx -oout
```
Ardından şunları inceleyin:

- `word/document.xml`
- Dış ilişkiler için `word/_rels/`
- `word/media/` içindeki gömülü medya

## References

- [1] [Poppler pdfdetach kılavuzu](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf documentation - QDF mode and object streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions temelleri](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML dosya biçimleri](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary File Format giriş](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF specification reference](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
