# Kryptografie

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt behandelt praktische Kryptografie für Security-Tests und CTFs: gängige Muster erkennen, geeignete Tools auswählen und bekannte Angriffe anwenden.

Techniken, bei denen Daten in Dateien verborgen werden, findest du im Abschnitt **Stego**.

## Verwendung dieses Abschnitts

Identifiziere zunächst die Primitive und ihre Parameter. Ermittle anschließend, was der Angreifer kontrolliert oder beobachten kann, etwa ein Oracle, einen geleakten Wert oder die Wiederverwendung eines Nonce, bevor du einen Angriff auswählst.

### CTF-Workflow

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetrische Kryptografie

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs und KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Kryptografie mit öffentlichen Schlüsseln

{{#ref}}
public-key/README.md
{{#endref}}

### TLS und Zertifikate

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Kryptografie in Malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Verschiedenes

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Schnellstart

Erstelle eine isolierte Python-Umgebung und installiere häufig verwendete Pakete. Die Dokumentation von PyCryptodome empfiehlt, `pycryptodome` mit `pip` zu installieren; SageMath bietet separate Installationsanleitungen für jede unterstützte Plattform.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath ist oft für algebraische Berechnungen sowie Berechnungen mit Gittern, RSA und elliptischen Kurven nützlich.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome-Dokumentation - Installation](https://www.pycryptodome.org/src/installation)
- [2] [SageMath-Dokumentation - Installationsanleitung](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
