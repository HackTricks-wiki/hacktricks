# Kryptografie

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt konzentriert sich auf praktische Kryptografie für Security-Tests und CTFs: das Erkennen gängiger Muster, die Auswahl geeigneter Tools und die Anwendung bekannter Angriffe.

Für Techniken, die Daten in Dateien verstecken, siehe den Abschnitt **Stego**.

## Verwendung dieses Abschnitts

Beginne damit, das Primitive und seine Parameter zu identifizieren. Bestimme anschließend, was der Angreifer kontrolliert oder beobachtet, beispielsweise ein Oracle, einen geleakten Wert oder die Wiederverwendung einer Nonce, bevor du einen Angriff auswählst.

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

## Schnelle Einrichtung

Erstelle eine isolierte Python-Umgebung und installiere häufig verwendete Pakete. Die Dokumentation von PyCryptodome empfiehlt, `pycryptodome` mit `pip` zu installieren; SageMath stellt separate Installationsanleitungen für jede unterstützte Plattform bereit.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath ist häufig für algebraische, Gitter-, RSA- und Elliptic-Curve-Berechnungen nützlich.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome-Dokumentation - Installation](https://www.pycryptodome.org/src/installation)
- [2] [SageMath-Dokumentation - Installationsanleitung](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
