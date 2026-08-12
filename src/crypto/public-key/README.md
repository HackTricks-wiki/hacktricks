# Kryptografie mit öffentlichen Schlüsseln

{{#include ../../banners/hacktricks-training.md}}

Viele fortgeschrittene CTF-Kryptografie-Herausforderungen beinhalten RSA, elliptische-Kurven-Kryptografie (ECC), ECDSA, Gitter oder schwache Zufallswerte.

## Empfohlene Tools

- [SageMath](https://www.sagemath.org/) für modulare Arithmetik, elliptische Kurven und Gitterreduktion<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) zum Testen häufiger RSA-Schwachstellen<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) zum Überprüfen, ob eine ganze Zahl bekannte Faktoren besitzt<sup>[[3]](#references)</sup>
- Die Python-[`ecdsa`-Bibliothek](https://ecdsa.readthedocs.io/) zum Parsen von Schlüsseln sowie zum Signieren und Verifizieren<sup>[[7]](#references)</sup>

## RSA

Beginne hier, wenn eine Challenge `n`, `e` und `c` sowie einen Hinweis wie einen gemeinsamen Modulus, einen niedrigen Exponenten, teilweise bekannte Schlüsselbits oder verwandte Nachrichten bereitstellt.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Wenn Signaturen beteiligt sind, teste auf Nonce-Wiederverwendung, Bias oder leaks, bevor du annimmst, dass das zugrunde liegende diskrete-Logarithmus-Problem gelöst werden muss.

### ECDSA nonce reuse / bias

ECDSA benötigt eine frische geheime Zahl `k` für jede Nachricht. Wenn dasselbe `k` zwei verschiedene Nachrichten-Hashes signiert, kann der private Schlüssel aus den öffentlichen Signaturwerten wiederhergestellt werden.<sup>[[4]](#references)</sup>

Auch wenn `k` nicht identisch ist, können Bias oder leaks von Nonce-Bits über viele Signaturen hinweg eine gitterbasierte Wiederherstellung ermöglichen.<sup>[[5]](#references)</sup>

Technische Wiederherstellung bei wiederverwendetem `k`:<sup>[[4]](#references)</sup>

ECDSA-Signaturgleichungen (Gruppenordnung `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Wenn dasselbe `k` für zwei Nachrichten `m1, m2` wiederverwendet wird und die Signaturen `(r, s1)` und `(r, s2)` entstehen:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Wenn ein Protokoll nicht validiert, dass ein Eingabepunkt auf der erwarteten Kurve und in der korrekten Untergruppe liegt, kann ein Angreifer Operationen in einer schwächeren Gruppe erzwingen und Informationen über einen geheimen Skalar wiederherstellen. SEC 1 spezifiziert Prüfungen zur Validierung öffentlicher Schlüssel, die solche Eingaben verhindern sollen.<sup>[[6]](#references)</sup>

Technischer Hinweis:

- Validiere, dass Punkte nicht der Punkt im Unendlichen sind, gültige Koordinaten besitzen, die Kurvengleichung erfüllen und zur erforderlichen Untergruppe gehören.<sup>[[6]](#references)</sup>
- In CTF-Challenges wird dies häufig als Server modelliert, der einen vom Angreifer gewählten Punkt mit einem geheimen Skalar multipliziert und einen abgeleiteten Wert zurückgibt.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Standard für digitale Signaturen](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner und Heninger: Biased Nonce Sense — Gitterangriffe gegen schwache ECDSA-Signaturen](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Kryptografie mit elliptischen Kurven](https://www.secg.org/sec1-v2.pdf)
- [7] [Python-`ecdsa`-Dokumentation](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
