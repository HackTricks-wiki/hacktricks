# Public-Key-Kryptografie

{{#include ../../banners/hacktricks-training.md}}

Viele fortgeschrittene CTF-Kryptografie-Challenges beinhalten RSA, Elliptic-Curve-Kryptografie (ECC), ECDSA, Gitter oder schwache Zufallszahlen.

## Empfohlene Tools

- [SageMath](https://www.sagemath.org/) für modulare Arithmetik, elliptische Kurven und Gitterreduktion<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) zum Testen verbreiteter RSA-Schwachstellen<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) zur Überprüfung, ob für eine ganze Zahl bekannte Faktoren existieren<sup>[[3]](#references)</sup>
- Die Python-[`ecdsa`-Bibliothek](https://ecdsa.readthedocs.io/) zum Parsen von Schlüsseln sowie zum Signieren und Verifizieren<sup>[[7]](#references)</sup>

## RSA

Beginne hier, wenn eine Challenge `n`, `e` und `c` sowie einen Hinweis wie einen gemeinsam genutzten Modulus, einen niedrigen Exponenten, teilweise bekannte Schlüsselbits oder verwandte Nachrichten bereitstellt.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Wenn Signaturen beteiligt sind, teste zuerst auf Nonce-Wiederverwendung, Bias oder Leakage, bevor du davon ausgehst, dass das zugrunde liegende Diskreter-Logarithmus-Problem gelöst werden muss.

### ECDSA-Nonce-Wiederverwendung / Bias

ECDSA benötigt für jede Nachricht eine neue geheime Zahl `k`. Wenn dasselbe `k` zum Signieren zweier unterschiedlicher Nachrichten-Hashes verwendet wird, kann der private Schlüssel aus den öffentlichen Signaturwerten wiederhergestellt werden.<sup>[[4]](#references)</sup>

Auch wenn `k` nicht identisch ist, können Bias oder Leakage von Nonce-Bits über viele Signaturen hinweg eine gitterbasierte Wiederherstellung ermöglichen.<sup>[[5]](#references)</sup>

Technische Wiederherstellung bei wiederverwendetem `k`:<sup>[[4]](#references)</sup>

ECDSA-Signaturgleichungen (Gruppenordnung `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Wird dasselbe `k` für zwei Nachrichten `m1, m2` wiederverwendet, die zu den Signaturen `(r, s1)` und `(r, s2)` führen:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-Curve-Angriffe

Wenn ein Protokoll nicht überprüft, ob ein Eingabepunkt auf der erwarteten Kurve und in der richtigen Untergruppe liegt, kann ein Angreifer Operationen in einer schwächeren Gruppe erzwingen und Informationen über einen geheimen Skalar wiederherstellen. SEC 1 legt Prüfungen zur Validierung öffentlicher Schlüssel fest, die solche Eingaben verhindern sollen.<sup>[[6]](#references)</sup>

Technischer Hinweis:

- Überprüfe, dass Punkte nicht der Punkt im Unendlichen sind, gültige Koordinaten haben, die Kurvengleichung erfüllen und zur erforderlichen Untergruppe gehören.<sup>[[6]](#references)</sup>
- In CTF-Challenges wird dies oft dadurch modelliert, dass ein Server einen vom Angreifer gewählten Punkt mit einem geheimen Skalar multipliziert und einen abgeleiteten Wert zurückgibt.

## Fehlerhafte ML-DSA-Signaturschlüssel und Leakage durch Rejection Sampling

Der erweiterte private Schlüssel von ML-DSA kodiert die Polynomvektoren `s1` und `s2` mit Koeffizienten in `[-η, η]`. FIPS 204 weist darauf hin, dass das Dekodieren fehlerhafter Bytes eines geheimen Schlüssels Koeffizienten außerhalb dieses Bereichs ergeben kann. Der Signaturalgorithmus verlangt selbst keine zusätzliche Konsistenzprüfung des privaten Schlüssels.<sup>[[8]](#references)</sup>

Voraussetzung ist die Kontrolle über einen **erweiterten Signaturschlüssel, bevor dieser importiert oder zum Signieren verwendet wird** – nicht über einen fehlerhaften öffentlichen Schlüssel, der einem Verifizierer vorgelegt wird. Ein permissiver Importpfad kann veränderte gepackte Koeffizienten akzeptieren und dennoch Signaturen erzeugen, die sich verifizieren lassen. Vergleiche die Akzeptanz beim Import und beim Signieren und überprüfe anschließend die resultierenden Signaturen anhand des [Fuzzing-Workflows für kryptografische Schlüsselcodierungen](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings).<sup>[[9]](#references)[[10]](#references)</sup>

Beim Signieren wird `z = y + c·s1` und `r0 = LowBits(w − c·s2)` berechnet; ein Kandidat wird verworfen, wenn `||z||∞ ≥ γ1 − β` oder `||r0||∞ ≥ γ2 − β` gilt. Durch diese Prüfungen sind akzeptierte Ausgaben unabhängig von den gültigen kleinen Geheimnissen. Koeffizienten geheimer Schlüssel außerhalb des zulässigen Bereichs können dieses Argument zum Rejection Sampling beeinträchtigen und einen geheimnisabhängigen Bias verursachen. Dies ist ein bedingter Leakage-Mechanismus, **keine** nachgewiesene Wiederherstellung des vollständigen Schlüssels aufgrund der gemeldeten Abweichung zwischen Bibliotheken.<sup>[[8]](#references)[[10]](#references)</sup>

Die Validierung privater Schlüssel ist von der Signaturverifizierung zu unterscheiden. Im gemeldeten Vergleich führten OpenSSL, BoringSSL und SymCrypt zusätzliche Prüfungen privater Schlüssel durch, während liboqs fehlerhafte erweiterte Schlüssel beim Signieren akzeptierte; das zugrunde liegende `mldsa-native` stellt einen `pk_from_sk()`-Validator bereit, den liboqs nicht zugänglich machte. FIPS 204 schreibt diese zusätzlichen Validierungsprüfungen nicht vor.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digitaler Signaturstandard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner und Heninger: Biased Nonce Sense – Gitterangriffe auf schwache ECDSA-Signaturen](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Kryptografie mit elliptischen Kurven](https://www.secg.org/sec1-v2.pdf)
- [7] [Python-`ecdsa`-Dokumentation](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Digitaler Signaturstandard auf Basis von Modulgittern](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Fehlende ML-DSA- und ML-KEM-Schlüsselprüfungen – liboqs issue #2517](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Stand der Implementierungen postquantenkryptografischer Verfahren](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
