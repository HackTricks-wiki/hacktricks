# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Un ataque homograph (también conocido como homoglyph) abusa del hecho de que muchos **puntos de código Unicode de scripts no latinos son visualmente idénticos o extremadamente similares a caracteres ASCII**. Al reemplazar uno o más caracteres latinos por sus equivalentes visuales, un atacante puede crear:

* Nombres visibles, asuntos o cuerpos de mensajes que parecen legítimos al ojo humano, pero evitan las detecciones basadas en palabras clave.
* Dominios, subdominios o rutas URL que engañan a las víctimas haciéndoles creer que están visitando un sitio de confianza.<sup>[[1]](#references)</sup>

Debido a que cada glifo se identifica internamente mediante su **punto de código Unicode**, un solo carácter sustituido basta para evadir comparaciones de cadenas ingenuas (por ejemplo, `"Παypal.com"` frente a `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Flujo de trabajo típico de Phishing

1. **Crear el contenido del mensaje** – Reemplazar letras latinas específicas de la marca / palabra clave suplantada por caracteres visualmente indistinguibles de otro script (griego, cirílico, armenio, cheroqui, etc.).
2. **Registrar la infraestructura de apoyo** – Registrar opcionalmente un dominio homoglyph y obtener un certificado TLS (la mayoría de las CA no realizan comprobaciones de similitud visual).
3. **Enviar email / SMS** – El mensaje contiene homoglyphs en una o más de las siguientes ubicaciones:
* Nombre visible del remitente (por ejemplo, `Ηеlрdеѕk`)
* Línea de asunto (`Urgеnt Аctіon Rеquіrеd`)
* Texto del hipervínculo o fully qualified domain name
4. **Cadena de redirecciones** – La víctima pasa por sitios web aparentemente benignos o URL shorteners antes de llegar al host malicioso que recopila credenciales / distribuye malware.<sup>[[1]](#references)</sup>

## Rangos Unicode comúnmente abusados

Los siguientes ejemplos son bloques Unicode que contienen caracteres usados habitualmente para crear equivalentes visuales entre scripts.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Rango | Glifo de ejemplo | Se parece a |
|--------|-------|------------------|-------------|
| Griego  | U+0370-03FF | `Η` (U+0397) | Latín `H` |
| Griego  | U+0370-03FF | `ρ` (U+03C1) | Latín `p` |
| Cirílico | U+0400-04FF | `а` (U+0430) | Latín `a` |
| Cirílico | U+0400-04FF | `е` (U+0435) | Latín `e` |
| Armenio | U+0530-058F | `օ` (U+0585) | Latín `o` |
| Cheroqui | U+13A0-13FF | `Ꭲ` (U+13A2) | Latín `T` |

> Consejo: Usa las tablas de códigos Unicode para consultar bloques y puntos de código.

## Técnicas de detección

### 1. Inspección de scripts mixtos

Los emails de Phishing dirigidos a una organización angloparlante rara vez deberían mezclar caracteres de varios scripts. Una heurística sencilla pero eficaz consiste en:

1. Iterar sobre cada carácter de la cadena inspeccionada.
2. Asociar el punto de código con su nombre de script o bloque Unicode.
3. Generar una alerta si hay más de un script presente **o** si aparecen scripts no latinos donde no se esperan (nombre visible, dominio, asunto, URL, etc.).<sup>[[3]](#references)</sup>

Proof-of-concept en Python:
```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
"display_name": "Ηоmоgraph Illusion",     # example data
"subject": "Finаnꮯiаl Տtatеmеnt",
"url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
blocks = defaultdict(int)
for ch in value:
if ch.isascii():
blocks['Latin'] += 1
else:
name = ud.name(ch, 'UNKNOWN')
block = name.split(' ')[0]     # e.g., 'CYRILLIC'
blocks[block] += 1
if len(blocks) > 1:
print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```
### 2. Normalización de Punycode (dominios)

Los nombres de dominio internacionalizados (IDN) tienen una forma Unicode y una forma **Punycode** compatible con ASCII, precedida por `xn--`. Convierte los nombres de host al formato IDNA/Punycode antes de incluirlos en listas de permitidos o compararlos, conservando la forma Unicode para su visualización.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Diccionarios / algoritmos de Homoglyph

Herramientas como **dnstwist** (`--fuzzers homoglyph`) o **urlcrazy** pueden enumerar permutaciones de dominios visualmente similares y son útiles para realizar takedown / monitoring proactivos.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevención y mitigación

* Aplicar políticas estrictas de DMARC/DKIM/SPF: evitar la suplantación desde dominios no autorizados.
* Implementar la lógica de detección anterior en **Secure Email Gateways** y playbooks de **SIEM/XSOAR**.
* Marcar o poner en cuarentena los mensajes cuyo dominio del nombre visible ≠ dominio del remitente.
* Educar a los usuarios: copiar y pegar el texto sospechoso en un inspector de Unicode, pasar el cursor sobre los enlaces y no confiar nunca en acortadores de URL.

## Ejemplos del mundo real

* Nombre visible: `Сonfidеntiаl Ꭲiꮯkеt` (`С`, `е`, `а` cirílicos; `Ꭲ` cheroqui; `ꮯ` en minúscula latina de tipo small capital).
* Cadena de dominios: `bestseoservices.com` ➜ directorio municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ inicio de sesión falso de Microsoft en `mlcorsftpsswddprotcct.approaches.it.com`, protegido por un CAPTCHA OTP personalizado.
* Suplantación de Spotify: remitente `Sρօtifս` con un enlace oculto detrás de `redirects.ca`.

Estas muestras proceden de una investigación de Unit 42 (julio de 2025) y muestran cómo el abuso de Homoglyph se combina con la redirección de URL y la evasión de CAPTCHA para eludir el análisis automatizado.<sup>[[1]](#references)</sup>

## References

- [1] [La ilusión de Homograph: no todo es lo que parece](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Tablas de códigos de caracteres Unicode](https://www.unicode.org/charts/)
- [3] [Estándar técnico Unicode n.º 39: mecanismos de seguridad de Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – motor de permutación de dominios](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – generador de errores tipográficos y variaciones de dominios](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: nombres de dominio internacionalizados para aplicaciones (IDNA): definiciones y marco documental](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
