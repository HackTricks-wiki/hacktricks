# Ataques de Homografía / Homoglifos en Phishing

{{#include ../../banners/hacktricks-training.md}}

## Descripción General

Un ataque de homografía (también conocido como homoglyph) abusa del hecho de que muchos **puntos de código Unicode de scripts no latinos son visualmente idénticos o extremadamente similares a caracteres ASCII**. Al reemplazar uno o más caracteres latinos con sus contrapartes visualmente similares, un atacante puede crear:

* Nombres de exhibición, asuntos o cuerpos de mensajes que parecen legítimos a la vista humana pero evitan detecciones basadas en palabras clave.
* Dominios, subdominios o rutas de URL que engañan a las víctimas haciéndoles creer que están visitando un sitio de confianza.

Debido a que cada glifo se identifica internamente por su **punto de código Unicode**, un solo carácter sustituido es suficiente para derrotar comparaciones de cadenas ingenuas (por ejemplo, `"Παypal.com"` vs. `"Paypal.com"`).

## Flujo de Trabajo Típico de Phishing

1. **Crear contenido del mensaje** – Reemplazar letras latinas específicas en la marca / palabra clave suplantada con caracteres visualmente indistinguibles de otro script (griego, cirílico, armenio, cherokee, etc.).
2. **Registrar infraestructura de soporte** – Opcionalmente registrar un dominio homoglyph y obtener un certificado TLS (la mayoría de las CAs no realizan verificaciones de similitud visual).
3. **Enviar correo electrónico / SMS** – El mensaje contiene homoglyphs en una o más de las siguientes ubicaciones:
* Nombre de exhibición del remitente (por ejemplo, `Ηеlрdеѕk`)
* Línea de asunto (`Urgеnt Аctіon Rеquіrеd`)
* Texto del hipervínculo o nombre de dominio completamente calificado
4. **Cadena de redirección** – La víctima es redirigida a través de sitios web aparentemente benignos o acortadores de URL antes de aterrizar en el host malicioso que recoge credenciales / entrega malware.

## Rangos de Unicode Comúnmente Abusados

| Script | Rango | Glifo de ejemplo | Se parece a |
|--------|-------|------------------|-------------|
| Griego | U+0370-03FF | `Η` (U+0397) | Latino `H` |
| Griego | U+0370-03FF | `ρ` (U+03C1) | Latino `p` |
| Cirílico | U+0400-04FF | `а` (U+0430) | Latino `a` |
| Cirílico | U+0400-04FF | `е` (U+0435) | Latino `e` |
| Armenio | U+0530-058F | `օ` (U+0585) | Latino `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latino `T` |

> Consejo: Los gráficos completos de Unicode están disponibles en [unicode.org](https://home.unicode.org/).

## Técnicas de Detección

### 1. Inspección de Script Mixto

Los correos electrónicos de phishing dirigidos a una organización de habla inglesa rara vez deberían mezclar caracteres de múltiples scripts. Una heurística simple pero efectiva es:

1. Iterar cada carácter de la cadena inspeccionada.
2. Mapear el punto de código a su bloque Unicode.
3. Generar una alerta si hay más de un script presente **o** si aparecen scripts no latinos donde no se esperan (nombre de exhibición, dominio, asunto, URL, etc.).

Prueba de concepto en Python:
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
### 2. Normalización de Punycode (Dominios)

Los Nombres de Dominio Internacionalizados (IDNs) se codifican con **punycode** (`xn--`). Convertir cada nombre de host a punycode y luego de vuelta a Unicode permite la comparación con una lista blanca o realizar verificaciones de similitud (por ejemplo, distancia de Levenshtein) **después** de que la cadena ha sido normalizada.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Diccionarios / Algoritmos de Homógrafos

Herramientas como **dnstwist** (`--homoglyph`) o **urlcrazy** pueden enumerar permutaciones de dominios visualmente similares y son útiles para la eliminación / monitoreo proactivo.

## Prevención y Mitigación

* Hacer cumplir políticas estrictas de DMARC/DKIM/SPF – prevenir el spoofing de dominios no autorizados.
* Implementar la lógica de detección anterior en **Secure Email Gateways** y **SIEM/XSOAR** playbooks.
* Marcar o poner en cuarentena mensajes donde el dominio del nombre de visualización ≠ dominio del remitente.
* Educar a los usuarios: copiar y pegar texto sospechoso en un inspector de Unicode, pasar el cursor sobre los enlaces, nunca confiar en acortadores de URL.

## Ejemplos del Mundo Real

* Nombre de visualización: `Сonfidеntiаl Ꭲiꮯkеt` (Cirílico `С`, `е`, `а`; Cherokee `Ꭲ`; letra latina en mayúscula `ꮯ`).
* Cadena de dominio: `bestseoservices.com` ➜ directorio municipal `/templates` ➜ `kig.skyvaulyt.ru` ➜ inicio de sesión falso de Microsoft en `mlcorsftpsswddprotcct.approaches.it.com` protegido por un CAPTCHA OTP personalizado.
* Suplantación de Spotify: remitente `Sρօtifւ` con enlace oculto detrás de `redirects.ca`.

Estos ejemplos provienen de la investigación de Unit 42 (julio de 2025) e ilustran cómo el abuso de homógrafos se combina con la redirección de URL y la evasión de CAPTCHA para eludir el análisis automatizado.

## Referencias

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
