# MediaTek XFlash Carbonara Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Resumen

"Carbonara" abusa de la ruta de descarga de MediaTek XFlash para ejecutar una fase modificada de Download Agent stage 2 (DA2) a pesar de las comprobaciones de integridad de DA1. DA1 almacena el SHA-256 esperado de DA2 en la RAM y lo compara antes de realizar el salto. En muchos loaders, el host controla completamente la dirección y el tamaño de carga de DA2, lo que proporciona una escritura de memoria no validada que puede sobrescribir ese hash en memoria y redirigir la ejecución a payloads arbitrarios (en el contexto pre-OS, con la invalidación de caché gestionada por DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Límite de confianza en XFlash (DA1 → DA2)

- **DA1** está firmado/cargado por BootROM/Preloader. Cuando Download Agent Authorization (DAA) está habilitado, solo debería ejecutarse DA1 firmado.
- **DA2** se envía mediante USB. DA1 recibe el **tamaño**, la **dirección de carga** y el **SHA-256**, calcula el hash del DA2 recibido y lo compara con un **hash esperado incrustado en DA1** (copiado en la RAM).
- **Debilidad:** En loaders sin parchear, DA1 no valida la dirección ni el tamaño de carga de DA2 y mantiene el hash esperado modificable en memoria, lo que permite al host manipular la comprobación.<sup>[[1]](#references)[[2]](#references)</sup>

## Flujo de Carbonara (truco de los "dos BOOT_TO")

1. **Primer `BOOT_TO`:** Entra en el flujo de staging de DA1→DA2 (DA1 asigna memoria, prepara la DRAM y expone el buffer del hash esperado en la RAM).
2. **Sobrescritura del hash:** Envía un payload pequeño que busca en la memoria de DA1 el hash esperado almacenado de DA2 y lo sobrescribe con el SHA-256 del DA2 modificado por el atacante. Esto aprovecha la carga controlada por el usuario para colocar el payload donde reside el hash.
3. **Segundo `BOOT_TO` + digest:** Activa otro `BOOT_TO` con los metadatos de DA2 modificados y envía el digest sin procesar de 32 bytes que coincide con el DA2 modificado. DA1 vuelve a calcular el SHA-256 sobre el DA2 recibido, lo compara con el hash esperado ya modificado y el salto se realiza correctamente hacia el código del atacante.

En los loaders afectados, la dirección y el tamaño no validados pueden proporcionar una primitiva de escritura de memoria pre-OS seleccionada por el atacante que va más allá del espacio del hash. Según el mapa de memoria del SoC y las fases posteriores de verificación, esto puede permitir early-boot implants, helpers de secure-boot-bypass o payloads de estilo rootkit. La ejecución de código de DA por sí sola no proporciona automáticamente persistencia ni un secure-boot-bypass completo; todavía se necesitan un mecanismo de persistencia independiente y una cadena de verificación compatible.<sup>[[1]](#references)[[2]](#references)</sup>

## Patrón de PoC mínimo (estilo mtkclient)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- El `payload` de 16 bytes reproduce el blob observado en el workflow de la herramienta de pago y utilizado por la implementación publicada para parchear el buffer del hash esperado. Es específico del loader, no un parche portable del slot del hash para cada SoC o DA.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` envía bytes sin procesar (no hexadecimales) para que DA1 compare con el buffer parcheado.
- En un loader vulnerable y compatible, DA2 puede ser una imagen creada por el atacante y los metadatos de carga elegidos controlan su ubicación en memoria. Valida la combinación DA/SoC antes de la transmisión, ya que las direcciones incorrectas pueden bloquear o dañar el objetivo.<sup>[[3]](#references)</sup>

## Panorama de parches (loaders reforzados)

- **Mitigación observada**: Los DAs reforzados examinados por los investigadores fuerzan la dirección de carga de DA2 a `0x40000000` e ignoran la dirección proporcionada por el host, evitando escrituras en la región de hash observada de DA1 cerca de `0x200000`. Trata ambas direcciones como específicas de la implementación, no como constantes arquitectónicas.
- **Detección de DAs parcheados**: mtkclient/penumbra analizan DA1 en busca de patrones que indiquen el refuerzo de la dirección; si los encuentran, Carbonara se omite. Los DAs antiguos exponen slots de hash modificables (comúnmente alrededor de offsets como `0x22dea4` en V5 DA1) y siguen siendo explotables.
- **V5 frente a V6**: Algunos loaders V6 (XML) todavía aceptan direcciones proporcionadas por el usuario; los binarios V6 más nuevos normalmente fuerzan la dirección fija y son inmunes a Carbonara, a menos que se haga downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Nota posterior a Carbonara (heapb8)

MediaTek parcheó Carbonara; una vulnerabilidad más reciente, **heapb8**, apunta al handler de descarga de archivos USB de DA2 en loaders V6 parcheados, proporcionando ejecución de código incluso cuando `boot_to` está reforzado. Abusa de un heap overflow durante las transferencias de archivos fragmentadas para tomar el control del flujo de ejecución de DA2. El exploit es público en Penumbra/mtk-payloads y demuestra que las correcciones de Carbonara no cierran toda la superficie de ataque de DA.<sup>[[4]](#references)</sup>

## Notas para triage y hardening

- Los dispositivos en los que la dirección/tamaño de DA2 no se comprueban y DA1 mantiene modificable el hash esperado son vulnerables. Si un Preloader/DA posterior aplica límites de dirección o mantiene el hash inmutable, Carbonara está mitigado.
- Activar DAA y garantizar que DA1/Preloader validen los parámetros de BOOT_TO (límites + autenticidad de DA2) cierra la primitive. Cerrar únicamente el parche del hash sin limitar la carga todavía deja riesgo de escritura arbitraria.

## References

- [1] [Carbonara: El exploit de MediaTek que nadie sirvió](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Documentación del exploit Carbonara](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Código fuente de Carbonara de Penumbra](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: explotando Download Agents V6 parcheados](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
