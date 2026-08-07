# MediaTek XFlash Carbonara Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Resumen

"Carbonara" abusa de la ruta de descarga XFlash de MediaTek para ejecutar una fase 2 (DA2) de Download Agent modificada a pesar de las comprobaciones de integridad de DA1. DA1 almacena en la RAM el SHA-256 esperado de DA2 y lo compara antes de realizar el salto. En muchos loaders, el host controla completamente la dirección y el tamaño de carga de DA2, lo que proporciona una escritura de memoria no validada capaz de sobrescribir el hash almacenado en memoria y redirigir la ejecución hacia payloads arbitrarios (en el contexto pre-OS, con la invalidación de caché gestionada por DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Límite de confianza en XFlash (DA1 → DA2)

- **DA1** está firmado/cargado por BootROM/Preloader. Cuando Download Agent Authorization (DAA) está habilitado, solo debería ejecutarse un DA1 firmado.
- **DA2** se envía mediante USB. DA1 recibe el **tamaño**, la **dirección de carga** y el **SHA-256**, calcula el hash del DA2 recibido y lo compara con un **hash esperado incluido en DA1** (copiado en la RAM).
- **Debilidad:** En loaders sin parchear, DA1 no valida la dirección ni el tamaño de carga de DA2 y mantiene el hash esperado modificable en memoria, lo que permite al host manipular la comprobación.<sup>[[1]](#references)[[2]](#references)</sup>

## Flujo de Carbonara (truco de los "dos BOOT_TO")

1. **Primer `BOOT_TO`:** Entra en el flujo de staging de DA1→DA2 (DA1 asigna memoria, prepara la DRAM y expone el buffer del hash esperado en la RAM).
2. **Sobrescritura del hash-slot:** Envía un payload pequeño que recorre la memoria de DA1 en busca del hash esperado de DA2 almacenado y lo sobrescribe con el SHA-256 del DA2 modificado por el atacante. Esto aprovecha la carga controlada por el usuario para colocar el payload donde reside el hash.
3. **Segundo `BOOT_TO` + digest:** Activa otro `BOOT_TO` con los metadatos de DA2 modificados y envía el digest raw de 32 bytes que coincide con el DA2 modificado. DA1 vuelve a calcular el SHA-256 sobre el DA2 recibido, lo compara con el hash esperado ya modificado y el salto se realiza correctamente hacia el código del atacante.

Como la dirección y el tamaño de carga están controlados por el atacante, la misma primitive puede escribir en cualquier lugar de la memoria (no solo en el buffer del hash), permitiendo implants de early-boot, helpers para el bypass de secure-boot o rootkits maliciosos.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `payload` replica el blob de la herramienta de pago que parchea el buffer de expected-hash dentro de DA1.
- `sha256(...).digest()` envía bytes sin procesar (no hexadecimales), por lo que DA1 compara con el buffer parcheado.
- DA2 puede ser cualquier imagen creada por el atacante; elegir la dirección/tamaño de carga permite una colocación arbitraria en memoria, con la invalidación de caché gestionada por DA.<sup>[[3]](#references)</sup>

## Panorama de parches (loaders reforzados)

- **Mitigación**: Los DAs actualizados fijan la dirección de carga de DA2 en `0x40000000` e ignoran la dirección proporcionada por el host, por lo que las escrituras no pueden alcanzar el slot del hash de DA1 (aproximadamente en el rango `0x200000`). El hash se sigue calculando, pero ya no puede ser escrito por el atacante.
- **Detección de DAs parcheados**: mtkclient/penumbra buscan en DA1 patrones que indican el refuerzo de la dirección; si los encuentran, Carbonara se omite. Los DAs antiguos exponen slots de hash escribibles (normalmente alrededor de offsets como `0x22dea4` en DA1 V5) y siguen siendo explotables.
- **V5 frente a V6**: Algunos loaders V6 (XML) todavía aceptan direcciones proporcionadas por el usuario; los binarios V6 más recientes normalmente fuerzan la dirección fija y son inmunes a Carbonara, salvo que se haga downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Nota posterior a Carbonara (heapb8)

MediaTek parcheó Carbonara; una vulnerabilidad más reciente, **heapb8**, apunta al handler de descarga de archivos USB de DA2 en loaders V6 parcheados, proporcionando ejecución de código incluso cuando `boot_to` está reforzado. Abusa de un heap overflow durante las transferencias de archivos fragmentadas para tomar el control del flujo de ejecución de DA2. El exploit es público en Penumbra/mtk-payloads y demuestra que las correcciones de Carbonara no cierran toda la superficie de ataque de DA.<sup>[[4]](#references)</sup>

## Notas para el triage y el hardening

- Los dispositivos en los que la dirección/tamaño de DA2 no se comprueban y DA1 mantiene escribible el hash esperado son vulnerables. Si un Preloader/DA posterior aplica límites de dirección o mantiene el hash inmutable, Carbonara queda mitigado.
- Activar DAA y garantizar que DA1/Preloader validen los parámetros de BOOT_TO (límites + autenticidad de DA2) cierra la primitiva. Cerrar únicamente el parcheo del hash sin limitar la carga sigue dejando un riesgo de escritura arbitraria.

## Referencias

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Documentación del exploit Carbonara](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Código fuente de Carbonara de Penumbra](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: explotación de Download Agents V6 parcheados](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
