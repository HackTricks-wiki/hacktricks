# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara" abusa de la ruta de descarga XFlash de MediaTek para ejecutar una etapa Download Agent stage 2 (DA2) modificada a pesar de las comprobaciones de integridad en DA1. DA1 almacena el SHA-256 esperado de DA2 en RAM y lo compara antes de realizar el salto. En muchos loaders, el host controla completamente la dirección/tamaño de carga de DA2, proporcionando una escritura en memoria no comprobada que puede sobrescribir ese hash en memoria y redirigir la ejecución a payloads arbitrarios (contexto pre-OS con invalidación de cache manejada por DA).

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** está firmado/cargado por BootROM/Preloader. Cuando Download Agent Authorization (DAA) está habilitado, solo debería ejecutarse DA1 firmado.
- **DA2** se envía por USB. DA1 recibe **size**, **load address**, y **SHA-256** y hashea el DA2 recibido, comparándolo con un **hash esperado incrustado en DA1** (copiado en RAM).
- **Weakness:** En loaders sin parchear, DA1 no valida la dirección/tamaño de carga de DA2 y mantiene el hash esperado escribible en memoria, permitiendo que el host manipule la comprobación.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Entrar en el flujo de staging DA1→DA2 (DA1 asigna, prepara DRAM y expone el buffer del hash esperado en RAM).
2. **Hash-slot overwrite:** Enviar un pequeño payload que escanee la memoria de DA1 en busca del hash esperado de DA2 almacenado y lo sobrescriba con el SHA-256 del DA2 modificado por el atacante. Esto aprovecha la carga controlada por el usuario para colocar el payload donde reside el hash.
3. **Second `BOOT_TO` + digest:** Disparar otro `BOOT_TO` con la metadata de DA2 parcheada y enviar el digest crudo de 32 bytes que coincide con el DA2 modificado. DA1 recalcula SHA-256 sobre el DA2 recibido, lo compara con el hash esperado ahora parcheado, y el salto hacia el código del atacante tiene éxito.

Debido a que la dirección/tamaño de carga están controlados por el atacante, la misma primitiva puede escribir en cualquier lugar de la memoria (no solo en el buffer de hash), permitiendo implantes de early-boot, ayudantes para bypass de secure-boot, o rootkits maliciosos.

## Minimal PoC pattern (mtkclient-style)
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
- `payload` replica el blob de la herramienta de pago que parchea el buffer expected-hash dentro de DA1.
- `sha256(...).digest()` envía bytes crudos (no hex) para que DA1 los compare contra el buffer parcheado.
- DA2 puede ser cualquier imagen creada por el atacante; elegir la dirección/tamaño de carga permite la colocación arbitraria en memoria con la invalidación de caché manejada por DA.

## Panorama de parches (cargadores endurecidos)

- **Mitigación**: Los DAs actualizados fijan en el código la dirección de carga de DA2 a `0x40000000` e ignoran la dirección que el host suministra, por lo que las escrituras no pueden alcanzar la ranura de hash de DA1 (rango ~`0x200000`). El hash sigue siendo calculado pero ya no es escribible por el atacante.
- **Detección de DAs parchados**: mtkclient/penumbra escanean DA1 en busca de patrones que indiquen el endurecimiento de la dirección; si se detecta, Carbonara se omite. Los DAs antiguos exponen ranuras de hash escribibles (comúnmente alrededor de offsets como `0x22dea4` en V5 DA1) y siguen siendo explotables.
- **V5 vs V6**: Algunos cargadores V6 (XML) aún aceptan direcciones suministradas por el usuario; los binarios V6 más recientes suelen imponer la dirección fija y son inmunes a Carbonara a menos que se degraden.

## Nota post-Carbonara (heapb8)

MediaTek parcheó Carbonara; una vulnerabilidad más reciente, **heapb8**, apunta al manejador de descarga de archivos USB de DA2 en cargadores V6 parchados, otorgando ejecución de código incluso cuando `boot_to` está endurecido. Abusa de un desbordamiento de heap durante transferencias de archivos en fragmentos para tomar el control del flujo de ejecución de DA2. El exploit es público en Penumbra/mtk-payloads y demuestra que las correcciones de Carbonara no cierran toda la superficie de ataque de los DA.

## Notas para triaje y endurecimiento

- Los dispositivos donde la dirección/tamaño de DA2 no se verifican y DA1 mantiene el hash esperado escribible son vulnerables. Si un Preloader/DA posterior impone límites de dirección o mantiene el hash inmutable, Carbonara está mitigado.
- Habilitar DAA y asegurar que DA1/Preloader validen los parámetros BOOT_TO (límites + autenticidad de DA2) cierra la primitiva. Cerrar solo el parche del hash sin acotar la carga aún deja riesgo de escritura arbitraria.

## Referencias

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
