# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Resumen

"Carbonara" abusa de la ruta de descarga XFlash de MediaTek para ejecutar un Download Agent modificado stage 2 (DA2) a pesar de las comprobaciones de integridad de DA1. DA1 almacena el SHA-256 esperado de DA2 en RAM y lo compara antes de transferir la ejecución. En muchos loaders, el host controla completamente la load address/size de DA2, lo que permite una escritura en memoria sin validar que puede sobrescribir ese hash en memoria y redirigir la ejecución a payloads arbitrarios (contexto pre-OS con cache invalidation manejada por DA).

## Límite de confianza en XFlash (DA1 → DA2)

- **DA1** está firmado/cargado por BootROM/Preloader. Cuando Download Agent Authorization (DAA) está habilitado, solo debería ejecutarse DA1 firmado.
- **DA2** se envía por USB. DA1 recibe **size**, **load address**, y **SHA-256**, y calcula el hash del DA2 recibido comparándolo con un **hash esperado embebido en DA1** (copiado en RAM).
- **Weakness:** En loaders sin parchear, DA1 no sanea la load address/size de DA2 y mantiene el hash esperado escribible en memoria, permitiendo que el host manipule la comprobación.

## Flujo de Carbonara ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Entra en el flujo de staging DA1→DA2 (DA1 asigna, prepara DRAM y expone el buffer del hash esperado en RAM).
2. **Hash-slot overwrite:** Envía un pequeño payload que escanea la memoria de DA1 buscando el hash esperado de DA2 y lo sobrescribe con el SHA-256 del DA2 modificado por el atacante. Esto aprovecha la carga controlada por el usuario para ubicar el payload donde reside el hash.
3. **Second `BOOT_TO` + digest:** Dispara otro `BOOT_TO` con los metadatos de DA2 parchados y envía el digest crudo de 32 bytes que coincide con el DA2 modificado. DA1 recalcula SHA-256 sobre el DA2 recibido, lo compara con el hash esperado ya parchado, y el salto hacia el código del atacante tiene éxito.

Debido a que la load address/size están controladas por el attacker, la misma primitive puede escribir en cualquier lugar de la memoria (no solo el buffer del hash), habilitando early-boot implants, helpers para secure-boot bypass, o rootkits maliciosos.

## Patrón mínimo de PoC (mtkclient-style)
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
- `payload` replica el blob de la herramienta de pago que parchea el expected-hash buffer dentro de DA1.
- `sha256(...).digest()` envía bytes crudos (no hex) por lo que DA1 los compara con el buffer parcheado.
- DA2 puede ser cualquier imagen construida por el atacante; elegir la dirección/tamaño de carga permite colocación arbitraria en memoria con la invalidación de caché manejada por DA.

## Notas para triage y hardening

- Los dispositivos donde la dirección/tamaño de DA2 no se validan y DA1 mantiene el expected-hash escribible son vulnerables. Si un Preloader/DA posterior impone límites de dirección o mantiene el hash inmutable, Carbonara queda mitigado.
- Habilitar DAA y asegurarse de que DA1/Preloader validen los parámetros BOOT_TO (límites + autenticidad de DA2) cierra la primitiva. Cerrar solo el hash patch sin acotar la carga sigue dejando riesgo de arbitrary write.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
