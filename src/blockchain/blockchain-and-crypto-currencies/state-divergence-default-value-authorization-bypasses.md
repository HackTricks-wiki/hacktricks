# Divergencia de estado y bypasses de autorización por valores predeterminados

{{#include ../../banners/hacktricks-training.md}}

La autorización a veces depende de un estado económico derivado en lugar de un rol explícito; por ejemplo, «el caller posee toda la oferta». Si los valores de ese predicado provienen de distintos almacenes, un duplicado desactualizado puede convertir un atajo legítimo de propiedad en un bypass de autorización. El módulo Provenance marker demostró la peligrosa combinación: se comparó el saldo actualizado del caller con metadatos locales del marker sobre la oferta, que no se actualizaban en el caso de activos con oferta no fija.<sup>[[1]](#references)</sup>

## Auditar el estado duplicado como límite de autorización

Para cada valor usado en una comprobación de permisos, enumera **todas las representaciones**: estado canónico del módulo, campos de objetos, agregados en caché, índices, snapshots, registros de bridges y mirrors off-chain. Después, rastrea cada ruta de creación, mint, burn, transferencia, reinicio, migración y sincronización para determinar qué copia se actualiza en cada modo de objeto. Un campo puede ser autoritativo en un modo e informativo en otro.<sup>[[1]](#references)</sup>

Un flujo de revisión práctico es:<sup>[[1]](#references)</sup>

1. Localiza las acciones protegidas y reduce cada rama de autorización a un predicado booleano.
2. Para cada operando, registra su almacén, rutas de actualización, estados del ciclo de vida y fuente de verdad.
3. Genera transiciones que actualicen solo una representación y luego compara todas las copias.
4. Intenta ejecutar la acción protegida desde una cuenta nueva después de cada transición.
5. Ve más allá del bypass: si la acción modifica una ACL, asígnate roles persistentes y llama a las API privilegiadas habituales.

Entre los patrones sospechosos se incluyen `cachedSupply == balance`, `metadataOwner == caller` o `snapshotShares == currentShares` cuando ambos lados tienen reglas de sincronización distintas. Consultar un valor autoritativo para un operando no hace que la comparación sea segura si el otro operando está desactualizado.<sup>[[1]](#references)</sup>

## Bypass por igualdad con valores predeterminados

Un predicado de igualdad también es inseguro cuando ambos operandos pueden tomar independientemente el mismo valor predeterminado. La comprobación de abajo concede «control total de la oferta» a cualquier cuenta vacía cuando `supply` es cero, independientemente de si el cero se debe a metadatos desactualizados o a un objeto legítimamente sin fondos.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

Cambiar al almacén canónico corrige la divergencia, pero **no** el caso de objeto vacío. La propiedad de seguridad debe incluir una condición de validez independiente; el parche de Provenance usa el suministro actual del banco y rechaza un suministro nulo o igual a cero antes de comparar el saldo del llamante.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Aplica el mismo razonamiento a los recuentos de quórum, los porcentajes de propiedad, la deuda, las garantías, las épocas, los nonces, las marcas de tiempo y los contadores: `callerValue == protectedValue` no debe autorizar a un caller hasta que el valor protegido sea válido de forma independiente y pertenezca al dominio esperado.<sup>[[1]](#references)</sup>

## Toma de control de ACL para ejecutar operaciones privilegiadas legítimas

Un bypass en una operación de edición de ACL es un mecanismo duradero de escalada de privilegios. En el caso de Provenance, una cuenta sin privilegios y con cero tokens podía superar la comprobación obsoleta `0 == 0` del suministro, concederse permisos administrativos, de acuñación y de retiro, y luego usar los message handlers habituales para acuñar activos o retirar fondos del escrow. Por lo tanto, el exploit no requería una segunda vulnerabilidad después del cambio de ACL.<sup>[[1]](#references)</sup>

Secuencia general de explotación:<sup>[[1]](#references)</sup>

1. Encuentra un objeto cuyo campo no autoritativo difiera del estado actual, o cuyo valor protegido sea el valor predeterminado.
2. Usa una identidad nueva o vacía para que su valor local coincida con ese valor obsoleto o predeterminado.
3. Llama al endpoint de gestión de roles, transferencia de propiedad o actualización de políticas y concédete capacidades duraderas.
4. Confirma la persistencia leyendo la ACL desde el estado canónico.
5. Ejecuta la operación legítima de alto impacto (acuñar, retirar, actualizar, transferir la propiedad o cambiar la política).

Al evaluar el impacto, inspecciona todas las capacidades accesibles desde el nuevo rol en lugar de detenerte en el bypass de autorización. Las cuentas similares a escrow pueden custodiar activos que no estén relacionados con el objeto cuyos metadatos obsoletos permitieron la toma de control.<sup>[[1]](#references)</sup>

## Invariantes y objetivos de fuzzing con estado

Especifica la autorización independientemente de la implementación. Para un atajo de suministro total, el invariante mínimo es:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Usa un fuzzer de modelo/máquina de estados para generar secuencias —no llamadas aisladas— que cubran creación, inicialización con valor cero, activación/finalización, acuñación, quema, transferencias, reinicios, migraciones, llamadas sync y cambios de ACL. Después de cada transición, compara las representaciones duplicadas y comprueba que una cuenta nueva no pueda realizar ninguna acción protegida. Incluye casos explícitos para valores cero, una unidad, propiedad parcial, propiedad total, valores obsoletos inferiores y valores obsoletos superiores.<sup>[[1]](#references)[[2]](#references)</sup>

Las propiedades de regresión más importantes son:<sup>[[1]](#references)[[2]](#references)</sup>

- Un suministro autoritativo igual a cero nunca implica propiedad ni administración.
- Los titulares parciales no pueden convertirse en administradores cuando un suministro duplicado coincide con su saldo.
- Un titular realmente pleno conserva el atajo previsto cuando el suministro actual es positivo.
- Los intentos fallidos de otorgarse permisos a sí mismo no modifican la ACL ni habilitan llamadas privilegiadas posteriores.
- Los cambios de modo no pueden cambiar silenciosamente qué representación considera autoritativa una comprobación de autorización.

## References

- [1] [La divergencia de estado permite el acceso no autorizado (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [PR #2734 de Provenance: corregir las comprobaciones de suministro obsoletas](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Commit c81fd65 de Provenance: rechazar el suministro cero en el atajo de autorización del suministro total](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
