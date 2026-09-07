# Bypass de autorización por divergencia de estado y valores predeterminados

{{#include ../../banners/hacktricks-training.md}}

La autorización a veces depende de un estado económico derivado en lugar de un rol explícito; por ejemplo, «el caller posee todo el suministro». Si los valores de ese predicado provienen de distintos almacenes, un duplicado obsoleto puede convertir un atajo legítimo de propiedad en un bypass de autorización. El módulo de marcadores de Provenance demostró la peligrosa combinación: un balance activo del caller se comparaba con metadatos del suministro locales al marcador que no se actualizaban para activos con suministro no fijo.<sup>[[1]](#references)</sup>

## Auditar el estado duplicado como límite de autorización

Para cada valor utilizado por una comprobación de permisos, enumera **todas las representaciones**: estado canónico del módulo, campos de objetos, agregados almacenados en caché, índices, snapshots, registros de bridges y réplicas off-chain. Después, sigue cada ruta de create, mint, burn, transfer, reset, migration y synchronization para determinar qué copia se actualiza en cada modo de objeto. Un campo puede ser autoritativo para un modo e informativo para otro.<sup>[[1]](#references)</sup>

Un flujo de revisión práctico es:<sup>[[1]](#references)</sup>

1. Localiza las acciones protegidas y reduce cada rama de autorización a un predicado booleano.
2. Para cada operando, registra su almacén, rutas de actualización, estados del ciclo de vida y fuente de verdad.
3. Genera transiciones que actualicen solo una representación y, después, compara todas las copias.
4. Intenta ejecutar la acción protegida desde una cuenta nueva después de cada transición.
5. Continúa más allá del bypass: si la acción modifica una ACL, asígnate roles persistentes y ejecuta las APIs privilegiadas normales.

Entre los patrones sospechosos se incluyen `cachedSupply == balance`, `metadataOwner == caller` o `snapshotShares == currentShares` cuando ambos lados tienen reglas de synchronization diferentes. Consultar un valor autoritativo para un operando no hace que la comparación sea segura cuando el otro operando está obsoleto.<sup>[[1]](#references)</sup>

## Bypass de igualdad con valores predeterminados

Un predicado de igualdad también es inseguro cuando ambos operandos pueden adoptar independientemente el mismo valor predeterminado. La comprobación siguiente concede «control total del suministro» a cualquier cuenta vacía cuando `supply` es cero, independientemente de que el cero sea consecuencia de metadatos obsoletos o de un objeto legítimamente sin fondos.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Cambiar al almacén canónico corrige la divergencia, pero **no** el caso del objeto vacío. La propiedad de seguridad debe incluir una condición de validez independiente; el parche de Provenance utiliza el suministro bancario actual y rechaza un suministro nulo o igual a cero antes de comparar el saldo del caller.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Aplica el mismo razonamiento a los recuentos de quórum, porcentajes de propiedad, deuda, colateral, epochs, nonces, timestamps y contadores: `callerValue == protectedValue` no debe autorizar a un caller hasta que el valor protegido sea válido de forma independiente y pertenezca al dominio esperado.<sup>[[1]](#references)</sup>

## Toma de control del ACL para realizar operaciones privilegiadas legítimas

Un bypass en una operación de edición del ACL es una primitiva duradera de escalada de privilegios. En el caso de Provenance, una cuenta sin privilegios y con cero tokens podía superar la comprobación de suministro obsoleto `0 == 0`, concederse permisos administrativos, de mint y de withdrawal, y después utilizar los message handlers ordinarios para hacer mint de assets o retirar fondos del escrow. Por tanto, el exploit no necesitaba una segunda vulnerabilidad después del cambio del ACL.<sup>[[1]](#references)</sup>

Secuencia general de explotación:<sup>[[1]](#references)</sup>

1. Encuentra un objeto cuyo campo no autoritativo difiera del estado actual o cuyo valor protegido sea el valor predeterminado.
2. Utiliza una identidad nueva/vacía para que su valor local coincida con ese valor obsoleto/predeterminado.
3. Llama al endpoint de gestión de roles, transferencia de ownership o actualización de políticas y concédete capacidades duraderas.
4. Confirma la persistencia leyendo el ACL desde el estado canónico.
5. Invoca la operación legítima de alto impacto (mint, withdrawal, upgrade, transferencia de ownership o cambio de política).

Al evaluar el impacto, inspecciona todas las capacidades accesibles desde el nuevo rol en lugar de detenerte en el bypass de autorización. Las cuentas similares a escrow pueden custodiar assets no relacionados con el objeto cuyos metadatos obsoletos permitieron la toma de control.<sup>[[1]](#references)</sup>

## Objetivos de invariant y stateful-fuzzing

Especifica la autorización independientemente de la implementación. Para un atajo de suministro total, el invariant mínimo es:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Usa un fuzzer de model/state-machine para generar secuencias, no llamadas aisladas, que cubran la creación, la inicialización con valor cero, la activación/finalización, el minting, el burning, las transferencias, los resets, las migraciones, las llamadas de sincronización y los cambios de ACL. Después de cada transición, compara las representaciones duplicadas y afirma que una cuenta nueva no puede realizar ninguna acción protegida. Siembra casos explícitos para valores cero, una unidad, ownership parcial, ownership total, stale-low y stale-high.<sup>[[1]](#references)[[2]](#references)</sup>

Las propiedades de regresión de mayor señal son:<sup>[[1]](#references)[[2]](#references)</sup>

- Un supply autoritativo cero nunca implica ownership ni administración.
- Los holders parciales no pueden convertirse en administradores cuando un supply duplicado es igual a su balance.
- Un holder verdaderamente total conserva el shortcut previsto cuando el supply live es positivo.
- Los self-grants fallidos no mutan el ACL ni habilitan llamadas privilegiadas posteriores.
- Los cambios de modo no pueden cambiar silenciosamente qué representación considera autoritativa un authorization check.

## References

- [1] [La divergencia de estado permite el acceso no autorizado (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Corrige las comprobaciones de supply obsoleto](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Commit c81fd65 de Provenance - Rechaza un supply cero en el shortcut de autorización del supply total](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
