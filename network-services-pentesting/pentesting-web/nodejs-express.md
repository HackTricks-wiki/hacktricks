# NodeJS Express

## Cookie Signature

The tool [https://github.com/DigitalInterruption/cookie-monster](https://github.com/DigitalInterruption/cookie-monster) is a utility for automating the testing and re-signing of Express.js cookie secrets.

### Single cookie with a specific name

```bash
cookie-monster -c eyJmb28iOiJiYXIifQ== -s LVMVxSNPdU_G8S3mkjlShUD78s4 -n session
```

### Custom wordlist

```bash
cookie-monster -c eyJmb28iOiJiYXIifQ== -s LVMVxSNPdU_G8S3mkjlShUD78s4 -w custom.lst
```

### Test multiple cookies using batch mode

```bash
cookie-monster -b -f cookies.json
```

### Test multiple cookies using batch mode with a custom wordlist

```bash
cookie-monster -b -f cookies.json -w custom.lst
```

### Encode and sign a new cookie

iI you know the secret you can sign a the cookie.

```bash
cookie-monster -e -f new_cookie.json -k secret
```
