# Ruby on Rails `_json` pollution

{{#include ../../banners/hacktricks-training.md}}

## Basic information

When a Rails endpoint receives a JSON body whose root value is not a hash, such as an array, the parsed value is exposed under the synthetic `_json` parameter. Depending on the parser and Rails version, an attacker-supplied `_json` member in an object can create an unexpected parameter shape or collide with application logic that also trusts `_json`.<sup>[[1]](#references)</sup>

This becomes a security issue when validation or authorization checks one parameter representation but a later operation consumes the polluted `_json` value. The following object illustrates attacker-controlled values placed under that reserved-looking key:<sup>[[1]](#references)</sup>

```json
{
  "id": 123,
  "_json": [456, 789]
}
```

## References

- [1] [Nasty Stereo - The Ruby on Rails `_json` juggling attack](https://nastystereo.com/security/rails-_json-juggling-attack.html)

{{#include ../../banners/hacktricks-training.md}}
