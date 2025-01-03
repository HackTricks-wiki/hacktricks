# Ruby _json pollution

{{#include ../../banners/hacktricks-training.md}}

This is a summary from the post [https://nastystereo.com/security/rails-_json-juggling-attack.html](https://nastystereo.com/security/rails-_json-juggling-attack.html)


## Basic information

When sending in a body some values not hashabled like an array they will be added into a new key called `_json`. However, It’s possible for an attacker to also set in the body a value called `_json` with the arbitrary values he wishes. Then, If the backend for example checks the veracity of a parameter but then also uses the `_json` parameter to perform some action, an authorisation bypass could be performed.

```json
{
  "id": 123,
  "_json": [456, 789]
}
```


## References

- [https://nastystereo.com/security/rails-_json-juggling-attack.html](https://nastystereo.com/security/rails-_json-juggling-attack.html)

{{#include ../../banners/hacktricks-training.md}}



