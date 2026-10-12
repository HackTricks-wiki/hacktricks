const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

const root = path.join(__dirname, "..")
const sponsorSource = fs.readFileSync(path.join(root, "theme/sponsor.js"), "utf8")
const translationWorkflow = fs.readFileSync(path.join(root, ".github/workflows/translate_all.yml"), "utf8")
assert.ok(translationWorkflow.includes("cp /tmp/immutable-images/* ./book/images/"))
const imageResolver = sponsorSource.match(/  function resolveSponsorImageUrl\(imageUrl\) \{[\s\S]*?\n  \}\n/)
assert.ok(imageResolver, "sponsor image resolver must exist")
const resolve = vm.runInNewContext(imageResolver[0] + "\nresolveSponsorImageUrl", {
  URL,
  window: { location: { origin: "https://example.test", href: "https://example.test/en/index.html" } },
  document: { baseURI: "https://example.test/en/index.html" },
})

for (const name of ["lee", "azrte", "grte", "lhe", "arte"]) {
  assert.ok(translationWorkflow.includes(`src/images/${name}-sponsor-v1.webp`), `${name} is missing from the translation snapshot`)
  const image = path.join(root, "src/images", `${name}-sponsor-v1.webp`)
  const bytes = fs.readFileSync(image)
  assert.equal(bytes.toString("ascii", 0, 4), "RIFF")
  assert.equal(bytes.toString("ascii", 8, 12), "WEBP")
  assert.ok(bytes.length < 50_000, `${name} sponsor image is unexpectedly large`)
  assert.equal(resolve(`/images/${name}.png`), `https://example.test/images/${name}-sponsor-v1.webp`)
}
assert.equal(resolve("/images/unrelated.png"), "https://example.test/images/unrelated.png")
assert.equal(resolve("https://other.test/images/lee.png"), "https://other.test/images/lee.png")
assert.equal(resolve(""), "")
console.log("Sponsor image routing and five WebP assets verified")
