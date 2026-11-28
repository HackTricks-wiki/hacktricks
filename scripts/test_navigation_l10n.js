"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("theme/book.js", "utf8");
const start = source.indexOf("(function localizeNavigation() {");
const end = source.indexOf("\n})();", start);
assert(start >= 0 && end > start);
const localize = new vm.Script(source.slice(start, end + "\n})();".length));
const searchSource = fs.readFileSync("theme/ht_searcher.js", "utf8");
const searchStart = searchSource.indexOf("  const searchLabels =");
const searchEnd = searchSource.indexOf("  const HOT=", searchStart);
assert(searchStart >= 0 && searchEnd > searchStart);
const searchStates = new vm.Script(searchSource.slice(searchStart, searchEnd) + "\nsetIconState;");
const resultStart = searchSource.indexOf("  const resultNumber =");
const resultEnd = searchSource.indexOf("  function makeTeaser(", resultStart);
assert(resultStart >= 0 && resultEnd > resultStart);
const resultMessages = new vm.Script(searchSource.slice(resultStart, resultEnd) + "\nresultMessage;");
const template = fs.readFileSync("theme/index.hbs", "utf8");
const keys = Array.from(new Set(Array.from(template.matchAll(/data-nav-label="([^"]+)"/g), match => match[1])));
const matrix = execFileSync("python3", ["scripts/translation_matrix.py"], { encoding: "utf8" });
const locales = JSON.parse(matrix.slice("matrix=".length)).include.map(entry => entry.branch);

function translate(language) {
    const nodes = keys.map(key => {
        const attributes = new Map([["aria-label", "English fallback"], ["placeholder", "English fallback"]]);
        if (key === "search") {
            attributes.set("title", "Search (S)");
            attributes.set("aria-keyshortcuts", "S");
        }
        return {
            id: key === "search" ? "search-toggle" : "",
            tagName: "SPAN",
            dataset: { navLabel: key },
            attributes,
            hasAttribute: name => attributes.has(name),
            getAttribute: name => attributes.get(name),
            setAttribute: (name, value) => attributes.set(name, value),
        };
    });
    const document = {
        documentElement: { lang: language },
        querySelectorAll: selector => selector === "[data-nav-label]" ? nodes : [],
    };
    localize.runInNewContext({ document });
    const labels = Object.fromEntries(nodes.map(node => {
        assert(node.textContent, `Missing ${language} label for ${node.dataset.navLabel}`);
        assert.equal(node.attributes.get("aria-label"), node.textContent);
        assert.equal(node.attributes.get("placeholder"), node.textContent);
        if (node.id === "search-toggle") {
            assert.equal(node.attributes.get("title"), `${node.textContent} (S)`);
        }
        return [node.dataset.navLabel, node.textContent];
    }));
    const icon = nodes.find(node => node.id === "search-toggle");
    icon.removeAttribute = name => icon.attributes.delete(name);
    const setIconState = searchStates.runInNewContext({ icon });
    assert.equal(icon.attributes.get("aria-label"), labels.search);
    for (const state of ["error", "loading"]) {
        setIconState(state);
        labels[state] = icon.attributes.get("aria-label");
        assert.equal(icon.attributes.get("title"), labels[state]);
        assert(labels[state]);
    }
    setIconState("ready");
    assert.equal(icon.attributes.get("aria-label"), labels.search);
    assert(!icon.attributes.has("title"));
    const resultMessage = resultMessages.runInNewContext({ searchLabels: icon.dataset });
    assert.equal(resultMessage(0, ""), "");
    const literalQuery = "<em>{count}</em>";
    labels.zero = resultMessage(0, literalQuery);
    labels.multiple = resultMessage(1234, literalQuery);
    for (const message of [labels.zero, labels.multiple]) {
        assert(message.includes(literalQuery));
        assert(!message.includes("{query}"));
    }
    assert(labels.multiple.includes(new Intl.NumberFormat(icon.dataset.searchLocale).format(1234)));
    labels.preview = icon.dataset.searchPreview;
    labels.book = icon.dataset.searchBookLabel;
    assert(labels.preview && labels.book);
    return labels;
}

test("the template labels are localized for every published language", () => {
    assert.equal(locales.length, new Set(locales).size);
    const english = translate("en");
    for (const locale of locales) {
        const localized = translate(locale);
        for (const key of Object.keys(english)) {
            assert.notEqual(localized[key], english[key], `English label in ${locale}: ${key}`);
        }
    }
});

test("regional tags select a translation and unknown tags use English", () => {
    assert.deepEqual(translate("pt-BR"), translate("pt"));
    assert.deepEqual(translate("zh-Hans"), translate("zh"));
    assert.deepEqual(translate("toString"), translate("en"));
    assert.deepEqual(translate("zz"), translate("en"));
});
