#!/usr/bin/env node

import fs from "node:fs";
import vm from "node:vm";

const [, , inputPath, outputPath] = process.argv;

if (!inputPath || !outputPath) {
    console.error("Usage: build_compact_search_index.mjs <searchindex.js> <output.json>");
    process.exit(1);
}

const context = { window: { search: {} } };
vm.runInNewContext(fs.readFileSync(inputPath, "utf8"), context, { filename: inputPath });

const source = context.window.search;
if (!source.index || !source.doc_urls) {
    throw new Error(`${inputPath} does not contain an mdBook search index`);
}

const index = source.index;
const storedDocs = index.documentStore.docs;
const storedInfo = index.documentStore.docInfo;
const documentCount = index.documentStore.length;
const documents = new Array(documentCount);

for (let ref = 0; ref < documentCount; ref++) {
    const doc = storedDocs[String(ref)];
    if (!doc) throw new Error(`Search document references must be contiguous; missing ${ref}`);
    documents[ref] = [doc.title || "", doc.body || "", doc.breadcrumbs || ""];
}

function encodeTypedArray(values, Type) {
    const typed = new Type(values);
    return Buffer.from(typed.buffer, typed.byteOffset, typed.byteLength).toString("base64");
}

function flattenTerms(root) {
    const entries = [];
    const stack = [["", root]];

    while (stack.length) {
        const [prefix, node] = stack.pop();
        if (node.df > 0) entries.push([prefix, node.docs]);

        for (const key of Object.keys(node)) {
            if (key !== "docs" && key !== "df") stack.push([prefix + key, node[key]]);
        }
    }

    entries.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
    return entries;
}

const fields = index.fields.map((name) => {
    const entries = flattenTerms(index.index[name].root);
    const postingOffsets = new Uint32Array(entries.length + 1);
    let postingCount = 0;

    for (let i = 0; i < entries.length; i++) {
        postingOffsets[i] = postingCount;
        postingCount += Object.keys(entries[i][1]).length;
    }
    postingOffsets[entries.length] = postingCount;

    const postingDocs = new Uint32Array(postingCount);
    const postingTermFrequencies = new Float64Array(postingCount);
    let cursor = 0;

    for (const [, postings] of entries) {
        for (const [ref, value] of Object.entries(postings)) {
            postingDocs[cursor] = Number(ref);
            postingTermFrequencies[cursor] = value.tf;
            cursor++;
        }
    }

    const fieldLengths = new Uint32Array(documentCount);
    for (let ref = 0; ref < documentCount; ref++) {
        fieldLengths[ref] = storedInfo[String(ref)]?.[name] || 0;
    }

    return {
        name,
        terms: entries.map(([term]) => term),
        posting_offsets: encodeTypedArray(postingOffsets, Uint32Array),
        posting_docs: encodeTypedArray(postingDocs, Uint32Array),
        posting_term_frequencies: encodeTypedArray(postingTermFrequencies, Float64Array),
        field_lengths: encodeTypedArray(fieldLengths, Uint32Array),
    };
});

const compact = {
    version: 1,
    pipeline: index.pipeline,
    results_options: source.results_options,
    search_options: source.search_options,
    doc_urls: source.doc_urls,
    documents,
    fields,
};

fs.writeFileSync(outputPath, JSON.stringify(compact));
console.log(`Compact search index: ${inputPath} -> ${outputPath} (${documents.length} documents)`);
