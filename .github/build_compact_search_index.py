#!/usr/bin/env python3

import ast
import base64
import json
import sys
from array import array
from pathlib import Path


if len(sys.argv) != 3:
    raise SystemExit("Usage: build_compact_search_index.py <searchindex.js> <output.json>")

input_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
source_text = input_path.read_text(encoding="utf-8")
prefix = "window.search = Object.assign(window.search, JSON.parse('"
suffix = "'));"

if not source_text.startswith(prefix) or not source_text.rstrip().endswith(suffix):
    raise ValueError(f"{input_path} does not have the expected mdBook search-index wrapper")

encoded_json = source_text[len(prefix):source_text.rfind(suffix)]
source = json.loads(ast.literal_eval("'" + encoded_json + "'"))

if "index" not in source or "doc_urls" not in source:
    raise ValueError(f"{input_path} does not contain an mdBook search index")

index = source["index"]
stored_docs = index["documentStore"]["docs"]
stored_info = index["documentStore"]["docInfo"]
document_count = index["documentStore"]["length"]
documents = []

for ref in range(document_count):
    doc = stored_docs.get(str(ref))
    if doc is None:
        raise ValueError(f"Search document references must be contiguous; missing {ref}")
    documents.append([doc.get("title", ""), doc.get("body", ""), doc.get("breadcrumbs", "")])


def encode_array(values):
    if sys.byteorder != "little":
        values.byteswap()
    return base64.b64encode(values.tobytes()).decode("ascii")


def flatten_terms(root):
    entries = []
    stack = [("", root)]
    while stack:
        term, node = stack.pop()
        if node["df"] > 0:
            entries.append((term, node["docs"]))
        for key, child in node.items():
            if key not in ("docs", "df"):
                stack.append((term + key, child))
    entries.sort(key=lambda entry: entry[0])
    return entries


fields = []
for name in index["fields"]:
    entries = flatten_terms(index["index"][name]["root"])
    posting_offsets = array("I", [0])
    posting_docs = array("I")
    posting_term_frequencies = array("d")

    for _, postings in entries:
        # JavaScript enumerates integer-like object keys numerically.
        for ref in sorted(postings, key=int):
            value = postings[ref]
            posting_docs.append(int(ref))
            posting_term_frequencies.append(value["tf"])
        posting_offsets.append(len(posting_docs))

    field_lengths = array(
        "I",
        (stored_info.get(str(ref), {}).get(name, 0) for ref in range(document_count)),
    )
    if posting_offsets.itemsize != 4 or posting_docs.itemsize != 4 or field_lengths.itemsize != 4:
        raise RuntimeError("Compact index requires 32-bit unsigned integer arrays")
    if posting_term_frequencies.itemsize != 8:
        raise RuntimeError("Compact index requires 64-bit floating-point arrays")

    fields.append(
        {
            "name": name,
            "terms": [term for term, _ in entries],
            "posting_offsets": encode_array(posting_offsets),
            "posting_docs": encode_array(posting_docs),
            "posting_term_frequencies": encode_array(posting_term_frequencies),
            "field_lengths": encode_array(field_lengths),
        }
    )

compact = {
    "version": 1,
    "pipeline": index["pipeline"],
    "results_options": source.get("results_options"),
    "search_options": source.get("search_options"),
    "doc_urls": source["doc_urls"],
    "documents": documents,
    "fields": fields,
}

with output_path.open("w", encoding="utf-8") as output:
    json.dump(compact, output, ensure_ascii=False, separators=(",", ":"))

print(f"Compact search index: {input_path} -> {output_path} ({document_count} documents)")
