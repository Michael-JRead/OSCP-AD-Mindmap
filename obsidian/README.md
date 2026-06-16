# AD Mindmap — Obsidian vault

This folder is an [Obsidian](https://obsidian.md) vault generated from the
[Orange Cyberdefense AD mindmap](https://orange-cyberdefense.github.io/ocd-mindmaps/)
source (`excalimap/mindmap/ad/*.md`).

## How to use

1. Open this `obsidian/` folder as a vault in Obsidian (*Open folder as vault*).
2. Start at **[[AD Mindmap]]** — the map of content with the grid layout and pivot graph.
3. Each note is one box of the mindmap. The **nested bullet lists are foldable trees** (fold/unfold with the gutter arrows) that mirror the branches of the original mindmap.
4. `➡️` arrows are `[[wikilinks]]`: they point to the box a technique pivots into, so the
   **graph view** reconstructs the mindmap's connections.
5. Command nodes keep a `[↗]` reference link to the tool, and CVE techniques are tagged `#CVE`.

## Regenerate

```bash
python3 convert_to_obsidian.py
```

Credit: Mayfly (@M4yFly), Viking (@Vikingfr), Sant0rryu (@Sant0rryu) and contributors.
