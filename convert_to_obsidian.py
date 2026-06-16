#!/usr/bin/env python3
"""
Convert the Orange Cyberdefense AD mindmap (excalimap source) into an
Obsidian-ready vault.

Each source file in excalimap/mindmap/ad/*.md is one "box" of the mindmap.
We re-parse it with the same rules excalimap uses (parsermd.py):

  # Title              -> the box / note title (container)
  ## Title >>> out ... -> a top-level branch of the tree (rendered as an H2)
  - text               -> an "info" leaf/branch (nested by 2-space indent)
  - `command`          -> a "command" leaf/branch
  >>> A || B >>> C     -> arrows to other boxes (rendered as [[wikilinks]])
  @CVE@                -> CVE marker
  [text](url)          -> a reference link attached to the previous item

The `>>>` arrow targets are resolved through conf.yml's `out:` table, which
maps every arrow label to a color_id, and each color_id corresponds to a
destination box -> so arrows become real links between the Obsidian notes,
mirroring the connections drawn in the mindmap.
"""

import os
import re
import yaml

SRC_DIR = os.path.join("excalimap", "mindmap", "ad")
OUT_DIR = "obsidian"

# color_id (from conf.yml) -> source file stem of the destination box
COLORID_TO_FILE = {
    "nocreds": "no_creds",
    "crack": "crack_hash",
    "valid_user": "valid_user",
    "creds": "authenticated",
    "lat": "lat_move",
    "mitm": "mitm",
    "low_hanging": "low_hanging",
    "delegation": "delegation",
    "da": "dom_admin",
    "acl": "acl",
    "adcs": "adcs",
    "admin": "admin",
    "low": "low_access",
    "sccm": "sccm",
    "cve": "know_vuln_auth",
    "trusts": "trusts",
    "persistence": "persistence",
    "authors": "authors",
}

# source file stem -> clean Obsidian note title (also the note filename)
FILE_TO_TITLE = {
    "no_creds": "No Credentials",
    "valid_user": "Valid User (No Password)",
    "authenticated": "Valid Credentials",
    "low_access": "Low Access (Privilege Escalation)",
    "delegation": "Kerberos Delegation",
    "admin": "Admin Access",
    "dom_admin": "Domain Admin",
    "low_hanging": "Quick Compromise",
    "mitm": "Man In The Middle",
    "know_vuln_auth": "Known Vulnerabilities (Authenticated)",
    "adcs": "ADCS",
    "lat_move": "Lateral Movement",
    "trusts": "Trusts",
    "crack_hash": "Crack Hash",
    "acl": "ACLs & ACEs Permissions",
    "sccm": "SCCM",
    "persistence": "Persistence",
    "authors": "Authors",
}

# short category tag per file (for frontmatter / Obsidian tags)
FILE_TO_TAG = {
    "no_creds": "recon",
    "valid_user": "recon",
    "authenticated": "enumeration",
    "low_access": "privesc",
    "delegation": "delegation",
    "admin": "credential-access",
    "dom_admin": "domain-admin",
    "low_hanging": "quick-win",
    "mitm": "mitm",
    "know_vuln_auth": "cve",
    "adcs": "adcs",
    "lat_move": "lateral-movement",
    "trusts": "trusts",
    "crack_hash": "cracking",
    "acl": "acl",
    "sccm": "sccm",
    "persistence": "persistence",
    "authors": "meta",
}

# emoji per file for nicer headers / index
FILE_TO_EMOJI = {
    "no_creds": "🔍",
    "valid_user": "👤",
    "authenticated": "🔑",
    "low_access": "🪜",
    "delegation": "🎫",
    "admin": "🛡️",
    "dom_admin": "👑",
    "low_hanging": "🍒",
    "mitm": "📡",
    "know_vuln_auth": "🐛",
    "adcs": "📜",
    "lat_move": "↔️",
    "trusts": "🤝",
    "crack_hash": "🔓",
    "acl": "🧬",
    "sccm": "🗄️",
    "persistence": "♾️",
    "authors": "✍️",
}


# Arrow labels that don't appear verbatim in conf.yml's `out:` table (so the
# original mindmap draws them as plain default boxes). We resolve them to the
# right destination box so the Obsidian graph stays fully connected.
LABEL_ALIASES = {
    "access": "admin",
    "admin mssql": "admin",
    "site db credentials": "creds",
    "lat": "lat",
    "search files": "lat",
}


def _norm_label(label):
    """Lowercase, treat '/' as space, collapse whitespace — so capitalization
    and spacing variants ('Pass The Certificate' vs 'Pass the certificate')
    resolve to the same target."""
    return re.sub(r"\s+", " ", label.replace("/", " ").lower()).strip()


def load_conf():
    with open(os.path.join(SRC_DIR, "conf.yml"), "r", encoding="utf-8") as f:
        conf = yaml.safe_load(f)
    # build a normalized index of the out-table for fuzzy resolution
    conf["_out_norm"] = {_norm_label(k): v for k, v in conf["out"].items()}
    return conf


def resolve_label(label, conf):
    """label -> destination file stem (or None). Tries exact match, then a
    case/spacing-insensitive match, then the manual alias table."""
    color_id = conf["out"].get(label)
    if color_id is None:
        norm = _norm_label(label)
        color_id = conf["_out_norm"].get(norm) or LABEL_ALIASES.get(norm)
    return COLORID_TO_FILE.get(color_id) if color_id else None


def parse_outs(raw, conf):
    """Parse the part of a line after the node text: 'A || B >>> C' -> list of
    stages, each stage a list of (label, target_file_or_None)."""
    stages = []
    for stage in raw.split(">>>"):
        labels = []
        for label in stage.split("||"):
            label = label.strip()
            if not label:
                continue
            labels.append((label, resolve_label(label, conf)))
        if labels:
            stages.append(labels)
    return stages


def tool_link_for(command, conf):
    """Replicate excalimap tool detection: first token after stripping
    'proxychains ' is the tool; look up its reference link."""
    cmd = command.replace("proxychains ", "")
    tool = cmd.split(" ")[0]
    info = conf["tools"].get(tool)
    if info:
        return info.get("link")
    return None


class Node:
    def __init__(self, kind, text, level, cve=False):
        self.kind = kind          # 'title' | 'info' | 'command'
        self.text = text
        self.level = level
        self.cve = cve
        self.outs = []            # list of stages (from >>>)
        self.url = None           # [text](url) reference link
        self.children = []


def parse_file(path, conf):
    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    title = None
    roots = []                    # top-level '##' nodes
    stack = {}                    # level -> node
    last_node = None

    for line in lines:
        cve = False
        outs = []

        work = line
        if ">>>" in work:
            head, _, tail = work.partition(">>>")
            outs = parse_outs(tail, conf)
            work = head
        if "@CVE@" in work:
            cve = True
            work = work.replace("@CVE@", "")

        if work.startswith("# "):
            title = work[2:].strip()
            continue

        if work.startswith("## "):
            node = Node("title", work[3:].strip(), 2, cve)
            node.outs = outs
            roots.append(node)
            stack = {2: node}
            last_node = node
            continue

        stripped = work.strip()

        # reference link line: [text](url) attaches to previous node
        if stripped.startswith("[") and last_node is not None:
            m = re.search(r"\((https?://[^)]+)\)", stripped)
            if m:
                last_node.url = m.group(1)
            continue

        m = re.match(r"(\s*)- (.+)", work.rstrip())
        if not m:
            continue
        indent = len(m.group(1))
        level = 3 + indent // 2
        body = m.group(2).strip()

        if body.startswith("`"):
            cm = re.match(r"`(.+?)`(.*)", body)
            text = cm.group(1) if cm else body.strip("`")
            node = Node("command", text, level, cve)
        else:
            node = Node("info", body, level, cve)
        node.outs = outs

        parent = stack.get(level - 1)
        if parent is None:
            # fall back to nearest shallower node
            for lv in range(level - 1, 1, -1):
                if lv in stack:
                    parent = stack[lv]
                    break
        if parent is None and roots:
            parent = roots[-1]
        if parent is not None:
            parent.children.append(node)
        stack[level] = node
        # drop deeper entries so siblings re-attach correctly
        for lv in list(stack):
            if lv > level:
                del stack[lv]
        last_node = node

    return title, roots


def render_outs(outs):
    """Render arrow stages as ' ➡️ [[Box|label]] → [[Box|label]]'."""
    if not outs:
        return ""
    stage_strs = []
    for stage in outs:
        parts = []
        for label, target in stage:
            if target and target in FILE_TO_TITLE:
                tt = FILE_TO_TITLE[target]
                parts.append(f"[[{tt}|{label}]]")
            else:
                parts.append(f"**{label}**")
        stage_strs.append(" / ".join(parts))
    return " ➡️ " + " → ".join(stage_strs)


def render_command(node, conf):
    text = node.text
    out = f"`{text}`"
    link = tool_link_for(text, conf)
    if link:
        out += f" [↗]({link})"
    if node.cve:
        out += " `#CVE`"
    out += render_outs(node.outs)
    if node.url:
        out += f" — [ref]({node.url})"
    return out


def render_info(node, conf):
    out = node.text
    if node.cve:
        out += " `#CVE`"
    out += render_outs(node.outs)
    if node.url:
        out += f" — [ref]({node.url})"
    return out


def render_children(nodes, conf, depth=0):
    out = []
    indent = "    " * depth
    for n in nodes:
        if n.kind == "command":
            line = render_command(n, conf)
        else:
            line = render_info(n, conf)
        out.append(f"{indent}- {line}")
        if n.children:
            out.extend(render_children(n.children, conf, depth + 1))
    return out


def build_note(stem, title, roots, conf):
    note_title = FILE_TO_TITLE[stem]
    emoji = FILE_TO_EMOJI.get(stem, "")
    tag = FILE_TO_TAG.get(stem, "ad")
    color_id = conf["container_color"].get(title)
    color = conf["color_id"].get(color_id) if color_id else None

    has_cve = any(_subtree_has_cve(r) for r in roots)
    tags = ["ad-mindmap", tag]
    if has_cve:
        tags.append("cve")

    lines = []
    lines.append("---")
    lines.append(f'title: "{note_title}"')
    lines.append(f"category: {tag}")
    if color:
        lines.append(f'color: "{color}"')
    lines.append("tags:")
    for t in tags:
        lines.append(f"  - {t}")
    lines.append("---")
    lines.append("")
    lines.append(f"# {emoji} {note_title}".strip())
    lines.append("")
    lines.append(f"> [!info] Mindmap box `{title}`")
    lines.append("> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.")
    lines.append("")

    for root in roots:
        head = f"## {root.text}"
        lines.append(head)
        arrows = render_outs(root.outs)
        flags = " `#CVE`" if root.cve else ""
        if arrows or flags:
            lines.append(f"{flags}{arrows}".strip())
        if root.url:
            lines.append(f"[ref]({root.url})")
        lines.append("")
        if root.children:
            lines.extend(render_children(root.children, conf))
            lines.append("")

    return note_title, "\n".join(lines).rstrip() + "\n"


def _subtree_has_cve(node):
    if node.cve:
        return True
    return any(_subtree_has_cve(c) for c in node.children)


def collect_edges(stem, roots):
    """Cross-box edges (source stem -> target stem) from every arrow stage."""
    edges = set()

    def walk(node):
        for stage in node.outs:
            for _label, target in stage:
                if target and target != stem:
                    edges.add((stem, target))
        for c in node.children:
            walk(c)

    for r in roots:
        walk(r)
    return edges


def build_index(conf, all_edges):
    matrix = conf["matrix"]
    lines = []
    lines.append("---")
    lines.append('title: "AD Mindmap"')
    lines.append("tags:")
    lines.append("  - ad-mindmap")
    lines.append("  - moc")
    lines.append("---")
    lines.append("")
    lines.append("# 🗺️ Active Directory Mindmap — v2025.03")
    lines.append("")
    lines.append(
        "> [!abstract] Map of Content\n"
        "> Obsidian conversion of the "
        "[Orange Cyberdefense AD mindmap](https://orange-cyberdefense.github.io/ocd-mindmaps/). "
        "Each box below is its own note; the nested bullets inside each note are the "
        "foldable tree branches, and `➡️` arrows are `[[wikilinks]]` to the box the "
        "technique pivots into. Original write-up: "
        "https://mayfly277.github.io/posts/AD-mindmap-2k25/"
    )
    lines.append("")
    lines.append(
        "> [!tip] New here? Start with the playbook\n"
        "> **[[Start Here — OSCP AD Methodology]]** — a linear, checkbox-driven workflow "
        "that walks the attack path step by step and links into the boxes below."
    )
    lines.append("")
    lines.append("## Attack flow (grid layout)")
    lines.append("")
    lines.append(
        "The columns follow the engagement progression, left to right: "
        "**No creds → Valid user → Authenticated → Low access → Delegation → Admin → Domain admin**."
    )
    lines.append("")

    # matrix table
    ncols = max(len(r) for r in matrix)
    header = "| " + " | ".join(f"Col {i+1}" for i in range(ncols)) + " |"
    sep = "| " + " | ".join(["---"] * ncols) + " |"
    lines.append(header)
    lines.append(sep)
    for row in matrix:
        cells = []
        for i in range(ncols):
            stem = row[i] if i < len(row) else ""
            if stem and stem in FILE_TO_TITLE:
                emoji = FILE_TO_EMOJI.get(stem, "")
                cells.append(f"{emoji} [[{FILE_TO_TITLE[stem]}]]")
            else:
                cells.append("")
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")

    # mermaid flow of cross-box arrows
    lines.append("## Pivot graph")
    lines.append("")
    lines.append("```mermaid")
    lines.append("flowchart LR")
    used = set()
    for row in matrix:
        for stem in row:
            if stem in FILE_TO_TITLE:
                used.add(stem)
    for stem in used:
        label = FILE_TO_TITLE[stem].replace('"', "'")
        lines.append(f'    {stem}["{label}"]')
    for src, dst in sorted(all_edges):
        if src in used and dst in used:
            lines.append(f"    {src} --> {dst}")
    lines.append("```")
    lines.append("")

    # full list
    lines.append("## All boxes")
    lines.append("")
    for stem, tt in FILE_TO_TITLE.items():
        emoji = FILE_TO_EMOJI.get(stem, "")
        lines.append(f"- {emoji} [[{tt}]]")
    lines.append("")

    return "AD Mindmap", "\n".join(lines).rstrip() + "\n"


def build_start_here():
    """A practical, ordered AD attack workflow for exam/lab use, with task
    checkboxes and links into the relevant mindmap boxes."""
    L = FILE_TO_TITLE
    lines = []
    lines.append("---")
    lines.append('title: "Start Here — OSCP AD Methodology"')
    lines.append("tags:")
    lines.append("  - ad-mindmap")
    lines.append("  - methodology")
    lines.append("  - oscp")
    lines.append("---")
    lines.append("")
    lines.append("# 🎯 Start Here — OSCP AD Methodology")
    lines.append("")
    lines.append(
        "> [!tip] How to use this vault\n"
        "> This is the linear playbook. Work top-to-bottom; each step links into the\n"
        f"> matching box of the [[AD Mindmap]] for the full command tree. Check items off\n"
        "> as you go. Boxes deeper than the core flow (ADCS, delegation, ACLs, SCCM,\n"
        "> trusts) are pivots you reach for when the path to DA isn't obvious."
    )
    lines.append("")

    steps = [
        ("1. Recon — no credentials", L["no_creds"], [
            "Find the DC / domain name (DNS, SMB, LDAP, ports 88/389/445)",
            "Anonymous / guest SMB + LDAP enumeration",
            "Enumerate or brute users to build a username list",
            "Check for quick wins on hosts (see below)",
        ]),
        ("2. Quick wins / known vulns", L["low_hanging"], [
            "Scan for unauthenticated RCE (Zerologon, EternalBlue, web apps, etc.)",
            "Also revisit once authenticated → " + f"[[{L['know_vuln_auth']}]]",
        ]),
        ("3. Get a username → get credentials", L["valid_user"], [
            "Password spray the user list (watch lockout policy)",
            "AS-REP roast accounts without preauth → crack the hash",
            "Poison & relay on the wire → " + f"[[{L['mitm']}]]",
            "Crack any captured hashes → " + f"[[{L['crack_hash']}]]",
        ]),
        ("4. Authenticated enumeration", L["authenticated"], [
            "Run BloodHound (collect with the lowest-priv account you have)",
            "Enumerate users, groups, shares, ACLs, delegation, GPOs",
            "Kerberoast SPN accounts → crack → " + f"[[{L['crack_hash']}]]",
            "Note ADCS / SCCM if present → " + f"[[{L['adcs']}]] / [[{L['sccm']}]]",
        ]),
        ("5. Move laterally", L["lat_move"], [
            "Reuse creds / hashes / tickets (PtH, PtT, PtC) across hosts",
            "Spot where your user is local admin → get a shell",
        ]),
        ("6. Escalate locally", L["low_access"], [
            "Enumerate the host (winPEAS, PrivescCheck)",
            "Abuse service accounts (SeImpersonate → Potato), UAC, exploits",
        ]),
        ("7. Loot credentials as admin", L["admin"], [
            "Dump LSASS, SAM, LSA secrets, DPAPI",
            "Feed new creds/hashes back into step 4–5",
        ]),
        ("8. Find the path to Domain Admin", None, [
            "Abusable ACLs/ACEs (GenericAll, WriteDacl, DCSync) → " + f"[[{L['acl']}]]",
            "Kerberos delegation (unconstrained/constrained/RBCD) → " + f"[[{L['delegation']}]]",
            "ADCS certificate abuse (ESC1–ESC15) → " + f"[[{L['adcs']}]]",
            "SCCM takeover → " + f"[[{L['sccm']}]]",
        ]),
        ("9. Domain Admin", L["dom_admin"], [
            "Dump NTDS.dit (DCSync / secretsdump) for every hash",
            "Grab DPAPI backup keys",
        ]),
        ("10. Cross trust boundaries / persist", L["trusts"], [
            "Hop child→parent / across trusts → " + f"[[{L['trusts']}]]",
            "Establish persistence if in scope → " + f"[[{L['persistence']}]]",
        ]),
    ]

    for title, box, items in steps:
        head = f"## {title}"
        lines.append(head)
        if box:
            lines.append(f"➡️ Full tree: [[{box}]]")
        lines.append("")
        for it in items:
            lines.append(f"- [ ] {it}")
        lines.append("")

    lines.append("---")
    lines.append("See the full grid and pivot graph in [[AD Mindmap]].")
    lines.append("")
    return "Start Here — OSCP AD Methodology", "\n".join(lines).rstrip() + "\n"


def build_readme():
    return (
        "# AD Mindmap — Obsidian vault\n\n"
        "This folder is an [Obsidian](https://obsidian.md) vault generated from the\n"
        "[Orange Cyberdefense AD mindmap](https://orange-cyberdefense.github.io/ocd-mindmaps/)\n"
        "source (`excalimap/mindmap/ad/*.md`).\n\n"
        "## How to use\n\n"
        "1. Open this `obsidian/` folder as a vault in Obsidian (*Open folder as vault*).\n"
        "2. Start at **[[Start Here — OSCP AD Methodology]]** for the linear, checkbox-driven\n"
        "   workflow, or **[[AD Mindmap]]** for the map of content (grid layout + pivot graph).\n"
        "3. Each note is one box of the mindmap. The **nested bullet lists are foldable trees** "
        "(fold/unfold with the gutter arrows) that mirror the branches of the original mindmap.\n"
        "4. `➡️` arrows are `[[wikilinks]]`: they point to the box a technique pivots into, so the\n"
        "   **graph view** reconstructs the mindmap's connections.\n"
        "5. Command nodes keep a `[↗]` reference link to the tool, and CVE techniques are tagged `#CVE`.\n\n"
        "## Regenerate\n\n"
        "```bash\n"
        "python3 convert_to_obsidian.py\n"
        "```\n\n"
        "Credit: Mayfly (@M4yFly), Viking (@Vikingfr), Sant0rryu (@Sant0rryu) and contributors.\n"
    )


def main():
    conf = load_conf()
    os.makedirs(OUT_DIR, exist_ok=True)

    all_edges = set()
    parsed = {}
    for fname in sorted(os.listdir(SRC_DIR)):
        if not fname.endswith(".md"):
            continue
        stem = fname[:-3]
        if stem not in FILE_TO_TITLE:
            continue
        title, roots = parse_file(os.path.join(SRC_DIR, fname), conf)
        parsed[stem] = (title, roots)
        all_edges |= collect_edges(stem, roots)

    for stem, (title, roots) in parsed.items():
        note_title, content = build_note(stem, title, roots, conf)
        with open(os.path.join(OUT_DIR, f"{note_title}.md"), "w", encoding="utf-8") as f:
            f.write(content)

    idx_title, idx_content = build_index(conf, all_edges)
    with open(os.path.join(OUT_DIR, f"{idx_title}.md"), "w", encoding="utf-8") as f:
        f.write(idx_content)

    sh_title, sh_content = build_start_here()
    with open(os.path.join(OUT_DIR, f"{sh_title}.md"), "w", encoding="utf-8") as f:
        f.write(sh_content)

    with open(os.path.join(OUT_DIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(build_readme())

    print(f"Generated {len(parsed)} box notes + index + README in {OUT_DIR}/")


if __name__ == "__main__":
    main()
