"""Write one error-analysis label into docs/ERROR-ANALYSIS.md: python3 scripts/p8_error_label.py ID CATEGORY [NOTE]"""
import sys
from pathlib import Path

CATS = {"FP": ["ignored guard", "context-induced", "ignored constant argument", "decompiler artifact",
               "invented sink/source", "other"],
        "FN": ["missed sink", "hallucinated guard", "context-induced", "decompiler artifact", "other"]}
if len(sys.argv) < 3:
    sys.exit(__doc__)
eid, cat = sys.argv[1], sys.argv[2]
note = sys.argv[3] if len(sys.argv) > 3 else ""
p = Path("docs/ERROR-ANALYSIS.md")
lines = p.read_text(encoding="utf-8").splitlines()
for i, l in enumerate(lines):
    c = [x.strip() for x in l.split("|")]
    if len(c) == 7 and c[2].split()[:1] == [eid]:
        if cat not in CATS[c[3]]:
            sys.exit(f"'{cat}' is not a {c[3]} category. Use one of: {CATS[c[3]]}")
        c[4], c[5] = cat, note.replace("|", "/")
        lines[i] = "| " + " | ".join(c[1:6]) + " |"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        done = sum(1 for x in lines if len(x.split("|")) == 7 and x.split("|")[1].strip().isdigit()
                   and x.split("|")[4].strip())
        print(f"{eid}: {cat}   ({done}/40 labelled)")
        sys.exit(0)
sys.exit(f"{eid} not found")