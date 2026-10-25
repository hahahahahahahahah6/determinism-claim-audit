"""Offline, non-executing documentation and AST audit."""
import ast
import re
from pathlib import Path

RULE = 'documented-deterministic-false'
FAMILIES = {
    'deterministic': r'\bdeterministic(?:ally)?\b',
    'reproducible': r'\b(?:reproducible|reproducibly|reproducibility)\b',
    'same-output': r'\b(?:same (?:output|result) (?:every|each) run|identical output every run)\b',
}
NEGATION = re.compile(r'\b(?:not deterministic|non-deterministic|nondeterministic|not reproducible|non-reproducible)\b', re.I)


def claims_in(text, filename):
    """Extract the first prose occurrence of each family, retaining line numbers."""
    lines = []
    fence = None
    for line in text.splitlines(True):
        match = re.match(r'^\s*(`{3,}|~{3,})', line)
        if match:
            token = match.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            lines.append('\n' if line.endswith('\n') else '')
        else:
            lines.append(line if fence is None else ('\n' if line.endswith('\n') else ''))
    prose = ''.join(lines)
    found = {}
    for sentence in re.finditer(r'[^.!?]+(?:[.!?]|$)', prose):
        if NEGATION.search(sentence.group()):
            continue
        for family, pattern in FAMILIES.items():
            match = re.search(pattern, sentence.group(), re.I)
            if match and family not in found:
                offset = sentence.start() + match.start()
                found[family] = dict(family=family, doc_file=filename,
                                     doc_line=prose.count('\n', 0, offset) + 1)
    return list(found.values())


def evidence_in(text, filename):
    tree = ast.parse(text, filename=filename)
    evidence = {}
    seeded = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == 'random'
                 and n.func.attr == 'seed' and len(n.args) == 1
                 and isinstance(n.args[0], ast.Constant)
                 and type(n.args[0].value) in (int, str) for n in ast.walk(tree))
    def record(kind, node):
        evidence[kind] = min(evidence.get(kind, node.lineno), node.lineno)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            module, attr = node.value.id, node.attr
            if (module == 'datetime' and attr in ('now', 'today', 'utcnow') or
                    module == 'time' and attr in ('time', 'monotonic', 'perf_counter', 'clock')):
                record('TIME', node)
            if module in ('random', 'secrets') or (module == 'os' and attr == 'urandom'):
                if not seeded:
                    record('RANDOM', node)
            if module == 'uuid' and attr in ('uuid1', 'uuid4'):
                record('UUID', node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'hash':
            record('ORDER', node)
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            value = node.iter
            if isinstance(value, (ast.Set, ast.SetComp)) or (
                    isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == 'set'):
                record('ORDER', value)
    return [dict(evidence_kind=k, evidence_file=filename, evidence_line=v)
            for k, v in sorted(evidence.items())]


def audit(root, fail_on='MEDIUM', ignore=()):
    """Return stable JSON-compatible findings. Never import or execute target code."""
    root = Path(root)
    if not root.is_dir():
        raise ValueError('path must be an existing directory')
    claims, production, test = [], [], []
    source_count = 0
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        # Skip links, including linked parent directories, and never open .env.
        if any((root.joinpath(*relative.parts[:i])).is_symlink()
               for i in range(1, len(relative.parts) + 1)):
            continue
        if path.name == '.env' or not path.is_file():
            continue
        name = relative.as_posix()
        is_doc = (len(relative.parts) == 1 and path.name.lower() in ('readme', 'readme.md')) or (
            relative.parts[0] == 'docs' and path.suffix.lower() == '.md')
        if is_doc:
            claims.extend(claims_in(path.read_text(encoding='utf-8'), name))
        if path.suffix != '.py' or 'examples' in relative.parts:
            continue
        source_count += 1
        is_test = any(p in ('tests', 'fixtures') or p.startswith('test_') or
                      p.endswith('_test') or p.endswith('_test.py') for p in relative.parts)
        try:
            evidence = evidence_in(path.read_text(encoding='utf-8'), name)
        except SyntaxError as exc:
            raise ValueError('cannot parse {}:{}'.format(name, exc.lineno)) from None
        (test if is_test else production).extend(evidence)
    # evidence_in retains the first location of each kind in each source file.
    selected = production if production else test
    findings, verified = [], []
    for claim in claims:
        if source_count == 0:
            findings.append(dict(claim, rule=RULE, severity='HIGH', evidence_kind='NO_SOURCE',
                                 evidence_file=claim['doc_file'], evidence_line=claim['doc_line']))
        elif selected:
            for evidence in selected:
                findings.append(dict(claim, **evidence, rule=RULE if production else RULE + '-test-only',
                                     severity='HIGH' if production else 'MEDIUM'))
        else:
            verified.append(claim)
    # Multiple phrase families in one document share the same evidence finding.
    unique = {}
    for finding in findings:
        key = (finding['doc_file'], finding['evidence_kind'],
               finding['evidence_file'], finding['evidence_line'],
               finding['family'] if finding['evidence_kind'] == 'NO_SOURCE' else '')
        unique.setdefault(key, finding)
    findings = [v for v in unique.values() if v['rule'] not in ignore]
    failed = any(f['severity'] == 'HIGH' or fail_on == 'MEDIUM' for f in findings)
    return dict(status='fail' if failed else 'pass', findings=findings, verified_claims=verified)
