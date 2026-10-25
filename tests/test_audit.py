import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from determinism_claim_audit.audit import audit, claims_in, evidence_in, RULE
from determinism_claim_audit.cli import main

FIXTURES = Path(__file__).parent / 'fixtures'


class AuditTests(unittest.TestCase):
    def test_good(self):
        self.assertEqual(audit(FIXTURES / 'good')['status'], 'pass')

    def test_bad(self):
        findings = audit(FIXTURES / 'bad')['findings']
        self.assertEqual(len(findings), 3)
        self.assertEqual({f['severity'] for f in findings}, {'HIGH'})
        self.assertEqual({f['evidence_kind'] for f in findings}, {'TIME', 'RANDOM', 'ORDER'})

    def test_test_only(self):
        result = audit(FIXTURES / 'test-only')
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['severity'], 'MEDIUM')
        self.assertEqual(audit(FIXTURES / 'test-only', 'HIGH')['status'], 'pass')

    def test_empty(self):
        self.assertEqual(audit(FIXTURES / 'empty-src')['findings'][0]['severity'], 'HIGH')

    def test_passing_fixtures(self):
        for name in ('seeded', 'sorted-set', 'negated', 'fenced-code'):
            with self.subTest(name=name):
                self.assertEqual(audit(FIXTURES / name)['status'], 'pass')

    def test_variable_seed(self):
        self.assertEqual(audit(FIXTURES / 'variable-seed')['status'], 'fail')

    def test_env_never_opened(self):
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            result = audit(FIXTURES / 'bad')
        self.assertNotIn('ENV_NEVER_READ_MARKER', json.dumps(result))

    def test_evidence_patterns(self):
        for source, kind in [('datetime.now()', 'TIME'), ('datetime.today', 'TIME'),
                             ('datetime.utcnow()', 'TIME'), ('time.monotonic()', 'TIME'),
                             ('time.perf_counter()', 'TIME'), ('time.clock()', 'TIME'),
                             ('secrets.token_hex()', 'RANDOM'), ('os.urandom(2)', 'RANDOM'),
                             ('uuid.uuid1()', 'UUID'), ('uuid.uuid4', 'UUID'),
                             ('hash(1)', 'ORDER'), ('[x for x in {1, 2}]', 'ORDER'),
                             ('for x in set(items):\n pass', 'ORDER'),
                             ('for x in {y for y in items}:\n pass', 'ORDER')]:
            with self.subTest(source=source):
                self.assertEqual(evidence_in(source, 'a.py')[0]['evidence_kind'], kind)

    def test_safe_patterns(self):
        for source in ('uuid.uuid5(a,b)', 'uuid.uuid3(a,b)', '[x for x in sorted({1,2})]',
                       'for x in {"a": 1}:\n pass', 'getattr(random, name)()'):
            with self.subTest(source=source):
                self.assertEqual(evidence_in(source, 'a.py'), [])

    def test_seed_does_not_guard_other_kinds(self):
        result = evidence_in('random.seed(42)\nrandom.random()\ntime.time()\nhash(x)', 'a.py')
        self.assertEqual({v['evidence_kind'] for v in result}, {'TIME', 'ORDER'})

    def test_string_seed(self):
        self.assertEqual(evidence_in('random.seed("fixed")\nrandom.choice(x)', 'a.py'), [])

    def test_dynamic_seed(self):
        self.assertEqual(len(evidence_in('random.seed(time.time())\nrandom.random()', 'a.py')), 2)

    def test_claim_families_and_lines(self):
        result = claims_in('Intro.\nDeterministically stable. Reproducibility. Same result each run.', 'README')
        self.assertEqual({c['family'] for c in result}, {'deterministic', 'reproducible', 'same-output'})
        self.assertEqual(result[0]['doc_line'], 2)

    def test_negations(self):
        for text in ('not deterministic', 'non-deterministic', 'nondeterministic',
                     'not reproducible', 'non-reproducible'):
            self.assertEqual(claims_in(text, 'README'), [])
        self.assertEqual(len(claims_in('Not deterministic. Reproducible.', 'README')), 1)

    def test_fences(self):
        self.assertEqual(claims_in('~~~text\ndeterministic\n~~~\n', 'README'), [])
        self.assertEqual(claims_in('```\nreproducible\n```', 'README'), [])

    def test_scope_and_no_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README').write_text('Deterministic.', encoding='utf-8')
            (root / 'main.py').write_text('raise RuntimeError("must not execute")', encoding='utf-8')
            (root / 'examples').mkdir()
            (root / 'examples' / 'bad.py').write_text('time.time()', encoding='utf-8')
            self.assertEqual(audit(root)['status'], 'pass')
            (root / 'test_one.py').write_text('time.time()', encoding='utf-8')
            self.assertEqual(audit(root)['findings'][0]['severity'], 'MEDIUM')

    def test_no_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'main.py').write_text('time.time()', encoding='utf-8')
            self.assertEqual(audit(root)['findings'], [])

    def test_missing_source_per_family(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('Deterministic and reproducible.', encoding='utf-8')
            self.assertEqual(len(audit(root)['findings']), 2)

    def test_evidence_per_source_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('Deterministic and reproducible.', encoding='utf-8')
            for name in ('a.py', 'b.py'):
                (root / name).write_text('time.time()\ntime.time()', encoding='utf-8')
            findings = audit(root)['findings']
            self.assertEqual(len(findings), 2)
            self.assertEqual({f['evidence_file'] for f in findings}, {'a.py', 'b.py'})

    def test_repeatable(self):
        self.assertEqual(audit(FIXTURES / 'bad'), audit(FIXTURES / 'bad'))


class CLITests(unittest.TestCase):
    def run_cli(self, args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                code = main(args)
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue()

    def test_json(self):
        code, output = self.run_cli([str(FIXTURES / 'bad'), '--json'])
        self.assertEqual(code, 2)
        self.assertEqual(len(json.loads(output)['findings']), 3)
        self.assertNotIn('ENV_NEVER_READ_MARKER', output)

    def test_good(self):
        self.assertEqual(self.run_cli([str(FIXTURES / 'good')])[0], 0)

    def test_version(self):
        self.assertEqual(self.run_cli(['--version']), (0, '0.1.0\n'))

    def test_ignore(self):
        code, output = self.run_cli([str(FIXTURES / 'bad'), '--ignore', RULE, '--json'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['findings'], [])

    def test_missing(self):
        self.assertEqual(self.run_cli(['/nonexistent/determinism-project'])[0], 1)

    def test_file_input(self):
        self.assertEqual(self.run_cli([str(FIXTURES / 'good' / 'README.md')])[0], 1)

    def test_bad_option(self):
        self.assertEqual(self.run_cli(['--fail-on', 'LOW'])[0], 1)

    def test_threshold(self):
        code, output = self.run_cli([str(FIXTURES / 'test-only'), '--fail-on', 'HIGH'])
        self.assertEqual(code, 0)
        self.assertIn('MEDIUM', output)

    def test_verbose(self):
        code, output = self.run_cli([str(FIXTURES / 'good'), '--verbose'])
        self.assertEqual(code, 0)
        self.assertIn('VERIFIED deterministic', output)


if __name__ == '__main__':
    unittest.main()
