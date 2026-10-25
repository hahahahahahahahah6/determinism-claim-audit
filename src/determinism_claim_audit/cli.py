"""Command line interface."""
import argparse
import json
import sys
from . import __version__
from .audit import audit


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, '{}: error: {}\n'.format(self.prog, message))


def main(argv=None):
    parser = Parser(description='Audit documented determinism claims without executing code.')
    parser.add_argument('path', nargs='?', default='.')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--fail-on', choices=('HIGH', 'MEDIUM'), default='MEDIUM')
    parser.add_argument('--ignore', default='', metavar='RULE,...')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    try:
        result = audit(args.path, args.fail_on, args.ignore.split(','))
    except (ValueError, OSError, UnicodeError) as exc:
        parser.exit(1, 'error: {}\n'.format(exc))
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        for f in result['findings']:
            print('{severity} {rule} {evidence_file}:{evidence_line} {evidence_kind} {doc_file}:{doc_line}'.format(**f))
        if args.verbose:
            for c in result['verified_claims']:
                print('VERIFIED {family} {doc_file}:{doc_line}'.format(**c))
        if not result['findings']:
            print('PASS')
    return 2 if result['status'] == 'fail' else 0
