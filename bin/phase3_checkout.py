"""Exact retained source verification, including the one known portal edit."""
import hashlib
from pathlib import Path
import subprocess

PROFILE_PIN = '1d75faba25a20d2931f0914fb584789411de1143'
PORTAL_ORIGINAL = '5c1ecc740cdedc8e7054cecb42d447f6c0662691164fa54b38a176c49ce80a82'
PORTAL_NORMALIZED = 'eb4bc94d9cbe7da345fb8b6007b2ae22d36325ea0dac201e6c19a578c30f9746'


def command(args):
    result = subprocess.run(args, capture_output=True, check=True, timeout=30)
    return result.stdout


def verify(root):
    root = Path(root).resolve(strict=True)
    git = ['git', '-C', str(root)]
    if command(git+['rev-parse', 'HEAD']).decode().strip() != PROFILE_PIN:
        raise ValueError('Accepted profile pin changed')
    status = command(git+['status', '--porcelain', '--untracked-files=no']).decode()
    if not status:
        return {'commit': PROFILE_PIN, 'portal_normalization': False}
    if status != ' M test-common.py\n':
        raise ValueError('Unreviewed tracked checkout changes')
    path = root/'test-common.py'
    if path.is_symlink() or not path.is_file():
        raise ValueError('Portal-normalized source is not regular')
    original = command(git+['show', 'HEAD:test-common.py'])
    normalized = original.replace(b'2.25.305821105408246119474742976030998643995',
                                  b'2.25.305821105.408246119.47474297.603099864.3995')
    modes = command(git+['diff', 'HEAD', '--summary'])
    if (hashlib.sha256(original).hexdigest() != PORTAL_ORIGINAL
            or path.read_bytes() != normalized
            or hashlib.sha256(normalized).hexdigest() != PORTAL_NORMALIZED or modes):
        raise ValueError('Portal normalization differs from the exact reviewed transformation')
    return {'commit': PROFILE_PIN, 'portal_normalization': True,
            'path': 'test-common.py', 'sha256': PORTAL_NORMALIZED}
