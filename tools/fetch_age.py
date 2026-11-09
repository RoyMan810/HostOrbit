"""Fetch the exact pinned age archive through official HTTPS release routes."""

import argparse
import hashlib
from pathlib import Path
import urllib.parse
import urllib.request


SOURCES = (
    'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz?download=1',
    'https://api.github.com/repos/FiloSottile/age/releases/assets/535541903',
)
SHA256 = 'cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10'
MAX_BYTES = 32 * 1024 * 1024


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('AGE_HTTPS_REQUIRED')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(output):
    opener = urllib.request.build_opener(HTTPSRedirect())
    for source in SOURCES:
        request = urllib.request.Request(source, headers={'Accept': 'application/octet-stream',
                                                         'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with opener.open(request, timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
        except OSError:
            continue
        if len(data) > MAX_BYTES:
            raise ValueError('AGE_ARCHIVE_SIZE_EXCEEDED')
        if hashlib.sha256(data).hexdigest() != SHA256:
            raise ValueError('AGE_ARCHIVE_CHECKSUM_MISMATCH')
        with Path(output).open('xb') as destination:
            destination.write(data)
        return
    raise RuntimeError('AGE_DOWNLOAD_UNAVAILABLE')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fetch(args.output)
    print('Pinned age archive verified')
