import hashlib
import hmac
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl
from .common import loads, SevError

SENSITIVE = re.compile(r'password|passwd|secret|token|cookie|authorization|api.?key|email|phone', re.I)
RESPONSE = re.compile(r'^HTTP/(?:1\.[01]|2(?:\.0)?) ([1-5][0-9]{2})(?: [^\n]*)?$', re.M)
REQUEST = re.compile(r'([A-Z]+) (\S+) HTTP/(?:1\.[01]|2(?:\.0)?)')

def clean_body(value):
    if isinstance(value, dict):
        return {k: '[REDACTED]' if SENSITIVE.search(k) else clean_body(v) for k,v in value.items()}
    if isinstance(value, list):
        return [clean_body(v) for v in value]
    return value

def message(text):
    head, sep, body = text.partition('\n\n')
    if not sep:
        raise SevError('HTTP_FORMAT', '헤더와 본문 사이에 빈 줄이 필요합니다.')
    lines = head.splitlines()
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(':')
        if not sep or not key or key.lower() in headers:
            raise SevError('HTTP_HEADERS', '잘못되거나 중복된 헤더입니다.')
        headers[key.lower()] = value.strip()
    return lines[0], headers, body

def parse_http(text, log_id, salt, session_cookie='session'):
    text = text.replace('\r\n', '\n')
    responses = list(RESPONSE.finditer(text))
    if len(responses) != 1:
        raise SevError('HTTP_FORMAT', '파일당 단일 요청·최종 응답만 지원합니다.')
    position = responses[0].start()
    first, headers, _ = message(text[:position])
    match = REQUEST.fullmatch(first)
    if not match:
        raise SevError('HTTP_REQUEST', '지원하지 않는 요청 행입니다.')
    response, response_headers, body = message(text[position:])
    method, target = match.groups()
    try:
        url = urlsplit(target)
        if url.username or url.password or url.fragment or not url.path.startswith('/') or url.scheme not in ('','http','https'):
            raise ValueError()
        authority = url.netloc or headers.get('host')
        if not authority:
            raise SevError('HTTP_TARGET_MISSING', 'Host 또는 절대 HTTP(S) URL이 필요합니다.')
    except ValueError:
        raise SevError('HTTP_URL', '올바른 HTTP(S) 요청 주소가 필요합니다.') from None
    query = [[k, '[REDACTED]' if SENSITIVE.search(k) else v] for k,v in parse_qsl(url.query, keep_blank_values=True)]
    cookies = {}
    for part in headers.get('cookie', '').split(';'):
        key, sep, value = part.strip().partition('=')
        if sep:
            if key in cookies:
                raise SevError('HTTP_COOKIE', '중복 쿠키는 지원하지 않습니다.')
            cookies[key] = value
    raw = cookies.get(session_cookie)
    session = hmac.new(salt, raw.encode(), hashlib.sha256).hexdigest() if raw else None
    try:
        value = loads(body.strip()) if body.strip() else None
    except SevError:
        if 'json' in response_headers.get('content-type', '').lower():
            raise SevError('HTTP_JSON_INVALID', 'JSON 응답 본문이 올바르지 않습니다.') from None
        value = {'text_sha256': hashlib.sha256(body.encode()).hexdigest()}
    return {'id': str(log_id), 'method': method, 'path': url.path,
            'target_id': hashlib.sha256(authority.lower().encode()).hexdigest(),
            'query': query, 'session': session, 'status': int(response.split()[1]), 'body': clean_body(value)}

def analyze_directory(directory, pattern='*.http', session_cookie='session'):
    root = Path(directory)
    if not root.is_dir() or Path(pattern).name != pattern or '**' in pattern:
        raise SevError('INPUT_DIRECTORY', '디렉터리와 현재 폴더 파일명 패턴이 필요합니다.')
    paths = sorted(root.glob(pattern))
    if not paths:
        raise SevError('NO_LOGS', '일치하는 로그 파일이 없습니다.')
    salt = secrets.token_bytes(32)
    logs = []
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
            raise SevError('INPUT_FILE', '일반 로그 파일(2MB 이하)만 지원합니다.')
        try:
            logs.append(parse_http(path.read_text(encoding='utf-8-sig'), path.stem, salt, session_cookie))
        except (OSError, UnicodeError):
            raise SevError('INPUT_READ', 'UTF-8 로그를 읽을 수 없습니다.') from None
    return {'schema_version': '1.0', 'logs': logs}
