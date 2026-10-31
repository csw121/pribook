import hashlib
import json
import math
import os
import tempfile
from pathlib import Path

class SevError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise SevError('JSON_DUPLICATE_KEY', 'JSON 중복 키를 허용하지 않습니다.')
        result[key] = value
    return result

def finite(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError()
    return value

def loads(text):
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_float=finite,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, RecursionError):
        raise SevError('JSON_INVALID', '유한한 값으로 구성된 올바른 JSON이 필요합니다.') from None

def read_json(path):
    try:
        path = Path(path)
        if path.stat().st_size > 10_000_000:
            raise SevError('INPUT_TOO_LARGE', 'JSON 입력 한도는 10MB입니다.')
        return loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, UnicodeError):
        raise SevError('INPUT_READ', '입력 파일을 읽을 수 없습니다.') from None

def canonical(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)

def digest(data):
    return hashlib.sha256(canonical(data).encode()).hexdigest()

def write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.sev-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as out:
            out.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def write_json(path, data):
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + '\n')
