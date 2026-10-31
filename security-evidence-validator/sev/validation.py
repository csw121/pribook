from importlib.resources import files
from jsonschema import Draft202012Validator
from .common import loads, SevError

def schema(name):
    return loads(files('sev').joinpath(name+'.schema.json').read_text(encoding='utf-8'))

def validate(data, name):
    if not Draft202012Validator(schema(name)).is_valid(data):
        raise SevError('SCHEMA_'+name.upper(), '입력 구조·자료형이 JSON 스키마와 일치하지 않습니다.')
    return data
