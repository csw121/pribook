import io
import zipfile
from collections import Counter
from pathlib import Path
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape
from .common import SevError

NS={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main','wp':'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing'}

def docx_bytes(text):
    paragraphs=''.join('<w:p><w:r><w:t xml:space="preserve">'+escape(line)+'</w:t></w:r></w:p>' for line in text.splitlines())
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml','<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr('_rels/.rels','<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr('word/document.xml','<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="'+NS['w']+'"><w:body>'+paragraphs+'<w:sectPr/></w:body></w:document>')
    return out.getvalue()

def inspect_docx(path,include_text=False):
    path=Path(path)
    if path.suffix.lower()!='.docx':
        raise SevError('DOCUMENT_UNSUPPORTED','DOCX만 지원합니다. 한글에서 원본을 보존하고 DOCX 사본으로 변환하세요.')
    try:
        if path.stat().st_size>20_000_000:raise ValueError()
        with zipfile.ZipFile(path) as z:
            infos=z.infolist()
            if len(infos)>10000 or sum(i.file_size for i in infos)>50_000_000 or len({i.filename for i in infos})!=len(infos):raise ValueError()
            data=z.read('word/document.xml')
            if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():raise ValueError()
            root=ET.fromstring(data);headings=[];styles=[]
            for paragraph in root.findall('.//w:p',NS):
                style=paragraph.find('./w:pPr/w:pStyle',NS)
                text=''.join(t.text or '' for t in paragraph.findall('.//w:t',NS))
                name=style.get('{'+NS['w']+'}val','') if style is not None else ''
                if 'heading' in name.lower() or text.startswith('#'):
                    styles.append(name or 'markdown');headings.append(text if include_text else '[LOCAL HEADING REDACTED]')
            return {'format':'docx','headings':headings,'repeated_heading_styles':dict(Counter(styles)),
                    'tables_rows_cell_counts':[[len(r.findall('./w:tc',NS)) for r in t.findall('./w:tr',NS)] for t in root.findall('.//w:tbl',NS)],
                    'images':sum(i.filename.startswith('word/media/') for i in infos),
                    'inline_image_positions':len(root.findall('.//wp:inline',NS)),
                    'anchored_image_positions':len(root.findall('.//wp:anchor',NS)),
                    'limitations':['XML 구조만 분석; 실제 페이지 좌표·렌더링·특정 보고서 양식 일치 미검증']}
    except (OSError,KeyError,ValueError,RuntimeError,zipfile.BadZipFile,ET.ParseError):
        raise SevError('DOCUMENT_INVALID','안전하게 읽을 수 있는 DOCX가 아닙니다.') from None
