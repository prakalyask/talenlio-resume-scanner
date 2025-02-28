# scanner/utils.py
import zipfile
from xml.etree.ElementTree import XML


def extract_text_from_docx(file_path):
    """
    Extracts text from a .docx file using only Python's standard library.
    Returns the extracted text as a string.
    """
    text = []
    with zipfile.ZipFile(file_path) as z:
        # 'word/document.xml' is the main content
        xml_content = z.read('word/document.xml')
        root = XML(xml_content)

        # Each <w:t> tag in the XML represents text
        for node in root.iter():
            if node.tag.endswith('}t'):
                # node.text can be None if it's empty
                text.append(node.text or "")

    return " ".join(text)


def naive_extract_text_from_pdf(file_path):
    """
    Very naive approach: read raw bytes and extract ASCII segments.
    This won't handle PDF compression or advanced encoding.
    """
    text_parts = []
    with open(file_path, 'rb') as f:
        raw_data = f.read()
    # Attempt to decode as ASCII ignoring errors
    extracted = raw_data.decode('ascii', errors='ignore')
    # We can attempt to find textual sections by splitting on newlines
    # or just return the entire ASCII chunk
    # This often includes lots of PDF-specific tags and gibberish
    text_parts.append(extracted)
    return "\n".join(text_parts)
