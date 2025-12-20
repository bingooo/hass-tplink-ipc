import hashlib
import base64
from typing import Union, List, Tuple
import rsa

# Entry method, supports encrypt type 2 and 3
def encrypt_password(password: str, nonce: str, key: str, encrypt_type: Union[str, List[str], None]) -> Tuple[str, str]:
    if isinstance(encrypt_type, list):
        encrypt_type_to_use = "2" if "2" in encrypt_type else str(encrypt_type[0])
    else:
        encrypt_type_to_use = str(encrypt_type) if encrypt_type else "3"

    if encrypt_type_to_use == "2":
        org_pwd = org_auth_pwd(password)
        plain_text = f"{org_pwd}:{nonce}"
        encrypted = rsa_encrypt_tplink(plain_text, key)
    else:
        encrypted = hashlib.md5(f"{password}:{nonce}".encode("utf-8")).hexdigest()
    
    return encrypted, encrypt_type_to_use

# Encrypt method 3 (legacy) - md5 hash 
def security_encode(a: str, c: str, b: str) -> str:
    d = ""
    f, g, h = len(a), len(c), len(b)
    e = max(f, g)
    for l in range(e):
        k = ord(a[l]) if l < f else 187
        m = ord(c[l]) if l < g else 187
        d += b[(k ^ m) % h]
    return d

# Encrypt method 2 - rsa encrypt
def rsa_encrypt_tplink(plain_text: str, key_base64: str) -> str:
    """使用 rsa 库进行加密"""
    try:
        # 1. 提取RSA公钥
        public_key = extract_tplink_key(key_base64)
        
        # 2. 使用rsa库加密
        encrypted_bytes = rsa.encrypt(plain_text.encode('utf-8'), public_key)
        encrypted_hex = encrypted_bytes.hex()
        
        # 3. TP-Link 长度重试逻辑
        for _ in range(50):
            if len(encrypted_hex) % 64 == 0:
                return base64_encode_hex(encrypted_hex)
            # 重新加密（rsa库每次加密结果可能不同）
            encrypted_bytes = rsa.encrypt(plain_text.encode('utf-8'), public_key)
            encrypted_hex = encrypted_bytes.hex()
        
        return base64_encode_hex(encrypted_hex)
    except Exception as e:
        raise ValueError(f"RSA encryption failed: {e}")

# ============================================================================
# 以下是一个宽容的 RSA 公钥解析实现
# 
# 正常情况下可以直接使用标准库（如 Crypto 或 cryptography）读取 DER 格式的 RSA 公钥，
# 但是部分TPLINK-IPC固件返回的公钥长度为 161 字节且不符合 ASN.1 规范，modulus 最高位为 1，
# 导致标准库无法解析。
# 
# 因此实现此宽容版本的密钥读取函数，与 webui js 版本逻辑一致。
# 若固件能确保都是规范公钥，直接按 DER 或使用固定偏移读取即可。
# ============================================================================

# 基础 TLV 解析
def read_len(buf, i):
    b = buf[i]
    if b < 0x80:
        return b, 1
    n = b & 0x7f
    return int.from_bytes(buf[i+1:i+1+n], "big"), 1+n

def parse_tlv(buf, i=0, end=None):
    if end is None:
        end = len(buf)
    nodes = []
    while i < end:
        tag = buf[i]
        length, ll = read_len(buf, i+1)
        hdr = 1 + ll
        start = i + hdr
        value = buf[start:start+length]
        children = None
        if tag == 0x30:  # SEQUENCE
            children = parse_tlv(value, 0, len(value))
        nodes.append((tag, value, children))
        i = start + length
    return nodes

# 提取 RSA 公钥（宽容版本，支持非标准 DER 格式）
def extract_rsa_key(der):
    # 解析最外层
    nodes = parse_tlv(der)
    # SPKI: [ SEQ , ... ]
    # AlgorithmIdentifier is nodes[0].children[0], skip it
    bit_string_node = nodes[0][2][1]  # second child of SPKI
    bit_content = bit_string_node[1]
    # Skip unused bits byte
    rsa_bytes = bit_content[1:]
    rsa_nodes = parse_tlv(rsa_bytes)
    rsa_seq = rsa_nodes[0][2]
    mod_node = rsa_seq[0]
    exp_node = rsa_seq[1]
    # 无符号去整数
    n = int.from_bytes(mod_node[1], "big", signed=False)
    e = int.from_bytes(exp_node[1], "big", signed=False)
    return n, e

def extract_tplink_key(key_base64: str):
    """
    从 TP-Link 的 DER 格式中提取模数(n)和指数(e)
    """
    der = base64.b64decode(key_base64)
    n, e = extract_rsa_key(der)
    return rsa.PublicKey(n, e)

def base64_encode_hex(hex_str: str) -> str:
    M = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    X = "="
    d = ""
    c = 0
    while c + 3 <= len(hex_str):
        b = int(hex_str[c:c+3], 16)
        d += M[b >> 6] + M[b & 63]
        c += 3
    if c + 1 == len(hex_str):
        b = int(hex_str[c:c+1], 16)
        d += M[b << 2]
    elif c + 2 == len(hex_str):
        b = int(hex_str[c:c+2], 16)
        d += M[b >> 2] + M[(b & 3) << 4]
    while len(d) & 3:
        d += X
    return d

def org_auth_pwd(password: str) -> str:
    return security_encode(
        password,
        # Magic string
        "RDpbLfCPsJZ7fiv", 
        # OrgAuth Public key
        "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
    )
