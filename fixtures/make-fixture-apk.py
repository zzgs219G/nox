#!/usr/bin/env python3
"""make-fixture-apk.py — 造一个专用测试 APK（用于 CI / 别人复现测试）

为什么需要它：
  test.sh 需要一个已签名的 APK（密钥由证书派生，这是设计）。
  但如果直接把正式签名包提交进仓库，等于公开你的证书指纹 ——
  任何人拿它就能解出用该证书加密的 so。

  所以这里生成一个【专用】的测试包：结构合法、可被解析、
  但证书只用于测试，与任何真实发布包无关。

它怎么做的：
  不调用 apksigner（依赖太多），直接手工拼 APK Signing Block。
  解析端（ncg_apk_first_cert_der / apk_first_signer_cert_sha256）
  只读证书 DER、不验签，所以结构合法即可。

⚠️ 这个包【不能安装】，只用于测试工具链能否正常解析。

用法：
    python3 fixtures/make-fixture-apk.py fixtures/sample.apk
"""
import io
import struct
import sys
import zipfile

# 一个最小的 DER 结构。解析端只按长度前缀取字节，不校验 ASN.1 内容，
# 所以这串只要能"被当作证书 DER 取出"就够用。
# 长度 666 字节是刻意对齐真实证书的量级（真实简盒证书就是 666 字节）。
CERT_DER = (
    b'\x30\x82\x02\x96'                       # SEQUENCE, len 0x296
    + b'\x30\x82\x01\x0a'                     # TBSCertificate
    + b'\xa0\x03\x02\x01\x02'                 # version v3
    + b'\x02\x01\x01'                         # serial 1
    + b'\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02'  # sigalg ecdsa-sha256
    + b'\x30\x15\x31\x13\x30\x11\x06\x03\x55\x04\x03\x0c\x0a'
    + b'nox-fixture'                          # CN=nox-fixture
    + b'\x30\x1e\x17\x0d' + b'260101000000Z'  # notBefore
    + b'\x17\x0d' + b'270101000000Z'          # notAfter
    + b'\x30\x15\x31\x13\x30\x11\x06\x03\x55\x04\x03\x0c\x0a'
    + b'nox-fixture'                          # subject
    + b'\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01'
    + b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00'
)
# 补齐到 666 字节（公钥位图 + 签名位图，随便填）
CERT_DER = CERT_DER + b'\x04' * (666 - len(CERT_DER))
assert len(CERT_DER) == 666, len(CERT_DER)


def lp(b):
    """4 字节小端长度 + 内容"""
    return struct.pack('<I', len(b)) + b


def build(out_path):
    # 1) 最小 zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('AndroidManifest.xml', b'\x03\x00\x08\x00' + b'\x00' * 240)
        z.writestr('classes.dex', b'dex\n035\x00' + b'\x00' * 240)
    data = buf.getvalue()

    # 2) v2 scheme 逐层组装
    #
    # ⚠️ 严格照 so-section-lock.py 的 _first_cert_der / _from_signer 的
    #    读法反向构造（不是凭规范直觉写）。解析器的实际读法：
    #
    #    val[0:4]        = signers_len（必须 == len(val)-4）
    #    val[4:8]        = signer_len（必须 == len(val)-8）
    #    signer = val[8 : 8+signer_len]
    #    signer[0:4]     = sd_len
    #    sd = signer[4 : 4+sd_len]
    #    sd[0:4]         = digests_len      ← 必须 >= 4（有 `if dg<4: return None`）
    #    q = 4+digests_len
    #    sd[q:q+4]       = certs_len
    #    sd[q+4:q+8]     = cert_len         ← 第一张证书长度
    #    cert = sd[q+8 : q+8+cert_len]
    #
    #    踩过的三个坑（每一个都会导致"v3/v2 中均未找到证书 DER"）：
    #    ① digests_len 写成 0 → 被 `if dg < 4` 直接拒
    #    ② signers_len 写成 len(signer) → 少 4（应为 4+len(signer)）
    #    ③ 长度字段多套一层 → 层层错位，在错误偏移读到看似合理的数字

    # digests：一个合法条目（长度前缀 + 内容）
    digest_entry = lp(b'\x04' * 32)          # 内容非空，避免长度歧义
    digests = lp(digest_entry)               # digests_len 段
    assert len(digests) >= 8 and int.from_bytes(digests[:4], 'little') >= 4

    # certificates：序列(长度 + DER)
    cert_seq = lp(CERT_DER)
    certs = lp(cert_seq)

    # additional attributes：空序列
    additional_attrs = lp(b'')

    signed_data = digests + certs + additional_attrs

    signatures = lp(b'')
    public_key = lp(b'')

    # signer = sd_len + signed_data + signatures + public_key
    signer = lp(signed_data) + signatures + public_key

    # val = signers_len + signer_len + signer
    val = struct.pack('<I', 4 + len(signer)) + lp(signer)

    # 自校验：逐层断言，任何一层错位立刻炸（而不是等到解析时才失败）
    assert int.from_bytes(val[0:4], 'little') == len(val) - 4, 'signers_len'
    assert int.from_bytes(val[4:8], 'little') == len(val) - 8, 'signer_len'
    _signer = val[8:]
    # sd_len 只覆盖 signed_data 部分（后面还有 signatures 与 public_key），
    # 所以不能断言 == len(_signer)-4，只能断言不越界。
    _sd_len = int.from_bytes(_signer[0:4], 'little')
    assert 8 <= _sd_len <= len(_signer) - 4, 'sd_len 越界'
    _sd = _signer[4:4 + _sd_len]
    _dg = int.from_bytes(_sd[0:4], 'little')
    assert _dg >= 4, 'digests_len 必须 >= 4'
    _q = 4 + _dg
    _cl = int.from_bytes(_sd[_q + 4:_q + 8], 'little')
    assert _cl == len(CERT_DER), 'cert_len 应等于 DER 长度'

    # 3) id-value 对：[8字节长度][4字节ID][value]
    id_value = struct.pack('<I', 0x7109871a) + val
    pair = struct.pack('<Q', len(id_value)) + id_value

    MAGIC = b'APK Sig Block 42'
    block_body = pair + struct.pack('<Q', len(pair) + 24) + MAGIC
    block = struct.pack('<Q', len(block_body)) + block_body

    # 4) 插到 Central Directory 之前，修正 EOCD 的 CD 偏移
    eo = data.rfind(b'PK\x05\x06')
    cd_off = struct.unpack('<I', data[eo + 16:eo + 20])[0]
    nd = data[:cd_off] + block + data[cd_off:]
    n_eo = eo + len(block)
    eocd = bytearray(nd[n_eo:n_eo + 22])
    eocd[16:20] = struct.pack('<I', cd_off + len(block))
    nd = nd[:n_eo] + bytes(eocd)

    # 5) 自校验：长度链必须自洽
    assert struct.unpack('<Q', nd[cd_off:cd_off + 8])[0] == len(block_body)
    open(out_path, 'wb').write(nd)
    return len(nd)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'fixtures/sample.apk'
    n = build(out)
    import hashlib
    print('已生成 %s（%d 字节）' % (out, n))
    print('证书 DER %d 字节' % len(CERT_DER))
    print('证书 SHA256 = %s' % hashlib.sha256(CERT_DER).hexdigest())
    print('（这是专用测试证书，与任何真实发布包无关）')
