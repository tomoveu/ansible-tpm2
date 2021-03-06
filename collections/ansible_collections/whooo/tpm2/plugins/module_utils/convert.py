# Copyright (c) 2020 by Erik Larsson
# SPDX-License-Identifier: GPL-3.0-or-later


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import (
    Hash,
    SHA256,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
    SECP256R1,
    ECDSA,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicNumbers,
    RSAPublicKey,
)
from tpm2_pytss.esys import ESYSBinding
from tpm2_pytss.binding import (
    TPM2_ALG_SHA256,
    TPM2_ALG_RSA,
    TPM2_ALG_ECC,
    TPM2_ECC_NIST_P256,
    TPM2_ALG_RSAPSS,
    TPM2_ALG_RSASSA,
    TPM2_ALG_ECDSA,
)
from cryptography.hazmat.primitives.asymmetric.padding import (
    PSS,
    PKCS1v15
)
from ansible_collections.whooo.tpm2.plugins.module_utils.marshal import marshal

def buffer_to_bytes(src, attr='buffer'):
    ba = bytearray()
    battr = getattr(src, attr)
    buf = ESYSBinding.ByteArray.frompointer(battr)
    for i in range(0, src.size):
        ba.append(buf[i])
    return ba

mappings = (
    (TPM2_ALG_SHA256, SHA256, 'SHA256'),
    (TPM2_ALG_RSA, RSAPublicKey, 'RSA'),
    (TPM2_ALG_RSAPSS, PSS, 'RSAPSS'),
    (TPM2_ALG_RSASSA, PKCS1v15, 'RSASSA'),
    (TPM2_ALG_ECC, EllipticCurvePublicKey, 'ECC'),
    (TPM2_ALG_ECDSA, ECDSA, 'ECDSA'),
)

def tpm2_to_crypto_alg(algid):
    for t, c, s in mappings:
        if t == algid:
            return c
    return None

def tpm2_to_string_alg(algid):
    for t, c, s in mappings:
        if t == algid:
            return s
    return None

curves = (
    (TPM2_ECC_NIST_P256, SECP256R1),
)

def curveid_to_curve(curveid):
    for cid, curve in curves:
        if cid == curveid:
            return curve()
    return None

def public_rsa_to_crypto(public):
    e = public.parameters.rsaDetail.exponent
    if e == 0:
        e = 65537 # F4, default exponent
    nbytes = buffer_to_bytes(public.unique.rsa)
    n = int.from_bytes(nbytes, 'big')
    key = RSAPublicNumbers(e, n).public_key(default_backend())
    return key

def public_ecc_to_crypto(public):
    cid = public.parameters.eccDetail.curveID
    curve = curveid_to_curve(cid)
    if curve is None:
        raise Exception("Unable to find curve for curveid {x}".format(cid))
    xbytes = buffer_to_bytes(public.unique.ecc.x)
    x = int.from_bytes(xbytes, 'big')
    ybytes = buffer_to_bytes(public.unique.ecc.y)
    y = int.from_bytes(ybytes, 'big')
    key = EllipticCurvePublicNumbers(x, y, curve).public_key(default_backend())
    return key

def public_to_crypto(public):
    keytype = public.publicArea.type
    if keytype == TPM2_ALG_RSA:
        return public_rsa_to_crypto(public.publicArea)
    elif keytype == TPM2_ALG_ECC:
        return public_ecc_to_crypto(public.publicArea)
    raise Exception("Unsupported key type: {}".format(keytype))

def get_name(area):
    halg = tpm2_to_crypto_alg(area.nameAlg)
    algp = area.nameAlg.to_bytes(2, 'big')
    pbuf = marshal(area)
    h = Hash(halg(), default_backend())
    h.update(pbuf)
    dig = h.finalize()
    name = algp + dig
    return name
