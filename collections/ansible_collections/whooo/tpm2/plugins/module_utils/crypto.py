# Copyright (c) 2020 by Erik Larsson
# SPDX-License-Identifier: GPL-3.0-or-later


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    ECDSA,
    ECDH,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)
from ansible_collections.whooo.tpm2.plugins.module_utils.marshal import marshal
from ansible_collections.whooo.tpm2.plugins.module_utils.convert import (
    public_to_crypto,
    tpm2_to_crypto_alg,
    buffer_to_bytes,
)
from tpm2_pytss.binding import (
    TPM2_ALG_RSA,
    TPM2_ALG_ECC,
    TPMS_ECC_POINT,
    TPM2B_ECC_PARAMETER,
    TPM2B_DIGEST
)

def kdfa(halg, key, label, contextU, contextV, bits):
    klen = int(bits / 8)
    context = contextU + contextV
    kdf = KBKDFHMAC(
        algorithm=halg(),
        mode=Mode.CounterMode,
        length=klen,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=label,
        context=context,
        fixed=None,
        backend=default_backend(),
    )
    return kdf.derive(key)

def kdfe(halg, z, use, partyuinfo, partyvinfo, bits):
    klen = int(bits / 8)
    otherinfo = use + partyuinfo + partyvinfo
    kdf = ConcatKDFHash(
        algorithm=halg(),
        length=klen,
        otherinfo=otherinfo,
        backend=default_backend()
    )
    return kdf.derive(z)

def encrypt(key, cv):
    # should use symmetric conf from EK
    buf = TPM2B_DIGEST(buffer=cv)
    cred = marshal(buf)
    aes = AES(key)
    iv = b"\x00" * int(aes.block_size / 8) # why / 8 ?
    ciph = Cipher(aes, modes.CFB(iv), backend=default_backend())
    encr = ciph.encryptor()
    enc_cred = encr.update(cred) + encr.finalize()
    return enc_cred

def hmac(halg, hmackey, enc_cred, name):
    h = HMAC(hmackey, halg(), backend=default_backend())
    h.update(enc_cred)
    h.update(name)
    return h.finalize()

def create_rsa_seed(key, seed, halg, label):
    mgf = MGF1(halg())
    padd = OAEP(mgf, halg(), lbal)
    enc_seed = key.encrypt(seed, padd)
    return enc_seed

def create_ecc_seed(key, halg, label):
    ekey = generate_private_key(key.curve, default_backend())
    epubnum = ekey.public_key().public_numbers()
    plength = int(key.curve.key_size / 8) # FIXME ceiling here
    exbytes = epubnum.x.to_bytes(plength, 'big')
    eybytes = epubnum.y.to_bytes(plength, 'big')
    epoint = TPMS_ECC_POINT(
        x=TPM2B_ECC_PARAMETER(buffer=exbytes),
        y=TPM2B_ECC_PARAMETER(buffer=eybytes),
    )
    secret = marshal(epoint)
    shared_key = ekey.exchange(ECDH(), key)
    pubnum = key.public_numbers()
    xbytes = pubnum.x.to_bytes(plength, 'big')
    seed = kdfe(halg, shared_key, label, exbytes, xbytes, halg.digest_size * 8)
    return (seed, secret)

def create_seed(public, label):
    key = public_to_crypto(public)
    halg = tpm2_to_crypto_alg(public.publicArea.nameAlg)
    if public.publicArea.type == TPM2_ALG_RSA:
        seed = secrets.token_bytes(32)
        enc_seed = create_rsa_seed(key, seed, halg, label)
    elif public.publicArea.type == TPM2_ALG_ECC:
        (seed, enc_seed) = create_ecc_seed(key, halg, label)
    else:
        raise Exception("unsupported seed algorithm {}".format(public.publicArea.type))
    return (seed, enc_seed)

def verify_signature_rsa(signature, key, halg, data):
    padding = tpm2_to_crypto_alg(signature.sigAlg)
    raise Exception('rsa signatures not yet implemented')

def verify_signature_ecc(signature, key, halg, data):
    sig = signature.signature
    rbytes = buffer_to_bytes(sig.ecdsa.signatureR)
    r = int.from_bytes(rbytes, 'big')
    sbytes = buffer_to_bytes(sig.ecdsa.signatureS)
    s = int.from_bytes(sbytes, 'big')
    dersig = encode_dss_signature(r, s)
    key.verify(dersig, data, ECDSA(halg()))

def verify_signature(signature, public, data):
    key = public_to_crypto(public)
    halg = tpm2_to_crypto_alg(signature.signature.any.hashAlg)
    if isinstance(key, RSAPublicKey):
        return verify_signature_rsa(signature, key, halg, data)
    elif isinstance(key, EllipticCurvePublicKey):
        return verify_signature_ecc(signature, key, halg, data)
    raise Exception('unsupported key type')
