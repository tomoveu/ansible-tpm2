# Copyright (c) 2020 by Erik Larsson
# SPDX-License-Identifier: GPL-3.0-or-later

#from secrets import token_bytes
import secrets
from tpm2_pytss.binding import (
    TPM2_ALG_RSA,
    TPM2_ALG_ECC,
    TPM2B_PUBLIC,
    TPM2B_DIGEST,
    TPM2B_ID_OBJECT,
    TPM2B_ENCRYPTED_SECRET,
    TPMS_ECC_POINT,
    TPM2B_ECC_PARAMETER,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import (
    OAEP,
    MGF1,
)
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, ECDH
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.hmac import HMAC
from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from ansible_collections.whooo.tpm2.plugins.module_utils.compare import compare_public
from ansible_collections.whooo.tpm2.plugins.module_utils.ak import get_ak_template
from ansible_collections.whooo.tpm2.plugins.module_utils.marshal import (
    b64unmarshal,
    b64marshal,
    marshal,
)
from ansible_collections.whooo.tpm2.plugins.module_utils.convert import (
    public_to_crypto,
    tpm2_to_crypto_alg,
    tpm2_to_string_alg,
)


"""
How make credential works:
Needed input is public key of EK, name of AK and a credential value

A protection seed is generated and encrypted

RSA seed encryption/generation
A protection seed is generated randomly, currently 32 bytes, for unknown reason, perhaps due to SHA256?
The seed is then encrypted with OAEP padding with a label of b"IDENTITY\x00" and using the hash alg
of the key (nameAlg), masking generation function MGF1 (the only one accepted)

* Document for ECC here

A symmetric key is derived using KDFa (KBKDFHMAC) with the nameAlg of the EK(?) as the hash function.
Arguments are:
mode is countermode (only option?)
length is length (in bytes) of the derived key, 128 bits, or 16 bytes as we use AES-128
rlen is size of counter in bytes (4)
llen is the length of length in bytes (4)
location is where the counter is stored in relation to fixed data (before fixed)
label is b"STORAGE" for symmetric key
context is name of AK
the protection seed is the input to the KDF

The symmetric key is used to encrypt the credential value with the symmetric value EK in CFB mode.
IV is all zeros.
Arguments are:
CV as a marshaled TPM2B_DIGEST, symmetric algorithm, key and IV of zeros
This is the inner encryption (encIdentity)

A HMAC key is derived using the same KDF function as the generation for the symmetric key
mode is countermode
length is the same size as the size of the digetst which nameAlg of the EK produces.
rlen and llen are four bytes
locatios is before fixed
label is b"INTEGRITY"
context is b""
the protection seed is the input to the KDF

The HMAC key is used calculate the HMAC of inner encryption (encIdentity) concated with name of the AK
The HMAC hash function is the same as the nameAlg function of the EK
this is the outerHMAC

A credential blob is created by marshaling outerHMAC and then appending encIdentity to that buffer

The blob and encrypted seed can then be passed to ActivateCredential

"""

def get_name(public):
    namealg = public.publicArea.nameAlg
    algprefix = namealg.to_bytes(2, 'big')
    halg = tpm2_to_crypto_alg(namealg)
    pbuf = marshal(public.publicArea)
    h = Hash(halg(), default_backend())
    h.update(pbuf)
    dig = h.finalize()
    return algprefix + dig

def create_rsa_seed(key, seed, halg):
    mgf = MGF1(halg())
    padd = OAEP(mgf, halg(), b"IDENTITY\x00")
    enc_seed = key.encrypt(seed, padd)
    return enc_seed

def create_ecc_seed(key, halg):
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
    seed = kdfe(halg, shared_key, b"IDENTITY\x00", exbytes, xbytes, halg.digest_size * 8)
    return (seed, secret)

def create_seed(public):
    key = public_to_crypto(public)
    halg = tpm2_to_crypto_alg(public.publicArea.nameAlg)
    if public.publicArea.type == TPM2_ALG_RSA:
        seed = secrets.token_bytes(32)
        enc_seed = create_rsa_seed(key, seed, halg)
    elif public.publicArea.type == TPM2_ALG_ECC:
        (seed, enc_seed) = create_ecc_seed(key, halg)
    else:
        raise Exception("unsupported seed algorithm {}".format(public.publicArea.type))
    return (seed, enc_seed)

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

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        b64ek = self._task.args.get('ek')
        b64ak = self._task.args.get('ak')
        cv = self._task.args.get('cv', b'FALAFEL')

        if isinstance(cv, str):
            cv = cv.encode('utf-8')
        
        ek = TPM2B_PUBLIC()
        b64unmarshal(b64ek, ek)
        ak = TPM2B_PUBLIC()
        b64unmarshal(b64ak, ak)

        aktype = tpm2_to_string_alg(ak.publicArea.type)
        aktempl = get_ak_template(aktype)
        try:
            compare_public(ak, aktempl)
        except Exception as e:
            raise AnsibleError("AK does not match template: {}".format(e))

        seed, enc_seed = create_seed(ek)
        
        halg = tpm2_to_crypto_alg(ek.publicArea.nameAlg)
        ak_name = get_name(ak)
        symbits = ek.publicArea.parameters.asymDetail.symmetric.keyBits.sym
        symkey = kdfa(halg, seed, b"STORAGE", ak_name, b"", symbits)
        enc_cred = encrypt(symkey, cv)

        hmackey = kdfa(halg, seed, b"INTEGRITY", b"", b"", halg.digest_size * 8)
        outerhmac = hmac(halg, hmackey, enc_cred, ak_name)
        hmac2b = TPM2B_DIGEST(buffer=outerhmac)
        hmacdata = marshal(hmac2b)
        
        credblob = TPM2B_ID_OBJECT(credential=hmacdata + enc_cred)
        secret = TPM2B_ENCRYPTED_SECRET(secret=enc_seed)

        b64blob = b64marshal(credblob)
        b64secret = b64marshal(secret)
        
        return dict(credblob=b64blob, secret=b64secret)
