# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later


from ansible_collections.whooo.tpm2.plugins.module_utils.convert import buffer_to_bytes
from tpm2_pytss.binding import (
    TPM2_ALG_RSA,
    TPM2_ALG_ECC,
    TPM2_ALG_KEYEDHASH,
    TPM2_ALG_ECDAA,
)

def compare_buffer(s1, s2, attr='buffer'):
    b1 = buffer_to_bytes(s1, attr)
    b2 = buffer_to_bytes(s2, attr)
    return b1 == b2

def compare_symmetric(s1, s2):
    if s1.algorithm != s2.algorithm:
        raise Exception('symmetric algorithm does not match')
    elif s1.keyBits.sym != s2.keyBits.sym:
        raise Exception('symmetric key size does not match')
    elif s1.mode.sym != s2.mode.sym:
        raise Exception('symmetric mode does not match')

def compare_scheme_with_hash(s1, s2):
    if s1.scheme != s2.scheme:
        raise Exception('signing scheme does not match')
    elif s1.details.anySig.hashAlg != s2.details.anySig.hashAlg:
        raise Exception('signing hash algorithm does not match')
    elif s1.scheme == TPM2_ALG_ECDAA:
        if s1.details.ecdaa.counter != s2.details.ecdaa.counter:
            raise Exception('ecdaa counter does not match')

def compare_keyedhash_parameters(s1, s2):
    raise Exception('keyedhash parameters compare not yet implemented')

def compare_sym_parameters(s1, s2):
    raise Exception('sym parameters compare not yet implemented')

def compare_rsa_parameters(s1, s2):
    compare_symmetric(s1.symmetric, s2.symmetric)
    compare_scheme_with_hash(s1.scheme, s2.scheme)
    if s1.keyBits != s2.keyBits:
        raise Exception('key size does not match')
    elif s1.exponent != s2.exponent:
        raise Exception('exponent does not match')
    return True

def compare_ecc_parameters(s1, s2):
    compare_symmetric(s1.symmetric, s2.symmetric)
    compare_scheme_with_hash(s1.scheme, s2.scheme)
    if s1.curveID != s2.curveID:
        raise Exception('curve does not match')
    return True

def compare_parameters(s1, s2, keytype):
    if keytype == TPM2_ALG_KEYEDHASH:
        compare_keyedhash(s1.keyedHashDetail, s2.keyedHashDetail)
    # check sym here
    elif keytype == TPM2_ALG_RSA:
        compare_rsa_parameters(s1.rsaDetail, s2.rsaDetail)
    elif keytype == TPM2_ALG_ECC:
        compare_ecc_parameters(s1.eccDetail, s2.eccDetail)

def compare_unique_attrs(s1, s2, keytype):
    if keytype == TPM2_ALG_KEYEDHASH:
        if s1.keyedHash.size != s2.keyedHash.size:
            raise Exception('key size does not match')
        # check sym here as well
    elif keytype == TPM2_ALG_RSA:
        if s1.rsa.size != s2.rsa.size:
            raise Exception('public key size does not match')
    elif keytype == TPM2_ALG_ECC:
        if s1.ecc.x.size != s2.ecc.x.size:
            raise Exception('public key x coordinate size does not match')
        elif s1.ecc.y.size != s2.ecc.y.size:
            raise Exception('public key y coordinate size does not match')

def compare_public(public, template):
    parea = public.publicArea
    tarea = template.publicArea
    if parea.type != tarea.type:
        raise Exception('key type does not match')
    elif parea.nameAlg != tarea.nameAlg:
        raise Exception('nameAlg does not match')
    elif parea.objectAttributes != tarea.objectAttributes:
        raise Exception('object attributes does not match')
    elif not compare_buffer(parea.authPolicy, tarea.authPolicy):
        raise Exception('policy does not match')
    compare_parameters(parea.parameters, tarea.parameters, parea.type)
    compare_unique_attrs(parea.unique, tarea.unique, parea.type)
    
