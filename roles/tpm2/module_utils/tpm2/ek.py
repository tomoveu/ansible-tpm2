# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later


import secrets
from contextlib import ExitStack
from tpm2_pytss.binding import (
    TPMT_PUBLIC,
    TPM2_ALG_SHA256,
    TPMA_OBJECT_RESTRICTED,
    TPMA_OBJECT_ADMINWITHPOLICY,
    TPMA_OBJECT_DECRYPT,
    TPMA_OBJECT_FIXEDTPM,
    TPMA_OBJECT_FIXEDPARENT,
    TPMA_OBJECT_SENSITIVEDATAORIGIN,
    TPM2B_DIGEST,
    TPMT_SYM_DEF_OBJECT,
    TPM2_ALG_AES,
    TPM2_ALG_CFB,
    TPMU_SYM_KEY_BITS,
    TPMU_SYM_MODE,
    TPM2_ALG_RSA,
    TPM2_ALG_NULL,
    TPM2_ALG_ECC,
    TPM2_ECC_NIST_P256,
    TPM2B_PUBLIC,
    TPM2B_NONCE,
    TPMT_SYM_DEF,
    ESYS_TR_NONE,
    TPM2_SE_POLICY,
    TPM2B_NONCE,
    ESYS_TR_PASSWORD,
    ESYS_TR_RH_ENDORSEMENT,
    TPM2B_TIMEOUT_PTR_PTR,
    TPMT_TK_AUTH_PTR_PTR,
)

ek_base_template = TPMT_PUBLIC(
    nameAlg = TPM2_ALG_SHA256,
    objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_ADMINWITHPOLICY \
        | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM \
        | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN,
    authPolicy = TPM2B_DIGEST(
        size=32,
        buffer=[
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
            0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
            0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
        ]
    )
)

ek_base_sym = TPMT_SYM_DEF_OBJECT(
        algorithm = TPM2_ALG_AES,
        keyBits = TPMU_SYM_KEY_BITS(aes=128),
        mode = TPMU_SYM_MODE(aes=TPM2_ALG_CFB),
)

def get_ek_template(keytype):
    pub = ek_base_template
    if keytype == 'rsa':
        pub.type = TPM2_ALG_RSA
        pub.parameters.rsaDetail.symmetric = ek_base_sym
        pub.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL
        pub.parameters.rsaDetail.keyBits = 2048
        pub.parameters.rsaDetail.exponent = 0
        pub.unique.rsa.size = 256
    elif keytype == 'ecc':
        pub.type = TPM2_ALG_ECC
        pub.parameters.eccDetail.symmetric = ek_base_sym
        pub.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL
        pub.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256
        pub.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL
        pub.unique.ecc.x.size = 32
        pub.unique.ecc.y.size = 32
    else:
        # fail here
        return None

    return TPM2B_PUBLIC(size=0, publicArea=pub)

def ek_session(ectx):
    nonce_caller = TPM2B_NONCE(buffer=secrets.token_bytes(32))
    nonce_tpm = TPM2B_NONCE()
    cphash = TPM2B_DIGEST()
    policy_ref = TPM2B_NONCE()
    sym = TPMT_SYM_DEF(algorithm=TPM2_ALG_NULL)
    obj = ectx.ESYS_TR_PTR()
    with ExitStack() as stack:
        timeout = stack.enter_context(TPM2B_TIMEOUT_PTR_PTR())
        ticket = stack.enter_context(TPMT_TK_AUTH_PTR_PTR())
        ectx.StartAuthSession(
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            nonce_caller,
            TPM2_SE_POLICY,
            sym,
            TPM2_ALG_SHA256,
            obj
        )
        ectx.PolicySecret(
            ESYS_TR_RH_ENDORSEMENT,
            obj.value(),
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            nonce_tpm, #FIXME
            cphash, #FIXME
            policy_ref, #FIXME
            0,
            timeout, #FIXME
            ticket, #FIXME
        )
        return obj.value()
