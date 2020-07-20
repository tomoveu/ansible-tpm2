# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later


from contextlib import ExitStack
from .ek import ek_session
from tpm2_pytss.binding import (
    ESYS_TR_NONE,
    ESYS_TR_PASSWORD,
    TPM2B_PUBLIC,
    TPMT_PUBLIC,
    TPMT_SYM_DEF_OBJECT,
    TPM2_ALG_SHA256,
    TPM2_ALG_RSA,
    TPM2_ALG_ECC,
    TPM2_ALG_RSAPSS,
    TPM2_ALG_ECDSA,
    TPM2_ALG_NULL,
    TPM2_ECC_NIST_P256,
    TPMA_OBJECT_RESTRICTED,
    TPMA_OBJECT_USERWITHAUTH,
    TPMA_OBJECT_SIGN_ENCRYPT,
    TPMA_OBJECT_FIXEDTPM,
    TPMA_OBJECT_FIXEDPARENT,
    TPMA_OBJECT_SENSITIVEDATAORIGIN,
    TPM2B_SENSITIVE_CREATE,
    TPM2B_DATA,
    TPML_PCR_SELECTION,
    TPM2B_PRIVATE_PTR_PTR,
    TPM2B_PUBLIC_PTR_PTR,
    TPM2B_CREATION_DATA_PTR_PTR,
    TPM2B_DIGEST_PTR_PTR,
    TPMT_TK_CREATION_PTR_PTR,
)

ak_base_template = TPMT_PUBLIC(
    nameAlg = TPM2_ALG_SHA256,
    objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_USERWITHAUTH \
        | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_FIXEDTPM \
        | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN,
)

def get_ak_template(keytype):
    keytype = keytype.lower()
    pub = ak_base_template
    if keytype == 'rsa':
        pub.type = TPM2_ALG_RSA
        pub.parameters.rsaDetail.symmetric = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG_NULL)
        pub.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSAPSS
        pub.parameters.rsaDetail.scheme.details.anySig.hashAlg = TPM2_ALG_SHA256
        pub.parameters.rsaDetail.keyBits = 2048
        pub.parameters.rsaDetail.exponent = 0
        pub.unique.rsa.size = 256
    elif keytype == 'ecc':
        pub.type = TPM2_ALG_ECC
        pub.parameters.eccDetail.symmetric = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG_NULL)
        pub.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA
        pub.parameters.eccDetail.scheme.details.anySig.hashAlg = TPM2_ALG_SHA256
        pub.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256
        pub.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL
        pub.unique.ecc.x.size = 32
        pub.unique.ecc.y.size = 32
    else:
        # fail here
        return None

    return TPM2B_PUBLIC(size=0, publicArea=pub)


def create_ak(ectx, parent, keytype):
    template = get_ak_template(keytype)
    ek_auth = ek_session(ectx)
    insens = TPM2B_SENSITIVE_CREATE()
    outsideinfo = TPM2B_DATA()
    creationpcr = TPML_PCR_SELECTION()
    with ExitStack() as stack:
        private = stack.enter_context(TPM2B_PRIVATE_PTR_PTR())
        public = stack.enter_context(TPM2B_PUBLIC_PTR_PTR())
        creationdata = stack.enter_context(TPM2B_CREATION_DATA_PTR_PTR())
        creationhash = stack.enter_context(TPM2B_DIGEST_PTR_PTR())
        creationtkt = stack.enter_context(TPMT_TK_CREATION_PTR_PTR())
        ectx.Create(
            parent,
            ek_auth,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            insens,
            template,
            outsideinfo,
            creationpcr,
            private,
            public,
            creationdata,
            creationhash,
            creationtkt,
        )
        return (private.value, public.value)
