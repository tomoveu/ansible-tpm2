# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later

from contextlib import ExitStack
from tpm2_pytss import tcti
from tpm2_pytss.esys import ESYS, ESYSBinding
from tpm2_pytss.binding import (
    ESYS_TR_NONE,
    ESYS_TR_PASSWORD,
    TPM2B_NV_PUBLIC_PTR_PTR,
    TPM2B_NAME_PTR_PTR,
    TPM2B_MAX_NV_BUFFER_PTR_PTR,
    TPMI_YES_NO_PTR,
    TPMS_CAPABILITY_DATA_PTR_PTR,
    TPM2_CAP_HANDLES,
    TPM2_HR_NV_INDEX,
    UINT32_ARRAY,
    TPM2_PT_NV_INDEX_MAX,
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
    TPM2B_PUBLIC
)


def esysctx(stack, tctiname="default", tcticonf=""):
    mtcti = tcti.TCTI.load(tctiname)
    esys = ESYS()
    tctx = stack.enter_context(mtcti(config=tcticonf))
    ectx = stack.enter_context(esys(tctx))
    return ectx

def appendba(dst, src, size):
    b = ESYSBinding.ByteArray.frompointer(src)
    for i in range(0, size):
        dst.append(b[i])

def frompublic(ectx, handle):
    obj = ectx.ESYS_TR_PTR()
    ectx.TR_FromTPMPublic(
        handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        obj
    )
    return obj.value()

def getnvpub(ectx, handle):
    with ExitStack() as stack:
        nvpub = stack.enter_context(TPM2B_NV_PUBLIC_PTR_PTR())
        nvname = stack.enter_context(TPM2B_NAME_PTR_PTR())
        ectx.NV_ReadPublic(
            handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            nvpub,
            nvname
        )
        return nvpub.value.nvPublic

def nvreadall(ectx, index):
    nvh = frompublic(ectx, index)
    nvpub = getnvpub(ectx, nvh)

    data = bytearray()
    count = int(nvpub.dataSize / 0x300) + ((nvpub.dataSize % 0x300) > 0)
    offset = 0
    with ExitStack() as stack:
        for i in range(0, count):
            size = 0x300
            if (nvpub.dataSize - offset) < 0x300:
                size = nvpub.dataSize - offset
            nvdata = stack.enter_context(TPM2B_MAX_NV_BUFFER_PTR_PTR())
            ectx.NV_Read(
                nvh,
                nvh,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                size,
                offset,
                nvdata
            )
            offset = offset + size
            appendba(data, nvdata.value.buffer, nvdata.value.size)
    return bytes(data)

def getnvindices(ectx):
    indices = list()
    with ExitStack() as stack:
        more = stack.enter_context(TPMI_YES_NO_PTR(True))
        while more.value == True:
            data = stack.enter_context(TPMS_CAPABILITY_DATA_PTR_PTR())
            ectx.GetCapability(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                TPM2_CAP_HANDLES,
                TPM2_HR_NV_INDEX,
                TPM2_PT_NV_INDEX_MAX,
                more,
                data,
            )
            handles = data.value.data.handles
            harray = UINT32_ARRAY.frompointer(handles.handle)

            for i in range(0, handles.count):
                index = harray[i]
                indices.append(index)
    return indices

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
