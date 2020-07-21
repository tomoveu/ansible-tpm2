# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later

from contextlib import ExitStack
from tpm2_pytss.esys import ESYSBinding
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
)


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
