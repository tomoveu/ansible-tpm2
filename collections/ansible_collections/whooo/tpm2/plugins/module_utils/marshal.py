# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later


from base64 import b64encode, b64decode
import tpm2_pytss.binding

def marshal(src):
    name = type(src).__name__
    fname = "Tss2_MU_{}_Marshal".format(name)
    mf = getattr(tpm2_pytss.binding, fname, None)
    if mf is None:
        raise Exception("No marshal function found for {}".format(name))
    buf = bytearray(4096) # choose better size here
    _, off = mf(src, buf, 0)
    return bytes(buf[0:off])

def b64marshal(src):
    b = marshal(src)
    return b64encode(b)

def unmarshal(src, dst):
    name = type(dst).__name__
    fname = "Tss2_MU_{}_Unmarshal".format(name)
    uf = getattr(tpm2_pytss.binding, fname, None)
    if uf is None:
        raise Exception("No umarshal function found for {}".format(name))
    _, off = uf(src, 0, dst)
    return off

def b64unmarshal(src, dst):
    bsrc = b64decode(src)
    return unmarshal(bsrc, dst)
