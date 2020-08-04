# Copyright (c) 2020 by Erik Larsson
# SPDX-License-Identifier: GPL-3.0-or-later


from contextlib import ExitStack
from tpm2_pytss import tcti
from tpm2_pytss.esys import ESYS
from ansible_collections.whooo.tpm2.plugins.module_utils.marshal import (
    b64unmarshal,
)
from tpm2_pytss.binding import (
    ESYS_TR_NONE,
    ESYS_TR_PASSWORD,
    TPMS_CONTEXT,
    TPM2B_PUBLIC,
    TPM2B_PRIVATE,
    TPM2B_SENSITIVE,
    TPM2B_SENSITIVE_CREATE,
    TPM2B_DATA,
    TPML_PCR_SELECTION,
    TPM2B_PUBLIC_PTR_PTR,
    TPM2B_CREATION_DATA_PTR_PTR,
    TPM2B_DIGEST_PTR_PTR,
    TPMT_TK_CREATION_PTR_PTR,
)

def setup_tcti(name, conf):
    t = tcti.TCTI.load(name)
    return t(config=conf)

def setup_ectx(tctx):
    stack = ExitStack()
    esys = ESYS()
    stctx = stack.enter_context(tctx)
    ectx = stack.enter_context(esys(stctx))
    return ectx

def load_key_template(ectx, b64template, hierarchy):
    template = TPM2B_PUBLIC()
    b64unmarshal(b64template, template)
    insensitive = TPM2B_SENSITIVE_CREATE(size=0)
    outsideinfo = TPM2B_DATA(size=0)
    creationpcr = TPML_PCR_SELECTION(count=0)
    obj = ectx.ESYS_TR_PTR()
    with ExitStack() as stack:
        outpublic = stack.enter_context(TPM2B_PUBLIC_PTR_PTR())
        creationdata = stack.enter_context(TPM2B_CREATION_DATA_PTR_PTR())
        creationhash = stack.enter_context(TPM2B_DIGEST_PTR_PTR())
        creationtkt = stack.enter_context(TPMT_TK_CREATION_PTR_PTR())
        ectx.CreatePrimary(
            hierarchy,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            insensitive,
            template,
            outsideinfo,
            creationpcr,
            obj,
            outpublic,
            creationdata,
            creationhash,
            creationtkt,
        )
    return obj.value()

def load_key_context(ectx, b64context):
    ctx = TPMS_CONTEXT()
    b64unmarshal(b64context, ctx)
    obj = ectx.ESYS_TR_PTR()
    self.ectx.ContextLoad(
        ctx,
        obj,
    )
    return obj.value()

def load_key_handle(ectx, handle):
    # check range here
    obj = ectx.ESYS_TR_PTR()
    ectx.TR_FromTPMPublic(
        handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        obj
    )
    return obj.value()

def load_key_pair(ectx, b64public, b64private, parent, parentauth):
    public = TPM2B_PUBLIC()
    b64unmarshal(b64public, public)
    private = TPM2B_PRIVATE()
    b64unmarshal(b64private, private)
    obj = ectx.ESYS_TR_PTR()
    ectx.Load(
        parent,
        parentauth,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        private,
        public,
        obj
    )
    return obj.value()

class TPM2Module():
    def load_primary(self, name, params, hierarchy):
        obj = None
        context = params.get("{}_{}".format(name, 'context'))
        handle = params.get("{}_{}".format(name, 'handle'))
        template = params.get("{}_{}".format(name, 'template'))
        if context:
            obj = load_key_context(self.ectx, context)
        elif handle:
            if isinstance(handle, str):
                handle = int(handle, base=0)
            obj = load_key_handle(self.ectx, handle)
        elif template:
            obj = load_key_template(self.ectx, template, hierarchy)
        else:
            raise Exception("key {} not in params".format(name))
        return obj

    def load_key(self, name, params, parent=None, parentauth=ESYS_TR_PASSWORD):
        obj = None
        context = params.get("{}_{}".format(name, 'context'))
        handle = params.get("{}_{}".format(name, 'handle'))
        public = params.get("{}_{}".format(name, 'public'))
        private = params.get("{}_{}".format(name, 'private'))
        if context:
            obj = load_key_context(self.ectx, context)
        elif handle:
            if isinstance(handle, str):
                handle = int(handle, base=0)
            obj = load_key_handle(self.ectx, handle)
        elif public and private:
            obj = load_key_pair(self.ectx, public, private, parent, parentauth)
        else:
            raise Exception("key {} not in params".format(name))
        return obj

    def __init__(self, module):
        tctiname = module.params.get('tctiname', 'device') #FIXME
        tcticonf = module.params.get('tcticonf')
        tctx = None
        # fix default tcti, regardless of .so-symlink
        if tctiname:
            tctx = setup_tcti(tctiname, tcticonf)
        self.ectx = setup_ectx(tctx)
