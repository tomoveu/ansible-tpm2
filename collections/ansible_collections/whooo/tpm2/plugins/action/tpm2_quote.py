#!/usr/bin/python3
# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later


import json
import secrets
from base64 import b64encode, b16decode
from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash
from ansible_collections.whooo.tpm2.plugins.module_utils.convert import (
    buffer_to_bytes,
    tpm2_to_crypto_alg,
)
from ansible_collections.whooo.tpm2.plugins.module_utils.crypto import (
    verify_signature,
)
from ansible_collections.whooo.tpm2.plugins.module_utils.marshal import (
    b64unmarshal,
    unmarshal
)
from tpm2_pytss.binding import (
    TPM2B_ATTEST,
    TPMT_SIGNATURE,
    TPM2B_PUBLIC,
    TPMS_ATTEST,
    TPM2_ST_ATTEST_QUOTE,
    TPMS_PCR_SELECTION_ARRAY,
    TPM2_ALG_SHA256,
    BYTE_ARRAY,
)

TPM2_GENERATED_VALUE = 0xff544347 # needed due to endianess issues

class ActionModule(ActionBase):
    def check_attest(self, attest, qdata):
        if not attest.magic == TPM2_GENERATED_VALUE:
            raise Exception('TPM2 magic does not match')
        if not attest.type == TPM2_ST_ATTEST_QUOTE:
            raise Exception('TPM2 attest type does not match')
        adata = buffer_to_bytes(attest.extraData)
        if not qdata == adata:
            raise Exception('TPM2 attest extraData does not match qualifyingData')

    def check_pcrs(self, pcrs, qinfo, halg):
        if not qinfo.pcrSelect.count == 1:
            raise Exception('too many PCR selections')
        parray = TPMS_PCR_SELECTION_ARRAY.frompointer(qinfo.pcrSelect.pcrSelections)
        pcrsel = parray[0]
        if not pcrsel.hash == TPM2_ALG_SHA256: # FIXME
            raise Exception('PCR bank does not match')
        h = Hash(halg(), default_backend())
        sel = 0
        for ps, v in pcrs.items():
            # FIXME, check keys
            p = int(ps)
            sel = sel | (1 << p)
            pv = b16decode(v)
            h.update(pv)
        dig = h.finalize()
        selb = sel.to_bytes(pcrsel.sizeofSelect, 'big')
        qselb = bytearray()
        qsarray = BYTE_ARRAY.frompointer(pcrsel.pcrSelect)
        for i in range(0, pcrsel.sizeofSelect):
            qselb.append(qsarray[i])
        qselb = bytes(qselb)
        if not qselb == selb:
            raise Exception('PCR selection does not match')
        qdig = buffer_to_bytes(qinfo.pcrDigest)
        if not dig == qdig:
            raise Exception('PCR digest does not match')

    def run(self, tmp=None, task_vars=None):
        ak_path = self._task.args.get('ak')
        with open(ak_path) as f:
            keys = json.load(f)
        ak_public = keys.get('public')
        ak_private = keys.get('private')
        ek_template = keys.get('parent_template')

        qdata = secrets.token_bytes(32)
        
        margs = dict(
            qdata=b64encode(qdata).decode('ascii'),
            ak_public=ak_public,
            ak_private=ak_private,
            ek_template=ek_template,
        )

        mres = self._execute_module(
            module_name='tpm2_quote',
            module_args=margs,
            task_vars=task_vars,
        )

        b64attest = mres.get('attest')
        attest = TPM2B_ATTEST()
        b64unmarshal(b64attest, attest)
        attb = buffer_to_bytes(attest, 'attestationData')

        b64sig = mres.get('signature')
        sig = TPMT_SIGNATURE()
        b64unmarshal(b64sig, sig)

        public = TPM2B_PUBLIC()
        b64unmarshal(ak_public, public)

        verify_signature(sig, public, attb)

        att = TPMS_ATTEST()
        unmarshal(attb, att)
        self.check_attest(att, qdata)

        pcrs = mres.get('pcrs')
        h = public.publicArea.parameters.asymDetail.scheme.details.anySig.hashAlg
        halg = tpm2_to_crypto_alg(h)
        self.check_pcrs(pcrs, att.attested.quote, halg)

        # add clock info here?
        results = dict(
            pcrs=pcrs,
            firmware_version=att.firmwareVersion,
        )
        return results
