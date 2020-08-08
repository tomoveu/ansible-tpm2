# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later


from base64 import b16decode, b16encode
from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from ansible_collections.whooo.tpm2.plugins.module_utils.convert import (
    tpm2_to_crypto_alg,
)
from ansible_collections.whooo.tpm2.plugins.module_utils.crypto import (
    extend,
)

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        pcrdigs = self._task.args.get('pcr_digests')
        pcrs = self._task.args.get('pcrs', [0,1,2,3,4,5,6,7])
        alg = self._task.args.get('alg', 0x0b)
        if not pcrdigs:
            raise AnsibleError('pcr_digests is required')

        halg = tpm2_to_crypto_alg(alg)
        digsize = halg.digest_size

        qdigs = dict()
        digs = dict()
        for k in pcrdigs:
            p = int(k)
            digs[p] = b"\x00" * digsize
            if p >= 17 and p <= 22: # Assume PC client profile
                digs[p] = b"\xFF" * digsize
            qdigs[p] = b16decode(pcrdigs[k])

        mres = self._execute_module(
            module_name='tpm2_efi_eventlog',
            module_args=dict(
                alg=alg,
            ),
            task_vars=task_vars,
        )

        for e in mres.get('entries', []):
            p = e['PCR']
            d = e['digest']
            digest = b16decode(d)
            digs[p] = extend(halg, digs[p], digest)

        failed = []
        for p in pcrs:
            if digs[p] != qdigs[p]:
                failed.append(p)

        if len(failed) > 0:
            fstr = ", ".join(failed)
            raise AnsibleError("PCRs {} does not match".format(fstr))
            
        d16 = dict()
        for k in pcrs:
           sk = "{:02d}".format(k)
           d16[sk] = b16encode(digs[k])

        results = dict(
            pcrs=d16,
            entries=mres.get('entries'),
            uintsize=mres.get('uintsize'),
        )
        return results
