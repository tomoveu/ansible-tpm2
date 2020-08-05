# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later


import os
import json
import secrets
import tempfile
from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from ansible.module_utils._text import to_bytes
from ansible_collections.whooo.tpm2.plugins.module_utils.ak import get_ak_template
from ansible_collections.whooo.tpm2.plugins.module_utils.convert import (
    get_name,
    tpm2_to_crypto_alg,
)
from ansible_collections.whooo.tpm2.plugins.module_utils.compare import compare_public
from ansible_collections.whooo.tpm2.plugins.module_utils.marshal import (
    b64marshal,
    b64unmarshal,
    marshal,
)
from ansible_collections.whooo.tpm2.plugins.module_utils.crypto import (
    create_seed,
    kdfa,
    encrypt,
    hmac,
)
from tpm2_pytss.binding import (
    TPM2B_PUBLIC,
    TPM2B_DIGEST,
    TPM2B_ID_OBJECT,
    TPM2B_ENCRYPTED_SECRET,
    TPM2_RH_ENDORSEMENT,
    TPM2B_PRIVATE,
)

# TODO
# Accept template structure from playbook
class ActionModule(ActionBase):
    def save_ak(self, path, public, private, parent_template):
        d = dict(
            hierarchy=TPM2_RH_ENDORSEMENT,
            parent_template=parent_template,
            public=public,
            private=private,
        )
        dirn = os.path.dirname(path)
        tmp = tempfile.NamedTemporaryFile(dir=dirn, suffix='.json', delete=False, mode='w+')
        json.dump(d, tmp)
        tmp.close()
        os.rename(tmp.name, path)

    def run(self, tmp=None, task_vars=None):
        ek_templ_path = self._task.args.get('ek_template')
        ek_public_path = self._task.args.get('ek_public')
        ak_path = self._task.args.get('ak')
        keytype = self._task.args.get('type', 'rsa')
        templ = self._task.args.get('template')
        
        if not ek_templ_path:
            raise AnsibleError('ek template is required')
        elif not os.path.isfile(ek_templ_path):
            raise AnsibleError("ek template {} is not a regular file".format(ek_templ))

        if not templ:
            template = get_ak_template(keytype)
            b64templ = b64marshal(template)
        else:
            # parse template here
            pass
        
        # check AK files here
        if ak_path and os.path.lexists(ak_path):
            return dict(changed=False)
        
        with open(ek_templ_path, 'r') as f:
            ek_templ = f.read()

        with open(ek_public_path, 'r') as f:
            ek_public64 = f.read()
        
        ek_public = TPM2B_PUBLIC()
        b64unmarshal(ek_public64, ek_public)

        margs = dict(
            ek_template=ek_templ,
            ak_template=b64templ.decode('ascii'),
        )

        mres = self._execute_module(
            module_name='tpm2_generate_ak',
            module_args=margs,
            task_vars=task_vars
        )

        if mres.get('failed', False):
            raise AnsibleError("failed to generate AK: {}".format(mres.get('msg')))

        b64private = mres.get('private')
        b64public = mres.get('public')
        public = TPM2B_PUBLIC()
        b64unmarshal(b64public, public)
        try:
            compare_public(public, template)
        except Exception as e:
            raise AnsibleError("AK key does not match template: {}".format(e))
        private = TPM2B_PRIVATE()
        b64unmarshal(b64private, private)
        
        cv = secrets.token_bytes(32)
        template.publicArea.unique = public.publicArea.unique
        ak_name = get_name(template.publicArea)

        halg = tpm2_to_crypto_alg(ek_public.publicArea.nameAlg)
        seed, enc_seed = create_seed(ek_public, b"IDENTITY\x00")
        
        symbits = ek_public.publicArea.parameters.asymDetail.symmetric.keyBits.sym
        symkey = kdfa(halg, seed, b"STORAGE", ak_name, b"", symbits)
        enc_cred = encrypt(symkey, cv)

        hmackey = kdfa(halg, seed, b"INTEGRITY", b"", b"", halg.digest_size * 8)
        outerhmac = hmac(halg, hmackey, enc_cred, ak_name)
        hmac2b = TPM2B_DIGEST(buffer=outerhmac)
        hmacdata = marshal(hmac2b)
        
        credblob = TPM2B_ID_OBJECT(credential=hmacdata + enc_cred)
        secret = TPM2B_ENCRYPTED_SECRET(secret=enc_seed)

        b64credblob = b64marshal(credblob).decode('ascii')
        b64secret = b64marshal(secret).decode('ascii')
        
        margs = dict(
            ek_template=ek_templ,
            ak_public=b64public,
            ak_private=b64private,
            credblob=b64credblob,
            secret=b64secret
        )

        mres = self._execute_module(
            module_name='tpm2_activatecred',
            module_args=margs,
            task_vars=task_vars
        )

        rcv = to_bytes(mres.get('cv'))
        if rcv != cv:
            raise AnsibleError('cv nonce does not match')

        if ak_path:
            self.save_ak(ak_path, b64public, b64private, ek_templ)
        
        return dict(changed=True, public=b64public, private=b64private)
