# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import tempfile
import subprocess
from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from ansible.module_utils._text import to_bytes
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from ansible_collections.whooo.tpm2.plugins.module_utils.marshal import b64unmarshal
from ansible_collections.whooo.tpm2.plugins.module_utils.convert import public_to_crypto
from tpm2_pytss.binding import TPM2B_PUBLIC

# TODO
# Verify certificate attributes?
# Store EK cert?
class ActionModule(ActionBase):
    def compare_rsa_cert_key(self, cnums, knums):
        if cnums.e != knums.e:
            raise AnsibleError('RSA exponent does not match')
        elif cnums.n != knums.n:
            raise AnsibleError('RSA modulus does not match')

    def compare_ecc_cert_key(self, cnums, knums):
        if type(cnums.curve) != type(knums.curve):
            raise AnsibleError('ECC curve does not match')
        elif cnums.x != knums.x:
            raise AnsibleError('ECC x component does not match')
        elif cnums.y != knums.y:
            raise AnsibleError('ECC y component does not match')
        
    def compare_cert_key(self, cert, key):
        ckey = cert.public_key()
        if not type(ckey) is type(key):
            raise AnsibleError('certificate and public key are not of the same type')
        cnums = ckey.public_numbers()
        knums = key.public_numbers()
        if isinstance(key, RSAPublicKey):
            self.compare_rsa_cert_key(cnums, knums)
        elif isinstance(key, EllipticCurvePublicKey):
            self.compare_ecc_cert_key(cnums, knums)
        else:
            raise AnsibleError('unsupported key type')

    def verify_cert(self, capath, pem, crlpath=None):
        # this is a bit ugly, but better the writing my own verifier
        tmp = tempfile.NamedTemporaryFile(prefix='tpm2verify', suffix='.pem')
        tmp.write(pem)
        tmp.flush()
        verify_args = ['openssl', 'verify', '-CAfile', capath]
        if crlpath:
            verify_args = verify_args + ['-CRLfile', crlpath]
        verify_args.append(tmp.name)
        res = subprocess.run(verify_args, capture_output=True)
        tmp.close()
        if res.returncode != 0:
            raise AnsibleError("certificate verification failed: {}".format(res.stderr.decode('utf-8')))
        return res.stdout.decode('utf-8')

    def save_template(self, dst, template, prefix):
        tdir = os.path.dirname(dst)
        tt = tempfile.NamedTemporaryFile(dir=tdir, delete=False)
        tt.write(template)
        tt.close()
        os.rename(tt.name, dst)
    
    def run(self, tmp=None, task_vars=None):
        changed = False
        keytype = self._task.args.get('type', 'rsa')
        templ_index = self._task.args.get('index')
        capath = self._task.args.get('capath')
        crlpath = self._task.args.get('crlpath')
        templpath = self._task.args.get('template_path')
        publicpath = self._task.args.get('public_path')
        if keytype not in ('rsa', 'ecc', 'high'):
            raise AnsibleError("Bad key type: {}".format(keytype))
        elif keytype == 'high' and not templ_index:
            raise AnsibleError('EK template NV index required')
        elif not capath:
            raise AnsibleError('capath is required')
        elif not os.path.isfile(capath):
            raise AnsibleError("capath {} is not a file".format(capath))
        elif crlpath and not os.path.isfile(crlpath):
            raise AnsibleError("crlpath {} is not a file".format(crlpath))

        if templpath and os.path.lexists(templpath):
            return dict()
        
        margs = dict(
            type=keytype,
            index=templ_index,
        )
        mres = self._execute_module(
            module_name='tpm2_get_certificate',
            module_args=margs,
            task_vars=task_vars
        )

        if mres.get('failed', False) == True:
            raise AnsibleError("failed to fetch EK: {}".format(mres.get('msg')))

        pem = to_bytes(mres.get('cert'))
        cert = load_pem_x509_certificate(pem, default_backend())

        public = TPM2B_PUBLIC()
        b64unmarshal(mres.get('public'), public)
        key = public_to_crypto(public)

        self.compare_cert_key(cert, key)

        self.verify_cert(capath, pem, crlpath)

        template = to_bytes(mres.get('template'))
        if templpath:
            self.save_template(templpath, template, 'ek_template')
            changed = True

        p = to_bytes(mres.get('public'))
        if publicpath:
            self.save_template(publicpath, p, 'ek_public')
            changed = True
            
        return dict(changed=changed, certificat=pem, template=template, public=p)
