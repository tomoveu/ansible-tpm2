# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess
import tempfile
import os
from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from ansible.module_utils._text import to_bytes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from tpm2_pytss.binding import TPM2B_PUBLIC
from ansible_collections.whooo.tpm2.plugins.module_utils.convert import public_to_crypto
from ansible_collections.whooo.tpm2.plugins.module_utils.marshal import b64unmarshal

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

    def verify_cert(self, cafile, pem, crlfile=None):
        # this is a bit ugly, but better the writing my own verifier
        tmp = tempfile.NamedTemporaryFile(prefix='tpm2verify', suffix='.pem')
        tmp.write(pem)
        tmp.flush()
        verify_args = ['openssl', 'verify', '-CAfile', cafile]
        if crlfile:
            verify_args.append('-CRLfile')
            verify_args.append(crlfile)
        verify_args.append(tmp.name)
        res = subprocess.run(verify_args, capture_output=True)
        tmp.close()
        if res.returncode != 0:
            raise AnsibleError("certificate verification failed: {}".format(res.stderr.decode('utf-8')))
        return res.stdout.decode('utf-8')

    def run(self, tmp=None, task_vars=None):
        pem = self._task.args.get('cert')
        b64public = self._task.args.get('public')
        cafile = self._task.args.get('cafile', 'tpm2-ca.pem')
        crlfile = self._task.args.get('crlfile')

        try:
            pem = to_bytes(pem)
            cert = x509.load_pem_x509_certificate(pem, default_backend())
        except Exception as e:
            raise AnsibleError("failed to load certificate: {}".format(e))

        try:
            public = TPM2B_PUBLIC()
            b64unmarshal(b64public, public)
        except Exception as e:
            raise AnsibleError("failed to unmarshal public part: {}".format(e))

        key = public_to_crypto(public)

        self.compare_cert_key(cert, key)

        out = self.verify_cert(cafile, pem, crlfile=crlfile)
        
        return dict(openssl_out=out)
