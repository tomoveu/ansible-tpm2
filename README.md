# ansible-tpm2
Ansible role for TPM 2.0 tasks

PoC for working with TPM 2.0 using ansible.
Can currently only fetch EK certficates and keys and verify them.
See example.yaml

Requires tpm2-pytss >= 0.1.8 locally and on the remote host as well as pyca and the openssl cli tool locally.
