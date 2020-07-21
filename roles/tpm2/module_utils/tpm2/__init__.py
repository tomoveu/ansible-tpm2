# Copyright (c) 2020 by Erik Larsson 
# SPDX-License-Identifier: GPL-3.0-or-later

from tpm2_pytss import tcti
from tpm2_pytss.esys import ESYS


def esysctx(stack, tctiname="default", tcticonf=""):
    mtcti = tcti.TCTI.load(tctiname)
    esys = ESYS()
    tctx = stack.enter_context(mtcti(config=tcticonf))
    ectx = stack.enter_context(esys(tctx))
    return ectx

