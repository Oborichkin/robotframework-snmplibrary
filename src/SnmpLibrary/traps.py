# Copyright 2015 Kontron Europe GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import logging
import warnings
import functools

import robot.utils

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
    from pysnmp.carrier.asynsock.dgram import udp
    from pysnmp.proto.api import decodeMessageVersion, v2c, v1, protoModules, protoVersion1, protoVersion2c
    from pyasn1.codec.ber import decoder

from . import utils

logger = logging.getLogger(__name__)


def _generic_trap_filter(domain, sock, pdu, **kwargs):
    snmpTrapOID = (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)
    if 'host' in kwargs and kwargs['host']:
        if sock[0] != kwargs['host']:
            return False

    if pdu.isSameTypeWith(v2c.TrapPDU()):
        for oid, val in v2c.apiPDU.getVarBindList(pdu):
            if 'oid' in kwargs and kwargs['oid']:
                if oid == snmpTrapOID:
                    if val[0][0][2] != v2c.ObjectIdentifier(kwargs['oid']):
                        return False
    elif pdu.isSameTypeWith(v1.TrapPDU()):
        logger.warning("No OID filtering for v1 Traps! Skipping")
    else:
        return False

    return True


def _trap_to_dict(pdu, version, pMod):
    if version == protoVersion1:
        var_binds = pMod.apiTrapPDU.getVarBinds(pdu)
    else:
        var_binds = pMod.apiPDU.getVarBinds(pdu)

    return {oid.prettyPrint(): val.prettyPrint() for oid, val in  var_binds}


def _trap_receiver(trap_filter, host, port, timeout):
    started = time.time()
    result = None

    def _trap_timer_cb(now):
        if now - started > timeout:
            raise AssertionError('No matching trap received in %s.' %
                                 robot.utils.secs_to_timestr(timeout))

    def _trap_receiver_cb(transport, domain, sock, msg):
        nonlocal result
        ver = int(decodeMessageVersion(msg))

        if ver in protoModules:
            pMod = protoModules[ver]
        else:
            raise RuntimeError('Unsupported SNMP version %s.' % ver)

        req, msg = decoder.decode(msg, asn1Spec=pMod.Message())
        pdu = pMod.apiMessage.getPDU(req)

        # Stop the receiver if the trap we are looking for was received.
        if trap_filter(domain, sock, pdu):
            result = _trap_to_dict(pdu, ver, pMod)
            transport.jobFinished(1)

    dispatcher = AsynsockDispatcher()
    dispatcher.registerRecvCbFun(_trap_receiver_cb)
    dispatcher.registerTimerCbFun(_trap_timer_cb)

    transport = udp.UdpSocketTransport().openServerMode((host, port))
    dispatcher.registerTransport(udp.domainName, transport)

    # we'll never finish, except through an exception
    dispatcher.jobStarted(1)

    try:
        dispatcher.runDispatcher()
        return result
    finally:
        dispatcher.closeDispatcher()


class _Traps:
    def __init__(self):
        self._trap_filters = dict()

    def new_trap_filter(self, name, host=None, oid=None):
        """Defines a new SNMP trap filter.

        At the moment, you can only filter on the sending host and on the trap
        OID.
        """
        trap_filter = functools.partial(_generic_trap_filter,
                                        host=host,
                                        oid=utils.parse_oid(oid))
        self._trap_filters[name] = trap_filter

    def wait_until_trap_is_received(self, trap_filter_name, timeout=5.0,
                                    host='0.0.0.0', port=1620):
        """Wait until the first matching trap is received."""
        if trap_filter_name not in self._trap_filters:
            raise RuntimeError('Trap filter "%s" not found.' % trap_filter_name)

        trap_filter = self._trap_filters[trap_filter_name]
        timeout = robot.utils.timestr_to_secs(timeout)

        return _trap_receiver(trap_filter, host, port, timeout)
