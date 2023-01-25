from SnmpLibrary.traps import _generic_trap_filter, _trap_to_dict

from pysnmp.proto.api import v1, decodeMessageVersion, protoVersion1
from pyasn1.codec.ber import decoder


def test_decode_v1_trap(v1_trap_example):
    assert decodeMessageVersion(v1_trap_example) == protoVersion1
    req, msg = decoder.decode(v1_trap_example, asn1Spec=v1.Message())
    pdu = v1.apiMessage.getPDU(req)
    d = _trap_to_dict(pdu, protoVersion1, v1)
    assert d == {"1.11.12.13.14.15": "teststring"}
