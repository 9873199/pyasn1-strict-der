#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.codec.ber import decoder as berDecoder
from pyasn1.codec.cer import decoder as cerDecoder
from pyasn1.codec.der import decoder
from pyasn1.error import PyAsn1Error
from pyasn1.error import SubstrateUnderrunError


def _assertRejected(testcase, substrate, message, **options):
    try:
        decoder.decode(substrate, strictCanonical=True, **options)
    except PyAsn1Error:
        pass
    else:
        testcase.fail('%s tolerated' % message)


class NonBlockingStream(io.BytesIO):
    def read(self, size=-1):
        chunk = io.BytesIO.read(self, size)
        if not chunk and size:
            return None
        return chunk


class StrictIntegerDecoderTestCase(BaseTestCase):
    def testMinimalLegalEncodings(self):
        for substrate, expected in (
                (b'\x02\x01\x00', 0),       # zero is a single 0x00
                (b'\x02\x01\x01', 1),       # task's canonical example
                (b'\x02\x01\x7f', 127),
                (b'\x02\x02\x00\x80', 128),
                (b'\x02\x01\x80', -128),    # minimal negative boundary
                (b'\x02\x02\x80\x00', -32768),
                (b'\x02\x01\xff', -1)):
            value, rest = decoder.decode(substrate, strictCanonical=True)
            assert value == expected
            assert rest == b''

    def testSuperfluousSignExtensionRejected(self):
        # 02 02 00 01 decodes to 1 but is not the canonical encoding
        _assertRejected(self, b'\x02\x02\x00\x01',
                        'non-minimal positive INTEGER')
        _assertRejected(self, b'\x02\x02\xff\x80',
                        'non-minimal negative INTEGER')
        # same rule for ENUMERATED (tag 0x0A)
        _assertRejected(self, b'\x0a\x02\x00\x01',
                        'non-minimal ENUMERATED')
        _assertRejected(self, b'\x0a\x02\xff\x80',
                        'non-minimal negative ENUMERATED')

    def testEmptyContentsRejected(self):
        _assertRejected(self, b'\x02\x00', 'empty INTEGER contents')
        _assertRejected(self, b'\x0a\x00', 'empty ENUMERATED contents')

    def testLenientDefaultKept(self):
        value, rest = decoder.decode(b'\x02\x02\x00\x01')
        assert value == 1 and rest == b''
        value, rest = decoder.decode(b'\x02\x00')
        assert value == 0 and rest == b''
        value, rest = decoder.decode(
            b'\x02\x02\x00\x01', strictCanonical=False)
        assert value == 1


class StrictTagAndLengthDecoderTestCase(BaseTestCase):
    def testMinimalLegalLengths(self):
        decoder.decode(b'\x04\x7f' + b'A' * 127, strictCanonical=True)
        decoder.decode(b'\x04\x81\x80' + b'A' * 128, strictCanonical=True)

    def testNonMinimalLengthRejected(self):
        # one long-form octet encoding a length that fits the short form
        _assertRejected(self, b'\x02\x81\x01\x01',
                        'long-form length for a one-octet value')
        # leading zero octet in the long form
        _assertRejected(self, b'\x02\x82\x00\x01\x01',
                        'length with superfluous leading zero')

    def testMinimalLegalHighTagNumber(self):
        spec = univ.Integer().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 31))
        value, rest = decoder.decode(
            b'\x9f\x1f\x01\x01', asn1Spec=spec, strictCanonical=True)
        assert value == 1 and rest == b''

    def testNonMinimalTagRejected(self):
        spec = univ.Integer().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 30))
        # tag 30 must use the low-tag-number form (0x9e), not 0x9f 0x1e
        _assertRejected(self, b'\x9f\x1e\x01\x01',
                        'low tag number in high-tag form', asn1Spec=spec)
        # superfluous 0x80 leading continuation octet
        _assertRejected(self, b'\x9f\x80\x1e\x01\x01',
                        'tag with leading zero continuation', asn1Spec=spec)


class StrictBooleanDecoderTestCase(BaseTestCase):
    def testCanonicalBooleansAccepted(self):
        value, _ = decoder.decode(b'\x01\x01\xff', strictCanonical=True)
        assert value == True
        value, _ = decoder.decode(b'\x01\x01\x00', strictCanonical=True)
        assert value == False

    def testNonCanonicalBooleanRejectedOnSchemaPath(self):
        # the schema-driven TYPE_MAP path inherits BER's lenient
        # Boolean decoder; strictCanonical must close that gap
        _assertRejected(self, b'\x01\x01\x01',
                        'Boolean 0x01 under asn1Spec',
                        asn1Spec=univ.Boolean())
        _assertRejected(self, b'\x01\x02\x00\x00',
                        'two-octet Boolean under asn1Spec',
                        asn1Spec=univ.Boolean())

    def testLenientSchemaPathKept(self):
        value, _ = decoder.decode(b'\x01\x01\x01', asn1Spec=univ.Boolean())
        assert value == True


class StrictBitStringDecoderTestCase(BaseTestCase):
    def testCanonicalBitStringsAccepted(self):
        decoder.decode(b'\x03\x01\x00', strictCanonical=True)
        decoder.decode(b'\x03\x02\x01\x80', strictCanonical=True)
        decoder.decode(b'\x03\x03\x03\xff\xf8', strictCanonical=True)
        # a 7-bit all-zero string is a legal non-empty BIT STRING
        decoder.decode(b'\x03\x02\x01\x00', strictCanonical=True)

    def testIllegalEmptyBitStringRejected(self):
        _assertRejected(self, b'\x03\x01\x01',
                        'empty BIT STRING with non-zero unused bits')

    def testNonZeroUnusedTrailingBitsRejected(self):
        _assertRejected(self, b'\x03\x02\x01\x41',
                        'non-zero unused trailing bit')
        _assertRejected(self, b'\x03\x03\x03\xff\xf1',
                        'non-zero unused trailing bits')


class StrictConstructedStringDecoderTestCase(BaseTestCase):
    def testConstructedOctetStringRejectedUnderSchema(self):
        spec = univ.OctetString()
        # without the option, the schema path stays permissive
        value, _ = decoder.decode(
            b'\x24\x06\x04\x01a\x04\x01b', asn1Spec=spec)
        assert value == b'ab'
        _assertRejected(self, b'\x24\x06\x04\x01a\x04\x01b',
                        'constructed OCTET STRING under asn1Spec',
                        asn1Spec=spec)

    def testConstructedBitStringRejectedUnderSchema(self):
        spec = univ.BitString()
        _assertRejected(
            self, b'\x23\x08\x03\x02\x03\x10\x03\x02\x00\xa5',
            'constructed BIT STRING under asn1Spec', asn1Spec=spec)

    def testIndefiniteLengthStillRejected(self):
        _assertRejected(self,
                        bytes((36, 128, 4, 15, 81, 0, 0)),
                        'indefinite length under strictCanonical')


class StrictSetOrderingDecoderTestCase(BaseTestCase):
    def testSetOfAscendingEncodingOrder(self):
        value, rest = decoder.decode(
            b'\x31\x06\x02\x01\x01\x02\x01\x02', strictCanonical=True)
        assert list(value) == [1, 2] and rest == b''
        # equal encodings are allowed
        decoder.decode(b'\x31\x06\x02\x01\x01\x02\x01\x01',
                       strictCanonical=True)
        # ordering compares the complete encoding, so the shorter
        # element sorts first even when its tag octets are a prefix
        decoder.decode(
            b'\x31\x07\x02\x01\x01\x02\x02\x00\x80',
            strictCanonical=True)

    def testSetOfMisorderRejected(self):
        _assertRejected(self, b'\x31\x06\x02\x01\x02\x02\x01\x01',
                        'unsorted SET OF')
        _assertRejected(self, b'\x31\x07\x02\x02\x00\x80\x02\x01\x01',
                        'long SET OF element before short one')

    def testSetOfMisorderRejectedUnderSchema(self):
        spec = univ.SetOf(componentType=univ.Integer())
        _assertRejected(self, b'\x31\x06\x02\x01\x02\x02\x01\x01',
                        'unsorted SET OF under asn1Spec', asn1Spec=spec)

    def testSetUsesTagOrderNotEncodingOrder(self):
        spec = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('b', univ.Boolean()),
            namedtype.NamedType('i', univ.Integer())))
        # BOOLEAN (universal tag 1) before INTEGER (universal tag 2)
        decoder.decode(b'\x31\x06\x01\x01\xff\x02\x01\x01',
                       asn1Spec=spec, strictCanonical=True)
        _assertRejected(self, b'\x31\x06\x02\x01\x01\x01\x01\xff',
                        'SET ordered by value instead of tag',
                        asn1Spec=spec)

    def testSetTagClassOrdering(self):
        spec = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('c', univ.Integer().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
            namedtype.NamedType('i', univ.Integer())))
        decoder.decode(b'\x31\x06\x02\x01\x01\x80\x01\x02',
                       asn1Spec=spec, strictCanonical=True)
        _assertRejected(self, b'\x31\x06\x80\x01\x02\x02\x01\x01',
                        'context tag before universal tag in SET',
                        asn1Spec=spec)

    def testSetHighTagNumberOrdering(self):
        spec = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('a', univ.Integer().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 31))),
            namedtype.NamedType('b', univ.Integer().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 32)))))
        decoder.decode(b'\x31\x08\x9f\x1f\x01\x01\x9f\x20\x01\x02',
                       asn1Spec=spec, strictCanonical=True)
        _assertRejected(self, b'\x31\x08\x9f\x20\x01\x02\x9f\x1f\x01\x01',
                        'high-tag SET components out of order',
                        asn1Spec=spec)

    def testSetHighTagNumberOrderingAcrossLengthBoundary(self):
        # tag 16383 (9f ff 7f) sorts below tag 16384 (9f 81 80 00) by
        # tag number, even though the raw octets order the other way
        spec = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('a', univ.Integer().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 16383))),
            namedtype.NamedType('b', univ.Integer().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 16384)))))
        ordered = b'\x31\x0b\x9f\xff\x7f\x01\x01\x9f\x81\x80\x00\x01\x02'
        value, rest = decoder.decode(
            ordered, asn1Spec=spec, strictCanonical=True)
        assert rest == b''
        _assertRejected(
            self, b'\x31\x0b\x9f\x81\x80\x00\x01\x02\x9f\xff\x7f\x01\x01',
            'SET ordered by raw tag octets instead of tag number',
            asn1Spec=spec)

    def testSequenceOfHasNoOrderingRule(self):
        # SEQUENCE OF keeps the wire order; no ordering check fires
        value, _ = decoder.decode(
            b'\x30\x06\x02\x01\x02\x02\x01\x01', strictCanonical=True)
        assert list(value) == [2, 1]

    def testSequenceHasNoTagOrderingRule(self):
        # BOOLEAN (tag 1) after INTEGER (tag 2) is fine in a SEQUENCE;
        # only SET carries the ascending-tag rule
        value, rest = decoder.decode(
            b'\x30\x06\x02\x01\x01\x01\x01\xff', strictCanonical=True)
        assert rest == b''
        assert value[0] == 1 and value[1] == True

    def testEmptySetOfAccepted(self):
        spec = univ.SetOf(componentType=univ.Integer())
        value, rest = decoder.decode(
            b'\x31\x00', asn1Spec=spec, strictCanonical=True)
        assert len(value) == 0 and rest == b''


class StrictPropagationDecoderTestCase(BaseTestCase):
    def testImplicitTagChecksUnderlyingValue(self):
        spec = univ.Integer().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 0))
        value, _ = decoder.decode(
            b'\x80\x01\x01', asn1Spec=spec, strictCanonical=True)
        assert value == 1
        _assertRejected(self, b'\x80\x02\x00\x01',
                        'non-minimal implicit-tagged INTEGER', asn1Spec=spec)

    def testExplicitWrapperChecksInnerValue(self):
        spec = univ.Integer().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 0))
        decoder.decode(b'\xa0\x03\x02\x01\x01',
                       asn1Spec=spec, strictCanonical=True)
        _assertRejected(self, b'\xa0\x04\x02\x02\x00\x01',
                        'non-minimal INTEGER inside explicit wrapper',
                        asn1Spec=spec)

    def testChoiceChecksChosenValue(self):
        spec = univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('i', univ.Integer())))
        decoder.decode(b'\x02\x01\x01', asn1Spec=spec, strictCanonical=True)
        _assertRejected(self, b'\x02\x02\x00\x01',
                        'non-minimal INTEGER inside CHOICE', asn1Spec=spec)

    def testNestedSequenceChecksChildren(self):
        _assertRejected(self, b'\x30\x04\x02\x02\x00\x01',
                        'non-minimal INTEGER inside SEQUENCE')

    def testOpenTypeCheckedWhenDecoded(self):
        openType = opentype.OpenType(
            'id', {1: univ.Integer(), 2: univ.OctetString()})
        spec = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType('id', univ.Integer()),
            namedtype.NamedType('blob', univ.Any(), openType=openType)))
        good = bytes((48, 6, 2, 1, 1, 2, 1, 12))
        value, _ = decoder.decode(
            good, asn1Spec=spec, decodeOpenTypes=True, strictCanonical=True)
        assert value[1] == 12
        # blob 02 02 00 01 carries a non-minimal INTEGER
        bad = bytes((48, 7, 2, 1, 1, 2, 2, 0, 1))
        _assertRejected(self, bad,
                        'non-minimal INTEGER inside open type',
                        asn1Spec=spec, decodeOpenTypes=True)
        # an opaque ANY blob is not recursively validated
        value, _ = decoder.decode(bad, asn1Spec=spec, strictCanonical=True)
        assert bytes(value[1]) == bytes((2, 2, 0, 1))


class StrictTailDecoderTestCase(BaseTestCase):
    def testOnlyConsumedObjectValidated(self):
        value, tail = decoder.decode(
            b'\x02\x01\x01' + b'\x02\x02\x00\x01', strictCanonical=True)
        assert value == 1
        assert tail == b'\x02\x02\x00\x01'


class StrictStreamingDecoderTestCase(BaseTestCase):
    def _feed(self, substrate, chunkSize, **options):
        stream = NonBlockingStream()
        iterator = iter(decoder.StreamingDecoder(
            stream, strictCanonical=True, **options))
        supplied = 0
        underruns = 0
        while True:
            value = next(iterator)
            if not isinstance(value, SubstrateUnderrunError):
                return value, underruns
            underruns += 1
            position = stream.tell()
            stream.seek(0, io.SEEK_END)
            supplied += stream.write(
                substrate[supplied:supplied + chunkSize])
            stream.seek(position)

    def testValidObjectResumesAcrossReadBoundaries(self):
        substrate = b'\x30\x06\x02\x01\x01\x02\x01\x02'
        value, underruns = self._feed(substrate, 1)
        assert underruns > 1
        assert list(value) == [1, 2]

    def testErrorWaitsForEnoughData(self):
        stream = NonBlockingStream()
        iterator = iter(decoder.StreamingDecoder(
            stream, strictCanonical=True))
        substrate = b'\x02\x02\x00\x01'
        supplied = 0
        underruns = 0
        while True:
            try:
                value = next(iterator)
            except PyAsn1Error:
                break
            assert isinstance(value, SubstrateUnderrunError)
            underruns += 1
            position = stream.tell()
            stream.seek(0, io.SEEK_END)
            supplied += stream.write(substrate[supplied:supplied + 1])
            stream.seek(position)
        assert underruns >= 1 and supplied == len(substrate)

    def testHeaderErrorRaisesWithoutContent(self):
        stream = NonBlockingStream(b'\x02\x81\x01')
        iterator = iter(decoder.StreamingDecoder(
            stream, strictCanonical=True))
        try:
            next(iterator)
        except PyAsn1Error:
            pass
        else:
            self.fail('non-minimal length tolerated on partial input')

    def testTagErrorRaisesAfterTagBoundary(self):
        stream = NonBlockingStream(b'\x9f')
        iterator = iter(decoder.StreamingDecoder(
            stream, strictCanonical=True))
        assert isinstance(next(iterator), SubstrateUnderrunError)
        position = stream.tell()
        stream.seek(0, io.SEEK_END)
        stream.write(b'\x1e\x01\x01')
        stream.seek(position)
        try:
            next(iterator)
        except PyAsn1Error:
            pass
        else:
            self.fail('non-minimal high tag tolerated after resume')


class LenientDefaultTestCase(BaseTestCase):
    def testDerDecodeWithoutOptionUnchanged(self):
        for substrate in (
                b'\x02\x02\x00\x01',
                b'\x02\x00',
                b'\x02\x81\x01\x01'):
            decoder.decode(substrate)
        # the schema-driven TYPE_MAP path stays permissive without
        # the option, including constructed string encodings
        decoder.decode(
            b'\x24\x06\x04\x01a\x04\x01b', asn1Spec=univ.OctetString())
        decoder.decode(b'\x01\x01\x01', asn1Spec=univ.Boolean())

    def testBerAndCerIgnoreOption(self):
        for codec in (berDecoder, cerDecoder):
            value, _ = codec.decode(
                b'\x02\x02\x00\x01', strictCanonical=True)
            assert value == 1
            value, _ = codec.decode(
                b'\x24\x06\x04\x01a\x04\x01b', strictCanonical=True)
            assert bytes(value) == b'ab'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
