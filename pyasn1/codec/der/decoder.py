#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import warnings

from pyasn1 import error
from pyasn1.codec.ber import decoder as berDecoder
from pyasn1.codec.cer import decoder
from pyasn1.codec.streaming import readFromStream
from pyasn1.type import univ

__all__ = ['decode', 'StreamingDecoder']

SubstrateUnderrunError = error.SubstrateUnderrunError


class BitStringPayloadDecoder(decoder.BitStringPayloadDecoder):
    supportConstructedForm = False


class OctetStringPayloadDecoder(decoder.OctetStringPayloadDecoder):
    supportConstructedForm = False


class BooleanPayloadDecoder(berDecoder.BooleanPayloadDecoder):
    """Boolean payload decoder with optional DER canonical checks.

    The CER Boolean decoder used on the schemaless path enforces the
    DER rules (single octet, ``0x00``/``0xFF``) unconditionally, while
    the schema-driven path consults ``TYPE_MAP`` and inherits BER's
    lenient Boolean decoder. This class is registered in ``TYPE_MAP``
    so that ``strictCanonical`` applies the DER rules on both paths;
    without the option it delegates to the BER behavior, keeping the
    default decode compatible.
    """

    def valueDecoder(self, substrate, asn1Spec,
                     tagSet=None, length=None, state=None,
                     decodeFun=None, substrateFun=None,
                     **options):
        if options.get('strictCanonical'):
            # X.690 11.1: BOOLEAN is a single contents octet, TRUE is
            # 0xFF and FALSE is 0x00
            if length != 1:
                raise error.PyAsn1Error('Not single-octet Boolean payload')

            for chunk in readFromStream(substrate, length, options):
                if isinstance(chunk, SubstrateUnderrunError):
                    yield chunk

            byte = chunk[0]

            if byte not in (0x00, 0xFF):
                raise error.PyAsn1Error(
                    'Unexpected Boolean payload: %s' % byte)

            yield self._createComponent(
                asn1Spec, tagSet, 1 if byte else 0, **options)
            return

        for value in super(BooleanPayloadDecoder, self).valueDecoder(
                substrate, asn1Spec,
                tagSet=tagSet, length=length, state=state,
                decodeFun=decodeFun, substrateFun=substrateFun,
                **options):
            yield value


# TODO: prohibit non-canonical encoding
RealPayloadDecoder = decoder.RealPayloadDecoder

TAG_MAP = decoder.TAG_MAP.copy()
TAG_MAP.update(
    {univ.BitString.tagSet: BitStringPayloadDecoder(),
     univ.OctetString.tagSet: OctetStringPayloadDecoder(),
     univ.Real.tagSet: RealPayloadDecoder()}
)

TYPE_MAP = decoder.TYPE_MAP.copy()

# Schema-driven Boolean decodes consult TYPE_MAP, which otherwise
# inherits BER's lenient decoder; install the strict-capable one.
TYPE_MAP[univ.Boolean.typeId] = BooleanPayloadDecoder()

# Put in non-ambiguous types for faster codec lookup
for typeDecoder in TAG_MAP.values():
    if typeDecoder.protoComponent is not None:
        typeId = typeDecoder.protoComponent.__class__.typeId
        if typeId is not None and typeId not in TYPE_MAP:
            TYPE_MAP[typeId] = typeDecoder


class SingleItemDecoder(decoder.SingleItemDecoder):
    __doc__ = decoder.SingleItemDecoder.__doc__

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP

    supportIndefLength = False

    strictCanonicalSupported = True


class StreamingDecoder(decoder.StreamingDecoder):
    """Streaming DER decoder.

    Behaves like the inherited BER/CER
    :class:`~pyasn1.codec.ber.decoder.StreamingDecoder`, but accepts the
    ``strictCanonical`` keyword: when true, every decoded object is
    checked against the DER canonical encoding rules (see the
    :attr:`decode` docstring for the rule set). The option defaults to
    false and never changes the underrun/resume semantics.
    """

    SINGLE_ITEM_DECODER = SingleItemDecoder


class Decoder(decoder.Decoder):
    __doc__ = decoder.Decoder.__doc__

    STREAMING_DECODER = StreamingDecoder


#: Turns DER octet stream into an ASN.1 object.
#:
#: Takes DER octet-stream and decode it into an ASN.1 object
#: (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative) which
#: may be a scalar or an arbitrary nested structure.
#:
#: Parameters
#: ----------
#: substrate: :py:class:`bytes`
#:     DER octet-stream
#:
#: Keyword Args
#: ------------
#: asn1Spec: any pyasn1 type object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:     A pyasn1 type object to act as a template guiding the decoder. Depending on the ASN.1 structure
#:     being decoded, *asn1Spec* may or may not be required. Most common reason for
#:     it to require is that ASN.1 structure is encoded in *IMPLICIT* tagging mode.
#: strictCanonical: :py:class:`bool`
#:     Reject encodings that decode to the same value but are not valid
#:     DER (ITU-T X.690): non-minimal tag or length octets, non-minimal
#:     INTEGER/ENUMERATED contents, non-canonical BOOLEAN and BIT
#:     STRING, constructed string encodings, and misordered SET/SET OF
#:     components. Defaults to :obj:`False`, preserving the historical
#:     lenient decoding behavior. Only the object consumed from the
#:     substrate is validated; the unprocessed tail is returned as usual.
#:
#: Returns
#: -------
#: : :py:class:`tuple`
#:     A tuple of pyasn1 object recovered from DER substrate (:py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     and the unprocessed trailing portion of the *substrate* (may be empty)
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error, ~pyasn1.error.SubstrateUnderrunError
#:     On decoding errors
#:
#: Examples
#: --------
#: Decode DER serialisation without ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03')
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
#: Decode DER serialisation with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03', asn1Spec=seq)
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
decode = Decoder()

def __getattr__(attr: str):
    if newAttr := {"tagMap": "TAG_MAP", "typeMap": "TYPE_MAP"}.get(attr):
        warnings.warn(f"{attr} is deprecated. Please use {newAttr} instead.", DeprecationWarning, stacklevel=2)
        return globals()[newAttr]
    raise AttributeError(attr)
