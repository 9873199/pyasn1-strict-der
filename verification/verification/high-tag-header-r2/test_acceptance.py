"""SET tag order must ignore length octets after a high-number tag."""
import pytest
from pyasn1.codec.der import decoder,encoder
from pyasn1.type import univ,namedtype,tag
from pyasn1.error import PyAsn1Error

def fixture():
 schema=univ.Set(componentType=namedtype.NamedTypes(namedtype.NamedType('text',univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,31))),namedtype.NamedType('number',univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,32)))))
 value=schema.clone();value['text']=b'x'*128;value['number']=1
 first=bytes.fromhex('9f1f8180')+b'x'*128;second=bytes.fromhex('9f200101');prefix=bytes.fromhex('318188')
 good=prefix+first+second;bad=prefix+second+first
 assert encoder.encode(value)==good
 return schema,good,bad

def test_positive_fixture_matches_original_der_encoder():
 schema,good,bad=fixture();value,tail=decoder.decode(good,asn1Spec=schema)
 assert not tail and value['text'].asOctets()==b'x'*128 and int(value['number'])==1

def test_high_tag_sorted_set_with_long_length_is_accepted():
 schema,good,bad=fixture();value,tail=decoder.decode(good,asn1Spec=schema,strictCanonical=True)
 assert not tail and value['text'].asOctets()==b'x'*128 and int(value['number'])==1

def test_high_tag_reversed_set_with_long_length_is_rejected():
 schema,good,bad=fixture()
 with pytest.raises(PyAsn1Error):decoder.decode(bad,asn1Spec=schema,strictCanonical=True)
