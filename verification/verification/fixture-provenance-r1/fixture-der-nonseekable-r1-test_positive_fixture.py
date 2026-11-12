import io
import pytest
from pyasn1.codec.der import decoder
from pyasn1.codec.ber import decoder as ber
from pyasn1.codec.cer import decoder as cer
from pyasn1.type import univ,namedtype,opentype,tag
from pyasn1.error import PyAsn1Error,SubstrateUnderrunError

def strict(h,**kw):return decoder.decode(bytes.fromhex(h),strictCanonical=True,**kw)
@pytest.mark.parametrize('h',['020101','0201ff','010100','0101ff','030100','030203a8','0400','0a0101'])
def test_minimal_legal_values(h):assert strict(h)[1]==b''
@pytest.mark.parametrize('h',['02020001','0202ffff','0a020001','0a02ffff','010101','010200ff','030101','030203a9','03020800','02810101','0282000101','1f020101','1f80020101'])
def test_noncanonical_primitive_forms(h):
 with pytest.raises(PyAsn1Error):strict(h)
def test_long_length_needed_for_128_bytes():
 x,tail=decoder.decode(b'\x04\x81\x80'+b'x'*128,strictCanonical=True);assert x.asOctets()==b'x'*128 and not tail
def test_tail_is_not_validated():
 x,tail=strict('02010102020001');assert int(x)==1 and tail==bytes.fromhex('02020001')
@pytest.mark.parametrize('decode',[decoder.decode,ber.decode,cer.decode])
def test_default_legacy_integer_acceptance(decode):
 x,tail=decode(bytes.fromhex('02020001'));assert int(x)==1 and not tail
def test_sequence_propagates_flag():
 with pytest.raises(PyAsn1Error):strict('300402020001')
def test_implicit_integer_propagates_flag():
 spec=univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,0))
 assert int(strict('800101',asn1Spec=spec)[0])==1
 with pytest.raises(PyAsn1Error):strict('80020001',asn1Spec=spec)
def test_explicit_integer_propagates_flag():
 spec=univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatConstructed,0))
 assert int(strict('a003020101',asn1Spec=spec)[0])==1
 with pytest.raises(PyAsn1Error):strict('a00402020001',asn1Spec=spec)
def test_choice_propagates_flag():
 spec=univ.Choice(componentType=namedtype.NamedTypes(namedtype.NamedType('integer',univ.Integer()),namedtype.NamedType('string',univ.OctetString())))
 with pytest.raises(PyAsn1Error):strict('02020001',asn1Spec=spec)
@pytest.mark.parametrize('h',['3106020101020102','3106020101020101'])
def test_sorted_set_of_including_equal_values(h):assert len(strict(h,asn1Spec=univ.SetOf(componentType=univ.Integer()))[0])==2
def test_reversed_set_of_refused():
 with pytest.raises(PyAsn1Error):strict('3106020102020101',asn1Spec=univ.SetOf(componentType=univ.Integer()))
def test_set_is_tag_order_not_set_of_order():
 spec=univ.Set(componentType=namedtype.NamedTypes(namedtype.NamedType('boolean',univ.Boolean()),namedtype.NamedType('integer',univ.Integer())))
 assert strict('31060101ff020101',asn1Spec=spec)[0]['integer']==1
 with pytest.raises(PyAsn1Error):strict('31060201010101ff',asn1Spec=spec)
def test_open_type_strict_value():
 spec=univ.Sequence(componentType=namedtype.NamedTypes(namedtype.NamedType('kind',univ.Integer()),namedtype.NamedType('value',univ.Any(),openType=opentype.OpenType('kind',{1:univ.Integer()}))))
 assert int(strict('3006020101020101',asn1Spec=spec,decodeOpenTypes=True)[0]['value'])==1
 with pytest.raises(PyAsn1Error):strict('300702010102020001',asn1Spec=spec,decodeOpenTypes=True)
def test_streaming_multiple_values():
 values=list(decoder.StreamingDecoder(io.BytesIO(bytes.fromhex('020101020102')),strictCanonical=True));assert [int(x) for x in values]==[1,2]
def test_streaming_noncanonical_nested_rejected():
 with pytest.raises(PyAsn1Error):list(decoder.StreamingDecoder(io.BytesIO(bytes.fromhex('300402020001')),strictCanonical=True))
class NonBlocking(io.BytesIO):
 block=True
 def read(self,size=-1):
  if self.block:self.block=False;return None
  self.block=True;return super().read(size)
def test_streaming_missing_data_semantics_preserved():
 source=NonBlocking(bytes.fromhex('020101'));events=[];it=iter(decoder.StreamingDecoder(source,strictCanonical=True))
 for _ in range(30):
  try:x=next(it)
  except StopIteration:break
  events.append(x)
 assert any(isinstance(x,SubstrateUnderrunError) for x in events)
 assert [int(x) for x in events if not isinstance(x,SubstrateUnderrunError)]==[1]
def test_explicit_false_preserves_default_compatibility():
 assert int(decoder.decode(bytes.fromhex('02020001'),strictCanonical=False)[0])==1

def test_set_of_order_uses_full_encoding_not_numeric_value():
 spec=univ.SetOf(componentType=univ.Integer())
 values=strict('31060201010201ff',asn1Spec=spec)[0];assert [int(x) for x in values]==[1,-1]
 with pytest.raises(PyAsn1Error):strict('31060201ff020101',asn1Spec=spec)

def test_set_order_ignores_constructed_bit_within_same_tag_class():
 boolean=univ.Boolean().subtype(explicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatConstructed,0))
 integer=univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,2))
 spec=univ.Set(componentType=namedtype.NamedTypes(namedtype.NamedType('b',boolean),namedtype.NamedType('i',integer)))
 value=strict('3108a0030101ff820101',asn1Spec=spec)[0];assert bool(value['b']) and int(value['i'])==1
 with pytest.raises(PyAsn1Error):strict('3108820101a0030101ff',asn1Spec=spec)

@pytest.mark.parametrize('schema,good,bad',[
 (univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,1)),'8101ff','810101'),
 (univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,2)),'82020780','82020781'),
 (univ.Enumerated().subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,5)),'850101','85020001')
])
def test_implicit_primitive_value_constraints(schema,good,bad):
 assert strict(good,asn1Spec=schema)[1]==b''
 with pytest.raises(PyAsn1Error):strict(bad,asn1Spec=schema)

def test_implicit_set_of_propagates_order_check():
 spec=univ.SetOf(componentType=univ.Integer()).subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatConstructed,0))
 assert len(strict('a006020101020102',asn1Spec=spec)[0])==2
 with pytest.raises(PyAsn1Error):strict('a006020102020101',asn1Spec=spec)

def test_minimal_high_tag_encoding_allowed():
 spec=univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,32))
 assert strict('9f2000',asn1Spec=spec)[0].asOctets()==b''
 with pytest.raises(PyAsn1Error):strict('9f802000',asn1Spec=spec)

@pytest.mark.parametrize('h',['30800000','2403040178','048100','0200','0a00','03020781'])
def test_existing_der_prohibitions_and_additional_nonminimal_forms(h):
 with pytest.raises(PyAsn1Error):strict(h)

class RawNonSeekable:
 def __init__(self,data):self.source=io.BytesIO(data)
 def read(self,size=-1):return self.source.read(size)
 def seekable(self):return False

def large_set_of(reverse=False):
 first=bytes.fromhex('020101');last=bytes.fromhex('020102')
 payload=(last+first*3999) if reverse else (first*3999+last)
 return b'\x31\x82'+len(payload).to_bytes(2,'big')+payload

def test_large_set_of_nonseekable_keeps_original_bytes_available():
 schema=univ.SetOf(componentType=univ.Integer())
 values=list(decoder.StreamingDecoder(RawNonSeekable(large_set_of()),asn1Spec=schema,strictCanonical=True))
 assert len(values)==1 and len(values[0])==4000
 assert int(values[0][0])==1 and int(values[0][-1])==2

def test_large_set_of_nonseekable_rejects_actual_child_misorder():
 schema=univ.SetOf(componentType=univ.Integer())
 with pytest.raises(PyAsn1Error):list(decoder.StreamingDecoder(RawNonSeekable(large_set_of(True)),asn1Spec=schema,strictCanonical=True))

def test_nonseekable_multiple_objects_and_nested_order():
 values=list(decoder.StreamingDecoder(RawNonSeekable(bytes.fromhex('0201013106020101020102020103')),strictCanonical=True))
 assert len(values)==3 and int(values[0])==1 and int(values[-1])==3
 assert [int(x) for x in values[1]]==[1,2]
