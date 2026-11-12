import json
from pyasn1.codec.der import decoder,encoder
from pyasn1.type import univ,namedtype,tag
boolean=univ.Boolean().subtype(explicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatConstructed,0))
integer=univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,2))
spec=univ.Set(componentType=namedtype.NamedTypes(namedtype.NamedType('b',boolean),namedtype.NamedType('i',integer)))
spec['b']=True;spec['i']=1
assert encoder.encode(spec)==bytes.fromhex('3108a0030101ff820101')
value,tail=decoder.decode(bytes.fromhex('3108a0030101ff820101'),asn1Spec=spec);assert not tail and int(value['i'])==1
value=univ.SetOf(componentType=univ.Integer());value.extend([1,-1]);assert encoder.encode(value)==bytes.fromhex('31060201010201ff')
value=univ.OctetString(b'').subtype(implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,32));assert encoder.encode(value)==bytes.fromhex('9f2000')
print(json.dumps({'der_fixture_encoder_checks':3,'set_tag_order':'tag class and number, not constructed bit','feature_evaluation':False}))
