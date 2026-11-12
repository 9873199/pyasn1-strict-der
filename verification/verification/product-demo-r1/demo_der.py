"""Separate verification console for the installed/frozen DER decoder, not product source."""
import io,json
from pyasn1.codec.der import decoder
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error

def check(label,hex_input,strict,should_accept,schema=None):
 print(label+' | input='+hex_input+' | strictCanonical='+str(strict),flush=True)
 try:
  options={'strictCanonical':strict}
  if schema is not None:options['asn1Spec']=schema
  value,tail=decoder.decode(bytes.fromhex(hex_input),**options)
  print('  decoded='+value.prettyPrint().replace('\n',' ')+' | remaining='+tail.hex(),flush=True)
  accepted=True
 except PyAsn1Error as error:
  print('  rejected: '+type(error).__name__+': '+str(error),flush=True);accepted=False
 passed=accepted==should_accept
 print('  '+('PASS' if passed else 'FAIL')+'\n',flush=True)
 return passed

def main():
 print('Canonical DER Decoder\n',flush=True)
 results=[check('Minimal integer','020101',True,True),check('Compatibility input','02020001',False,True),check('Nonminimal integer','02020001',True,False),check('Nested nonminimal integer','300402020001',True,False),check('Sorted SET OF','3106020101020102',True,True,univ.SetOf(componentType=univ.Integer())),check('Reversed SET OF','3106020102020101',True,False,univ.SetOf(componentType=univ.Integer()))]
 values=list(decoder.StreamingDecoder(io.BytesIO(bytes.fromhex('020101020102')),strictCanonical=True))
 streaming=[int(x) for x in values]==[1,2];print('Streaming values: '+repr([int(x) for x in values])+' | '+('PASS' if streaming else 'FAIL'),flush=True)
 print(json.dumps({'checks':len(results)+1,'passed':sum(results)+int(streaming),'source':'actual decoder calls; separate verification helper'}),flush=True)
 return 0 if all(results) and streaming else 1
if __name__=='__main__':raise SystemExit(main())
