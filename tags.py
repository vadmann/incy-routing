from pathlib import Path
def varint(b,i):
 n=s=0
 while True:
  v=b[i];i+=1;n|=(v&127)<<s
  if v<128:return n,i
  s+=7
def fields(b):
 i=0
 while i<len(b):
  k,i=varint(b,i);t=k&7
  if t==2:
   n,i=varint(b,i);v=b[i:i+n];i+=n
  elif t==0:v,i=varint(b,i)
  else:raise ValueError(t)
  yield k>>3,v
def tags(path):
 return {next(v.decode() for k,v in fields(msg) if k==1).lower() for k,msg in fields(Path(path).read_bytes()) if k==1}
if __name__=='__main__':
 for p in ['work/geosite.dat','work/geoip.dat']:
  print(p, sorted(tags(p)))
