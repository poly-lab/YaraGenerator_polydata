
import os
vir_path=[]
path='/data2/sample/virus_samples_to_xia_051010_class/virus_samples_to_xia_051010_class/vt/kaspersky'
for root,dirs,files in os.walk(path):
    for file in files:
        vir_path.append(root)
        
newlist=list(set(vir_path))
for li in newlist:
    a=open('w.txt','a')
    a.write(li)
    a.close