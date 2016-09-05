import os
path='/data2/sample/virus_samples_to_xia_051010_class/virus_samples_to_xia_051010_class/vt/kaspersky'


import os.path
def processDirectory ( args, dirname, filenames ):
    print 'Directory',dirname
 
os.path.walk(path, processDirectory, None )
