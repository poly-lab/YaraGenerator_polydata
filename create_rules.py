#coding:UTF-8
import os
import ConfigParser,struct
from lib.common.constants import YARA_ROOT
from third.YaraGenerator.yaraGenerator import yaramain
from multiprocessing import Pool

config=ConfigParser.ConfigParser()
config.read(os.path.join(YARA_ROOT,"conf","conf.conf"))
input_path=config.get("input", "file_path")
output_path=config.get("output", "rule_path")
author=config.get("auther", "auther")
#获取种类地址
def get_path(input_path):
    new_path=[]
    for root,dirs,files in os.walk(input_path):
        for file in files:
            new_path.append(root)
    print len(new_path)
    new_path=list(set(new_path))
    return new_path
    
#定义文件类型   
def typeList():    
    return {  
        "FFD8FF": "jpg",  
        "89504E47": "png",  
        "47494638": "gif",  
        "49492A00": "tif",  
        "424D": "bmp",  
        "41433130": "dwg",  
        "38425053": "psd",  
        "7B5C727466": "rtf",  
        "3C3F786D6C": "xml",  
        "68746D6C3E": "js-html",  
        "44656C69766572792D646174653A": "email",  
        "CFAD12FEC5FD746F": "dbx",  
        "2142444E": "pst",  
        "D0CF11E0": "xls.or.doc",  
        "5374616E64617264204A": "mdb",  
        "FF575043": "wpd",  
        "252150532D41646F6265": "eps.or.ps",  
        "255044462D312E": "pdf",  
        "AC9EBD8F": "qdf",  
        "E3828596": "pwl",  
        "504B0304": "zip",  
        "52617221": "rar",  
        "57415645": "wav",  
        "41564920": "avi",  
        "2E7261FD": "ram",  
        "2E524D46": "rm",  
        "000001BA": "mpg",  
        "000001B3": "mpg",  
        "6D6F6F76": "mov",  
        "3026B2758E66CF11": "asf",  
        "4D546864": "mid",  
        "4D5A": "exe"  
        }    
    
# 字节码转16进制字符串    
def bytes2hex(bytes):    
    num = len(bytes)    
    hexstr = u""    
    for i in range(num):    
        t = u"%x" % bytes[i]    
        if len(t) % 2:    
            hexstr += u"0"    
        hexstr += t    
    return hexstr.upper()    
    
# 获取文件类型    
def get_filetype(filename):    
    binfile = open(filename, 'rb') # 必需二制字读取    
    tl = typeList()    
    ftype = 'unknown'    
    for hcode in tl.keys():  
        numOfBytes = len(hcode) / 2 # 需要读多少字节  
        binfile.seek(0) # 每次读取都要回到文件头，不然会一直往后读取    
        hbytes = struct.unpack_from("B"*numOfBytes, binfile.read(numOfBytes)) # 一个 "B"表示一个字节  
        f_hcode = bytes2hex(hbytes)  
        if f_hcode == hcode:    
            ftype = tl[hcode]    
            break    
    binfile.close()    
    return ftype            

def create_rules(path):
    RulesName=path.split('/')
    RulesName=RulesName[-4]+'_'+RulesName[-3]+'_'+RulesName[-2]+'_'+RulesName[-1]
    RulesName=RulesName.replace('-','')
            
    for root,li,files in os.walk(path):
        file_path=root+'/'+files[0]
        ftype=get_filetype(file_path)
    if 'Word'  in path:
        FileType='office'  
    elif  'Excel' in path:
        FileType='office'         
    elif 'exe'==ftype:
        FileType='exe'
    elif 'pdf'==ftype:   
        FileType='pdf'
    elif 'email'==ftype:
        FileType='email'
    else:
        FileType='unkown'
    
    
    InputDirectory=path+'/'
    Tags='APT'
    Verbose='OK'
    RulesName=os.path.join(output_path,RulesName)
    #调用yaraGenerator生成rules
    yaramain(InputDirectory, RulesName, Author, Description, Tags, Verbose, FileType)    

if __name__=="__main__":
    Author=author
    Description='test'
    new_path=get_path(input_path)
    pool = Pool(processes=20)
    pool.map(create_rules,new_path)
    pool.join()
    pool.close()
    