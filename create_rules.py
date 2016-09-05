import os
import ConfigParser
from lib.common.constants import YARA_ROOT
from third.YaraGenerator.yaraGenerator import yaramain

def get_config():
    config=ConfigParser.ConfigParser()
    config.read(os.path.join(YARA_ROOT,"conf","conf.conf"))
    input_path=config.get("input", "file_path")
    output_path=config.get("output", "rule_path")
    author=config.get("auther", "auther")
    
def get_path(input_path):
    roots,dirs,files =os.walk(input_path)
    for root in roots:
        print root 
    
        
def get_file_type():
    pass

if __name__=="__main__":
    
    yaramain(InputDirectory, RulesName, Author, Description, Tags, Verbose, FileType)
    