import os
import ConfigParser
from lib.common.constants import YARA_ROOT
from third.YaraGenerator.yaraGenerator import yaramain

def get_config():
    config=ConfigParser.ConfigParser()
    config.read(os.path.join(YARA_ROOT,"conf","conf.conf"))
    input_path=config.get(section, option)
    
    output_path=config.get(section, option)
    author=config.get(section, option)
    
def get_path():
    pass
def get_file_type():
    pass

if __name__=="__main__":
    yaramain(InputDirectory, RulesName, Author, Description, Tags, Verbose, FileType)
    