#以二进制的方式读取文件
#coding: UTF-8

import struct

SIZE_OF_MEM_UNIT = 16
SIZE_OF_IP_UNIT = 40

def parseProfiler():
    g = open('../data/profiler.log','r')
    data = g.readlines()
    g.close()

    newData = []
    for s in data:
        if not "C|" in s:
            x = s.strip('\n')
            if len(x) > 11 + 2:
                newData.append(s)

    g = open('../data/profiled.log','w')
    for s in newData:
        g.write(s)
    g.close()

    g = open('../config/hotmem.cfg','w')
    for s in newData:
        g.write(s[2:10] + "\n")
    g.close()


    
if __name__=="__main__":
    parseProfiler()

