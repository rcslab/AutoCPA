import sys
#from ghidra.program.model.data import DataType
from ghidra.program.model.data import DataTypeManager

class DT_record():
    def __init__(self, dt):
        self.__dt=dt
        self.__components_data=self.__initcomponents_data()
    
    def __findComponents(self):
        if self.__dt is not None:
            #print "Chosen data type: " + str(dt)
            #print(dt)
            print(self.__dt.getName())
            field_lst=self.__dt.getComponents()
        return field_lst
    
    def __initcomponents_data(self):
        compdata={}
        fld_lst=self.__findComponents()        
        for i in range (len(fld_lst)):
            compdata[fld_lst[i].getOffset()]=0

        return compdata

    def print_datatype(self):
        fld_lst=self.__findComponents()
        print "length of datatype:", len(fld_lst)
        for i in fld_lst:
            #i.setComment("Hi bada!")
            print(i)
        return

    def update_stats(self, offset, cache_miss):

        print "the field being updated:", self.__dt.getComponentAt(offset).getFieldName()
        #self.__components_data[self.__dt.getComponentAt(offset).getOrdinal()] += cache_miss
        self.__components_data[offset] += cache_miss
        return

    def printcomponents_data(self):
        for k in self.__components_data.keys():
            print(str(k)+": "+str(self.__components_data[k]))
        return

    def setcomments(self):
        
        for k in self.__components_data.keys():
            self.__dt.getComponentAt(k).setComment(str(self.__components_data[k]))
        return

    def dumpDT(self, lst):
        for k in lst:
            print(self.__dt.getComponentAt(k[0]))
        return  
    def hash2list(self):
        return [(k,self.__components_data[k]) for k in self.__components_data.keys()]   


class ghidra_bcpi():
    def __init__(self, currentProgram):
        self.__currentProgram=currentProgram
        self.__struct_mapp={}
        self.__listing = self.__currentProgram.getListing()
        self.__dtm = self.__currentProgram.getDataTypeManager()	 
    
    def __find_codeunit(self, addr):
        iterator=self.__listing.getCodeUnits(True)
        while True:
            if iterator.hasNext():
                codeUnit=iterator.next()
                codeunit_addr=codeUnit.getAddressString(True, False)
                codeunit_addr=codeunit_addr[codeunit_addr.find(":")+1:]
                if codeunit_addr==addr:
                    print("Found!!")
                    break
            else:
                codeUnit=None
                break
        return codeUnit

    def __getRefsfromCU(self, addr):
        codeUnit=self.__find_codeunit(addr)
        if not codeUnit:
            raise(Exception("Address not found"))
        refs=codeUnit.getReferencesFrom()
        #print "number of memory references from this codeunit(address):", len(refs)#for debugging
        return refs

    def __findDTbyname(self, DTname):        
        datatype_lst=[]
        self.__dtm.findDataTypes("Alphabet", datatype_lst)
        #print "Number of DataTypes found with the given name:", len(datatype_lst)#for debugging
        return datatype_lst

    def __getSymbol(self, addr):    
        print("add symbols:")
        sym=getSymbolAt(addr)
        if sym != None:
            print(sym.getName())
        else:
            print("no symbol found at this address")
        return

    def __getOffset(self, data, address):
        minaddr=data.getMinAddress()
        addroff=address.subtract(minaddr)
        print "offset:", addroff
        return addroff

    def update_stats(self, cache_miss, address):
        refs=self.__getRefsfromCU(address)
        if len(refs)!=1:
            raise(Exception("there is NOT only one memory ref from this codeunit"))
        address=refs[0].getToAddress()
        print(str(address))
        print(refs[0])

        self.__getSymbol(address)
        data=self.__listing.getDataContaining(address)
        addroff=self.__getOffset(data, address)
        dtname=str(data.getDataType())
        print(dtname)


        dtlist=self.__findDTbyname(dtname)
        if len(dtlist)!=1:
            raise(Exception("there is NOT only one datatype under this name"))
        if dtname not in self.__struct_mapp:
            self.__struct_mapp[dtname]=DT_record(dtlist[0])
        
        #self.__struct_mapp[dtname].print_datatype() #for debugging
        self.__struct_mapp[dtname].update_stats(addroff, cache_miss)
        #self.__struct_mapp[dtname].printcomponents_data()#for debugging



    def dump_DT(self, version):
        for k in self.__struct_mapp.keys():
            self.__struct_mapp[k].setcomments()
            components_lst=self.__struct_mapp[k].hash2list()
            if version=="fixed":
                components_lst=sorted(components_lst, key=lambda a :a[1], reverse=True)
            elif version=="original":
                components_lst=sorted(components_lst, key=lambda a :a[0])
            else:
                raise(Exception("wrong use of function dump_DT!"))   
            print "printing : ", version
            self.__struct_mapp[k].dumpDT(components_lst)
            
        return

      



def main(currentProgram):   

    gbcpi=ghidra_bcpi(currentProgram)
    gbcpi.update_stats(120, "00201a2a")
    gbcpi.update_stats(12, "0020158d")

    gbcpi.dump_DT("original")
    gbcpi.dump_DT("fixed")



main(currentProgram)