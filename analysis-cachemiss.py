import sys
import csv
import pickle
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.address import AddressSet
from ghidra.program.util import ProgramLocation
from ghidra.program.model.address import Address
from ghidra.util.task import ConsoleTaskMonitor
from java.util.function import Consumer
from ghidra.app.services import DataTypeReferenceFinder
from ghidra.util.classfinder import ClassSearcher
from ghidra.program.model.data import DataType
from collections import defaultdict
import time

lst_map = defaultdict(list)


class err_in_address(BaseException):
    def __init__(self, str1):
        self.s = str1


class err_in_Toaddress(BaseException):
    def __init__(self, str1):
        self.s = str1

# def check_number(a,b):
#     if a>b:
#         raise err_in_address("error happened in line 11")
#     else:
#         raise err_in_Toaddress()

# a=3
# b=2

# try:
#     check_number(a,b)
# except err_in_address as e:
#     print(e.s)


class component_data():
    def __init__(self, size):
        self.__missesWCB = 0
        self.__missesWOCB = 0
        self.__size = size

    def getsize(self):
        return self.__size

    def updateWCB(self, cache_misses):
        self.__missesWCB += cache_misses
        return

    def updateWOCB(self, cache_misses):
        self.__missesWOCB += cache_misses
        return

    def getMisses_wcb(self):
        return self.__missesWCB

    def getMisses_wocb(self):
        return self.__missesWOCB


class references():
    def __init__(self, addr, cb):
        self.__addr_refs = addr
        self.__cb_refs = cb  # cb_refs do not include addr_refs
        self.__updated_cacheline = []

    def get_addr_refs(self):
        return self.__addr_refs

    def get_cb_refs(self):
        return self.__cb_refs

    def setcacheline(self, cacheline):
        if cacheline not in self.__updated_cacheline:
            self.__updated_cacheline.append(cacheline)
            # print "cache line number which was updated is :",cacheline, "------------------------"#for debugging
        return

    def getcacheline(self):
        return self.__updated_cacheline


class DT_record():
    def __init__(self, dt):
        self.__dt = dt
        self.__components_table = self.__initcomponents_table()
        self.__saved_misses = None

    def __findComponents(self):
        if self.__dt is not None:
            print "adding datatype", self.__dt.getName(), "to the struct_mapp"  # for debugging
            if self.__dt.getName().find("*") != -1:
                raise err_in_address("removed pointers *!!!!!!!!!!!!!!!!!")
            if self.__dt.getName() == "robj":
                raise err_in_address("removed robj!!!!!!!!!!")
            field_lst = self.__dt.getComponents()
        return field_lst

    def __initcomponents_table(self):
        compdata = {}
        fld_lst = self.__findComponents()
        for i in range(len(fld_lst)):
            compdata[fld_lst[i].getOffset()] = component_data(
                fld_lst[i].getDataType().getLength())

        return compdata

    def print_datatype(self):
        fld_lst = self.__findComponents()
        print "num of fields in this dt:", len(fld_lst)
        for i in fld_lst:
            #i.setComment("Hi bada!")
            print(i)
        return

    def update_stats(self, offset, cache_miss, version):

        # print "the field being updated:", self.__dt.getComponentAt(offset).getFieldName()
        if self.__dt.getComponentAt(offset).getDataType().getDisplayName() == "undefined":
            raise err_in_Toaddress(
                "preventing updating stats for UNDEFINED fields")
        self.__components_table[offset].updateWCB(cache_miss)
        if version == "addr":
            self.__components_table[offset].updateWOCB(cache_miss)
        return

    def printcomponents_table(self):
        for k in self.__components_table.keys():
            print(str(k)+": "+str(self.__components_table[k].getMisses_wcb()))
        return

    def setcomments(self, cb_option):

        for k in self.__components_table.keys():
            if cb_option == "wcb":
                self.__dt.getComponentAt(k).setComment(
                    str(self.__components_table[k].getMisses_wcb()))
            elif cb_option == "wocb":
                self.__dt.getComponentAt(k).setComment(
                    str(self.__components_table[k].getMisses_wocb()))
        return

    def dumpDT(self, lst):
        for k in lst:
            print(self.__dt.getComponentAt(k[0]))
            # print(self.__components_table[k[0]].getsize())#for debugging
        return

    def dumpDT_pretty(self, lst):
        print "struct "+self.__dt.getName()+"{"
        for k in lst:
            # print(self.__dt.getComponentAt(k[0]))
            if self.__dt.getComponentAt(k[0]).getDataType().getDisplayName() != "undefined":
                print self.__dt.getComponentAt(k[0]).getDataType().getDisplayName()+" "+self.__dt.getComponentAt(k[0]).getFieldName()+";"
            # print(self.__components_table[k[0]].getsize())#for debugging
        print "};"
        return

    def getAslist(self, cb_option):
        if cb_option == "wcb":
            return [(k, self.__components_table[k].getMisses_wcb()) for k in self.__components_table.keys()]
        elif cb_option == "wocb":
            return [(k, self.__components_table[k].getMisses_wocb()) for k in self.__components_table.keys()]

    def __count_saved_misses(self, lst):
        l = len(lst)
        indx, total = 0, 0
        while indx < l:
            miss, offset, loc = 0, 0, 0
            curr_offset = lst[indx][2]
            if curr_offset > 64:
                curr_offset %= 64
            while indx < l and offset+curr_offset < 65:
                if loc != 0:
                    miss += lst[indx][1]
                offset += curr_offset
                indx += 1
                loc += 1
            total += miss
        return total
    # def __count_saved_misses(self, lst):
    #     temp=[]
    #     cnt=0
    #     cm=0
    #     for item in lst:
    #         if (cnt<65) and ((cnt + item[2])>64):
    #             temp.append(cm)
    #             cm=0
    #             cnt=0
    #         if cnt !=0:
    #             cm +=item[1]
    #         cnt +=item[2]
    #     return sum(temp)

    def set_savedmisses(self):
        lst = []
        for j in self.__components_table.keys():
            lst.append((j, self.__components_table[j].getMisses_wocb(
            ), self.__components_table[j].getsize()))

        sorted_lst = sorted(lst, key=lambda a: a[1], reverse=True)
        self.__saved_misses = self.__count_saved_misses(sorted_lst)
        # print "num of saved misses:",self.__saved_misses
        return

    def get_savedmisses(self):
        return self.__saved_misses


class ghidra_bcpi():
    def __init__(self, currentProgram):
        self.__currentProgram = currentProgram
        self.__struct_mapp = {}
        self.__listing = self.__currentProgram.getListing()
        self.__dtm = self.__currentProgram.getDataTypeManager()

    def __find_codeunit(self, addr):
        iterator = self.__listing.getCodeUnits(True)
        while True:
            if iterator.hasNext():
                codeUnit = iterator.next()
                codeunit_addr = codeUnit.getAddressString(True, False)
                codeunit_addr = codeunit_addr[codeunit_addr.find(":")+1:]
                if codeunit_addr == addr:
                    # print("Found!!")#for debugging
                    break
            else:
                codeUnit = None
                break
        if not codeUnit:
            raise err_in_address("CodeUnit not found!!!!!!!!!!!")

        return codeUnit

    def __getcodeblockinfo(self, cu):

        cu_addr = cu.getMinAddress()
        BBModel = BasicBlockModel(self.__currentProgram)
        CBs = BBModel.getCodeBlocksContaining(cu_addr, None)
        if len(CBs) != 1:
            raise err_in_address(
                "there is NOT only one codeblock that contains this codeunit")
        CB_maxaddr = CBs[0].getMaxAddress()

        # print "cu min addr & CB max addr:", cu_addr, CB_maxaddr #for debugging

        return cu_addr, CB_maxaddr

    def __getRefsfromrange(self, addr1, addr2):
        temp = addr1
        final = addr2.next()
        refs = []
        while True:
            if temp.next() == final:
                break
            temp = temp.next()
            if str(temp) in lst_map:
                if len(lst_map[str(temp)]) != 0:
                    refs.extend(lst_map[str(temp)])
        return refs

    def __getRefsfromCB(self, cu):
        cu_addr, cb_maxaddr = self.__getcodeblockinfo(cu)
        refs = self.__getRefsfromrange(cu_addr, cb_maxaddr)

        return refs

    # def __findDTbyname(self, DTname):
    #     datatype_lst=[]
    #     # tmp_indx=DTname.find("*")##these 3 lines remove pointers from DTname
    #     # if tmp_indx!=-1:
    #     #     DTname=DTname[:tmp_indx-1]
    #     self.__dtm.findDataTypes(DTname, datatype_lst)
    #     if len(datatype_lst)!=1:
    #         #raise Exception("error in finding datatype by name")
    #         print "Num of DataTypes found with the given name:", len(datatype_lst)#for debugging
    #         raise err_in_address("removed dataTypes found under a name with problem!!!!")
    #
    #     return datatype_lst

    def __main_update_phase(self, address, cache_miss, version, refs):

        #dt, addroff=self.__findDTbyname(address[0])[0], address[1]
        dt, addroff = self.__dtm.getDataType(address[0]), address[1]
        if dt not in self.__struct_mapp:
            self.__struct_mapp[dt] = DT_record(dt)

        # self.__struct_mapp[dt].print_datatype() #for debugging
        # if version=="cb":#the following three lines are to prevent updating any fields in another cacheline
        #     if addroff//64 not in refs.getcacheline():
        #         raise err_in_Toaddress("this field is on another cacheline")
        self.__struct_mapp[dt].update_stats(addroff, cache_miss, version)
        # self.__struct_mapp[dt].printcomponents_table()#for debugging

        return addroff//64

    def __getRefsInCB(self, addr):
        cu = self.__find_codeunit(addr)
        cb_refs = self.__getRefsfromCB(cu)
        return cb_refs

    def update_stats(self, cache_miss, address):
        if address not in lst_map:
            raise err_in_address("addr " + address + " isn't in lst_map")

        # addr_reflst is a list of tuple (dt, offset) for a given address
        addr_reflst = lst_map[address]
        # cb_reflst is a list of tuple (dt, offset) in cb of a given address
        cb_reflst = self.__getRefsInCB(address)
        refs = references(addr_reflst, cb_reflst)
        self.__update_from_refs(cache_miss, refs, "addr")
        self.__update_from_refs(cache_miss, refs, "cb")

        return

    def __update_from_refs(self, cache_miss, refs, version):
        if version == "addr":
            lst = refs.get_addr_refs()
        elif version == "cb":
            lst = refs.get_cb_refs()

        for i in lst:  # i is a single tuple
            try:
                cacheline = self.__main_update_phase(
                    i, cache_miss, version, refs)
                if version == "addr":
                    refs.setcacheline(cacheline)

            except err_in_Toaddress as e:
                print e.s
                continue
        return

    def __sortComponents(self, components_lst):
        zeroLst, positiveLst = [], []
        for item in components_lst:
            if item[1] != 0:
                positiveLst.append(item)
            else:
                zeroLst.append(item)
        positiveLst.sort(key=lambda a: a[1], reverse=True)
        zeroLst.sort(key=lambda a: a[0])
        return positiveLst+zeroLst

    def dump_DT(self, version, cb_option):
        for k in self.__struct_mapp.keys():
            self.__struct_mapp[k].setcomments(cb_option)
            components_lst = self.__struct_mapp[k].getAslist(cb_option)
            if version == "fixed":
                components_lst = self.__sortComponents(components_lst)
            elif version == "original":
                components_lst = sorted(components_lst, key=lambda a: a[0])
            else:
                raise(Exception("wrong use of function dump_DT!"))
            if cb_option == "wcb":
                s = "with"
            elif cb_option == "wocb":
                s = "without"
            print "printing : Datatype ", k.getName(), version, s, "code block information added"
            self.__struct_mapp[k].dumpDT(components_lst)
            if version == "fixed":
                print "Pretty printing : Datatype ", k.getName(), version, s, "code block information added"
                self.__struct_mapp[k].dumpDT_pretty(components_lst)

        return

    def print_summary(self):

        dt_lst = []
        for i in self.__struct_mapp.keys():
            # print "printing number of misses saved in struct", i
            self.__struct_mapp[i].set_savedmisses()
            dt_lst.append(
                (i.getName(), self.__struct_mapp[i].get_savedmisses()))
        dt_lst = sorted(dt_lst, key=lambda a: a[1], reverse=True)
        for dt in dt_lst:
            print "In datatype ", dt[0], " you will save", dt[1], "number of misses"

        return


def read_csv(path):
    try:
        rows = []
        with open(path, 'r') as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                rows.append(row)
            print("Total Num of rows: %d" % (csvreader.line_num))
        return rows

    except:
        raise(Exception("Error in reading CSV file. Please check the input path"))


def unpickle_table(cp, pickle_path):
    global lst_map
    with open(pickle_path, 'rb') as pickleFile:
        lst_map = pickle.load(pickleFile)


def main(currentProgram):
    ##############################
    # hachi=[("00201a16", 120), ("00201a6e", 12)]
    # gbcpi=ghidra_bcpi(currentProgram)
    # unpickle_table(currentProgram)
    # for i in hachi:
    #     try:
    #         gbcpi.update_stats(i[1], i[0])
    #
    #     except err_in_address as e:
    #         print e.s
    #         continue
    # gbcpi.print_summary()
    # gbcpi.dump_DT("original", "wocb")
    # gbcpi.dump_DT("fixed", "wocb")
    # gbcpi.dump_DT("original", "wcb")
    # gbcpi.dump_DT("fixed", "wcb")
    ##############################

    start_time = time.time()

    csv_path = getScriptArgs()[0]
    pickle_path = getScriptArgs()[1]
    data = read_csv(csv_path)
    gbcpi = ghidra_bcpi(currentProgram)
    unpickle_table(currentProgram, pickle_path)

    # print lst_map["0025d571"]
    for i in range(len(data)):
        try:

            gbcpi.update_stats(int(data[i][0]), "00"+data[i][1])
            print "Stats for address "+"00"+str(data[i][1])+" updated"
            print("i=", i)
            print("*****************************************")
            # gbcpi.update_stats(120, "00201a2a")
            # gbcpi.update_stats(12, "0020158d")

        except err_in_address as e:
            print e.s
            continue
    print "num of nodes: ", len(data)
    print "num of references: ", len(lst_map)
    gbcpi.print_summary()
    gbcpi.dump_DT("original", "wocb")
    gbcpi.dump_DT("fixed", "wocb")
    gbcpi.dump_DT("original", "wcb")
    gbcpi.dump_DT("fixed", "wcb")

    duration = (time.time() - start_time)/60
    print "duration: --- "+str(duration)+" minutes ---"


main(currentProgram)
