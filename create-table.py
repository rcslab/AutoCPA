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
import os
import time


lst_map = defaultdict(list)
glb_offset = None
glb_datatype = None


def AddReftoTable(ref):
    global lst_map, glb_offset, glb_datatype
    dtPath = glb_datatype.getDataTypePath()
    dtCat = glb_datatype.getCategoryPath()
    lst_map[str(ref.getAddress())].append(
        (dtPath.getPath(), glb_offset, dtCat.getPath(), dtCat.getName()))
    #lst_map[str(ref.getAddress())].append((ref.getDataType().getName(), glb_offset))


class java_consumer(Consumer):
    def __init__(self, func):
        self.accept = func


class ghidra_bcpi():
    def __init__(self, currentProgram):
        self.__currentProgram = currentProgram
        self.__struct_mapp = {}
        self.__listing = self.__currentProgram.getListing()
        self.__dtm = self.__currentProgram.getDataTypeManager()

    def getUsesofAllFilteredStructures(self):
        print "Num of all data types in this executable: ", self.__dtm.getDataTypeCount(True)
        struct_iterator = self.__dtm.getAllStructures()
        dt_lst = []
        self.__filter_dt(struct_iterator, dt_lst)
        print "Num of filtered structures: ", len(dt_lst)
        self.__createRefTable(dt_lst)
        print "num of references found(# of unique addresses): ", len(lst_map)
        return

    def __createRefTable(self, dataTypes):
        global glb_offset, glb_datatype
        jc = java_consumer(AddReftoTable)
        finders = ClassSearcher.getInstances(DataTypeReferenceFinder)
        for dt in dataTypes:
            glb_datatype = dt
            components = dt.getComponents()
            for cmp in components:
                fieldName, glb_offset = cmp.getFieldName(), cmp.getOffset()
                for finder in finders:
                    finder.findReferences(
                        currentProgram, dt, fieldName, jc, ConsoleTaskMonitor())
                glb_offset = None
            glb_datatype = None
        print "Table of references is created successfully."

    def __filter_dt(self, iterator, lst):
        reject_filters = {"/std/", "/stdlib.h/",
                          "/stdio.h/", "/_UNCATEGORIZED_/"}
        pass_filters = {"DWARF/"}
        count, ignore = 0, False
        while iterator.hasNext():
            dt = iterator.next()
            ignore = False
            name = str(dt.getPathName())
            for f in pass_filters:
                indx = name.find(f)
                if indx == -1:
                    ignore = True
                    break
            if ignore:
                continue
            for f in reject_filters:
                indx = name.find(f)
                if indx != -1:
                    ignore = True
                    break
            if not ignore:
                lst.append(dt)
        return


def main(currentProgram):
    start_time = time.time()
    gbcpi = ghidra_bcpi(currentProgram)
    gbcpi.getUsesofAllFilteredStructures()
    f_path = "/net/charm/usr/home/zahra/mantou/"+currentProgram.getName()+".pkl"
    # f_path="C:/Users/Zahra/Desktop/"+currentProgram.getName()+".pkl"
    f = open(f_path, "wb")
    pickle.dump(lst_map, f)
    f.close()
    duration = time.time() - start_time
    print "duration: --- "+str(duration)+" seconds or "+str(duration/60)+" minutes ---"


main(currentProgram)
