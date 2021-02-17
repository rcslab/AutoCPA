#####python query.py -d 2020-03-14_22:49:00 2020-03-18_23:05:00 -p v3_bb3 -c mem_load_retired.l1_miss -n 300
import pandas as pd
import numpy as np
import glob, os
import argparse
import datetime


path = "./tmp"


def process_args(l):
    size=np.zeros((len(l), 2))
    data=pd.DataFrame(size, columns=["name", "time"])
    data["name"]=l

    for i in range(0, data.shape[0]):
        name=data.iloc[i, 0]
        year=int(name[0:4])
        month=int(name[5:7])
        day=int(name[8:10])
        hour=int(name[11:13])
        minute=int(name[14:16])
        second=int(name[17:19])
        # data.iloc[i, 1:]=[year, month, day, hour, minute, second]
        data.iloc[i, 1]=datetime.datetime(year, month, day, hour, minute, second)
    data=data["time"]
    return data

def get_inputs():

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--date", nargs=2, metavar=('date1', 'date2'),
                            help="Enter the starting data and the ending date")

    parser.add_argument("-p", "--program", nargs=1, type=str, action='store', dest='program',
                            help="Enter the program you want to monitor")

    parser.add_argument("-c", "--counter", nargs=1, type=str, action='store', dest='counter',
                            help="Enter the performance counter you want to monitor")

    parser.add_argument("-n", "--topnodes", nargs=1, type=int, action='store', dest='nodenum',
                            help="Enter the number of top nodes you want to monitor")

    args = parser.parse_args()
    progname=args.program
    countername=args.counter
    nodenum=args.nodenum
    date11, date22 = args.date
    listofdates=[date11, date22]
    arg_dates=process_args(listofdates)

    return arg_dates, progname[0], countername[0], nodenum[0]

def filter(startend_dates, all_files):

    filtered= all_files[(all_files["time"]<=startend_dates.iloc[1]) &(all_files["time"]>=startend_dates.iloc[0])]

    filtered=filtered["name"].tolist()
    print(filtered)
    print(len(filtered))
    return filtered

def reframe(ff):
    size=np.zeros((len(ff), 2))
    data=pd.DataFrame(size, columns=["name", "time"])
    data["name"]=ff

    for i in range(0, data.shape[0]):
        name=data.iloc[i, 0]
        name=name[name.find("_")+1:]
        year=int(name[0:4])
        month=int(name[5:7])
        day=int(name[8:10])
        hour=int(name[11:13])
        minute=int(name[14:16])
        second=int(name[17:19])
        data.iloc[i, 1]=datetime.datetime(year, month, day, hour, minute, second)
        # data.iloc[i, 1:]=[year, month, day, hour, minute, second]
    return data

def get_files():
    cwd = os.getcwd()
    print ("Current working directory %s" % cwd)
    os.chdir(path)
    cwd = os.getcwd()
    print ("Directory changed successfully %s" % cwd)

    f=[]
    for file in glob.glob("*.rcs.uwaterloo.ca.bin"):
        f.append(file)

    return reframe(f)


def create_path(files, progname, countername, nodenum):
    mid_path=""
    for i in range(0, len(files)):
        mid_path += " -f tmp//"+files[i]
    path2="./bcpiutil/bcpiutil"+mid_path
    path2=path2+" -c "+countername+" -o "+progname+" -n "+str(nodenum) 

    return path2

def main():
    startend_dates, progname, countername, nodenum=get_inputs()
    all_files=get_files()
    filtered_files=filter(startend_dates , all_files)
    path2=create_path(filtered_files, progname, countername, nodenum)
    os.chdir("/net/charm/usr/home/zahra/zahra_rem/bcpinew")
    print(path2)
    os.system(path2)
    return

if __name__=="__main__":
    main()
