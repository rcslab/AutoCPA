
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
    args = parser.parse_args()
    date11, date22 = args.date
    listofdates=[date11, date22]
    arg_dates=process_args(listofdates)
    # print( "Dates that are entered are: {} avali {} 2vomi {} ".format(
    #         args.date,
    #         date11,
    #         date22
    #         ))

    return arg_dates

def filter(startend_dates, all_files):
    # print("start and ending dates(minutes and seconds ):")
    # print(startend_dates.iloc[1, 5], startend_dates.iloc[1, 6])
    # print(startend_dates.iloc[0, 5], startend_dates.iloc[0, 6])
    #filtered=data[(data["month"]<=12) & (data["month"]>5) & (data["minute"]>40)]
    #filtered=all_files[(all_files["month"]==12) & (all_files["day"]== 11) & (all_files["hour"]==19) & (all_files["minute"]<36) & (all_files["minute"]>33)]
    filtered= all_files[(all_files["time"]<=startend_dates.iloc[1]) &(all_files["time"]>=startend_dates.iloc[0])]
    # filtered=all_files[(all_files["year"]<=startend_dates.iloc[1, 1]) & (all_files["year"] >= startend_dates.iloc[0, 1]) &
    #                     (all_files["month"]<=startend_dates.iloc[1, 2]) & (all_files["month"] >= startend_dates.iloc[0, 2]) &
    #                     (all_files["day"]<=startend_dates.iloc[1, 3]) & (all_files["day"] >= startend_dates.iloc[0, 3]) &
    #                     (all_files["hour"]<=startend_dates.iloc[1, 4]) & (all_files["hour"] >= startend_dates.iloc[0, 4]) &
    #                     (all_files["minute"]<=startend_dates.iloc[1, 5]) & (all_files["minute"] >= startend_dates.iloc[0, 5]) &
    #                     (all_files["second"]<=startend_dates.iloc[1, 6]) & (all_files["second"] >= startend_dates.iloc[0, 6])]

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


def create_path(files):
    mid_path=""
    for i in range(0, len(files)):
        mid_path += " -f tmp//"+files[i]
    #path2="./a.out"+mid_path+" -c mem_load_retired.l1_miss -o version3 -n 10"
    path2="./bcpiutil/bcpiutil"+mid_path
    path2=path2+" -c mem_load_retired.l1_miss -o version3 -n 10" 

    return path2

def main():
    startend_dates=get_inputs()
    all_files=get_files()
    filtered_files=filter(startend_dates , all_files)
    path2=create_path(filtered_files)
    os.chdir("/net/charm/usr/home/zahra/zahra_rem/bcpinew")
    #os.chdir("/net/charm/usr/home/zahra/Desktop/bcpiutil_new")
    #os.system("ls")
    print(path2)
    os.system(path2)
    return

if __name__=="__main__":
    main()
