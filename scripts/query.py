#!/usr/bin/env python

# Example:
# python query.py -d 2020-03-14_22:49:00 2020-03-18_23:05:00 -p v3_bb3 -c mem_load_retired.l1_miss -n 300

import pandas as pd
import numpy as np
import glob
import os
import argparse
import datetime


def process_args(l):
    size = np.zeros((len(l), 2))
    data = pd.DataFrame(size, columns=["name", "time"])
    data["name"] = l

    for i in range(0, data.shape[0]):
        name = data.iloc[i, 0]
        year = int(name[0:4])
        month = int(name[5:7])
        day = int(name[8:10])
        hour = int(name[11:13])
        minute = int(name[14:16])
        second = int(name[17:19])
        data.iloc[i, 1] = datetime.datetime(
            year, month, day, hour, minute, second)
    data = data["time"]
    return data


def get_inputs():
    parser = argparse.ArgumentParser()

    parser.add_argument("-C", "--dir", default="/var/tmp", type=str, action='store',
                        help="The directory containing bcpid data")

    parser.add_argument("-d", "--date", nargs=2, metavar=('date1', 'date2'),
                        help="Enter the starting data and the ending date")

    parser.add_argument("-p", "--program", type=str, action='store', dest='program',
                        help="Enter the program you want to monitor")

    parser.add_argument("-c", "--counter", type=str, action='store', dest='counter',
                        help="Enter the performance counter you want to monitor")

    parser.add_argument("-n", "--topnodes", type=int, action='store', dest='nodenum',
                        help="Enter the number of top nodes you want to monitor")

    args = parser.parse_args()
    dir = args.dir
    progname = args.program
    countername = args.counter
    nodenum = args.nodenum
    date11, date22 = args.date
    listofdates = [date11, date22]
    arg_dates = process_args(listofdates)

    return arg_dates, dir, progname, countername, nodenum


def filter(startend_dates, all_files):

    filtered = all_files[(all_files["time"] <= startend_dates.iloc[1]) & (
        all_files["time"] >= startend_dates.iloc[0])]
    filtered = filtered["name"].tolist()
    return filtered


def reframe(ff):
    size = np.zeros((len(ff), 2))
    data = pd.DataFrame(size, columns=["name", "time"])
    data["name"] = ff

    for i in range(0, data.shape[0]):
        name = data.iloc[i, 0]
        name = name[name.find("_")+1:]
        year = int(name[0:4])
        month = int(name[5:7])
        day = int(name[8:10])
        hour = int(name[11:13])
        minute = int(name[14:16])
        second = int(name[17:19])
        data.iloc[i, 1] = datetime.datetime(
            year, month, day, hour, minute, second)

    return data


def get_files(dir):
    files = glob.glob(dir + "/bcpi_*.bin")
    return reframe(files)


def create_path(files, progname, countername, nodenum):
    mid_path = ""
    for file in files:
        mid_path += " -f " + file
    path2 = "./bcpiquery/bcpiquery" + mid_path
    path2 = path2 + " -c " + countername + " -o " + progname + " -n " + str(nodenum)
    return path2


def main():
    startend_dates, dir, progname, countername, nodenum = get_inputs()
    all_files = get_files(dir)
    filtered_files = filter(startend_dates, all_files)
    cmd = create_path(filtered_files, progname, countername, nodenum)
    os.system(cmd)


if __name__ == "__main__":
    main()
