from config import *
from manager import TopoManager, StatisticsAndRuleManager
import logging
import time
import optparse
import sys
import threading
import pandas as pd
import math
import numpy as np
import matplotlib.pyplot as plt
import statistics

#from dijkstar import find_path

# python3 test_mtd_manager.py

statisticsRuleManager = StatisticsAndRuleManager()
topoManager = TopoManager()

if __name__ == '__main__':


    #parser = optparse.OptionParser()
    #parser.add_option("--one-shot", action="store_true", dest="oneshot", default=False, help="poll only once")
    #(options, args) = parser.parse_args()


    original_server = "00:00:00:00:00:FA"
    shadow_servers = ["00:00:00:00:00:FB",   "00:00:00:00:00:FC", "00:00:00:00:00:FD"]

    #original_server = "00:00:00:00:00:04"
    #shadow_servers = ["00:00:00:00:00:05",   "00:00:00:00:00:06"]

    attacker = '00:00:00:00:00:01'
    
    removeMTP = {}
    removeMTP["conn1"] =  {'macsrc': attacker, 'macdst':shadow_servers[0]}
    removeMTP["conn2"] =  {'macsrc': attacker, 'macdst':shadow_servers[1]}

    dropping = {}
    dropping["conn1"] =  {'macsrc': attacker, 'macdst':original_server}

    # test each module
    topoManager = TopoManager()
    if topoManager.is_topo_available():
        print("topology")
        topoManager.draw_topo()
        for i in range(0,1):
            #statisticsRuleManager.movingTargetDefense(attacker, original_server, shadow_servers)
            #statisticsRuleManager.removeMTDCommand(attacker, shadow_servers)
            #resetCommand(resetConnection)
            
            #statisticsRuleManager.dropCommand(dropping)
            statisticsRuleManager.removeDropCommand(dropping)
            #topoManager.get_hosts()
            #print(topoManager.__hosts)

    ## test the MTD module
    # mtd_times = []
    # topoManager = TopoManager()
    # if topoManager.is_topo_available():
    #     for i in range(0,1000):
    #         # add
    #         time.sleep(5)
    #         start = time.time()           
    #         statisticsRuleManager.removeMTDCommand(attacker, shadow_servers)
    #         statisticsRuleManager.removeDropCommand(dropping)
    #         statisticsRuleManager.movingTargetDefense(attacker, original_server, shadow_servers)
    #         end = time.time()
    #         mtd_times.append(end-start)
    
    # drop_times = []
    # if topoManager.is_topo_available():
    #     for i in range(0,1000):
    #         # add
    #         time.sleep(5)
    #         start = time.time()           
    #         statisticsRuleManager.removeMTDCommand(attacker, shadow_servers)
    #         statisticsRuleManager.removeDropCommand(dropping)
    #         statisticsRuleManager.dropCommand(dropping)
    #         end = time.time()
    #         drop_times.append(end-start)

    # recover_times = []
    # if topoManager.is_topo_available():
    #     for i in range(0,1000):
    #         # add
    #         time.sleep(5)
    #         start = time.time()           
    #         statisticsRuleManager.removeMTDCommand(attacker, shadow_servers)
    #         statisticsRuleManager.removeDropCommand(dropping)
    #         end = time.time()
    #         recover_times.append(end-start)

    # file1 = "/home/marcelo/Documents/FlowCollectionDataset/Times-"+"actions"+".txt"
    # with open(file1,"a") as f:
    #     f.write(','.join([str(elem) for elem in recover_times])+'\n')
    #     f.write(','.join([str(elem) for elem in mtd_times])+'\n')
    #     f.write(','.join([str(elem) for elem in drop_times])+'\n')


    # print(statistics.mean(recover_times), statistics.mean(mtd_times), statistics.mean(drop_times))


