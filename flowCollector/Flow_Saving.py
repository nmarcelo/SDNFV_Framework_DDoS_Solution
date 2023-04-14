# -*- coding: utf-8 -*-
"""
Created on Mon Sep  7 10:40:31 2020

@author: Marcelo
"""
from flask import Flask, request, abort
from keras.models import load_model
from numpy import load
import pickle, time
import os
import logging
import pandas as pd
logging.basicConfig(level=logging.DEBUG)
#log = logging.getLogger('werkzeug')
#log.setLevel(logging.ERROR)
import sys
import numpy as np
app = Flask(__name__)
ids_slowrate_Flows = {}
ids_highrate_Flows = {}

# slow rate
columns = [ # flow identifier
		'SWID',
		'SrcMac',
		'DstMac']
class_values_application = {
    0:"normal",
    1:"slowbody",
    2:"slowread",
    5:"slowheader"
}

class_values_transport = {
    0:"normal",
    1:"syn",
    2:"udp"
}


ip_victim     = {"192.168.56.101":'ip'} # SW6

currentAttack = "slowread"
experiment = "_a_1_r_400"

file = "/home/marcelo/Documents/FlowCollectionDataset/eval3-"+currentAttack+experiment+".txt"

def raw_flow_to_values(flow):
	return [list(flow.values())]

def saving(ipsource, ipdestination, df):
    global ip_victim,currentAttack,file1
    real_label = "normal"
    if (ipsource in ip_victim) or (ipdestination in ip_victim): # labeled as an attack
        real_label =  currentAttack
    saveflow = str(','.join(str(e) for e in df))+","+str(real_label)+"\n"
    with open(file,"a") as f:
        f.write(saveflow)
    return 0
 
@app.route("/save", methods=['GET','POST'])
def test():
	global xtest, lstmModel  
	if request.method == 'POST':
		values = request.json
		df = pd.DataFrame.from_dict(values, orient='index')
		df = df[0]
		ipsource = df['SrcIP']
		ipdestination = df['DstIP']
		timeStamp = df['Timestamp']     
		df.drop(columns,axis='rows',inplace=True)
		df = df.values.tolist()
	saving(ipsource, ipdestination, df)
	return "saved",202
 
def start_IDS_Server():
    app.run(debug=True, host='0.0.0.0', port = 9001)

if __name__ == '__main__':
    # start IDS
    start_IDS_Server() 
