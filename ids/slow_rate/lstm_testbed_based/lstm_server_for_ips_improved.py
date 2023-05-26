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
import threading
import sys
import numpy as np
import joblib
import tensorflow as tf
import time


#app = Flask(__name__)
xtest = []
lstmModel = None
totalFlows = 0 # total of flows received
ids_slowrate_Flows = {}

from multiprocessing import  Manager
manager = Manager()
start_experiment = manager.Value('d',0.0)
triggered_start_mearesument = 0


columns =['FlowDuration', 'TotFwdPkts', 'TotBwdPkts', 'TotLenFwdPkts',
       'TotLenBwdPkts', 'FwdPktLenMax', 'FwdPktLenMin',
       'FwdPktLenStd', 'BwdPktLenMax', 'BwdPktLenMin',
       'BwdPktLenStd', 'FlowBytss', 'FlowPktss', 'FlowIATMean',
       'FlowIATStd', 'FlowIATMax', 'FlowIATMin', 'FwdIATMean',
       'FwdIATStd', 'FwdIATMin', 'BwdIATTot', 'BwdIATMean',
       'BwdIATStd', 'BwdIATMax', 'BwdIATMin', 'FwdPSHFlags',
       'FwdPktss', 'BwdPktss', 'PktLenMin', 'PktLenMax',
       'PktLenMean', 'PktLenStd', 'PktLenVar', 'FINFlagCnt',
       'SYNFlagCnt', 'RSTFlagCnt', 'PSHFlagCnt', 'DownUpRatio',
       'BwdPktsbAvg', 'BwdBlkRateAvg', 'SubflowFwdPkts',
       'SubflowFwdByts', 'SubflowBwdByts', 'InitFwdWinByts',
       'InitBwdWinByts', 'FwdSegSizeMin', 'IdleMean', 'IdleStd',
       'IdleMin']

class_values = {
    0:"normal",
    1:"slowread",
    2:"incomplete"
}

# Modify according to your targets
nsteps = 1   # for memoryless models, n = 1
ip_victim     = "192.168.56.101" 
currentAttack = "slowread"   # copy from class_values*, needs to be precise
experiment = "_a_1_r_300"
file1 = "/home/marcelo/Documents/FlowCollectionDataset/evalIPS-"+currentAttack+experiment+".txt"
modelPath  = "/home/marcelo/Documents/ReactiveSecuritySolution/ids/slow_rate/lstm_testbed_based/LSTM"
file2 = "/home/marcelo/Documents/FlowCollectionDataset/evalIPS-"+"learning"+experiment+".txt"

def getids_slowrate_Flows():
    global ids_slowrate_Flows
    r = ids_slowrate_Flows.copy()
    ids_slowrate_Flows.clear()
    return r

def raw_flow_to_values(flow):
	return [list(flow.values())]

def load_lstm_model():
    global lstmModel, yytest, center, scale, pca
    lstmModel = load_model(modelPath+"/model.h5")
    scale = joblib.load(modelPath+'/sc.joblib')
    pca = joblib.load(modelPath+'/pca.joblib')
def preprocessing(x_received):
     x_scaled = scale.transform(x_received.reshape(1,len(columns)))
     xpca = pca.transform(x_scaled)
     return xpca
def addapting(x):
    global xtest, nsteps
    #print(xtest)
    if len(xtest) < nsteps-1:
        xtest.append(x)
        return False
    else:
        xtest.append(x)
        return True
def evaluating(ipsource, macsource, ipdestination,macdestination, sourcePort, dstPort, protocol,timeStamp, pred_label):
    global totalFlows, ip_attacker,ip_victim,currentAttack,file1, ids_slowrate_Flows
    totalFlows = totalFlows + 1
    if pred_label != "incomplete": # systems with memory
        real_label = "normal"
        if ipsource == ip_victim or ipdestination == ip_victim: # labeled as an attack
            real_label =  currentAttack
        #print("Real: ",real_label,"Predicted: ",pred_label)
        #with open(file1,"a") as f:
        #    f.write(str(ipsource)+','+str(ipdestination)+ ','+str(sourcePort)+ ','+str(dstPort)+ ','+str(protocol)+ ','+str(timeStamp)+','+str(real_label)+','+str(pred_label)+','+str(totalFlows)+'\n')
        
        ids_slowrate_Flows[str(ipsource)+','+str(ipdestination)+ ','+str(sourcePort)+ ','+str(dstPort)+ ','+str(protocol)] = {'src':str(ipsource),'macsrc':str(macsource), 'dst':str(ipdestination),'macdst':str(macdestination), 'protocol':protocol, 'pred_label':str(pred_label),'totalFlows':totalFlows}
    return 0

def saving_action_IPS(ipsource, ipdestination,action,start_experiment):
    with open(file1,"a") as f:
        elapsed = time.time()
        f.write(str(ipsource)+','+str(ipdestination)+ ','+str(action)+','+str(elapsed)+'\n')
    return 0


def saving_learning_events(source,destination,e,timestep,curret_state, q_values,action,next_state,reward, epsilon):
    with open(file2,"a") as f:
        elapsed = time.time()
        f.write(str(source)+','+str(destination)+','+str(elapsed)+','+e+','+timestep+','+str(curret_state)+','+action+','+next_state+','+ reward +','+ epsilon +'\n')
    return 0

def setupFlask():
    app = Flask("lstm_server_for_ips_improved")
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    @app.route("/predict/slowrate", methods=['GET','POST'])
    def test():
    	global xtest, lstmModel 

    	yyhat = 2                       # incomplete state, if nstep>1, LSTM and GRU
    	if request.method == 'POST':
    		values = request.json
    		df = pd.DataFrame.from_dict(values, orient='index')
    		df = df[0]
    		ipsource = df['SrcIP']
    		macsource = df['SrcMac']
    		sourcePort = df['SrcPort']
    		ipdestination = df['DstIP']
    		macdestination = df['DstMac'] 
    		dstPort = df['DstPort']
    		protocol = df['Protocol']
    		timeStamp = df['Timestamp']
    		df = df[columns]
    		df = df.values.tolist()
    		x_pca = preprocessing(np.array(df))
    		if addapting(x_pca):
    		    xxtest = np.array(xtest)
    		    xtest = []
    		    xxtest = (np.resize(xxtest,(len(xxtest),15)))
    		    xxtest = np.array([xxtest])
    		    if xxtest.shape == (1,1,15):
        		    	try:
        		    	     xxtest = tf.convert_to_tensor(xxtest, dtype=tf.float32)
        		    	     yyhat = lstmModel.predict(xxtest)
        		    	     yyhat = np.argmax(yyhat)
        		    	except:
        		    	     print("Error on using lstm model")
        		             #print(class_values[yyhat])
    	evaluating(ipsource, macsource, ipdestination, macdestination, sourcePort, dstPort, protocol,timeStamp ,class_values[yyhat])
    	return class_values[yyhat],202

    @app.route("/AttackStarted", methods=['GET','POST'])
    def SetBeginoFStartAttack():
        global start_experiment
        if request.method == 'POST':
            values = request.json
            df = pd.DataFrame.from_dict(values, orient='index')
            df = df[0]
            ipdestination = df['DstIP']
            ipsource = df['SrcIP']
            macsource = df['SrcMac']
            macdestination = df['DstMac']
            saving_action_IPS(macsource,macdestination,'New_Experiment',start_experiment)
            saving_learning_events("0","0","0", "0", "0","0","0","0")

            print("********* triggered_start_measument *********")
        return "ok",202


    @app.route("/ips/getids_slowrate_Flows", methods=['GET'])
    def _getids_slowrate_Flows_():
        global ids_slowrate_Flows
        r = ids_slowrate_Flows.copy()
        ids_slowrate_Flows.clear()
        return r, 202 

    app.run(debug=False, host='127.0.0.1', port = 9001)

def start_IDS_Server():
    load_lstm_model() # slow rate
    print("Starting IDS")
    a = threading.Thread(target=setupFlask)
    a.daemon = True
    a.start()
    #a.join()


if __name__ == '__main__':
    # start IDS
    print("****************IDS started*************************")
