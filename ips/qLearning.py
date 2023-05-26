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
from threading import Thread
import itertools
from random import randrange
import coloredlogs

logging = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG',logging=logging)


from multiprocessing import Process, Manager
from tensorflow.keras.optimizers import Adam

from dijkstar import find_path


sys.path.insert(0, '/home/marcelo/Documents/SDNFV_Framework_DDoS_Solution/ids/slow_rate/lstm_testbed_based')


#python3 qLearning.py

from lstm_server_for_ips_improved import *

conns_testing = [["00:00:00:00:00:%s" % f"{n:02X}" ,   "00:00:00:00:00:FA"] for n in range(1,46)]


# for stress testing: Pending threads management
#
original_server = "00:00:00:00:00:FA"
shadow_servers = ["00:00:00:00:00:FB",   "00:00:00:00:00:FC",  "00:00:00:00:00:FD"]


from agentq import *


class Enviroment:
    def __init__(self, conn, index,network_state):
        global state
        self.statisticsRuleManager = StatisticsAndRuleManager()
        self.topoManager = TopoManager()
        self.conns_name  = conn
        self.conns_index = index
        self.child_state = self.getState(index,network_state,0)
        self.temp = {}
        self.action_space = ["Recover","MTD","Drop"]
        self.action_size  = len(self.get_actions())
        self.terminated   = False
       
    def get_actions(self):
        return self.action_space

    def reset(self,network_state,blockFlag):
        return self.getState(self.conns_index,network_state,blockFlag)

    def recover_action(self):
        temp = {}
        temp[str(self.conns_name[0])+','+str(self.conns_name[1])] = {'macsrc':str(self.conns_name[0]),'macdst':str(self.conns_name[1])}
        logging.warning("[IPS] Recovering Src: %s  Dst: %s",self.conns_name[0], self.conns_name[1]) 
        self.statisticsRuleManager.removeDropCommand(temp)
        self.statisticsRuleManager.removeMTDCommand(self.conns_name[0], shadow_servers)

    def auxiliar_action(self):
        temp = {}
        temp[str(self.conns_name[0])+','+str(self.conns_name[1])] = {'macsrc':str(self.conns_name[0]),'macdst':str(self.conns_name[1])}
        self.statisticsRuleManager.removeDropCommand(temp)
        self.statisticsRuleManager.removeMTDCommand(self.conns_name[0], shadow_servers)

    def drop_action(self):
        temp = {}
        temp[str(self.conns_name[0])+','+str(self.conns_name[1])] = {'macsrc':str(self.conns_name[0]),'macdst':str(self.conns_name[1])}
        logging.error("[IPS] Dropping Src: %s  Dst: %s",self.conns_name[0], self.conns_name[1]) 
        self.statisticsRuleManager.dropCommand(temp)
            
    def bandwidthAllocation_action(self):
        newPaths = {}
        if self.topoManager.is_topo_available():
            newpath = getattr(find_path(self.topoManager.graphDijkstar, str(self.hosts[0]) , str(self.hosts[1])), 'nodes' )
            newPaths [self.hosts[0] +"-"+ self.hosts[1]] = {'n'+str(i):newpath[i] for i in range(1,len(newpath)-1)}
        logging.info("[IPS] Rerouting : %s",newPaths) 
        self.statisticsRuleManager.reroutingCommand(newPaths)

    def moving_target_defense_action(self):
        self.statisticsRuleManager.movingTargetDefense(self.conns_name[0], original_server, shadow_servers)


    def reset_connection_action(self):
        temp = {}
        temp[str(self.conns_name[0])+','+str(self.conns_name[1])] = {'macsrc':str(self.conns_name[0]),'macdst':str(self.conns_name[1])}
        logging.info("[IPS] Reset Src: %s  Dst: %s",self.conns_name[0], self.conns_name[1]) 
        self.statisticsRuleManager.resetCommand(temp)

     
    def getState(self, index, network_state,blockFlag):
        try:
            child_state = np.array([np.max(np.array([network_state[:,index[0],index[1]],  network_state[:,index[1],index[0]]]),axis=0)])
        except:
            print("Error updating child_state")

        mT = 0.1
        if  child_state[0,1]   < mT and blockFlag == 0: # m=0 and bk=0
            self.child_state = 0 
        elif child_state[0,1]  < mT and blockFlag == 1: # m=0 and bk=1
            self.child_state = 1
        elif child_state[0,1]  >= mT and blockFlag == 0: # m=1 and bk=0
            self.child_state = 2
        elif  child_state[0,1] >= mT and blockFlag == 1: # m=1 and bk=1    
            self.child_state = 3
        return self.child_state

    def execute(self, action,start_experiment):
        saving_action_IPS(str(self.conns_name[0]),str(self.conns_name[1]),action,start_experiment)
        if action == "Drop":
            self.auxiliar_action() # clean previous rules
            self.drop_action()
            time.sleep(5)
        elif action =="MTD":
            self.auxiliar_action() # clear previous rules
            self.moving_target_defense_action()
        elif action == "Recover":
            self.recover_action() 
        else:
            pass

    def cost_action(self, action):
        if  action==1:
            return (0.2)  
        else : # no chance
            return 0

    def get_reward(self,timestep, action):
        
        self.terminated = False 

        # set reward
        if  self.child_state == 0: # m=0 and bk=0
            return (1 - self.cost_action(action)) 
        if  self.child_state == 1: # m=0 and bk=1
            return (0-self.cost_action(action)) 
        if  self.child_state == 2: # m=1 and bk=0
            #self.terminated = True
            return (-2-self.cost_action(action)) 
        if  self.child_state == 3: # m=1 and bk=1
            return (0-self.cost_action(action))  
        else : # no chance
            return -100

    def step(self, timestep, action,network_state,start_experiment):
        self.execute(self.action_space[action],start_experiment)
        time.sleep(5)
        if action == 2:  # block 
            blockFlag = 1
        else:
            blockFlag = 0
        next_state = self.getState(self.conns_index,network_state,blockFlag) 
        reward = self.get_reward(timestep, action)    
        info = "cool"
        return next_state, reward, self.terminated, blockFlag


def QLearning(conn, index, main_state, start_experiment):
    # wait all threads start
    time.sleep(20)
    # Prepare Agent for training
    optimizer = Adam(learning_rate=0.05)

    enviroment = Enviroment(conn, index,np.array(main_state))

    agent = AgentQ(enviroment, optimizer)
    nts = 70 # number of training samples
    nsut = 80 # number of steps before to update the target dnn
    num_of_episodes = 1000000
    timesteps_per_episode = 10000


    for e in range(1, num_of_episodes):
        #print("============== Episode ", e,"=============")
        # Reset the enviroment
        agent_state = enviroment.reset(np.array(main_state),agent.blockFlag)

        # Initialize variables
        terminated = False

        initial_epsilon = 0.6
        for timestep in range(1, timesteps_per_episode):
            # Select action e greedy
            print('step', timestep)
            
            agent.set_epsilon_simulated_annealing(timestep,initial_epsilon)

            action = agent.act(agent_state) # choose action to apply
            
            # Take action    
            next_state, reward, terminated, blockFlag = enviroment.step(timestep, action,np.array(main_state),start_experiment)              
            agent.blockFlag = blockFlag


            # save event for performance analysis
            saving_learning_events(str(conn[0]),str(conn[1]),str(e),str(timestep), agent_state, str(agent.q_values), str(enviroment.action_space[action]),str(next_state),str(reward),str(agent.get_epsilon()))
            print("***St: " + str(agent_state) + "||" + "Q = "+str(agent.q_values) + "||"+ "ACTION: ", str(enviroment.action_space[action]) +"||"+ "St+1: " + str(next_state)+ "||" +"REWARD: " + str(reward) )
            
            # TD update
            best_next_action = np.argmax(agent.q_values[next_state])    
            td_target = reward + agent.gamma  * agent.q_values[next_state][best_next_action]
            td_delta = td_target - agent.q_values[agent_state][action]
            agent.q_values[agent_state][action] += agent.alpha * td_delta

            # update agent state
            agent_state = next_state
            


            
            
def activation_function_dropping(x): # check
    indexes_0 = (x==0) # force the function to start from zero
    y = 1/(1+np.exp(-(x-6)))
    y[indexes_0] = 0
    return y


class threading_main(Process): # changed Thread
   def __init__(self,ids_slowrate_Flows_process,start_experiment):
       # Call the Thread class's init function
       Process.__init__(self) # changed Thread
       self.ids_slowrate_Flows_process = ids_slowrate_Flows_process # proxy access
       self.start_experiment = start_experiment
       self.statisticsRuleManager = StatisticsAndRuleManager()
       self.topoManager = TopoManager()
       if self.topoManager.is_topo_available():
        self.hosts = self.topoManager.get_hosts()


   def getConnsBW_state(self):
        conns = self.statisticsRuleManager.getconnsbandwidth()
        df = pd.DataFrame(conns,columns=['Src','Dst','bw'])
        N = int(math.sqrt(df.shape[0]))
        B = (df['bw'].values).reshape((N,N))
        B = B/EDGE_BANDWIDTH_LIMIT 
        return B

   def getConnsD_state_slow(self):
        D1 = pd.DataFrame(0,index=self.hosts,columns = self.hosts)
        M1 = pd.DataFrame(0,index=self.hosts,columns = self.hosts)
        #temp = getids_slowrate_Flows()
        temp   = dict(self.ids_slowrate_Flows_process)
        if len(temp)>0:
            for flowid, info in (temp.copy()).items():
                if info["pred_label"] != 'normal':
                    D1[info['macsrc']][info['macdst']] = 1
                    M1[info['macsrc']][info['macdst']] +=1
            M1 = activation_function_dropping(M1.to_numpy())
            return D1.to_numpy(), M1
        print("No data received from IDS")
        return D1.to_numpy(), M1.to_numpy()

   def getState(self):
    global state
    if self.topoManager.is_topo_available():
        B = self.getConnsBW_state()
        [D,M] = self.getConnsD_state_slow()
        if B.shape == D.shape:
            state = np.array([D,M,B])
        else:
            print("ONOS controller unable to monitor bandwidth")
            state = np.array([D,M,M]) # zeros
    return state

   def run(self):
       time.sleep(10)
       manager = Manager()
       main_state = manager.list()
       # get hosts of system
       #print('Hosts in the System: ', self.hosts)
       print('Number of hosts: ',len(self.hosts))
       
       activeThreadsForSuspiciousConns = {};
       controlOFThreats = 1
       while 1:
            try: # update main state
                current_state = self.getState()
                main_state[:] = current_state.tolist()
                #print('state main_thread',sum(current_state[2]))
            except:
                 print("Error updating Main state")
            
            # TODO control of threads
            if (controlOFThreats == 1):
                conns   = itertools.combinations(self.hosts,2)

                indexes = itertools.combinations(range(0,len(self.hosts)),2)
                for conn, index in zip(conns, indexes):
                    for conn_testing in conns_testing:
                        if ((conn[0]== conn_testing[0] and conn[1] == conn_testing[1])) or ((conn[1]== conn_testing[0] and conn[0] == conn_testing[1])): 
                            x = Process(target=QLearning, args=(conn_testing,index,main_state,self.start_experiment))
                            x.daemon = True
                            x.start()
                            activeThreadsForSuspiciousConns[str(index)] = {'index':str(index),'state':'Active','conn':str(conn_testing)}
                            print("Active threads:" + str(len(activeThreadsForSuspiciousConns)))
                            break    
                controlOFThreats = controlOFThreats + 1
            time.sleep(5) # provide enough time so that the BW can be captured correctly
            print('next step')
                


def network_state_monitoring(name): # monitor states D and M
    global ids_slowrate_Flows_process
    k = 1
    while 1:
        time.sleep(4)
        temp = getids_slowrate_Flows()
        ids_slowrate_Flows_process[:] = temp.items()

if __name__ == '__main__':
    global ids_slowrate_Flows, state, ids_slowrate_Flows_process
    main_manager = Manager()
    ids_slowrate_Flows_process = main_manager.list()


    # state monitoring thread
    state_monitor_thread = Thread(target=network_state_monitoring, args=(1,)) 
    state_monitor_thread.start()


    # Supervisor Process
    main_thread = threading_main(ids_slowrate_Flows_process, start_experiment)
    main_thread.start()

    #  IDs server
    start_IDS_Server() # all process must be execute before this line

    





