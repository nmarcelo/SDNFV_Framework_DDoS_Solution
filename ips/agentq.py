import numpy as np
import random
from random import randrange
from IPython.display import clear_output
from collections import deque
import progressbar
from tensorflow.keras import Model, Sequential
from tensorflow.keras.layers import Dense, Embedding, Reshape, Conv2D, Dropout, MaxPooling1D, Flatten
from collections import defaultdict


# Agent
class AgentQ:
    def __init__(self, enviroment, optimizer):
        
        # Initialize atributes
        self._action_size = len(enviroment.action_space)
        self._optimizer = optimizer
        self.enviroment = enviroment

        
        self.q_values   = defaultdict(lambda: np.zeros(self._action_size))
        self.blockFlag  = 0

        # Initialize discount and exploration rate
        self.gamma = 0.7
        self.epsilon = 0.6
        self.alpha = 0.6


    def get_epsilon(self):
        return self.epsilon


    def set_epsilon_simulated_annealing(self, step, initial_epsilon):
        Temperature = 10
        if self.epsilon > 0.10:
            self.epsilon = (initial_epsilon)*np.exp(-step/Temperature)

    def calculate_epsilon(self, episode):
        Temperature = 10
        if self.epsilon > 0.05:
            return (0.6)*np.exp(-episode/Temperature) # 0.6 is the initial epsilon

    def get_random_action(self):
        return randrange(self._action_size) 

    
    def act(self, state):
        print("epsilon: ", self.epsilon)
        if np.random.rand() <= self.epsilon:
            print("Exploring")
            return self.get_random_action()

        return np.argmax(self.q_values[state])


