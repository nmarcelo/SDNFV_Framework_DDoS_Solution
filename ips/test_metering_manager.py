from config import *
from manager import TopoManager, StatisticsAndRuleManager

test_meter = {}

topoManager = TopoManager()
statisticsRuleManager = StatisticsAndRuleManager()
test_meter["conn1"] =  {'macsrc': "00:00:00:00:00:01", 'macdst':"00:00:00:00:00:03"}

if __name__ == '__main__':

    if topoManager.is_topo_available():
        statisticsRuleManager.meterCommand(test_meter)