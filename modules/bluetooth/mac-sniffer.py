import csv
import os
import threading

logfile = 'log.txt'

addresses = set()

def filterList():
  threading.Timer(2.0, filterList).start()

  fw = open(logfile, "r")
  for line in fw:
    if "Nest" in line or "Cam" in line:
      addresses.add(line[:17])
  fw.close()

  fw = open("addresses.csv", "w")
  writer = csv.writer(fw)
  writer.writerow(list(addresses))
  fw.close()
  

filterList()

# Scan mac addresses and log them
os.system('sudo hcitool lescan >> ' + logfile)
