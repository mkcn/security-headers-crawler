#!/use/bin/python

import mChecker
import mCVS
import sys
import traceback

'''		
	Given a file .csv with a list of sites
	and a list of possible user agents
	it downloads for each of them the used headers
	and it saves all the headers in a DB.
	
	The main goal is to check which site uses the CSP.
	
	Mirko Conti
'''

# name file web sites list 500
defaultNameFieSites500 = "input/top-500.csv"
# name file web sites list 1 milion
defaultNameFileSites1M = "input/top-1m.csv"
# debug list
defaultNameFileSitesDebug = 'input/listSiteDebug.csv'
# name file user agents list 
defaultNameFileAgents = "input/listUserAgents.csv"


'''
The main function handles the input parameters,
it starts the workers and then it is listening to receive the results 
'''
def main(argv):
	try:
		# now set the default values (first user agent of the list)
		cvsAgent = mCVS.CVS(defaultNameFileAgents,1)
		cvsAgent.openFile()
		listUserAgents = cvsAgent.getArray()
		# object to retrieve the list of web sites  
		cvsSites = mCVS.CVS(defaultNameFileSites1M,1000000)
		# boolean used to decide what to print 
		remoteExecution = False
		debug = False 
		# number of worker for each CPU 
		numWorkerForCPU = 32
		
		if len(argv) >= 2:
			indexArg = 1
			while indexArg < len(argv):
				if argv[indexArg] == "-d":  	# debug
					cvsSites = mCVS.CVS(defaultNameFileSitesDebug,max)
					debug = True
				elif argv[indexArg] == "-m":  	# multi agent
					cvsAgent = mCVS.CVS(defaultNameFileAgents,max)
					cvsAgent.openFile()
					listUserAgents = cvsAgent.getArray()
				elif argv[indexArg] == "-n": 
					cvsSites = mCVS.CVS(defaultNameFileSites1M,int(argv[indexArg + 1]))
					indexArg = indexArg + 1  	# skip next arg
				elif argv[indexArg] == "-r": 
					remoteExecution = True
				elif argv[indexArg] == "-w": 
					numWorkerForCPU = int(argv[indexArg + 1])
					indexArg = indexArg + 1  	# skip next arg
				elif argv[indexArg] == "-i":  	# input
					cvsSites = mCVS.CVS(argv[indexArg + 1],max)
					indexArg = indexArg + 1  	# skip next arg
				else: 							# -h
					print "Usage: python checker.py [OPTION]"
					print "Default loaded list : " + defaultNameFileSites1M
					print ""
					print " -d			debug mode, use the debug list: " + defaultNameFileSitesDebug
					print " -m			multi user agents mode"
					print " -r			remote execution mode"
					print " -w num			num of worker for each CPU , defaul 32"
					print " -n num			use just the first n item of the default list"
					print " -i name_list_file.csv	input file .csv with the list of web sites"
					exit(0)
				indexArg = indexArg + 1
		
		# get the list of web sites
		cvsSites.openFile()	
		listSites = cvsSites.getArray()	

		print "Loaded %d sites" % (len(listSites))
		print "Loaded %d user agents" % (len(listUserAgents))
		# 
		checker =  mChecker.Checker(listSites, listUserAgents,remoteExecution,debug,numWorkerForCPU)
		# start  tasks
		checker.generateATaskForEachWorker()
		# start the receiver
		checker.receiveresults()
				
	except Exception , inst:
		print "General error"	
		print "Type of error: " + str(type(inst))
		print "Args: " + str(inst.args)
		print "Inst: " + str(inst)
		print traceback.print_exc()
		return None

if __name__ == "__main__":
	main(sys.argv)	
	#this stops the threads of the workers in case of error of the main thread
	exit(0)

		












