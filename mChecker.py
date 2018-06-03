#!/use/bin/python
import mSql
import mWorker
import mTask
import mPrinter

import sys
import time
import multiprocessing

import traceback


# https://www.owasp.org/index.php/List_of_useful_HTTP_headers
# https://securityheaders.io/
cspHeader = ["content-security-policy", "CSP"]
cspReportHeader = ["content-security-policy-report-only", "CSPR"]
xcspHeader = ["x-content-security-policy", "XCSP"]
xWebKitCSPHeader = ["x-webkit-csp", "WebKit"]
publicKeyPinsHeader = ["public-key-pins", "PKP"]
publicKeyPinsReportOnlyHeader = ["public-key-pins-report-only", "PKPR"]
strictTransportSecurityHeader = ["strict-transport-security", "STS"]
xssHeader = ["x-xss-protection", "XSS"]
xFrameOptionsHeader = ["x-frame-options", "X_frame"]
xContentTypeOptionHeader = ["x-content-type-options", "X_content_type"]
xFirefoxSpyd = ["x-firefox-spdy", "X_firefox_spyd"]
p3pHeader = ["p3p", "p3p"]

headersList = [
	cspHeader,
	cspReportHeader,
	xssHeader,
	xcspHeader,
	xWebKitCSPHeader,
	publicKeyPinsHeader,
	publicKeyPinsReportOnlyHeader,
	strictTransportSecurityHeader,
	xFrameOptionsHeader,
	xContentTypeOptionHeader,
	xFirefoxSpyd,
	p3pHeader
	]

# counters for progress info
countError = 0
countMetaError = 0
countCSP = 0
countCSPMetaTag = 0
countCSPReport = 0
countCSPReportMetaTag = 0

countXSSProt = 0

'''
Class of the main 'thread' 
It creates the tasks, calls the workers and handles the result
'''
class Checker(object):

	def __init__(self, listSites, listUserAgents,remoteExecution,debug,numWorkerForCPU):
		# set as private variables
		self.listSites = listSites
		self.listUserAgents = listUserAgents
		self.remoteExecution = remoteExecution
		self.debug = debug
		
		# create the db
		sqlObj = mSql.Database(headersList)
		sqlObj.create()
		
		# open file
		self.sqlObj = sqlObj
				
		# Establish communication queues
		self.tasks = multiprocessing.JoinableQueue()
		self.result = multiprocessing.Queue()
		#
		if(debug):
			self.num_workers = 1
		else:
			self.num_workers = multiprocessing.cpu_count() * numWorkerForCPU
		self.indexSite = 0
		self.indexAgent = 0
		
		if self.num_workers > len(listSites):
			self.num_workers = len(listSites)
			
	'''
	Given a list of headers it return the filtered list (with only the security headers) 
	'''
	def filterHeaders(self,result):
		filteredList = []
		if(result != None):
			for res in result:
				for item in headersList:
					if item[0] == res[0].lower():
						filteredList.append((res[0].lower(),res[1]))
		return filteredList
	'''
	Set some counters for statistic usage
	'''
	def updateStatistics(self,status,result,resultMeta):
		global countError
		global countMetaError
		global countCSP
		global countCSPReport
		global countCSPReportMetaTag
		global countXSSProt
		global totTime
		global countCSPMetaTag
		
		if result == None :
			countError = countError + 1
		else:
			for tup in result:
				if tup[0] == cspHeader[0]:
					countCSP = countCSP + 1
				elif tup[0] == cspReportHeader[0]:
					countCSPReport = countCSPReport + 1
				elif tup[0] == xssHeader[0]:
					countXSSProt = countXSSProt + 1

			#analise the meta only if the result is not null 
			if resultMeta == None :
				countMetaError = countMetaError + 1
			else:
				for tup in resultMeta:
					if tup[0] == cspHeader[0]:
						countCSPMetaTag = countCSPMetaTag + 1
					elif tup[0] == cspReportHeader[0]:
						countCSPReportMetaTag = countCSPReportMetaTag + 1
	
	'''
	It prints the found headers (belonging to the headersList)
	'''
	def getStringFoundHeaders(self,resultStatus,resultHeaders, resultMetaTags):
		text = "Result: " + str(resultStatus) + "\n"  + "-"*mPrinter.sizeDrawLine + "\n"
		if resultHeaders != None and len(resultHeaders) > 0:  # and (res.status == 200 or res.status == 302):
			text += (mPrinter.printWithSpace("Header", 30) + mPrinter.printWithSpace("Value", mPrinter.sizeDrawLine - 30) + "\n")
			for row in resultHeaders:
				text += (mPrinter.printWithSpace(row[0], 30) + 
					mPrinter.printWithSpace(row[1], mPrinter.sizeDrawLine - 30) + "\n")
		else:
			text += "No secure headers \n"
		text +=  "-"*mPrinter.sizeDrawLine + "\n"
		# print the meta found tags
		if resultMetaTags != None and len(resultMetaTags) > 0:
			text += "Header meta:\n"
			for row in resultMetaTags:
				text += (mPrinter.printWithSpace(row[0], 30) + 
					mPrinter.printWithSpace(row[1], mPrinter.sizeDrawLine - 30) + "\n")
		else:
			text += "No secure meta tags \n"
		text += "-"*mPrinter.sizeDrawLine
		return text

	'''
	Ex it returns a string with:
	
	Progress:	[ Tot: 4 | Done:4 | Working:0 ]
	Mode:		[ Workers: 1 | User agents: 1 ]
	Site:		[ opensource.org ]
	Agent:		[ Firefox 45 Ubuntu ]
	Counters:	[ CSP: 0 | CSP R: 0 | CSP Meta: 0 | XSS: 0 | Errors: 0 ]
	Estimate time:	[ Past : 0 h 0 m 24 s | Left 0 h 0 m 0 s ]
	'''
	def getStringInfo(self,currentNum, tot, totTime, site, user_agent):
		text = ("\n" + "#"*mPrinter.sizeDrawLine + "\n" +
		 		"Progress:	[ " + ("Tot: " + str(tot) + " | " + 
				"Done:" + str(currentNum) + " | " + 
				"Working:" + str((self.indexSite)*len(self.listUserAgents) + self.indexAgent - currentNum) +  " ]")	+ "\n" +	
		 		"Site:		[ " + site + " ]" + "\n"
		 		"Agent:		[ " + user_agent + " ]" + "\n"
		 		"Counters:	[ " + ("CSP: " + str(countCSP) + " | " + "CSP R: " + str(countCSPReport)  +  
				" | " + "CSP Meta: " + str(countCSPMetaTag)  + " | " +"CSP R Meta: " + str(countCSPReportMetaTag) + 
				" | " + "XSS: " + str(countXSSProt)  + 
				" | " + "Errors: " + str(countError) + " | " + "Errors Meta: " + str(countMetaError) + " ]") + "\n")
		
		####
		tm = (totTime / (currentNum+1) * (tot - currentNum))
		text += ("Estimate time:	[ Past : " + str(int((totTime) / 60 / 60)) + " h "
			    	+ str(int(((totTime) / 60) % 60)) + " m "
			    	+ str(int((totTime) % 60)) + " s"
				+ " | Left " + str(int(tm / 60 / 60)) + " h "
			    	+ str(int(tm / 60 % 60)) + " m "
			    	+ str(int(tm % 60)) + " s ]" + "\n" +
				 "#"*mPrinter.sizeDrawLine) 
		return text
	
	'''
	Add a task in the queue 
	'''
	def addATask(self):
		if(self.indexSite < len(self.listSites) ):
			self.tasks.put(mTask.Task(
								int(self.listSites[self.indexSite][0]) * len(self.listUserAgents) + self.indexAgent , 
								self.listSites[self.indexSite][1].replace("/", ""), 
								self.listUserAgents[self.indexAgent],self.debug))
			if(self.indexAgent >= (len(self.listUserAgents)-1)):
				self.indexAgent = 0
				self.indexSite += 1
			else:	
				self.indexAgent += 1
	
	'''
	Start the workers and add some tasks to the queue
	'''	
	def generateATaskForEachWorker(self):
		# Start Workers
		print 'Creating %d workers..' % self.num_workers
		workers = [ mWorker.Worker(self.tasks, self.result) for i in xrange(self.num_workers) ]
		for w in workers:
			w.start()
			
		# Enqueue a job for each worker
		while (self.indexSite)*len(self.listUserAgents) + self.indexAgent < self.num_workers:
			self.addATask()
			
	'''
	It get the result form the queue, it prints them and it saves them in the local database
	'''	
	def receiveresults(self):
		try:
			# start recording
			startTime = time.time()
			doneTasks = 0
			countForCommit = 0
			
			# the number of row * the number of agents used)
			totTasks = len(self.listSites) * len(self.listUserAgents)
			
			# Start read the self.result
			while doneTasks < totTasks:
				# get the result
				result = self.result.get()
				doneTasks += 1
				# start a new task
				self.addATask()
				# update time statistic
				totTime = time.time() - startTime
				# results
				resultId = result[0]				# 1
				resultSite = result[1]				# www.google.it
				resultStatus = result[2]			# 200
				resultAgent = result[3]				# [Firefox 45,'Mozilla/5.0 (Windows..)'] 
				resultTime = result[4]				# 1.3 (s)
				resultAllHeaders = result[5]		# [(name,value),(name2,value2)..]
				resultAllMetaHeaders = result[6]	# [(name,value),(name2,value2)..]
				resultHTMLPage = result[7]          # <html>....

				# filters
				securityHeaders = self.filterHeaders(resultAllHeaders)
				securityMetaHeaders = self.filterHeaders(resultAllMetaHeaders)
				# update statistics
				self.updateStatistics(resultStatus,resultAllHeaders,resultAllMetaHeaders)
				
				# clear the console
				if not self.remoteExecution:
					sys.stderr.write("\x1b[2J\x1b[H")
				
				toprint = self.getStringInfo(doneTasks, totTasks, totTime, resultSite , resultAgent) + "\n"

				if not self.remoteExecution:
					toprint += self.getStringFoundHeaders(resultStatus,securityHeaders, securityMetaHeaders) + "\n"

				# join the two set without duplications 
				securityHeaders.extend(val for val in securityMetaHeaders if val not in securityHeaders)

				# add a row to the DB
				toprint += self.sqlObj.addToDb(resultId,resultSite,resultStatus,resultAgent,resultTime,resultHTMLPage,resultAllHeaders,resultAllMetaHeaders,securityHeaders) + "\n"
				print toprint
					
				# every n row save on disk
				countForCommit += 1
				if (countForCommit >= 100):
					countForCommit = 0
					self.sqlObj.commit()
				
			print "*"*mPrinter.sizeDrawLine
			print "All tasks are done"
			print "\nFinish in %d s" % ((time.time() - startTime))
			#set end task to stops the workers
			for i in xrange(self.num_workers):
				self.tasks.put(None)
				
			# Wait for all of the self.tasks to finish
			self.tasks.join()
			print "All workers are stopped"
	
			# print the result
			if self.debug:
				print self.sqlObj.printTable()	
		
		except Exception , inst:
			print "*"*mPrinter.sizeDrawLine
			print "Type of error: " + str(type(inst))
			print "Args: " + str(inst.args)
			print "Inst: " + str(inst)
			print traceback.print_exc()
			print "*"*mPrinter.sizeDrawLine				
			return None
			
		finally:
			print "*"*mPrinter.sizeDrawLine
			print "Save and close db.."
			# close the db
			self.sqlObj.commit()
			self.sqlObj.close()
			print "Done!"
			print "*"*mPrinter.sizeDrawLine







