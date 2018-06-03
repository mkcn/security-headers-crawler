#!/use/bin/python
import httplib
import urlparse
import csv
import sys
import sqlite3
import datetime
import time
import os
from lxml.html import fromstring


'''		
	Given a file csv with a list of sites
	and a list of possible user agents
	it downloads for each of them the used headers
	and it saves all the headers in a DB.
	
	The final goal is to check which site use the CSP.
	
	Mirko Conti
'''
#name database
defaultOutputDirectory = "output/"
defaultNameDatabase = "result.db"
#name file web sites list
defaultNameFileSite = "input/listSites.csv"
#name file agents list
fileAgent = "input/listAgents"


#list column sql
columnId = "ID"
columnSite = "Site"
columnAgent = "Agent"
columnCode = "Code"
columnTime = "Time"
columnHeaders = "Headers"

#https://www.owasp.org/index.php/List_of_useful_HTTP_headers
#https://securityheaders.io/
cspHeader = ["content-security-policy" , "CSP"]
cspReportHeader = ["content-security-policy-report-only", "CSPR"]
xcspHeader =  ["X-Content-Security-Policy","XCSP"]
xWebKitCSPHeader = ["X-WebKit-CSP","WebKit"]

publicKeyPinsHeader = ["Public-Key-Pins", "PKP"]
publicKeyPinsReportOnlyHeader = ["Public-Key-Pins-Report-Only","PKPR"]
strictTransportSecurityHeader = ["strict-transport-security","STS"]
xssHeader = ["x-xss-protection","XSS"]
xFrameOptionsHeader = ["x-frame-options", "X_frame"]
xContentTypeOptionHeader = ["x-content-type-options","X_content_type"]
xFirefoxSpyd = ["X-Firefox-Spdy","X_firefox_spyd"]
p3pHeader = ["p3p","p3p"]

headersList = [
	cspHeader,
	cspReportHeader,
	xcspHeader,
	xWebKitCSPHeader,
	publicKeyPinsHeader,
	publicKeyPinsReportOnlyHeader,
	strictTransportSecurityHeader,
	xssHeader,
	xFrameOptionsHeader,
	xContentTypeOptionHeader,
	xFirefoxSpyd,
	p3pHeader
	]
	
#meta tag value
cspMeta = ["content-security-policy", "CSPmeta"]
csprMeta = ["content-security-policy-report-only", "CSPRmeta"]

#http and https
http = "http"
https = "https"

#counters for progress info
countError = 0
countCSP = 0
countCSPReport = 0
countCSPMetaTag = 0
countXSSProt = 0

#save the time
totTime = 0

#graphic element
sizeDrawLine = 100

#list of agents that we want to check
multi_agent = [
	["Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36","Chrome  41 Windows"],
	["Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0","Firefox 45 Ubuntu"],
	["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36","Chrome  49 Linux"]
	]
	
#single agent
single_agent = [["Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0","Firefox 45 Ubuntu"]]
	

	
#list of website just for debug
debug_list = [
	["1","stackoverflow.com"], 	# used for meta tag
	["2","discuz.net"],		# weird redirect
	["3","blogger.com"],		# redirect in google with pars
	["4","w3.org"],		# different behaviour
	["5","geocities.jp"],   	# p3p header
	["6","youtu.be"],      	# doesn't with www
	["7","fda.gov"],     		# doesn't work without www
	["8","youtube.com"],		# sometime use csp , but not always
	["9","cocolog-nifty.com"], 	# xss header
	["10","webs.com"],    		# weird location
	["11","mozilla.com"], 		# 5 redirects
	["12","upenn.edu"],  		#
	["13","yellowbook.com"],
	["14","army.mil"],       	#
	["15","clickbank.net"], 	# 403
	["16","fda.gov.com"]		# offline website
	]

'''
used for create eq distances between columns in table in the terminal
'''
def printWithSpace(strs,space):
	dis = space
	if len(strs) > dis:
		return strs[0:dis] + "|"
	else:
		return strs + " "*(dis-len(strs)) + "|"

'''
given a site and an agent it does the request and get the headers
it stores them in the DB and it shows them in the terminal
'''
def downloadHeaders(site,protocol,path, agent,depth):
	try:
		#https://stackoverflow.com/questions/14949644/python-get-header-information-from-url
		#conn = httplib.HTTPConnection(site)
		print "\n"
		print "** Now working on.. **"
		print "Site: "+ site
		print "Protocol:" + protocol
		print "Path: " + path

       		depth += 1
       		#to avoid infinite loops
       		if depth < 10 :
       			if (protocol == http):
				conn = httplib.HTTPConnection(site, timeout=10)
			else: #https
				conn = httplib.HTTPSConnection(site, timeout=10)
			conn.putrequest("GET", path)
			conn.putheader('User-Agent',agent)
			conn.putheader('Upgrade-Insecure-Requests',1) #header send by chrome to require CSP
			conn.endheaders()
			res = conn.getresponse()
			
			#TODO
			#try do a request without www. and if fail try with it
				
			#if redirected
			if(res.status == 301 or res.status == 302 or res.status == 303 or res.status == 307):
				newLoc = res.getheader("location")
				print  site + " -> move to -> " + newLoc
				if (newLoc != None):
					urlp = urlparse.urlparse(newLoc,allow_fragments=True)
					if( urlp.netloc == ''): # case of location = "/it/"
						newSite = site
					else:	#case of location = "www.otherwebsite.it"
						newSite = urlp.netloc
					if ( urlp.scheme == ''): # case of location = "//www.site.org/"
						newScheme = http
					else:
						newScheme = urlp.scheme
					return downloadHeaders(newSite,newScheme,urlp.path, agent,depth)
			return res
		else:
			return None	
	except Exception , inst:
		print "*"*sizeDrawLine
		print "Error in downloadHeaders with: " + site + "," + agent
	 	print "Type of error: " + str(type(inst))
		print "Args: " + str(inst.args)
		print "Inst: "+ str(inst)
		print "*"*sizeDrawLine
		return None


'''
look for CPS usage in meta tag
#TODO look for CSPR and other Headers
'''
def findMetaTags(res):
	try:
		if (res != None):
			tree = fromstring(res.read())
			#out =  tree.xpath("//meta[@http-equiv]/@content") #generic http-equiv
			out =  tree.xpath("//meta[@http-equiv='" + cspHeader[0] + "']/@content")
			if (out != None and len(out) > 0):
				return out
			else:
				return None
	except Exception , inst:
		print "*"*sizeDrawLine
		print "Error in findMetaTags"
	 	print "Type of error: " + str(type(inst))
		print "Args: " + str(inst.args)
		print "Inst: "+ str(inst)
		print "*"*sizeDrawLine
		return None

'''
set some counter for statistic results
'''
def updateStatistics(res,tags,startTime):
	global countError
	global countCSP
	global countCSPReport
	global countXSSProt
	global totTime
	global countCSPMetaTag
	
	#update time statistic
	totTime =  time.time() - startTime
	
	if res != None : #and (res.status == 200 or res.status == 302):
	    	if(str(res.getheader(cspHeader[0])) != "None"):
	    		countCSP = countCSP + 1
	    	if(str(res.getheader(cspReportHeader[0])) != "None"):
			countCSPReport = countCSPReport + 1
		if(str(res.getheader(xssHeader[0])) != "None"):
			countXSSProt = countXSSProt + 1		
	else:
		countError = countError + 1
	
	if tags != None and len(tags) > 0:
		countCSPMetaTag = countCSPMetaTag + 1
	

'''
it print the found headers (belong to the headersList)
and the meta tag about
'''
def getStringFoundHeaders(res,tags):
	if res != None : #and (res.status == 200 or res.status == 302):
		print "Code reply: " + str(res.status)
		print "-"*sizeDrawLine
		print (printWithSpace("Header",30) + printWithSpace( "Value",sizeDrawLine-30))
		print "-"*sizeDrawLine
		for index in range(len(headersList)):
		   	print (printWithSpace(headersList[index][0],30) +
				printWithSpace( str(res.getheader(headersList[index][0])),sizeDrawLine-30))
	else:
		print "Error: web site not available"
		
	print "-"*sizeDrawLine
	#print the meta found tags
	if tags != None and len(tags) > 0:
		print "Header meta:"
		for row in tags:
			print str(row)
		print "-"*sizeDrawLine
	else:
		print "No meta tag"
		print "-"*sizeDrawLine

'''
print ex:

Site:         [ 1/500 - facebook.com ]
Agent:        [ 2/3 - Firefox 45 Ubuntu ]
Statistics:   [ CSP: 2/3 | CSP R: 0/3 | CSP Meta: 0/3 | XSS: 2/3 | Errors: 0/3 ]
Stimate time: [ Past : 0 h 0 m 8 s | Left 0 h 13 m 11 s ]
'''
def getStringInfo(currentNum,tot,indexAgent,site,user_agent):
	print "\n"
	print "#"*sizeDrawLine
	print "Site:         [ " + str(currentNum) + "/" + str(tot) + " - " + site + " ]"
	print "Agent:        [ " + (str(indexAgent + 1) + "/" + str(len(user_agent)) + " - "
			+  user_agent[indexAgent][1] + " ]" )
	print "Statistics:   [ " + ("CSP: " + str(countCSP)  + "(/" + str(len(user_agent)) + ")" +
			 " | " + "CSP R: " + str(countCSPReport)  + "(/" + str(len(user_agent)) + ")"+
			 " | " + "CSP Meta: " + str(countCSPMetaTag)  + "(/" + str(len(user_agent)) + ")" +
			 " | " + "XSS: " + str(countXSSProt) + "(/" + str(len(user_agent)) + ")" +
			 " | " + "Errors: " + str(countError)  + "(/" + str(len(user_agent)) + ")" + " ]")
	
	####
	print ("Stimate time: [ Past : " + str(int((totTime)/60/60)) +" h "
		    	+ str(int(((totTime)/60) % 60 )) +" m "
		    	+ str(int((totTime) % 60)) + " s"
			+ " | Left " + str(int((totTime/currentNum*(tot-currentNum))/60/60)) +" h "
		    	+ str(int(((totTime/currentNum*(tot-currentNum))/60) % 60 )) +" m "
		    	+ str(int((totTime/currentNum*(tot-currentNum)) % 60)) + " s ]" )
	print "#"*sizeDrawLine

'''
add a row to the db
with id, site,time of request, code , agent and the headers
'''
def addToDb(connSql, sqlTableName, num,res,tags,site,agent,time):
	comma = "','"
	try:
		#TODO use secure sql queries ..VALUES (%s, %s, %s)
		print "Executing query.."
		exeInsert = ("INSERT INTO " + sqlTableName + " ( " +
		 	     columnId + "," + 		#id site
		 	     columnSite + "," + 	#name site
			     columnAgent + "," + 	#used agent
			     columnTime + "," + 	#reply time
		 	     columnCode + ",")		#reply code http
		for name in headersList:
			exeInsert += (name[1] + ",")	#single header
		exeInsert += (columnHeaders + "," + 	#all headers
			     cspMeta[1] )		#meta tag
		#now the values
		exeInsert += (")\nVALUES ('" +
			     str(num) + comma +		#it an int
			     site + comma +
			     agent + "'," +
			     str(time) + ",") 		#it's a float
		
		
		#set the headers
		if res != None : #and (res.status == 200 or res.status == 302):
			exeInsert += (str(res.status) + ",'") #code
			for name in headersList:
				exeInsert += (str(res.getheader(name[0])).replace("'","") + comma)
			exeInsert += (str(res.getheaders()).replace("'","") + comma )
		else:
			exeInsert += ("-1" + ",'") # code error no connection
			for name in headersList:   #single headers
				exeInsert += ("" + comma)
			exeInsert += ("" + comma)   #all headers
			
		if tags != None and len(tags) > 0:
			exeInsert += (tags[0] + "')") #temp, save just the first
		else:
			exeInsert += ("" + "')")
		#print exeInsert + "..."
		connSql.execute(exeInsert);
		print "Execution query complete!"
	except Exception , inst:
		print "*"*sizeDrawLine
		print "Error in addToDb with : " + site + "," + agent
	 	print "Type of error: " + str(type(inst))
		print "Args: " + str(inst.args)
		print "Inst: "+ str(inst)
		print "*"*sizeDrawLine
		return None
	
		
'''
it calls the downloadHeaders using different agents
'''	
def generateTasks(connSql,sqlTableName,num,tot,site,startTime,user_agent):
	#useWWW = False
	lenAgentList = len(user_agent)
	for indexAgent in range(lenAgentList):
		res = None
		#we start trying with http
		start = time.time()

		#get the header from an http request
		res =  downloadHeaders(site,http,"/", user_agent[indexAgent][0],0)
		stop = time.time()
		diffTime = (stop - start)
		
		#look for header in meta tag in the html
		tags = findMetaTags(res)
		#clear the console
		sys.stderr.write("\x1b[2J\x1b[H")
		#update counters
		updateStatistics(res,tags,startTime)
		#print info
		getStringInfo(num,tot,indexAgent, site,user_agent)
		#print headers
		getStringFoundHeaders(res,tags)
		#add row to the DB
		addToDb(connSql,sqlTableName,(num*lenAgentList + indexAgent),res,tags,site,user_agent[indexAgent][1],diffTime)
		
		#we test with different browsers only the first 200 web sites
		#for speed reason
		#if (num > 200):
		#	break;
		
		#if error block the for
		if (res == None):
			break;

'''
print same column of the table
'''
def printTable(connSql,sqlTableName):
	cursor = connSql.execute(("SELECT " + columnId  + "," +
					columnSite + "," +
					columnCode + "," +
					columnAgent + "," +
					columnTime + "," +
					cspHeader[1] + "," +
					xssHeader[1] + " from " + sqlTableName))
	print ("|" + printWithSpace(columnId,5) +
		printWithSpace(columnSite,20)   +
		printWithSpace(columnCode,5)    +
		printWithSpace(columnAgent,10)   +
		printWithSpace(columnTime,15)   +
	 	printWithSpace(cspHeader[1],30) +
	 	printWithSpace(xssHeader[1],20))

	print "|" + "-"*(sizeDrawLine-1)
	for row in cursor:
		print ("|" + printWithSpace(str(row[0]),5)
		 	+ printWithSpace(row[1],20)
		 	+ printWithSpace(str(row[2]),5)  # code
		 	+ printWithSpace(row[3],10)
		 	+ printWithSpace(str(row[4]),15) # TIME FLOAT
		 	+ printWithSpace(row[5],30)
		 	+ printWithSpace(row[6],20))
	print "|" + "-"*(sizeDrawLine-1)


def getListSite(nameFileSite):
	# opens the csv file
	fo = open(nameFileSite, 'rb')
	# get total rows of the csv
	totLine = len(fo.readlines())
	fo = open(nameFileSite, 'rb')

	#skip header lines
	totLine = totLine - 1
	r = 0
	while r < 1:
		fo.next()
		r = r + 1
	reader = csv.reader(fo)
	return (reader,totLine,fo)

def createDB():
	#check if directory exist
	if not os.path.exists(defaultOutputDirectory):
    		os.makedirs(defaultOutputDirectory)
	#connect to the database
	connSql = sqlite3.connect(defaultOutputDirectory + defaultNameDatabase)

	#Set an unique name for the table
	today = datetime.datetime.now()
	sqlTableName = ("T_" + str(today.year) + "_" +
		str(today.month) + "_" +
		str(today.day) + "_" +
		str(today.hour) + "_" +
		str(today.minute) + "_" +
		str(today.second))
	#create new table
	createString = ("CREATE TABLE " + str(sqlTableName) + " ( "  +
		columnId  + " STRING PRIMARY KEY NOT NULL,\n  " +
		columnSite + " TEXT NOT NULL,\n  " +
		columnAgent + " TEXT NOT NULL,\n  " +
		columnTime + " FLOAT,\n  " +
		columnCode + " INT NOT NULL,\n  ")
	for name in headersList:
		createString += (name[1]  + " TEXT,\n  ")
	# we save all headers
	createString += (columnHeaders + " TEXT,\n  ")
	# we save the meta tag about csp
	createString += (cspMeta[1] + " TEXT,\n  ")
	createString += (csprMeta[1] + " TEXT);\n  ")
	
	print "\n-> Table creation in db :" + defaultOutputDirectory + defaultNameDatabase
	print "\n" + createString
	connSql.execute(createString)
	return (connSql,sqlTableName)

'''
main function
'''
def main(argv):
	#private vars
	#slq = None
	user_agent = None
	list_sites = None
	
	try:
		#if not args, defualt value
		user_agent = single_agent   #defualt single user agent
		list_sites = getListSite(defaultNameFileSite)
		if len(argv) >= 2:
			indexArg = 1
			while indexArg < len(argv):
				if argv[indexArg] == "-d": #debug
					list_sites = (debug_list, len(debug_list), None)
				elif argv[indexArg] == "-m": #multi agent
					user_agent = multi_agent
				elif argv[indexArg] == "-i": #input
					list_sites = getListSite(argv[indexArg+1])
					indexArg = indexArg + 1 # skip next arg
				else:
					print "Usage: python checker.py [OPTION]"
					print ""
					print " -d 				debug mode"
					print " -m 				multi user agents mode"
					print " -i name_list_file.csv		input file .csv with the list of web sites"
					exit(0)
				indexArg = indexArg + 1
				
		#create the db
		sql = createDB()
		#start recording
		startTime = time.time()
		#iterate the list
	    	for row in list_sites[0]:
	    		#generateTasks(connSql,sqlTableNam,num,tot,site,startTime,user_agent):
	    		generateTasks(sql[0],sql[1],int(row[0]),list_sites[1],row[1].replace("/",""),startTime,user_agent)
	    		#quit after too many errors #TODO ASK
	    		if countError > 500 :
				print "Too many errors.. quit"
				break
	finally:
		print "\n\n-> Save db";
		print "-> Close file list web sites"
		print "-> Final total time: " + str(totTime)
		print "-> Print final DB and close"
		try:
			sql[0].commit()
			printTable(sql[0],sql[1])
			sql[0].close()
			if (list_sites != None):
				list_sites[2].close()
		except Exception:
			print "Error in closing DB"
		print "\n\n"

if __name__ == "__main__":
    main(sys.argv)
       		
       		

		












