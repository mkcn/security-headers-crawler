#!/use/bin/python

import mPrinter

import os
import sqlite3
import datetime
import zlib

# name database
defaultOutputDirectory = "output/"
defaultNameDatabase = "result.db"

# list column sql
columnId = "ID"
columnSite = "Site"
columnAgent = "Agent"
columnCode = "Code"
columnTime = "Time"
columnHTML = "HTML"
columnHeaders = "Headers"
columnMetaTags = "MetaTags"

'''
Class to handle the local database
'''
class Database(object):
    
    def __init__(self, headersList):
        self.headersList = headersList

    '''
    Open the database and create a new table based on the current time
    '''
    def create(self):
        # check if directory exist
        if not os.path.exists(defaultOutputDirectory):
                os.makedirs(defaultOutputDirectory)
        # connect to the database
        self.connSql = sqlite3.connect(defaultOutputDirectory + defaultNameDatabase)
    
        # Set an unique name for the table
        today = datetime.datetime.now()
        self.sqlTableName = ("T_" + str(today.year) + "_" + 
            str(today.month) + "_" + 
            str(today.day) + "_" + 
            str(today.hour) + "_" + 
            str(today.minute) + "_" + 
            str(today.second))
        # create new table
        createString = ("CREATE TABLE " + str(self.sqlTableName) + " ( " + 
            columnId + " STRING PRIMARY KEY NOT NULL,\n  " + 
            columnSite + " TEXT ,\n  " +
            columnAgent + " TEXT ,\n  " +
            columnTime + " FLOAT,\n  " +
            columnHTML + " TEXT,\n  "  +
            columnCode + " INT,\n  ")
        for name in self.headersList:
            createString += (name[1] + " TEXT,\n  ")
        # we save all headers
        createString += (columnHeaders + " TEXT,\n  ")
        # we save the meta tag about csp
        createString += (columnMetaTags + " TEXT);\n  ")
        
        self.connSql.execute(createString)
        return ("\n-> Table creation in db :" + defaultOutputDirectory 
                + defaultNameDatabase + "\n" + createString)
    
    '''
    Given a list [(key,value),..] and a key it returns the corresponding value
    '''
    def getValueHeader(self,listHeaders,key):
        for item in listHeaders:
            if item[0] == key:
                return item[1]
        return ""
    
    '''
    Add an almost empty row in the database to notify an error
    '''
    def addToDbError(self,num,site,agent):
        comma = "','"
        try:
            exeInsert = ("INSERT INTO " + self.sqlTableName + 
                         " ( " + 
                    columnId + "," +  # id site
                    columnSite + "," +  # name site
                    columnAgent + "," +  # used agent
                    ")\n")  # meta tag 
            exeInsert += ("VALUES ('" + 
                     str(num) + comma +  # it an int
                     site + comma + 
                     agent +  "')")
        
            return "Error added into the table"
        except Exception , inst:
            error =  ("*"*mPrinter.sizeDrawLine +  
                      "\nError in addToDb with : " + site + "," + agent + 
                      "\nType of error: " + str(type(inst)) +
                      "\nArgs: " + str(inst.args) +
                      "\nInst: " + str(inst) +
                      "\n*"*mPrinter.sizeDrawLine)
            return error   


    '''
       Add a row to the db in a secure way
       use secure sql queries ..VALUES (%s, %s, %s)
    '''
    def addToDb(self, num, site, status, agent, time, HTMLPage, allHeaders, allMetaHeaders, securityHeaders):
        comma = " , "
        try:
            exeInsert = ("INSERT INTO " + self.sqlTableName +
                         " ( " +
                         columnId + comma +       # id site
                         columnSite + comma +     # name site
                         columnAgent + comma +    # used agent
                         columnTime + comma +     # reply time
                         columnHTML + comma +     # reply html
                         columnCode + comma +     # reply code http
                         columnHeaders + comma +  # all headers
                         columnMetaTags ) # meta tag

            for name in self.headersList:
                exeInsert += ( "," + name[1] )  # single headers , x 12

            exeInsert += ")\n"

            # now the values
            exeInsert += ("VALUES (" +
                            "?," +        # id
                            "?," +        # name
                            "?," +        # used agent
                            "?," +        # reply time
                            "?," +        # reply html
                            "?," +        # reply code http
                            "?," +        # all headers
                            "?" )        # meta tag
            for name in self.headersList:  # single headers
                exeInsert += ",?"

            exeInsert += ")"

            #fill the array of values
            tupleValue = list()
            tupleValue.append(num)
            tupleValue.append(site)
            tupleValue.append(agent)
            tupleValue.append(time)
            if (HTMLPage != None):
                tupleValue.append(buffer(zlib.compress(HTMLPage)))
            else:
                tupleValue.append(buffer(zlib.compress("None")))
            tupleValue.append(status)
            tupleValue.append(str(allHeaders))
            tupleValue.append(str(allMetaHeaders))

            # set the headers
            if allHeaders != None and securityHeaders != None:
                for name in self.headersList:
                    tupleValue.append(self.getValueHeader(securityHeaders, name[0]))
            else:
                for name in self.headersList:  # single headers
                    tupleValue.append(None)

            #print exeInsert
            #print tupleValue
            self.connSql.executemany(exeInsert,[tupleValue])
            return "Execution query complete!"

        except Exception, inst:
            error2 = self.addToDbError(num, site, agent)
            error = ("*" * mPrinter.sizeDrawLine +
                     "\nError in addToDb with : " + site + "," + agent +
                     "\nType of error: " + str(type(inst)) +
                     "\nArgs: " + str(inst.args) +
                     "\nInst: " + str(inst) +
                     "\n" +
                     "*" * mPrinter.sizeDrawLine)
            return error + "\n\n" + error2

    '''
    Add a row to the db  NOT USED!
    '''
    def unsecureAddToDb(self, num, site,status, agent, time,HTMLPage, allHeaders, allMetaHeaders,securityHeaders):
        comma = "','"
        try:
            # TODO use secure sql queries ..VALUES (?, ?, ?)
            exeInsert = ("INSERT INTO " + self.sqlTableName + 
                         " ( " + 
                    columnId + "," +  # id site
                    columnSite + "," +  # name site
                    columnAgent + "," +  # used agent
                    columnTime + "," +  # reply time
                    columnHTML + "," +  # reply html
                    columnCode + ",")  # reply code http
            for name in self.headersList:
                exeInsert += (name[1] + ",")  # single header

            exeInsert += (columnHeaders + "," +  # all headers
                     columnMetaTags + ")\n")  # meta tag
            
            # now the values
            exeInsert += ("VALUES ('" + 
                     str(num) + comma +  # it an int
                     site + comma + 
                     agent + "'," + 
                     str(time) + ",'" +  # it's a float
                     HTMLPage.replace("'", "") + "',")

            # set the headers
            if allHeaders != None and securityHeaders != None:
                exeInsert += (str(status) + ",'")       # es status == 200
                for name in self.headersList:
                    exeInsert += (self.getValueHeader(securityHeaders,name[0]).replace("'", "") + comma)
                exeInsert += (str(allHeaders).replace("'", "") + comma)
            else:
                exeInsert += ("-1" + ",'")  # code error no connection
                for name in self.headersList:  # single headers
                    exeInsert += ("" + comma)
                exeInsert += ("" + comma)  # all headers
            
            
            if allMetaHeaders != None:
                exeInsert += str(allMetaHeaders).replace("'", "") + "')"
            else:
                exeInsert += ("" + "')")
            
            #print exeInsert
            self.connSql.execute(exeInsert);
            return "Execution query complete!"
        
        except Exception , inst:
            error2 =self.addToDbError(num,site,agent)
            error =  ("*"*mPrinter.sizeDrawLine +  
                      "\nError in addToDb with : " + site + "," + agent + 
                      "\nType of error: " + str(type(inst)) +
                      "\nArgs: " + str(inst.args) +
                      "\nInst: " + str(inst) +
                      "\n" +
                      "*"*mPrinter.sizeDrawLine)
            return error + "\n\n" + error2
        
    '''
    Return a string summary of the created table
    '''
    def printTable(self):
        printedTable = ""
        cursor = self.connSql.execute(("SELECT " + columnId + "," + 
                        columnSite + "," + 
                        columnCode + "," + 
                        columnAgent + "," + 
                        columnTime +  ","  +
                        self.headersList[0][1]  + "," +
                        columnHeaders + " from " + self.sqlTableName))
        printedTable += ("|" + mPrinter.printWithSpace(columnId, 5) + 
            mPrinter.printWithSpace(columnSite, 20) + 
            mPrinter.printWithSpace(columnCode, 5) + 
            mPrinter.printWithSpace(columnAgent, 10) + 
            mPrinter.printWithSpace(columnTime, 15) +
            mPrinter.printWithSpace(self.headersList[0][1],20 )+
            mPrinter.printWithSpace(columnHeaders,30 ))
            
    
        printedTable += "\n|" + "-"*(mPrinter.sizeDrawLine - 1)
        for row in cursor:
            printedTable += ("\n|" + mPrinter.printWithSpace(str(row[0]), 5)
                 + mPrinter.printWithSpace(row[1], 20)
                 + mPrinter.printWithSpace(str(row[2]), 5)  # code
                 + mPrinter.printWithSpace(row[3], 10)
                 + mPrinter.printWithSpace(str(row[4]), 15)  # TIME FLOAT
                 + mPrinter.printWithSpace(str(row[5]), 20)
                 + mPrinter.printWithSpace(str(row[6]), 30)
                 )
        printedTable += "\n|" + "-"*(mPrinter.sizeDrawLine - 1)
        return printedTable
    
    def commit(self):
    	#save on the db
    	self.connSql.commit()
    
    def close(self):
        self.connSql.close()
    

