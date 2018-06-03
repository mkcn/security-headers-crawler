#!/use/bin/python

import csv

'''
Class to handle the CVS files
'''
class CVS(object):
    
    def __init__(self, nameFile,maxValue):
        self.nameFile = nameFile
        self.maxValue = maxValue

    '''
    Open the file , skip the header line and get the "reader"
    '''
    def openFile(self):
        # opens the csv file
        self.fo = open(self.nameFile, 'rb')
        
        r = 0
        # skip header line
        while r < 1:
            self.fo.next()
            r = r + 1
        self.reader = csv.reader(self.fo)
        
    '''
    From the "reader" return an array
    '''
    def getArray(self):
        arr = []
        i = 0
        for item in self.reader:
            arr.append(item)
            i += 1
            # from "reader" read at maximum n row
            if i >= self.maxValue:
                break
        return arr
        
    '''
    Close the file
    '''
    def closeFile(self):
        self.fo.close()
        
        