#!/use/bin/python
import mPrinter

import httplib
import urlparse
import time
import Cookie
import traceback
import zlib
from lxml.html import fromstring

# http and https
http = "http"
https = "https"

'''
Class to execute a task 
Given a site , an index and an user agent it get the used headers
'''
class Task(object):
    
    def __init__(self,index, site, agent,debug):
        self.site = site
        self.agent = agent
        self.index = index
        self.path = "/"
        self.debug = debug
        self.cookieContainer = Cookie.SimpleCookie()
        
    def __call__(self):
        start = time.time() 
        #get the response objects
        res =  self.downloadHeaders(self.site,http,self.path, self.agent[1],self.cookieContainer, 0)

        if(res != None):
            htmlPage = self.getHTML(res);
            # get the list of meta tag about headers+
            if (htmlPage != None):
                metatag = self.findMetaTags(res,htmlPage)
            else:
                metatag = []
            diffTime = (time.time() - start)
            # save HTML only of the first 1000 website
            if (self.index > 1000):
            	htmlPage = None
            return [self.index , self.site, res.status,self.agent[0], diffTime, res.getheaders(), metatag, htmlPage]
        else:
            diffTime = (time.time() - start)
            return [self.index , self.site, None, self.agent[0], diffTime, None,None,None]
    def __str__(self):
        return '%s - %s with %s' % (self.index, self.site, self.agent[0])
    
    
    '''
    Add/update the cookies in the container 
    '''
    def addCookie(self,cookieContainer,headerCookie):
        cookieContainer.load(headerCookie)
        if self.debug:
            print "\nAdded cookie: " + str(headerCookie)
    
    
    '''
    A vary basic function to retrieve the cookies to send to the server in the HTTP request. 
    Note: not all cases are covered, we consider only the 'domain' and 'path' fields! 
    '''
    def getCookie(self,cookieContainer,domain,path ):
        #https://docs.python.org/2/library/cookie.html
        replyString = ''
        for cookie in cookieContainer:
            # remove(",","") needed because the library leave the , 
            if cookieContainer[cookie]['domain'].replace(",","") in domain and cookieContainer[cookie]['path'].replace(",","") in path:
                replyString += cookieContainer[cookie].key + "=" + cookieContainer[cookie].value + "; "
        if self.debug:
            print "\nCookie reply: " + str(replyString)
        return replyString
    
    
    '''
    Given a site, an agent and a protocol it :
        - does the web request and get the headers
        - saves the cookies 
        - looks for security headers in the meta tag of the HTML
        - handles the main 3xx Redirection
        - retries the request with HTTPS if it fails 
    '''
    def downloadHeaders(self, site, protocol, path, agent, cookieContainer, depth):
        try:
            # https://stackoverflow.com/questions/14949644/python-get-header-information-from-url
            if self.debug:
                print "\n"
                print "** Now working on.. **"
                print "Site: " + site
                print "Protocol:" + protocol
                print "Path: " + path
    
            depth += 1
            # to avoid infinite loops
            if depth < 12 :
                if (protocol == http):
                    conn = httplib.HTTPConnection(site, timeout=30) #some site has a long delay
                else:  # https
                    conn = httplib.HTTPSConnection(site, timeout=30)
                conn.putrequest("GET", path)
                conn.putheader('User-Agent', agent)
                conn.putheader('Upgrade-Insecure-Requests', 1)  # header send by chrome to require CSP
                
                conn.putheader('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
                conn.putheader('Accept-Language','en-US,en;q=0.5')
                #conn.putheader('Accept-Encoding','gzip')	# if enable , we need to decode the reply
                conn.putheader('Connection','keep-alive')
                
                cookieHeader =  self.getCookie(cookieContainer,site,path)
                if cookieHeader != '':
                    conn.putheader('Cookie',cookieHeader)
                
                conn.endheaders()
                res = conn.getresponse()
    
                # if redirected
                if(res.status == 301 or res.status == 302 or res.status == 303 or res.status == 307):
                    newLoc = res.getheader("location")
                    if self.debug:
                        print  site + " -> move to -> " + newLoc
                        
                    if (newLoc != None):
                        urlp = urlparse.urlparse(newLoc, allow_fragments=True)
                        if(urlp.netloc != ''):  # avoid particular case of location = "/it/"
                            site = urlp.netloc
                        if (urlp.scheme != ''):  # case of location = "//www.site.org/"
                            protocol = urlp.scheme
                            
                        if (urlp.query == '' and urlp.path != '' ): # case of "www.site.org/path"
                            path = urlp.path
                        elif (urlp.query != '' and urlp.path == ''): # case of "www.site.org?us=2"
                            path = "?" + urlp.query
                        elif (urlp.query != '' and urlp.path != ''): # case of "www.site.org/path?us=2"
                            path = urlp.path + "?" + urlp.query
                          
                        if not path.startswith("/"):    # case of "index.ph"  
                            path = "/" + path 
                        receivedCookie = res.getheader("set-cookie")  
                        if (receivedCookie != None): #get string cookie
                            self.addCookie(cookieContainer,receivedCookie)
                            
                        return self.downloadHeaders(site, protocol, path, agent ,cookieContainer, depth)
                return res
            else:
                return None    
       
        except Exception , inst:
            if not site.startswith("www."):  # try using www. (case of geocities.jp)
                return self.downloadHeaders("www." + site, protocol, path, agent,cookieContainer, depth)
            else:
                if self.debug:
                    print "*"*mPrinter.sizeDrawLine
                    print "Error in downloadHeaders with: " + site + "," + agent
                    print "Type of error: " + str(type(inst))
                    print "Args: " + str(inst.args)
                    print "Inst: " + str(inst)
                    print traceback.print_exc()
                    print "*"*mPrinter.sizeDrawLine
                return None

    '''
        Retrive HTML code from the response
    '''
    def getHTML(self, res):
        try:
            return res.read();
        except Exception, inst:
            if self.debug:
                print "*" * mPrinter.sizeDrawLine
                print "Error in getHTML"
                print "Type of error: " + str(type(inst))
                print "Args: " + str(inst.args)
                print "Inst: " + str(inst)
                print traceback.print_exc()
                print "*" * mPrinter.sizeDrawLine
            return None
    '''
    It looks for the CPS usage in meta tag
    #TODO look for CSPR and other Headers
    #TODO error of parsing with 'qpic.cn'
    '''
    def findMetaTags(self,res,HTML):
        try:
            if (res.getheader('Content-Encoding') == "gzip"):
                text=zlib.decompress(HTML, 16+zlib.MAX_WBITS)
                tree = fromstring(text)
                name = tree.xpath("//meta[@http-equiv]/@http-equiv")
                value = tree.xpath("//meta[@http-equiv]/@content")
                out = zip(name, value)

                #out =  tree.xpath("//meta[@http-equiv]/@content") #generic http-equiv
                #out = tree.xpath("//meta[@http-equiv='" + cspHeader[0] + "']/@content")
                if (out != None and len(out) > 0):
                    return out
                else:
                    return []
            else:
                return []
        except Exception , inst:
            if self.debug:
                print "*"*mPrinter.sizeDrawLine
                print "Error in findMetaTags"
                print "Type of error: " + str(type(inst))
                print "Args: " + str(inst.args)
                print "Inst: " + str(inst)
                print traceback.print_exc()
                print "*"*mPrinter.sizeDrawLine
            return None


