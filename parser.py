"""Limits:
    - can't read brackets in brackets
    - avoid using more then one bracket per line. Normally it should work, but be carefull
    - problems by differncing ttl/domaine, if domain[:-1].isdigit()"""
#from typing import List, Any
from time import strftime

CLASSES = ["IN", "HS", "CH", "CS"]
RRsTYPES = ["A","AAAA", "A6", "AFSDB", "APL", "CERT", "CNAME", "DHCID", "DNAME",
            "DNSKEY", "DS", "GPOS", "HINFO", "IPSECKEY", "ISDN", "KEY", "KX", "LOC",
            "MX", "NAPTR", "NSAP", "NS", "NSEC", "NSEC3","NSEC3PARAM", "NXT", "PTR",
            "PX", "RP", "PRSIG", "RT", "SIG", "SOA", "SPF", "SRV", "SSHFP", "TXT", "WKS", "X25"]
import time

class ZoneFileError(Exception):
    def __init__(self, error, file):
        self.error = str(error)
        self.file = str(file)
    def __str__(self):
        return """Please check the given zone file {0}.\nFollowing Error occured: {1}""".format(self.file, self.error)

class _Parser():
    def __init__(self, file):
        self.file = file
        self.zone = list()
        self.RRsTable = list() # need?
        self.Table = list() # format: [primKey, name, ttl, class, type, value]
        self.stream = open(file)
        self.zone_org = self.stream.read()
        self.stream.close()
        self.zone = self.zone_org.splitlines()
        self.rmComment()
        self.rmCompleteParanthese()
        self.split()
        self.cleanUp()
        self.parse()


    def error(self, error):
        """returns error"""
        raise ZoneFileError(error, self.file)

    def getIndexe(self, pattern):
        """return every index of fitting patter"""
        self.counter = 0
        self.result = list()
        for i in range(self.zone_org.count(pattern)):
            self.result.append(self.zone_org.find(pattern, self.counter))
            self.counter = self.result[-1] + 1
        return self.result

    def rmComment(self):
        """Removes comments from zone (;, #, /**/, //)"""
        if ";" in self.zone_org: self.zone = [i.split(";")[0] for i in self.zone if i != ";"]
        if "#" in self.zone_org: self.zone = [i.split("#")[0] for i in self.zone if i != "#"]
        if "//" in self.zone_org: self.zone = [i.split("//")[0] for i in self.zone if i != "//"]
        if "/*" in self.zone_org:
            self.pop = list()
            self.counter = False
            for i in range(len(self.zone)):
                if "/*" in self.zone[i]:
                    self.counter = True
                    self.zone[i] = self.zone[i].split("/*")[0]
                    continue
                if "*/" in self.zone[i]:
                    self.pop.append(i)  # warnig: complete line is removed. Problem with: /*comment\nbla\nbla*/command?
                    self.counter = False
                    continue
                if self.counter:
                    self.pop.append(i)
            self.pop.sort(reverse = True) # To avoid collaps of mapping
            for i in self.pop:
                self.zone.pop(i)

    def move(self, index):
        """Merge index + 1 with index."""
        self.zone[index] += " " + self.zone[index + 1]
        self.zone.pop(index + 1)

    def rmParanthese(self):
        """removes paranthes if closed from zone file line"""
        self.zone = [self.zone[i].replace("(", "").replace(")", "") if self.zone[i].count("(") == self.zone[i].count(")") else self.zone[i] for i in range(len(self.zone)) ]

    def mergeParanthese(self):
        """Merge every paranthes to one line"""
        self.paranthese = 0
        self.subt = 0
        for i in range(len(self.zone)):
            i -= self.subt # to compense the mapping collaps
            try:
                self.zone[i]
            except IndexError:
                break
            if "(" in self.zone[i]:
                self.paranthese += 1
                self.use_index = i
                continue
            if ")" in self.zone[i]:
                self.paranthese -= 1
                self.move(self.use_index)
                self.subt += 1
                continue
            if self.paranthese:
                self.move(self.use_index)
                self.subt += 1

    def rmCompleteParanthese(self):
        """removes every paranthes from zone by merging"""
        self.count = 0
        while [i for i in self.zone if "(" in i or ")" in i]:
            self.count += 1
            self.rmParanthese()
            self.mergeParanthese()
            if self.count > 100:
                self.error("Paranthese Syntax: Please avoid using Paranthese in Paranthese or more then more paranthese per line")
        self.rmParanthese()
        del self.count

    def split(self):
        """splits zone to fields"""
        self.zone = [i.split() for i in self.zone]
    def addRRs(self, Name, TTL, Class, Type, Value):
        """Adds a regular RRs entry to internal table"""
        self.RRsTable.append([Name, TTL, Class, Type, Value])
    def handle(self, primKey, Name, TTL, Class, Type, Value):
        """Handler for parser return. Here you get all data -> api""" # later mySQL?
        self.Table.append([primKey, Name, TTL, Class, Type, Value])
    def isType(self, object):
        """returns true if object is a entry type like NS, eg."""
        return True if object in RRsTYPES else False
    def isClass(self, object):
        """returns True if obeject is a class like IN, eg."""
        return True if object in CLASSES else False
    def isTTL(self, liste):
        """returns True if given list from zone is TTL record"""
        return True if liste[0] == '$TTL' and len(liste) < 3 else False
    def isTTLobj(self, object):
        """Returns if given object is ttl. Warning: it's just probatly correct"""
        return True if object[:-1].isdigit() else False # -1 because of 23h for eg.

    def cleanUp(self):
        """removes empty strings and lists from zone"""
        self.zone = [i for i in self.zone if i and i[0] != '']
    def getType(self, liste):
        """returns type of given entry"""
        for i in liste:
            if self.isType(i):
                return i
    def getClass(self, liste):
        for i in liste:
            if self.isClass(i):
                return i


    def parse(self):
        self.primKey = 0
        for entry in self.zone:
            if self.isTTL(entry):
                self.default_TTL = entry[1] # default ttl
                continue
            self.type = self.getType(entry)
            self.klasse = self.getClass(entry)
            if self.type: self.default_type = self.type
            else:
                self.error("Please check your zonfile. Error at {0}.\nType not found".format(" ".join(entry))) # Type has there to be
                #try:
                #    self.type = self.default_type
                #except NameError: self.error("Please check your zonfile. Error at {0}.\nType not found".format(" ".join(entry)))
            if self.klasse: self.default_klasse = self.klasse
            else:
                try:
                    self.klasse = self.default_klasse
                except NameError: self.error("Please check your zonfile. Error at {0}.\nClass not found".format(" ".join(entry)))
            self.typeindex = entry.index(self.type)
            self.value = " ".join(entry[self.typeindex+1:])
            entry = entry[:self.typeindex] # over: probatly name, probatly ttl, probatly class
            self.over = len(entry)
            if self.over == 3:
                if entry.pop(2) != self.klasse:
                    self.error("There occured a fatal logical error at {0}.\nPlease contact support for more iformation".format(" ".join(entry)))
                self.over = len(entry)
            if self.over == 2: # Possible: class, ttl, name but: entry[1] = {TTL//class}
                if entry[1] == self.klasse: entry.pop()
                #elif self.isTTLobj(entry[1]): self.ttl = entry[1]
                else: self.ttl = entry.pop() # Have to be ttl
                self.over = len(entry)
            if self.over == 1: # possible: name, class, ttl
                if entry[0] == self.klasse: entry.pop()
                elif self.isTTLobj(entry[0]): self.ttl = entry.pop(); print("warning at {0}".format(" ".join(entry))) # carefull!!! 123456d as dom -> error
                else: self.name = entry[0]
            self.handle(self.primKey, self.name,self.ttl, self.klasse, self.type, self.value)
            self.ttl = self.default_TTL
            del self.value
            self.primKey += 1

class Parser():
    def __init__(self, file):
        self.parser = _Parser(file)
        self.table = self.parser.Table
        self.TTL = self.parser.default_TTL
        del self.parser # RAM clean

    def getValues(self):
        return set([i[5] for i in self.table])
    def getTypes(self):
        return set([i[4] for i in self.table])
    def getClasses(self):
        return set([i[3] for i in self.table])
    def getTTLs(self):
        return set([i[2] for i in self.table])
    def getDomains(self):
        return set([i[1] for i in self.table])
    def getIDs(self):
        return set([i[0] for i in self.table])

    def getDefaultTTL(self):
        return self.TTL

    def getRecords(self, ID = False, Domain = False, TTL = False, Class = False, Type = False, Value = False):
        self.result = list()
        for i in self.table:
            if ID and ID != i[0]: continue
            if ID == 0 and i[0] != 0: continue # 0 is False
            if Domain and Domain != i[1]: continue
            if TTL and TTL != i[2]: continue
            if Class and Class != i[3]: continue
            if Type and Class != i[4]: continue
            if Value and Value != i[5]: continue
            self.result.append(i)
        return self.result

    def getValue(self, Value):
        return [i for i in self.table if i[5] == Value]
    def getType(self, Type):
        return [i for i in self.table if i[4] == Type]
    def getClass(self, Class):
        return [i for i in self.table if i[3] == Class]
    def getTTL(self, TTL):
        return [i for i in self.table if i[2] == str(TTL)]
    def getName(self, Name):
        return [i for i in self.table if i[1] == Name]
    def getID(self, ID):
        return [i for i in self.table if i[0] == ID]

    # def getSOAcontext(self, ID):
    #     """retruns parent SOA record for given ID.""" # Are there more then 1 soa records per zone allowed?
    #     for i in [i[0] for i in self.getType("SOA")]:
    #         if i < ID:
    #             return self.getID(i)
    def getZoneOrigin(self):
        return self.getType("SOA")[0][5].split()[0]
    def getZoneContact(self):
        return self.getType("SOA")[0][5].split()[1]
    def getSerial(self):
        return self.getType("SOA")[0][5].split()[2]
    def getRefreshTime(self):
        return self.getType("SOA")[0][5].split()[3]
    def getRetryTime(self):
        return self.getType("SOA")[0][5].split()[4]
    def getExpireTime(self):
        return self.getType("SOA")[0][5].split()[5]
    def getNegativeCache(self):
        return self.getType("SOA")[0][5].split()[6]

    def mkSerial(self, check = True):
        """Sets timestamp allone. If check, no serial > 90 are supported"""
        self.old_time = self.getSerial()[:8]
        self.new_time = strftime("%Y%m%d")
        if self.old_time != self.new_time:
            self.serial = "00"
        else:
            self.serial = str(int(self.getSerial()[8:]) + 1)
            if check: assert int(self.serial) < 100, """More then 99 changes aren't supported per day."""
        print(self.old_time)
        if len(self.serial) < 2:
            self.serial = "0{0}".format(self.serial)
        print(self.serial)
        return "{0}{1}".format(self.new_time, self.serial)
