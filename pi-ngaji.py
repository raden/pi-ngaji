#Licensed under GPL v 3
#merged and modified from Joxean Zerowine VM detect, Aurora Regular expressions search for static analysis
#modified by Najmi (2011)
import hashlib
import time
import binascii
import string
import os, sys
import commands
import pefile
import peutils
import string
import re

INTERESTING_CALLS = ["CreateMutex", "CopyFile", "CreateFile.*WRITE", "NtasdfCreateFile", "call shell32", "advapi32.RegOpenKey",
        "KERNEL32.CreateProcess", "shdocvw", "gethostbyname", "ws2_32.bind", "ws2_32.listen", "ws2_32.htons",
        "advapi32.RegCreate", "advapi32.RegSet", "http://","Socket",
        "^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])",
        "OutputDebugString","GetEnvironmentStrings","LoadLibraryA","WSASocketA", "GetProcAddress",
        "FindWindow","CreateProcess","DuplicateTokenEx","ImpersonateNamedPipeClient","RevertToSelf","signal",
        "IsDebuggerPresent"
        ]
INTERESTING_CALLS_DLLS=["KERNEL32.DLL","advapi32.dll","comctl32.dll","gdi32.dll","ole32.dll","oleaut32.dll","user32.dll","wsock32.dll","ntdll.dll"]

INTERESTING_SYS_CALLS=["ping.exe","telnet.exe"]

REGISTRY_CALLS =["HKEY_CURRENT_USER","HKEY_CLASSES_ROOT","HKEY_LOCAL_MACHINE","autorun.inf"]

ONLINE_WORK =["IRC","Joined channel","Port","BOT","Login","flood","ddos","NICK","ECHO","PRIVMSG","ADMIN",
"AWAY","CONNECT","KICK","LIST","MODE","MOTD","PING","PONG","QUIT","SERVLIST","SERVICE","NAMES","JOIN","INVITE","INFO","TRACE","USERHOST","WHO","WHOIS","VERSION"]

DETECTION_TRICKS = {
        "Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
        "VirtualPc trick":"\x0f\x3f\x07\x0b",
        "VMware trick":"VMXh",
        "VMCheck.dll":"\x45\xC7\x00\x01",
        "VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
        "Xen":"XenVMM", # Or XenVMMXenVMM
        "Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63",
        "Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
        "Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
        }
DEBUGGING_TRICKS = {
	"""
	
	Should be this way but, well, Python is a shit to analyze an string with the char '\'.
	
	"%%.%SICE":"SoftIce detection",
	"%%.%SIWVID":"SoftIce detection",
	"%%.%NTICE":"SoftIce detection",
	"%%.%REGSYS":"Regmon detection",
	"%%.%REGVXG":"Regmon detection",
	"%%.%FILEVXG":"Filemon detection",
	"%%.%FILEM":"Filemon detection",
	"%%.%TRW":"TRW detection",
	"%%.%TWX":"TRW detection",
	"%%.%ICEEXT":"SoftIce detection",
	"%%.%NTFIRE.S":"'DemoVDD By elicz' technique",
	"""
	"SICE":"SoftIce detection",
	"SIWVID":"SoftIce detection",
	"NTICE":"SoftIce detection",
	"REGSYS":"Regmon detection",
	"REGVXG":"Regmon detection",
	"FILEVXG":"Filemon detection",
	"FILEM":"Filemon detection",
	"TRW":"TRW detection",
	"TWX":"TRW detection",
	"ICEEXT":"SoftIce detection",
	"NTFIRE.S":"'DemoVDD By elicz' technique",
	"OLLYDBG":"OllyDbg detection",
	"FileMonClass":"Filemon detection",
	"isDebuggerPresent":"Generic debugger detection",
	"CheckRemoteDebuggerPresent":"Generic debugger detection",
	"OutputDebugString":"Generic debugger detection",
	"SoftICE":"SoftIce detection",
	"Compuware":"SoftIce detection",
	"NuMega":"SoftIce detection",
	"WinDbgFrameClass":"WinDbg detection",
	"GBDYLLO": "Themida's tricks",
	"pediy0":"Themida's tricks",
	"PROCMON_WINDOW_CLASS":"Process Monitor"
	}	
#def file_read(file):
# rfile = file.read()
# print rfile

#	if len(sys.argv) == 1:
#	   file_read(sys.stdin)
#	else:
#	   file_read(open(sys.argv[1], 'r'))
malware=sys.argv[1]
hosts= open(malware,'r').readlines()
print "Analyzing binary ",malware

pe = pefile.PE(sys.argv[1])
print "DLL \t\t API NAME"
for imp in pe.DIRECTORY_ENTRY_IMPORT:     
	print imp.dll
for api in imp.imports:
	print "\t\t%s" %api.name


def main(the_file):

    try:
        f = file(the_file, "rb")
    except:
        print "Error opening file:", sys.exc_info()[1]
        sys.exit(1)

    buf = f.read()
    f.close()

    tricks = check_tricks(buf)
    tricks2= showDebuggingTricks(buf
)
    print "\n[+]Detecting VM tricks.."
    if len(tricks) > 0:
        for trick in tricks:
            print "***Detected trick %s" % trick

        print
#        print "Total of %d trick(s) detected." % len(ret)
    else:
        print "***No VM trick detected."


   	print "\n[+]Now check for binary entropy.."
	for sec in pe.sections:
		#s = "%-10s %-12s %-12s %-12s %-12f" % (
		s = "%-10s %-12s" %(
		''.join([c for c in sec.Name if c in string.printable]),
    			sec.get_entropy())
		if sec.SizeOfRawData == 0 or (sec.get_entropy() > 0 and sec.get_entropy() < 1) or sec.get_entropy() > 7:
                   		 s += "[SUSPICIOUS]"
                print "",s


   # print "[+]Detecting Debugger tricks.."
    #if len(tricks2) > 0:
    #    	for trick in tricks2:
    #        		print "[+]Detected debuggger trick %s" % trick
    #else:
    #tricks2= showDebuggingTricks(buf)
    #if len(tricks2)==0:
    #    	print "***No debugger trick detected.\n"
    #		print "%s",len(tricks2)


def check_trick_from_file(the_file):
    f = file(the_file, "rb")
    buf = f.read()
    f.close()

    return check_tricks(buf)

def check_tricks(buf):
    tricks = 0
    ret = []
    for trick in DETECTION_TRICKS:
        if buf.lower().find(DETECTION_TRICKS[trick].lower())>-1:
            ret.append(trick)

    return ret

#def showDebuggingTricks(filename, md5Dir, msg):
def showDebuggingTricks(buf):
     i = 0
     checkTricks = []

     print "\n[+]Detecting Anti Debugger Tricks..."
#        for line in msg:
     for trick in DEBUGGING_TRICKS:
	if buf.lower().find(trick.replace("%", "\\").lower()) > -1:
#		checkTricks.append(trick)
		if not trick in checkTricks:
			i += 1
			print "***Detected trick %s (%s)" % (trick, DEBUGGING_TRICKS[trick])
			checkTricks.append(trick)
        	if i == 0:
                        print "No debugger detection trick found"

	#return checkTricks

def usage():
    print "Usage:", sys.argv[0], "<file>"

if __name__ == "__main__":
#    banner()
    if len(sys.argv) == 1:
        usage()
        sys.exit(1)
    else:
        main(sys.argv[1])

def start_analysis_registry():
        for line in hosts:
                for calls in REGISTRY_CALLS:
                        if re.search(calls, line):
                                print "[+] Malware is Adding a Key at Hive: ",calls
                                print line

def start_analysis_online():
        performed=[]
        for line in hosts:
                for calls in ONLINE_WORK:
                        if re.search(calls, line):
                                if not calls in performed:
                                        print "[+] Malware Seems to be IRC BOT: Verified By String :",calls
                                        performed.append(calls)

def start_analysis_system_calls():
        performed=[]
        for line in hosts:
                for calls in INTERESTING_CALLS:
                        if re.search(calls, line):
                                if not calls in performed:
                                        print "[+] Found an Interesting call to: ",calls
                                        performed.append(calls)




def najmi_check():
	print "Analyzing registry..."
	start_analysis_registry()

	print "Check whether this binary is a bot..."
	start_analysis_online()

	print "Analyzing interesting calls.."
	start_analysis_system_calls()


najmi_check()
