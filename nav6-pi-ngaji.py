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

import hashlib, httplib, mimetypes, os, pprint, simplejson, sys, urlparse
DEFAULT_TYPE = 'application/octet-stream'

REPORT_URL = 'https://www.virustotal.com/api/get_file_report.json'
SCAN_URL = 'https://www.virustotal.com/api/scan_file.json'

API_KEY = '5f666ccd6cd27088767898c90b9faf3fc0e8178444966d79fa16cce303ba8d3b'

# The following function is modified from the snippet at:
# http://code.activestate.com/recipes/146306/

#Uncommenting the original, I want to test nav6 API call instances

#INTERESTING_CALLS = ["CreateMutex", "CopyFile", "CreateFile.*WRITE", "NtasdfCreateFile", "call shell32", "advapi32.RegOpenKey",
#        "KERNEL32.CreateProcess", "shdocvw", "gethostbyname", "ws2_32.bind", "ws2_32.listen", "ws2_32.htons",
#        "advapi32.RegCreate", "advapi32.RegSet", "http://","Socket",
#        "^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])",
#        "OutputDebugString","GetEnvironmentStrings","LoadLibraryA","WSASocketA", "GetProcAddress",
#        "FindWindow","CreateProcess","DuplicateTokenEx","ImpersonateNamedPipeClient","RevertToSelf","signal",
#        "IsDebuggerPresent"
#        ]

#These are calls that we being used by Altyeb in "Computer Virus Detection Using Features Ranking and Machine Learning", 2011

INTERESTING_CALLS = ["GetSystemTimeAsFileTime",
"SetUnhandledExceptionFilter",
"GetCurrentProcess",
"TerminateProcess",
"LoadLibraryExW",
"GetVersionExW",
"GetModuleFileNameW",
"GetTickCount",
"SetLastError",
"GetCurrentProcessId",
"GetModuleHandleW",
"LoadLibraryW",
"InterlockedExchange",
"UnhandledExceptionFilter",
"FreeLibrary",
"GetCurrentThreadId",
"QueryPerformanceCounter",
"CreateFileW",
"InterlockedCompareExchange",
"UnmapViewOfFile",
"GetProcAddress"]



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



def encode_multipart_formdata(fields, files=()):
    """
    fields is a dictionary of name to value for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be
    uploaded as files.
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for key, value in fields.items():
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' %
                 (key, filename))
        content_type = mimetypes.guess_type(filename)[0] or DEFAULT_TYPE
        L.append('Content-Type: %s' % content_type)
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def post_multipart(url, fields, files=()):
    """
    url is the full to send the post request to.
    fields is a dictionary of name to value for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be
    uploaded as files.
    Return body of http response.
    """
    content_type, data = encode_multipart_formdata(fields, files)
    url_parts = urlparse.urlparse(url)
    if url_parts.scheme == 'http':
        h = httplib.HTTPConnection(url_parts.netloc)
    elif url_parts.scheme == 'https':
        h = httplib.HTTPSConnection(url_parts.netloc)
    else:
        raise Exception('Unsupported URL scheme')
    path = urlparse.urlunparse(('', '') + url_parts[2:])
    h.request('POST', path, data, {'content-type':content_type})
    return h.getresponse().read()

def scan_file(filename):
    files = [('file', filename, open(filename, 'rb').read())]
    json = post_multipart(SCAN_URL, {'key':API_KEY}, files)
    return simplejson.loads(json)

def get_report(filename):
    md5sum = hashlib.md5(open(filename, 'rb').read()).hexdigest()
    json = post_multipart(REPORT_URL, {'resource':md5sum, 'key':API_KEY})
    data = simplejson.loads(json)
    if data['result'] != 1:
        print 'Result not found, submitting file.'
        data = scan_file(filename)
        if data['result'] == 1:
            print 'Submit successful.'
            print 'Please wait a few minutes and try again to receive report.'
        else:
            print 'Submit failed.'
            pprint.pprint(data)
    else:
        pprint.pprint(data['report'])


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage: %s filename' % sys.argv[0]
        sys.exit(1)

    filename = sys.argv[1]
    if not os.path.isfile(filename):
        print '%s is not a valid file' % filename
        sys.exit(1)


def pegi_check():
	print "Analyzing registry..."
	start_analysis_registry()

	print "Check whether this binary is a bot..."
	start_analysis_online()

	print "Analyzing interesting calls.."
	start_analysis_system_calls()


pegi_check()
print "\nChecking VirusTotal results...\n"
get_report(filename)
