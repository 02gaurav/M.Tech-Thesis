

# IMPORTS ================================================================
import os
import sys
import time
import datetime
import difflib
import shutil
import re
import string
import simplejson
import urllib
import urllib2
import hashlib
import pandas as pd
import json
import glob

from subprocess import Popen

# VARIABLES ================================================================
version = "2.1.5"
path_to_volatility = "vol.py"
max_concurrent_subprocesses = 3
diff_output_threshold = 100
ma_output_threshold = 60
vt_api_key = "473db868008cddb184e609ace3ca05de8e51f806e57eba74005aba2efa4a1e6e"  # the rate limit os 4 requests per IP per minute
devnull = open(os.devnull, 'w')

# volatility plugins to run:
plugins_to_run = [ "psscan"]

# volatility plugins to report / only used when a baseline memory image is provided:
plugins_to_report = ["psscan"]

# REGEX EXPRESSIONS ================================================================
# regex expressions used to analyse imports
ransomware_imports = "CreateDesktop"
keylogger_imports = "GetKeyboardState|GetKeyState"
password_extract_imports = "SamLookupDomainInSamServer|NlpGetPrimaryCredential|LsaEnumerateLogonSessions|SamOpenDomain|SamOpenUser|SamGetPrivateData|SamConnect|SamRidToSid|PowerCreateRequest|SeDebugPrivilege|SystemFunction006|SystemFunction040"
clipboard_imports = "OpenClipboard"
process_injection_imports = "VirtualAllocEx|AllocateVirtualMemory|VirtualProtectEx|ProtectVirtualMemory|CreateProcess|LoadLibrary|LdrLoadDll|CreateToolhelp32Snapshot|QuerySystemInformation|EnumProcesses|WriteProcessMemory|WriteVirtualMemory|CreateRemoteThread|ResumeThread|SetThreadContext|SetContextThread|QueueUserAPC|QueueApcThread|WinExec|FindResource"
uac_bypass_imports = "AllocateAndInitializeSid|EqualSid|RtlQueryElevationFlags|GetTokenInformation|GetSidSubAuthority|GetSidSubAuthorityCount"
anti_debug_imports = "SetUnhandledExceptionFilter|CheckRemoteDebugger|DebugActiveProcess|FindWindow|GetLastError|GetWindowThreadProcessId|IsDebugged|IsDebuggerPresent|NtCreateThreadEx|NtGlobalFlags|NtSetInformationThread|OutputDebugString|pbIsPresent|Process32First|Process32Next|TerminateProcess|ThreadHideFromDebugger|UnhandledExceptionFilter|ZwQueryInformation|Sleep|GetProcessHeap"
web_imports = "InternetReadFile|recvfrom|WSARecv|DeleteUrlCacheEntry|CreateUrlCacheEntry|URLDownloadToFile|WSASocket|WSASend|WSARecv|WS2_32|InternetOpen|HTTPOpen|HTTPSend|InternetWrite|InternetConnect"
listen_imports = "RasPortListen|RpcServerListen|RpcMgmtWaitServerListen|RpcMgmtIsServerListening"
service_imports = "OpenService|CreateService|StartService|NdrClientCall2|NtLoadDriver"
shutdown_imports = "ExitWindows"
registry_imports = "RegOpenKey|RegQueryValue|ZwSetValueKey"
file_imports = "CreateFile|WriteFile"
atoms_imports = "GlobalAddAtom"
localtime_imports = "GetLocalTime|GetSystemTime"
driver_imports = "DeviceIoControl"
username_imports = "GetUserName|LookupAccountNameLocal"
machine_version_imports = "GetVersion"
startup_imports = "GetStartupInfo"
diskspace_imports = "GetDiskFreeSpace"
sysinfo_imports = "CreateToolhelp32Snapshot|NtSetSystemInformation|NtQuerySystemInformation|GetCurrentProcess|GetModuleFileName"

# regex expressions used to analyse strings (from process executables)
web_regex_str = "cookie|download|proxy|responsetext|socket|useragent|user-agent|urlmon|user_agent|WebClient|winhttp|http"
antivirus_regex_str = "antivir|anvir|avast|avcons|avgctrl|avginternet|avira|bitdefender|checkpoint|comodo|F-Secure|firewall|kaspersky|mcafee|norton|norman|safeweb|sophos|symantec|windefend"
virtualisation_regex_str = "000569|001C14|080027|citrix|parallels|proxmox|qemu|SbieDll|Vbox|VMXh|virm|virtualbox|virtualpc|vmsrvc|vpc|winice|vmware|xen"
sandbox_regex_str = "anubis|capturebat|cuckoo|deepfreeze|debug|fiddler|fireeye|inctrl5|installwatch|installspy|netmon|noriben|nwinvestigatorpe|perl|processhacker|python|regshot|sandb|schmidti|sleep|snort|systracer|uninstalltool|tcpdump|trackwinstall|whatchanged|wireshark"
sysinternals_regex_str = "filemon|sysinternal|procdump|procexp|procmon|psexec|regmon|sysmon"
shell_regex_str = "shellexecute|shell32"
keylogger_regex_str = "backspace|klog|keylog|shift"
filepath_regex_str = 'C:\\\(?:[^\\\/:*?"<>|\r\n]+\\\)*[^\\\/:*?"<>|\r\n]*'
password_regex_str = "brute|credential|creds|mimikatz|passwd|password|pwd|sniff|stdapi|WCEServicePipe|wce_krbtkts"
powershell_regex_str = "powerview|powershell"
sql_regex_str = "SELECT|INSERT|sqlite|MySQL"
infogathering_regex_str = "driverquery|gethost|wmic|GetVolumeInformation|systeminfo|tasklist|reg.exe"
tool_regex_str = "cain|clearev|ipscan|netsh|rundll32|timestomp|torrent"
banking_regex_str = "banc|banco|bank|Barclays|hsbc|jpmorgan|lloyds|natwest|nwolb|paypal|rbc.com|santander"
socialsites_regex_str = "facebook|instagram|linkedin|pastebin|twitter|yahoo|youtube"
exec_regex_str = ".*\.bat|.*\.cmd|.*\.class|.*\.exe|.*\.jar|.*\.js|.*\.jse|.*\.SCR|.*\.VBE|.*\.vbs"
crypto_regex_str = "bitlocker|bitcoin|CIPHER|crypt|locker|logkey|publickey|ransom|truecrypt|veracrypt"
rat_regex_str = "backdoor|botnet|login|malware|rootkit|screenshot|Trojan|Vnc|VncStart"
browser_regex_str = "chrome|firefox|mozilla|opera"
other_regex_str = "admin|currentversion|hosts|registry|smtp|UserInit|.*\.pdb"

# regex expressions used to extract ips, domains and email addresses
ips_regex = r"(?!\b\d{1,3}\.\d{1,3}\.\d{1,3}\.0\b)\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
domains_regex_http = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
domains_regex_ftp = 'ftp[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
domains_regex_file = 'file[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
emails_regex = r"\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\b"

# regex expressions used to analyse registry handles
registry_infogathering_regex = "SOFTWARE\\\MICROSOFT|Parameters|SOFTWARE\\\POLICIES"
registry_proxy_settings_regex = "INTERNET SETTINGS"
registry_locale_regex = "NLS\\\LOCALE"
registry_hostname_regex = "COMPUTERNAME"
registry_installed_programs_regex = "CurrentVersion\\\App Paths|CurrentVersion\\\Uninstall|Installed Components"
registry_remote_control_regex = "Terminal Server|Realvnc"
registry_firewall_regex = "firewall"
registry_services_regex = "CurrentControlSet\\\services"
registry_network_regex = "NetworkList|Tcpip"
registry_autorun_regex = "CurrentVersion\\\Explorer|CurrentVersion\\\Run|CurrentVersion\\\Windows|Current Version\\\Policies\\\Explorer|CurrentVersion\\\Winlogon|Shell Extensions"
registry_command_processor_regex = "Command Processor"
registry_crypto_regex = "CRYPTOGRAPHY"
registry_tracing_regex = "TRACING"
registry_file_associations_regex = "SYSTEMFILEASSOCIATIONS"
registry_ie_security_regex = "INTERNET EXPLORER\\\SECURITY"
registry_security_center_regex = "Security Center"

# suspicious processes and dlls
hacker_process_regex = "at.exe|chtask.exe|clearev|ftp.exe|net.exe|nbtstat.exe|net1.exe|ping.exe|powershell|procdump.exe|psexec|quser.exe|reg.exe|regsvr32.exe|schtasks|systeminfo.exe|taskkill.exe|timestomp|winrm|wmic|xcopy.exe"
hacker_dll_regex = "mimilib.dll|sekurlsa.dll|wceaux.dll|iamdll.dll|VMCheck.dll"
# suspicious process names
l33t_process_name = "snss|crss|cssrs|csrsss|lass|isass|lssass|lsasss|scvh|svch0st|svhos|svchst|svchosts|lsn|g0n|l0g|nvcpl|rundii|wauclt|spscv|spppsvc|sppscv|sppcsv|taskchost|tskhost|msorsv|corsw|arch1ndex|wmipvr|wmiprse|runddl|crss.exe"
# "usual" process names
usual_processes = "sppsvc.exe|audiodg.exe|mscorsvw.exe|SearchIndexer|TPAutoConnSvc|TPAutoConnect|taskhost.exe|smss.exe|wininit.exe|services.exe|lsass.exe|svchost.exe|lsm.exe|explorer.exe|winlogon|conhost.exe|dllhost.exe|spoolsv.exe|vmtoolsd.exe|WmiPrvSE.exe|msdtc.exe|TrustedInstall|SearchFilterHo|csrss.exe|System|ipconfig.exe|cmd.exe|dwm.exe|mobsync.exe|DumpIt.exe|VMwareTray.exe|wuauclt.exe|LogonUI.exe|SearchProtocol|vssvc.exe|WMIADAP.exe"
# suspicious filepaths
susp_filepath = "\\\ProgramData|\\\Recycle|\\\Windows\\\Temp|\\\Users\\\All|\\\Users\\\Default|\\\Users\\\Public|\\\ProgramData|AppData"
temp_filepath = "\\\TMP|\\\TEMP|\\\AppData"
# usual timers
usual_timers = "ataport.SYS|ntoskrnl.exe|NETIO.SYS|storport.sys|afd.sys|cng.sys|dfsc.sys|discache.sys|HTTP.sys|luafv.sys|ndis.sys|Ntfs.sys|rdbss.sys|rdyboost.sys|spsys.sys|srvnet.sys|srv.sys|tcpip.sys|usbccgp.sys|netbt.sys|volsnap.sys|dxgkrnl.sys|bowser.sys|fltmgr.sys"
# usual gditimers
usual_gditimers = "dllhost.exe|explorer.exe|csrss.exe"
# usual ssdt
usual_ssdt = "(ntos|win32k)"
# usual atoms and atomscan dlls
usual_atoms_dlls = "system32\\\wls0wndh.dll|System32\\\pnidui.dll|system32\\\stobject.dll|vmusr\\\\vmtray.dll|system32\\\EXPLORERFRAME.dll|system32\\\uxtheme.dll|system32\\\MsftEdit.dll|system32\\\SndVolSSO.DLL|system32\\\\fxsst.dll|system32\\\WINMM.dll"
# extensions of interest
susp_extensions_regex = "\.job$|\.pdb$|\.xls$|\.doc$|\.pdf$|\.tmp$|\.temp$|\.rar$|\.zip$|\.bat|\.cmd$|\.class$|\.jar$|\.jse$|\.SCR$|\.VBE$|\.vbs$"

# DICTIONARIES/LISTS USED FOR PROCESS CHECKS ================================================================
# list of "unique" processes
uniq_processes = ["services.exe", "System", "wininit.exe", "smss.exe", "lsass.exe", "lsm.exe", "explorer.exe"]
# expected execution path for some processes
process_execpath = {'smss.exe': "\systemroot\system32\smss.exe",
                    "crss.exe": "\windows\system32\csrss.exe",
                    "wininit.exe": "wininit.exe",
                    "services.exe": "\windows\system32\services.exe",
                    "lsass.exe": "\windows\system32\lsass.exe",
                    "svchost.exe": "\windows\system32\svchost.exe",
                    "lsm.exe": "\windows\system32\lsm.exe",
                    "explorer.exe": "\windows\explorer.exe",
                    "winlogon.exe": "winlogon.exe",
                    "sppsvc.exe": "\windows\system32\sppsvc.exe"}

# expected process parent/child relationship
parent_child = {'services.exe': ["sppsvc.exe", "taskhost.exe", "mscorsvw.exe", "TPAutoConnSvc", "SearchIndexer", "svchost.exe", "taskhost.exe", "spoolsv.exe"],
                'System': ["smss.exe"], 'csrss.exe': ["conhost.exe"],
                'svchost.exe': ["WmiPrvSE.exe", "audiodg.exe"],
                'wininit.exe': ["services.exe", "lsass.exe", "lsm.exe"]
                }

# expected process sessions
session0_processes = ["wininit.exe", "services.exe", "svchost.exe", "lsm.exe", "lsass.exe"]
session1_processes = ["winlogon.exe"]

# VOLATILITY PROFILES ================================================================
profiles = ["VistaSP0x86", "VistaSP0x64", "VistaSP1x86", "VistaSP1x64", "VistaSP2x86", "VistaSP2x64",
            "Win2003SP0x86", "Win2003SP1x86", "Win2003SP1x64", "Win2003SP2x86", "Win2003SP2x64",
            "Win2008SP1x86", "Win2008SP1x64", "Win2008SP2x86", "Win2008SP2x64", "Win2008R2SP0x64", "Win2008R2SP1x64",
            "Win2012R2x64", "Win2012x64",
            "Win7SP0x86", "Win7SP0x64", "Win7SP1x86", "Win7SP1x64",
            "Win8SP0x86", "Win8SP0x64", "Win8SP1x86", "Win8SP1x64",
            "WinXPSP2x86", "WinXPSP1x64", "WinXPSP2x64", "WinXPSP3x86"]

preferred_profiles = ["Win7SP0x86", "Win7SP0x64", "Win7SP1x86", "Win7SP1x64"]


# PRINT VOLDIFF BANNER ================================================================

# PRINT HELP SECTION ================================================================
def print_help():
    print ("Usage: ./VolDiff.py [BASELINE_IMAGE] INFECTED_IMAGE PROFILE [OPTIONS]")
    print ("\nOptions:")
    print ("--help                display this help and exit")
    print ("--version             display version information and exit")
    print ("--dependencies        display information about script dependencies and exit")
    print ("--malware-checks      hunt and report suspicious anomalies (slow, recommended)")
    print ("--output-dir [dir]    custom directory to store analysis results")
    print ("--no-report           do not create a report")
    print ("\nTested using Volatility 2.5 (vol.py) on Windows 7 images.")
    sys.exit()


# PRINT VERSION INFORMATION ================================================================
def print_version():
    print ("This is a free software: you are free to change and redistribute it.")
    print ("There is no warranty, to the extent permitted by law.")
    print ("Written by @aim4r. Report bugs to voldiff[@]gmail.com.")
    sys.exit()


# PRINT DEPENDENCIES ================================================================
def print_dependencies():
    print ("Requires volatility 2.5 (vol.py) to be installed.")
    sys.exit()


# VERIFY PATH TO VOLATILITY EXISTS ================================================================
def check_volatility_path(path):
    if os.path.isfile(path):
        return True
    for p in os.environ["PATH"].split(os.pathsep):
        full_path = os.path.join(p, path)
        if os.path.exists(full_path):
            return True
    return False


# VERIFY ENOUGH ARGUMENTS ARE SUPPLIED ================================================================
def check_enough_arguments_supplied(n=4):
    if len(sys.argv) < n:
        print("Not enough arguments supplied. Please use the --help option for help.")
        sys.exit()


# SET PROFILE AND FIND PATH TO MEMORY IMAGE(S) ================================================================
def check_profile(pr):
    if pr not in profiles:
        print ("Please specify a valid Volatility Windows profile for use (such as Win7SP1x64).")
        sys.exit()
    if pr not in preferred_profiles:
        print(
            "WARNING: This script was only tested using Windows 7 profiles. The specified profile (%s) seems different!" % pr)
    else:
        print ("Profile: %s" % pr)
    return


# COMPLETION AND CLEANUP FUNCTION ================================================================
def script_completion(start_time):
    if 'report' in globals():
        report.write("\n\nEnd of report.")
        report.close()
        open_report(output_dir + "/VolDiff_Report.txt")
    notify_completion("VolDiff execution completed.")
    shutil.rmtree(output_dir + '/tmpfolder')
    completion_time = time.time() - start_time
    a = int(completion_time / 60)
    b = int(completion_time % 60)
    if 'devnull' in globals():
        devnull.close()
    print("\nVolDiff execution completed in %s minutes and %s seconds." % (a, b))
    sys.exit()


# DIFFING RESULTS ================================================================
def diff_files(path1, path2, diffpath):
    with open(path1, "r") as file1:
        with open(path2, "r") as file2:
            diff = difflib.unified_diff(file1.readlines(), file2.readlines())
            with open(diffpath, 'w+') as file3:
                print >> file3, ''.join(list(diff))
                file3.seek(0)
                lines = file3.readlines()
                file3.seek(0)
                for line in lines:
                    if line.startswith("+") and not line.startswith("+++"):
                        file3.write(line[1:])
                file3.truncate()
    return


# REPORT CREATION ================================================================
def report_plugin(plugin, header_lines=0, threshold=diff_output_threshold):
    report.write("\n\nNew %s entries." % plugin)
    report.write("\n==========================================================================================================================\n")
    if header_lines != 0:
        with open(output_dir + "/" + plugin + "/infected_" + plugin + ".txt") as f:
            for i in range(header_lines):
                line = next(f, '').strip()
                report.write(line + "\n")
    line_counter = 0
    with open(output_dir + "/" + plugin + "/diff_" + plugin + ".txt") as diff:
        for line in diff:
            line_counter += 1
            if line_counter < threshold:
                report.write(line)
            else:
                report.write("\nWarning: too many new entries to report, output truncated!\n")
                break
    return


# OPENING REPORT ================================================================
def open_report(report_path):
    if os.name == 'posix':
        p = Popen(['xdg-open', report_path], stdout=devnull, stderr=devnull)
        p.wait()
    elif os.name == 'mac':
        p = Popen(['open', report_path], stdout=devnull, stderr=devnull)
        p.wait()
    elif os.name == 'nt':
        p = Popen(['cmd', '/c', 'start', report_path], stdout=devnull, stderr=devnull)  # cmd /c start [filename]
        p.wait()


# NOTIFYING ABOUT SCRIPT COMPLETION ================================================================
def notify_completion(message):
    if os.name == 'posix':
        p = Popen(['notify-send', message], stdout=devnull, stderr=devnull)
        p.wait()


# MALWARE ANALYSIS FUNCTIONS ================================================================
def open_full_plugin(plugin="psscan", lines_to_ignore=2, state="infected"):
    if os.path.isfile(output_dir + "/" + plugin + "/" + state + "_" + plugin + ".txt"):
        f = open(output_dir + "/" + plugin + "/" + state + "_" + plugin + ".txt")
    else:
        f = open(output_dir + "/" + plugin + "/" + plugin + ".txt")
    for i in xrange(lines_to_ignore):
        next(f, '')
    return f


def open_diff_plugin(plugin="psscan", lines_to_ignore=2):
    if os.path.isfile(output_dir + "/" + plugin + "/diff_" + plugin + ".txt"):
        f = open(output_dir + "/" + plugin + "/diff_" + plugin + ".txt")
    else:
        f = open(output_dir + "/" + plugin + "/" + plugin + ".txt")
        for i in xrange(lines_to_ignore):
            next(f, '')
    return f


def anomaly_search(plugin, regex_to_include, ignorecase='yes', regex_to_exclude='', diff="diff"):
    match_list = []
    if diff == "diff":
        f = open_diff_plugin(plugin)
    else:
        f = open_full_plugin(plugin)
    for line in f:
        if ignorecase == 'yes':
            if re.search(regex_to_include, line, re.IGNORECASE):
                if regex_to_exclude == '':
                    match_list.append(line)
                elif not re.search(regex_to_exclude, line, re.IGNORECASE):
                    match_list.append(line)
        else:
            if re.search(regex_to_include, line):
                if regex_to_exclude == '':
                    match_list.append(line)
                elif not re.search(regex_to_exclude, line):
                    match_list.append(line)
    f.close()
    return match_list


def anomaly_search_inverted(plugin, regex_to_exclude, ignorecase='yes', regex_to_include=''):
    match_list = []
    f = open_diff_plugin(plugin)
    for line in f:
        if ignorecase == 'yes':
            if not re.search(regex_to_exclude, line, re.IGNORECASE):
                if regex_to_include == '':
                    match_list.append(line)
                elif re.search(regex_to_include, line, re.IGNORECASE):
                    match_list.append(line)
        else:
            if not re.search(regex_to_exclude, line):
                if regex_to_include == '':
                    match_list.append(line)
                elif re.search(regex_to_include, line):
                    match_list.append(line)
    f.close()
    return match_list


def report_anomalies(headline, anomaly_list, delim="=", plugin="", header_lines=0, threshold=ma_output_threshold):
    if len(anomaly_list) != 0:
        report.write("\n\n%s" % headline)
        if delim == "=":
            report.write(
                "\n==========================================================================================================================\n")
        elif delim == '-':
            report.write(
                "\n--------------------------------------------------------------------------------------------------------------------------\n")
        if header_lines != 0 and plugin != "":
            if os.path.isfile(output_dir + "/" + plugin + "/infected_" + plugin + ".txt"):
                with open(output_dir + "/" + plugin + "/infected_" + plugin + ".txt") as f:
                    for i in range(header_lines):
                        line = next(f, '').strip()
                        report.write(line + "\n")
            else:
                with open(output_dir + "/" + plugin + "/" + plugin + ".txt") as f:
                    for i in range(header_lines):
                        line = next(f, '').strip()
                        report.write(line + "\n")
        if len(anomaly_list) > threshold:
            anomaly_list_to_report = anomaly_list[0:threshold]
            anomaly_list_to_report.append("\nWarning: too many entries to report, output truncated!\n")
        else:
            anomaly_list_to_report = anomaly_list
        for line in anomaly_list_to_report:
            report.write(line)
    return


def extract_substrings(input_list, regex):
    extracted_list = []
    for entry in input_list:
        subentries = entry.split(' ')
        for subentry in subentries:
            if re.search(regex, subentry, re.IGNORECASE):
                extracted_list.append(subentry)
    return extracted_list


def tidy_list(input_list):
    updatedlist = []
    for entry in input_list:
        if not re.search("\\n", entry):
            entry += '\n'
        updatedlist.append(entry)
    updatedlist = sorted(set(updatedlist))
    return updatedlist


def find_ips_domains_emails(plugin):
    f = open_diff_plugin(plugin, 0)
    ips = []
    ips_to_report = []
    ips_regex_exclude = r"127\.0\.0\.1|0\.0\.0\.0"
    for line in f:
        if re.search(ips_regex, line, re.IGNORECASE):
            ips += re.findall(ips_regex, line, re.IGNORECASE)
    for ip in ips:
        if not re.search(ips_regex_exclude, ip, re.IGNORECASE):
            ips_to_report.append(ip)
    domains = []
    f.seek(0)
    for line in f:
        if re.search(domains_regex_http, line, re.IGNORECASE):
            domains += re.findall(domains_regex_http, line, re.IGNORECASE)
        if re.search(domains_regex_ftp, line, re.IGNORECASE):
            domains += re.findall(domains_regex_ftp, line, re.IGNORECASE)
        if re.search(domains_regex_file, line, re.IGNORECASE):
            domains += re.findall(domains_regex_file, line, re.IGNORECASE)
    emails = []
    f.seek(0)
    for line in f:
        if re.search(emails_regex, line, re.IGNORECASE):
            emails += re.findall(emails_regex, line, re.IGNORECASE)
    ips_domains_emails = ips_to_report + domains + emails
    ips_domains_emails = tidy_list(ips_domains_emails)
    f.close()
    return ips_domains_emails


def get_pids(procname, plugin="psscan"):
    pids = []
    if procname == "":
        return pids
    f = open_full_plugin(plugin, 2)
    for line in f:
        if re.search(' ' + procname + ' ', line, re.IGNORECASE):
            pids.append(re.sub(' +', ' ', line).split(' ')[2])
    pids = sorted(set(pids))
    f.close()
    return pids


def get_associated_process_lines_pids(pids, plugin="psscan"):
    f = open_full_plugin(plugin, 2)
    associated_psscan_lines = []
    for line in f:
        for pid in pids:
            if re.sub(' +', ' ', line).split(' ')[2] == str(pid):
                associated_psscan_lines.append(line)
    f.close()
    return associated_psscan_lines


def get_associated_process_lines_ppids(ppids, plugin="psscan"):
    f = open_full_plugin(plugin, 2)
    associated_psscan_lines = []
    for line in f:
        for ppid in ppids:
            if re.sub(' +', ' ', line).split(' ')[3] == str(ppid):
                associated_psscan_lines.append(line)
    f.close()
    return associated_psscan_lines


def get_childs_of(pids):
    f = open_full_plugin("psscan", 2)
    childs = []
    for line in f:
        for pid in pids:
            ppid = re.sub(' +', ' ', line).split(' ')[3]
            if ppid == str(pid):
                childs.append(re.sub(' +', ' ', line).split(' ')[2])
    childs = sorted(set(childs))
    f.close()
    return childs


def get_parent_pids_of(childs):
    f = open_full_plugin("psscan", 2)
    parents = []
    for line in f:
        for child in childs:
            if re.sub(' +', ' ', line).split(' ')[2] == child:
                parents.append(re.sub(' +', ' ', line).split(' ')[3])
    parents = sorted(set(parents))
    f.close()
    return parents


def get_procnames(pids):
    f = open_full_plugin("psscan", 2)
    procnames = []
    for line in f:
        for pid in pids:
            if re.sub(' +', ' ', line).split(' ')[2] == pid:
                procnames.append(re.sub(' +', ' ', line).split(' ')[1])
    f.close()
    return procnames


def get_all_pids(exception_regex=''):
    f = open_full_plugin("psscan", 2)
    pids = []
    for line in f:
        if exception_regex != '' and re.search(exception_regex, line, re.IGNORECASE):
            continue
        else:
            pid = re.sub(' +', ' ', line).split(' ')[2]
            if pid != "0":
                pids.append(pid)
    pids = sorted(set(pids))
    f.close()
    return pids


def get_diff_pids(exception_regex=''):
    f = open_diff_plugin("psscan", 2)
    pids = []
    for line in f:
        if exception_regex != '' and re.search(exception_regex, line, re.IGNORECASE):
            continue
        else:
            pid = re.sub(' +', ' ', line).split(' ')[2]
            if pid != "0":
                pids.append(pid)
    pids = sorted(set(pids))
    f.close()
    return pids


def get_procname(pid, plugin='psscan'):
    f = open_full_plugin(plugin, 2)
    procnamee = ""
    for line in f:
        if re.search(r"[a-zA-Z\.]\s+%s " % pid, line, re.IGNORECASE):
            procnamee = (re.sub(' +', ' ', line).split(' ')[1])
            break
    procnamee = str(procnamee)
    f.close()
    return procnamee


def get_all_procnames(plugin='psscan', exception_regex=''):
    f = open_full_plugin(plugin, 2)
    procnames = []
    for line in f:
        if exception_regex != '' and re.search(exception_regex, line, re.IGNORECASE):
            continue
        else:
            procnames.append(re.sub(' +', ' ', line).split(' ')[1])
    procnames = sorted(set(procnames))
    f.close()
    return procnames


def get_all_ppids(exception_regex=''):
    f = open_full_plugin("psscan", 2)
    ppids = []
    for line in f:
        if exception_regex != '' and re.search(exception_regex, line, re.IGNORECASE):
            continue
        elif re.sub(' +', ' ', line).split(' ')[2] != "0":
            ppids.append(re.sub(' +', ' ', line).split(' ')[3])
    ppids = sorted(set(ppids))
    f.close()
    return ppids


def get_session(pid):
    session = ""
    f = open_full_plugin("pslist", 2)
    for line in f:
        if re.search(' ' + str(pid) + ' ', line, re.IGNORECASE):
            session = re.sub(' +', ' ', line).split(' ')[6]
            break
    f.close()
    return session


def get_execpath(pid):
    execpath = ''
    procnamep = get_procname(pid)
    f = open_full_plugin("dlllist", 0)
    for line in f:
        if re.search(procnamep + ' pid.*' + str(pid), line, re.IGNORECASE):
            command_line = next(f, '')
            execpath = re.sub("Command line : ", "", command_line)
            execpath = re.sub(".:", "", execpath)
            execpath = re.sub(" .*", "", execpath)
            execpath = re.sub("\n", "", execpath)
    f.close()
    return execpath


def get_cmdline(pid):
    cmdline = []
    procnamec = get_procname(pid)
    f = open_full_plugin("cmdline", 0)
    for line in f:
        if re.search(procnamec + ' pid.* ' + pid, line, re.IGNORECASE):
            cmdline.append(line)
            line = next(f, '')
            cmdline.append(line)
            break
    if cmdline:
        if not re.search("Command", cmdline[1], re.IGNORECASE):
            cmdline = []
    f.close()
    return cmdline


def deadproc_activethreads():
    f = open_full_plugin("psxview", 2)
    dead_proc_active_threads = []
    for line in f:
        if 'UTC' in str(re.sub(' +', ' ', line).split(' ')[9:]) and re.sub(' +', ' ', line).split(' ')[5] == "True":
            dead_proc_active_threads.append(line)
    f.close()
    return dead_proc_active_threads


def get_hosts_contents(memory_image_file):
    hostscontent = []
    f = open_full_plugin("filescan", 2)
    qaddressb = ""
    for line in f:
        if re.search("etc\\\hosts$", line, re.IGNORECASE):
            qaddressb = re.sub(' +', ' ', line).split(' ')[0]
            break
    if qaddressb != "":
        hostsfolder = tmpfolder + "hosts/"
        if not os.path.isdir(hostsfolder):
            os.makedirs(hostsfolder)
        process_var = Popen([path_to_volatility, "--profile", profile, "-f", memory_image_file, "dumpfiles", "-Q", qaddressb, "-D", hostsfolder], stdout=devnull, stderr=devnull)
        process_var.wait()
        dumped_hosts_filename = os.listdir(hostsfolder)
        if len(dumped_hosts_filename) == 1:
            with open(hostsfolder + str(dumped_hosts_filename[0]), mode='rb') as hosts:
                for line in hosts:
                    if not re.search("^#", line) and re.search(" ", line):
                        hostscontent.append(line)
    hostscontent = sorted(set(hostscontent))
    f.close()
    return hostscontent


def filter_new_services():
    filtered_services = []
    diff_svcscan = open_diff_plugin("svcscan", 0)
    baseline_svcscan = open_full_plugin("svcscan", 0, "baseline")
    for line in diff_svcscan:
        if line not in baseline_svcscan and not re.search("Offset:", line, re.IGNORECASE):
            filtered_services.append(line)
        baseline_svcscan.seek(0)
    filtered_services = set(filtered_services)
    baseline_svcscan.close()
    diff_svcscan.close()
    return filtered_services


def get_associated_services(pid):
    services = []
    full_svcscan = open_full_plugin("svcscan", 0)
    for line in full_svcscan:
        if re.search("Process ID: " + str(pid) + "\n", line, re.IGNORECASE):
            services.append("\n")
            services.append(line)
            for i in xrange(5):
                line = next(full_svcscan, '')
                services.append(line)
    full_svcscan.close()
    return services


def get_malfind_pids():
    malfind_pids = []
    f = open_diff_plugin("malfind", 0)
    for line in f:
        if re.search("Address:", line):
            malfind_pids.append(re.sub(' +', ' ', line).split(' ')[3])
    malfind_pids = sorted(set(malfind_pids))
    f.close()
    return malfind_pids


def get_malfind_injections(pid, m="dual"):
    malfind_injections = []
    f = open_diff_plugin("malfind", 0)
    if m == "dual":
        n = 6
    else:
        n = 7
    for line in f:
        if re.search("Pid: " + str(pid) + " ", line):
            malfind_injections.append("\n")
            malfind_injections.append(line)
            for i in xrange(n):
                line = next(f, '')
                malfind_injections.append(line)
    f.close()
    return malfind_injections


def analyse_registry(pid):
    rhit = False
    registry_analysis_matrix = {"\nCollects information about system": registry_infogathering_regex,
                                "\nQueries / modifies proxy settings": registry_proxy_settings_regex,
                                "\nReads information about supported languages": registry_locale_regex,
                                "\nIdentifies machine name": registry_hostname_regex,
                                "\nIdentifies installed programs": registry_installed_programs_regex,
                                "\nQueries / modifies remote control settings": registry_remote_control_regex,
                                "\nQueries / modifies firewall settings": registry_firewall_regex,
                                "\nQueries / modifies service settings": registry_services_regex,
                                "\nQueries / modifies network settings": registry_network_regex,
                                "\nHas access to autorun registry keys": registry_autorun_regex,
                                "\nQueries / modifies the Windows command processor": registry_command_processor_regex,
                                "\nQueries / modifies encryption seettings": registry_crypto_regex,
                                "\nQueries / modifies file association settings": registry_file_associations_regex,
                                "\nQueries / modifies security seettings": registry_ie_security_regex,
                                }
    res = {"\nCollects information about system": 0,
                                "\nQueries / modifies proxy settings": 0,
                                "\nReads information about supported languages": 0,
                                "\nIdentifies machine name": 0,
                                "\nIdentifies installed programs": 0,
                                "\nQueries / modifies remote control settings": 0,
                                "\nQueries / modifies firewall settings": 0,
                                "\nQueries / modifies service settings": 0,
                                "\nQueries / modifies network settings": 0,
                                "\nHas access to autorun registry keys": 0,
                                "\nQueries / modifies the Windows command processor": 0,
                                "\nQueries / modifies encryption seettings": 0,
                                "\nQueries / modifies file association settings": 0,
                                "\nQueries / modifies security seettings": 0,
                                }
    for reg_key in registry_analysis_matrix:
        registry = anomaly_search("handles", registry_analysis_matrix[reg_key], "yes", "", "diff")
        registry_to_report = []
        for key in registry:
            if re.search(" " + str(pid) + " ", key, re.IGNORECASE) and re.search("Key", key, re.IGNORECASE):
                a = re.sub(' +', ' ', key).split(' ')[5:]
                b = re.sub('\n', '', ' '.join(a))
                registry_to_report.append(b)
        if len(registry_to_report) > 0:
           
            if not rhit:
                report.write("\n\nInteresting registry handles:")
                report.write(
                    "\n--------------------------------------------------------------------------------------------------------------------------\n")
                rhit = True
            report_string = ""
            registry_to_report = sorted(set(registry_to_report))
        
            for regkey in registry_to_report:
                report_string += "  " + regkey + "\n"
            report.write(reg_key + ":\n" + report_string)
            res[reg_key]=len(registry_to_report)
    return res

def analyse_imports(pid):
    import_analysis_matrix = {"Can create new desktops ": ransomware_imports,
                              "Can track keyboard strokes ": keylogger_imports,
                              "Can extract passwords ": password_extract_imports,
                              "Can access the clipboard ": clipboard_imports,
                              "Can inject code to other processes ": process_injection_imports,
                              "Can bypass UAC ": uac_bypass_imports,
                              "Can use antidebug techniques ": anti_debug_imports,
                              "Can receive or send files from or to internet ": web_imports,
                              "Can listen for inbound connections ": listen_imports,
                              "Can create or start services ": service_imports,
                              "Can restart or shutdown the system ": shutdown_imports,
                              "Can interact with the registry ": registry_imports,
                              "Can create or write to files ": file_imports,
                              "Can create atoms ": atoms_imports,
                              "Can identify machine time ": localtime_imports,
                              "Can interact with or query device drivers ": driver_imports,
                              "Can enumerate username ": username_imports,
                              "Can identify machine version information ": machine_version_imports,
                              "Can query startup information ": startup_imports,
                              "Can enumerate free disk space ": diskspace_imports,
                              "Can enumerate system information ": sysinfo_imports
                              }
    res = {"Can create new desktops ": 0,
                              "Can track keyboard strokes ": 0,
                              "Can extract passwords ": 0,
                              "Can access the clipboard ": 0,
                              "Can inject code to other processes ": 0,
                              "Can bypass UAC ": 0,
                              "Can use antidebug techniques ": 0,
                              "Can receive or send files from or to internet ": 0,
                              "Can listen for inbound connections ": 0,
                              "Can create or start services ": 0,
                              "Can restart or shutdown the system ": 0,
                              "Can interact with the registry ": 0,
                              "Can create or write to files ": 0,
                              "Can create atoms ": 0,
                              "Can identify machine time ": 0,
                              "Can interact with or query device drivers ": 0,
                              "Can enumerate username ": 0,
                              "Can identify machine version information ": 0,
                              "Can query startup information ": 0,
                              "Can enumerate free disk space ": 0,
                              "Can enumerate system information ": 0
                              }
    impscanfolder = tmpfolder + "impscan/"
    hit = False
    if os.path.isfile(impscanfolder + str(pid) + ".txt"):
        for susp_imports_codename in import_analysis_matrix:
            regex = import_analysis_matrix[susp_imports_codename]
            susp_functions = []
            with open(impscanfolder + str(pid) + ".txt", "r") as imports:
                for function in imports:
                    if re.search(regex, function, re.IGNORECASE):
                        susp_functions.append(re.sub(' +', ' ', function).split(' ')[3])
            if len(susp_functions) > 0:
                if not hit:
                    report.write("\n\nInteresting imports:")
                    report.write(
                        "\n--------------------------------------------------------------------------------------------------------------------------\n")
                    hit = True
                report_string = ""
                susp_functions = sorted(set(susp_functions))
                for function in susp_functions:
                    if function == susp_functions[-1]:
                        report_string += re.sub("\n", "", function)
                    else:
                        report_string += (re.sub("\n", "", function) + ", ")
                report.write(susp_imports_codename + "(" + report_string + ").\n")
                res[susp_imports_codename]=len(susp_functions)
    return res

def strings(filepath, minimum=4):
    with open(filepath, "rb") as f:
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= minimum:
                yield result
            result = ""


def analyse_strings(pid):
    strings_analysis_matrix = {"IP address(es)": ips_regex,
                               "Email(s)": emails_regex,
                               "HTTP URL(s)": domains_regex_http,
                               "FTP URL(s)": domains_regex_ftp,
                               "File URL(s)": domains_regex_file,
                               "Web related keyword(s)": web_regex_str,
                               "Keylogger keyword(s)": keylogger_regex_str,
                               "Password keyword(s)": password_regex_str,
                               "RAT keyword(s)": rat_regex_str,
                               "Tool(s)": tool_regex_str,
                               "Banking keyword(s)": banking_regex_str,
                               "Social website(s)": socialsites_regex_str,
                               "Antivirus keyword(s)": antivirus_regex_str,
                               "Anti-sandbox keyword(s)": sandbox_regex_str,
                               "Virtualisation keyword(s)": virtualisation_regex_str,
                               "Sysinternal tool(s)": sysinternals_regex_str,
                               "Powershell keyword(s)": powershell_regex_str,
                               "SQL keyword(s)": sql_regex_str,
                               "Shell keyword(s)": shell_regex_str,
                               "Information gathering keyword(s)": infogathering_regex_str,
                               "Executable file(s)": exec_regex_str,
                               "Encryption keyword(s)": crypto_regex_str,
                               "Filepath(s)": filepath_regex_str,
                               "Browser keyword(s)": browser_regex_str,
                               "Misc keyword(s)": other_regex_str
                               }
    dumpfolder = tmpfolder + str(pid) + "/"
    filelist = os.listdir(dumpfolder)
    hit = False
    for susp_strings_codename in strings_analysis_matrix:
        regex = strings_analysis_matrix[susp_strings_codename]
        susp_strings = []
        for f in filelist:
            for stringa in strings(dumpfolder + f):
                if re.search(regex, stringa, re.IGNORECASE):
                    for i in re.findall(regex, stringa, re.IGNORECASE):
                        susp_strings.append(i)
        if len(susp_strings) > 0:
            if not hit:
                report.write("\n\nSuspicious strings from process memory:")
                report.write("\n--------------------------------------------------------------------------------------------------------------------------\n")
                hit = True
            report_string = ""
            susp_strings = sorted(set(susp_strings))
            for susp_string in susp_strings:
                if susp_string == susp_strings[-1]:
                    report_string += re.sub("\n", "", susp_string)
                else:
                    report_string += (re.sub("\n", "", susp_string) + ", ")
            report.write(susp_strings_codename + ": " + report_string + "\n")


def check_expected_parent(pid):
    fl = False
    expected_parent = ""
    childname = get_procname(pid, 'psscan')
    parent = ""
    for parent in parent_child:
        if childname in parent_child[parent]:
            fl = True
            expected_parent = parent
            break
    if fl:
        actual_parent = get_procname(get_parent_pids_of([pid, ])[0], "psscan")
        if actual_parent.lower() != parent.lower():
            j = get_associated_process_lines_pids(get_pids(actual_parent))
            l = get_associated_process_lines_pids(get_pids(expected_parent))
            k = get_associated_process_lines_pids([pid, ])
            report_anomalies("Unexpected parent process (" + actual_parent + " instead of " + expected_parent + "):", k + j + l, '-', "psscan", 2)


def get_remote_share_handles(pid):
    share_handles_to_report = []
    remote_share = anomaly_search("handles", "Device\\\(LanmanRedirector|Mup)", 'yes', '', "diff")
    for share_handle in remote_share:
        if re.sub(' +', ' ', share_handle).split(' ')[1] == pid:
            share_handles_to_report.append(share_handle)
    return share_handles_to_report


def get_raw_sockets(pid):
    raw_sockets_to_report = []
    raw_sockets = anomaly_search("handles", "\\\Device\\\RawIp", 'yes', '', "diff")
    for raw_socket in raw_sockets:
        if re.sub(' +', ' ', raw_socket).split(' ')[1] == pid:
            raw_sockets_to_report.append(raw_socket)
    return raw_sockets_to_report


def get_md5(pid):
    md5 = ""
    dump_folder = tmpfolder + str(pid) + "/"
    filelist = os.listdir(dump_folder)
    for f in filelist:
        if f == "executable." + str(pid) + ".exe":
            md5 = hashlib.md5(open(dump_folder + f).read()).hexdigest()
            break
    return md5


def report_virustotal_md5_results(md5, api):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": md5, "apikey": api}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response_dict = {}
    network_error = False
    try:
        response = urllib2.urlopen(req)
        json = response.read()
        if json != "":
            response_dict = simplejson.loads(json)
    except urllib2.URLError:
        network_error = True
    if not network_error:
        report.write("\n\nVirusTotal scan results:")
        report.write("\n--------------------------------------------------------------------------------------------------------------------------\n")
        report.write("MD5 value: " + md5 + "\n")
        if "response_code" in response_dict:
            if response_dict["response_code"] == 1:
                report.write("VirusTotal scan date: " + str(response_dict["scan_date"]) + "\n")
                report.write("VirusTotal engine detections: " + str(response_dict["positives"]) + "/" + str(response_dict["total"]) + "\n")
                report.write("Link to VirusTotal report: " + str(response_dict["permalink"]) + "\n")
            else:
                report.write("Could not find VirusTotal scan results for the MD5 value above.\n")
        else:
            report.write("VirusTotal request rate limit reached, could not retrieve results.\n")
##################################
global output_dir
global report
global tmpfolder
global profile
global baseline_memory_image
global infected_memory_image
global memory_image
global profile


profile='Win7SP1x64'

if not check_volatility_path(path_to_volatility):
        print("vol.py does not seem to be installed. Please ensure that volatility is installed/functional before using VolDiff.")
        sys.exit()
cuckoop = "/home/gaurav/.cuckoo/storage/analyses"
#dirs=os.listdir(cuckoop)
#################################
idval=''
dirs=[]
with open('/home/gaurav/fifile.txt') as f:
    for line in f:
        idval=line
dirs.append(int(str(idval.rsplit()[8][1:])))
print dirs
#################################################
count=0
for d in dirs:
        
        
        path =str(d)+'/Memory'#+'/memoryAAAAAAAAAAAAaa.dmp'to memory folder
        print path
        epath=str(d)+'/task.json'
        naya=os.path.join(cuckoop, path)
        print cuckoop
        eirs=glob.glob(naya+'/*') #to all files in memory
        print eirs
        flag=0
        prev=''
        mcount =0
        zero=[]
        to_delete=[]
        eirs.sort()
        for e in eirs:
                print e
                count+=1
                memory_image =e #os.path.join(cuckoop, path)
                mcount+=1
                # CREATE FOLDER TO STORE OUTPUT ================================================================

                starttime = time.time()

                output_dir = 'VolDiff_' +str(d)+str(count)+str(mcount)+ datetime.datetime.now().strftime("%d-%m-%Y_%H:%M")
                #if os.name == 'nt':
                 #       output_dir = 'VolDiff_' + datetime.datetime.now().strftime("%d-%m-%Y_%H%M")  # can't name file/dir with :
                tmpval = False
                for arg in sys.argv:
                        if tmpval:
                            output_dir = arg
                            tmpval = False
                        if arg == "--output-dir":
                            tmpval = True
                tmpfolder = output_dir + '/tmpfolder/'
                os.makedirs(tmpfolder)
                mode="single"
                print ("\nRunning a selection of volatility plugins (time consuming):")
                sub_procs = {}
                file_dict = {}
                proc_counter = 0
                for plugin in plugins_to_run:
                        print("Volatility plugin %s execution in progress..." % plugin)
                        plugin_path = output_dir + '/' + plugin + '/'
                        os.makedirs(plugin_path)

                        option = ''
                        # option set, running vol.py processes in //:

                        file_dict[plugin] = open(output_dir + '/' + plugin + '/' + plugin + ".txt", "w")
                        sub_procs[plugin] = Popen([path_to_volatility, "--profile", profile, "-f", memory_image, plugin, option], stdout=file_dict[plugin], stderr=devnull)
                        proc_counter += 1
                        if proc_counter >= max_concurrent_subprocesses:
                                for pr in sub_procs:
                                    sub_procs[pr].wait()
                                proc_counter = 0
                                sub_procs = {}
                # ensuring that all subprocesses are completed before proceeding:
                for pr in sub_procs:
                        sub_procs[pr].wait()
                for f in file_dict:
                        file_dict[f].close()        

                ###################################################
                with open(os.path.join(cuckoop, epath), "r") as cucko_report:
                    file_name=str(json.load(cucko_report).get("target", {}))
                vect=file_name.replace('/',' ')
                vect=vect.rsplit(' ',1)[1][:14]
                file_name=vect
                print file_name

                ############################################
                final_pid=get_pids(file_name)
                print final_pid
                pids_to_analyse=final_pid
                
                ############################################
                if len(final_pid)>0:
                    flag=1
                    if prev=='':
                        prev=e
                    else:
                        to_delete.append(prev)
                        prev=e
                    
                else:
                    to_delete.append(e)
                    
        if len(to_delete)==7:
                shutil.rmtree(str(d), ignore_errors=False, onerror=None)
        else:
                for files in to_delete:
                    os.remove(files)

