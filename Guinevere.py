#!/usr/bin/python
#!/usr/bin/env python

"""Guinevere is a tool used to automate security assessment reporting"""

import MySQLdb, os, docx, argparse, math, netaddr

#Requires MySQL driver, python-mysqldb for Linux. Seems to be installed in Kali
#Requires python-docx library, apt-get update; apt-get install -y python-pip;pip install python-docx

#################################################
#           Gauntlet Variables                  #
#################################################
__author__ = "Russel Van Tuyl"
__license__ = "GPL"
__version__ = "0.8"
__maintainer__ = "Russel Van Tuyl"
__email__ = "Russel.VanTuyl@gmail.com"
__status__ = "Development"
#################################################
#CHANGE TO MATCH YOUR DATABASE
g_ip = "127.0.0.1"         # Database IP address
g_p = 3306                 # Database Port
g_user = "gauntlet"        # Database Username
g_pass = "password"        # Database Password
#################################################

#Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-H', '--db-host', type=str, default=g_ip, help="MySQL Database Host. Default set in script")
parser.add_argument('-U', '--db-user', type=str, default=g_user, help="MySQL Database Username. Default set in script")
parser.add_argument('-P', '--db-pass', type=str, default=g_pass, help="MySQL Database Password. Default set in script")
parser.add_argument('-p', '--db-port', type=str, default=g_p, help="MySQL Database Port. Default set in script")
parser.add_argument('-l', '--lines', type=int, default=10, help="Number of lines to display when selecting an engagement. Default is 10")
#parser.add_argument('-X', '--db-xml', type=argparse.FileType('r'), help="XML Database file")
parser.add_argument('-A', '--all-vulns', action='store_true', default=False, help="Include all vulnerability headings when there are no associated report narratives")
parser.add_argument('-V', '--all-verb', action='store_true', default=False, help="Include all vureto vulnerability verbiage when there are no associated report narratives")
parser.add_argument('-sC', action='store_false', default=True, help="Exclude Critical-Severity Vulnerabilities")
parser.add_argument('-sH', action='store_false', default=True, help="Exclude High-Severity Vulnerabilities")
parser.add_argument('-sM', action='store_false', default=True, help="Exclude Medium-Severity Vulnerabilities")
parser.add_argument('-sL', action='store_true', default=False, help="Include Low-Severity Vulnerabilities")
parser.add_argument('-sI', action='store_true', default=False, help="Include Informational-Severity Vulnerabilities")
#parser.add_argument('-O', '--output', type=str, required=True, help="Output directory for .docx file")
args = parser.parse_args()

def get_assessment (sel):
    """Connects to the assessment database and prompts user to select an engagement"""

    db = MySQLdb.connect(host=args.db_host, user=args.db_user, passwd=args.db_pass, port=args.db_port)
    gauntlet=db.cursor()
    gauntlet.execute("""show databases""")
    hosts = gauntlet.fetchall()
    gauntlet.close()
    dbs = []
    os.system('clear')
    banner()
    p = args.lines  #number of databases to print at a time
    for i in hosts: #add all databases that start with 'gauntlet_' to a list
        if i[0].startswith('gauntlet'):
            dbs.append(i[0].replace("gauntlet_", ''))

    #Print engagements to screen and have user choose one
    s = 0       #Counter for number of engagements printed to the screen
    z = False   
    i = p       #Counter for the number of engagements to display at a time
    while z != True:
        if (s <= i) and (s < len(dbs)):
            print "[" + str(s) + "]" + dbs[s]
            s = s+1
        else:
            print "[99]More..."
            print "[Q]Quit"
            x = raw_input("\nPlease select "+sel+": ")
            try:
                if ((x == "99") or (x == "")):
                    if s == len(dbs):
                        s = 0
                        i = p
                    else:
                        i = i + p
                    os.system('clear')
                    banner()
                elif x == "Q" or x == "q":
                    exit()
                elif dbs[int(x)]:
                    z = True
                else:
                    pass
            except:
                    os.system('clear')
                    banner()
                    print "[!]ERROR: " + x + " is not a valid option. Try again"
                    s = 0
                    i = p
    os.system('clear')
    return dbs[int(x)]

def get_crosstable (assessment):
    """Select the which assessment crosstable to use"""

    crs = ""
    cross = ()
    i = 0
    #Find all the crosstables for the assessment
    while not cross:
        try:
            if i < 100:
                q = """SELECT DISTINCT table_id from cross_data_nva"""
                cross = db_query(q, assessment)
            else:
                print "Its broken try again"
                break
        except:
            i = i+1

    while not crs:
        if len(cross) > 1:  #If there is more than 1 crosstable, have the user choose
            a = 0
            for i in cross:
                print "[" + str(a) + "]",i[0]
                a += 1
            try:
                x = raw_input("\nWhich Crosstable would you like to use: ")
                crs = cross[int(x)]
            except:
                os.system('clear')
                banner()
                print "[!]Error: please try again"
        else:
            crs = cross[0]
    os.system('clear')
    banner()
    return crs[0]

def assessment_vulns (assessment, crosstable):
    """Builds a list of the assessment vulnerabilities"""

    vulns = []

    #Import data from gauntlet db for the selected crosstable
    hosts = db_query("select * from cross_data_nva WHERE table_id = '" + crosstable +"'", assessment)
    plugins = ""
    for i in hosts:
        if ((i[2].startswith('Nessus') or i[2].startswith('Netsparker') or i[2].startswith('Acunetix') or i[2].startswith('BurpSuite')) and i[2] not in plugins):
            plugins += "\n\t[!]" + i[2] + " plugin needs to be added to your Gauntlet database"
        else:
            vulns.append(i[2])   #Vuereto Vuln ID is in spot 2 of the tuple returned by i
    if plugins != "":
        print plugins
        raw_input("Press Enter to Continue")
    return vulns

def assessment_report(vulns):
    """Builds a unique list of Report IDs for the selected assessment and crosstable"""

    temp = []
    for i in vulns:
        if vulns[i]['vuln_report_id'] is not None:
            temp.append(vulns[i]['vuln_report_id'])
        else:
            pass
    return set(temp)

def get_vulns(vuln_IDs, assessment, crosstable):
    """Build dictionary containing the assessment vulnerabilities and their associated information"""
    vulns = {}
    db = MySQLdb.connect(host=args.db_host, user=args.db_user, passwd=args.db_pass, port=args.db_port, db='gauntletdata')
    for i in vuln_IDs:      #Need to just read the database into python once instead of over and over per id
        #need to remove "Nessus 1111" entries
        if (i.startswith('Nessus') or i.startswith('Netsparker') or i.startswith('Acunetix') or i.startswith('BurpSuite')):
            print "[!]", i, "plugin needs to be added to your Gauntlet database"
        else:
            gauntlet=db.cursor()
            #gauntlet.execute("""select title, description, solution, report_id from vulns WHERE vureto_id=%s""",(i,)) #Switch to line below for use with Gauntlet instead of Vureto db
            gauntlet.execute("""select title, description, solution, report_id from vulns WHERE gnaat_id=%s""",(i,))
            temp = gauntlet.fetchone()
            gauntlet.close()
            if temp[3] is not None:
                vulns[i] = {'vuln_id': i, 'vuln_title': temp[0], 'vuln_desc': temp[1], 'vuln_sol': temp[2], 'vuln_report_id': int(temp[3])}
            else:
                vulns[i] = {'vuln_id': i, 'vuln_title': temp[0], 'vuln_desc': temp[1], 'vuln_sol': temp[2], 'vuln_report_id': temp[3]}
    db2 = MySQLdb.connect(host=args.db_host, user=args.db_user, passwd=args.db_pass, port=args.db_port, db='gauntlet_'+ assessment)
    
    #Add all hosts with the associated vulnerability to the rpt dictionary
    for j in vuln_IDs:
        if (j.startswith('Nessus') or j.startswith('Netsparker') or j.startswith('Acunetix') or j.startswith('BurpSuite')):
            pass
        else:
            gauntlet=db2.cursor()
            gauntlet.execute("""SELECT host FROM cross_data_nva WHERE cross_data_nva.table_id =%s AND vuln_id=%s AND (s1='Y' or s2='Y' or s3='Y' or s4='Y' or s5='Y')""",(crosstable,j))
            temp2 = gauntlet.fetchall()
            #print vuln[j]['vuln_title'], temp2 #DEBUG
            vulns[j].update({'vuln_hosts': temp2})
        
    #Determine the rank of the vulnerability
    db3 = MySQLdb.connect(host=args.db_host, user=args.db_user, passwd=args.db_pass, port=args.db_port, db='gauntlet_'+ assessment)
    for k in vuln_IDs:
        if (k.startswith('Nessus') or k.startswith('Netsparker') or k.startswith('Acunetix') or k.startswith('BurpSuite')):
            pass
        else:
            gauntlet=db3.cursor()
            gauntlet.execute("""SELECT s1, s2, s3, s4, s5 FROM cross_data_nva WHERE vuln_id =%s""",(k,))
            temp3 = gauntlet.fetchone()
            if temp3[0] is 'Y':
                vulns[k].update({'vuln_rating': 'Critical'})
            elif temp3[1] is 'Y':
                vulns[k].update({'vuln_rating': 'High'})
            elif temp3[2] is 'Y':
                vulns[k].update({'vuln_rating': 'Medium'})
            elif temp3[3] is 'Y':
                vulns[k].update({'vuln_rating': 'Low'})
            elif temp3[4] is 'Y':
                vulns[k].update({'vuln_rating': 'Informational'})
            else:
                vulns[k].update({'vuln_rating': None})
    return vulns

def get_report(report_IDs, vuln):
    """Build a dictionary containing all of the reporting information"""

    rpt = {}
    db = MySQLdb.connect(host=args.db_host, user=args.db_user, passwd=args.db_pass, port=args.db_port, db='gauntletdata') #change to gauntletdata after dev/or vureto for dev
    
    for i in report_IDs:
        gauntlet=db.cursor()
        gauntlet.execute("""select title, identification, explanation, impact, recommendation from report WHERE report_id=%s""",(i,))
        temp = gauntlet.fetchone()
        gauntlet.close()
        rpt[i] = {'report_id': i, 'report_title': temp[0], 'report_identification': temp[1], 'report_explanation': temp[2], 'report_impact': temp[3], 'report_recommendation': temp[4]}
    for i in vuln: #Add all vulnerabilities with this report ID to the dictionary
        if vuln[i]['vuln_report_id'] is not None:
            if 'vulns' in rpt[vuln[i]['vuln_report_id']]:
                rpt[vuln[i]['vuln_report_id']]['vulns'][vuln[i]['vuln_id']] = vuln[i]
            else:
                rpt[vuln[i]['vuln_report_id']]['vulns'] = {vuln[i]['vuln_id']: vuln[i]}
        else:
            pass

    for i in rpt: #Determine the highest severity level and set it for the reporting record
        r = []
        for j in rpt[i]['vulns']:
            r.append(rpt[i]['vulns'][j]['vuln_rating'])
        if 'Critical' in r:
            rpt[i]['report_rating'] = 'Critical'
            continue
        elif 'High' in r:
            rpt[i]['report_rating'] = 'High'
            continue
        elif 'Medium' in r:
            rpt[i]['report_rating'] = 'Medium'
            continue
        elif 'Low' in r:
            rpt[i]['report_rating'] = 'Low'
            continue
        elif 'Informational' in r:
            rpt[i]['report_rating'] = 'Informational'
            continue
        else:
            rpt[i]['report_rating'] = None
    return rpt

def banner():
    """Guinevere's banner"""
    #Art retrieved from http://www.geocities.com/spunk1111/women.htm#pop

    print """              _,,,_"""
    print """            .'     `'."""
    print "           /     ____ \\"
    print "          |    .`_  _\/"
    print "          /    ) a  a|           ################################################"
    print "         /    (    > |           #               Guinevere v"+__version__+"                 #"
    print """        (      ) ._  /           #                                              #"""
    print "        )    _/-.__.'`\\          #                                              #"
    print """       (  .-'`-.   \__ )         #   Automated Security Assessment Reporting    #"""
    print """        `/      `-./  `.         ################################################"""
    print "         |    \      \  \\"
    print "         |     \   \  \  \\"
    print "         |\     `. /  /   \\"
    print "____________________________________________________________________\n"

def int_to_string(i):
    """Converts an integer to its spelled out version; Used in reporting narratives"""
    
    s = { 0: "", #Dictionary of integers to spelled out words
        1: "one",  
        2: "two",
        3: "three",
        4: "four",
        5: "five",
        6: "six",
        7: "seven",
        8: "eight",
        9: "nine",
        10: "ten",
        11: "eleven",
        12: "twelve",
        13: "thirteen",
        14: "fourteen",
        15: "fifteen",
        16: "sixteen",
        17: "seventeen",
        18: "eighteen",
        19: "nineteen",
        20: "twenty",
        30: "thirty",
        40: "forty",
        50: "fifty",
        60: "sixty",
        70: "seventy",
        80: "eighty",
        90: "ninety"
        }

    #break i into ones, tens, hundreds, thousands and then build string
    #ONES
    if len(str(i)) is 1 and str(i) is "1":  #Spelling for host as opposed to hosts
        return s[i] +" (" + str(i) + ") host"
    elif len(str(i)) is 1 and str(i) is not "1": #Spelling for single digit hosts
        return s[i] +" (" + str(i) + ") hosts"
    #TENS
    elif len(str(i)) is 2 and str(i).startswith("1") :  #To grab spelling for 11 through 19
        return s[i]+" (" + str(i) + ") hosts"
    elif len(str(i)) is 2 and not str(i).startswith("1") and not str(i).endswith("0"): #To grab spelling for 20 through 99 where the number doesn't end in 0
        return s[(i/10)*10]+"-"+s[i -((i/10)*10)] +" (" + str(i) + ") hosts"
    elif len(str(i)) is 2 and not str(i).startswith("1") and str(i).endswith("0"): #To grab spelling for 20 through 99 where the number doesn't end in 0
        return s[(i/10)*10]+s[i -((i/10)*10)] +" (" + str(i) + ") hosts"
    #HUNDREDS
    elif len(str(i)) is 3 and "0" not in str(i): #to grab spelling for 100's where the number doesn't have a zero
        return s[(i/100)]+"-hundred "+s[((i -((i/100)*100))/10)*10]+"-"+s[i-(((i/100)*100)+((i -((i/100)*100))/10)*10)] +" (" + str(i) + ") hosts"
    elif len(str(i)) is 3 and not str(i).endswith("0") and "0" in str(i): #to grab spelling for 100's where the 10s place is 0
        return s[(i/100)]+"-hundred"+s[((i -((i/100)*100))/10)*10]+" "+s[i-(((i/100)*100)+((i -((i/100)*100))/10)*10)] +" (" + str(i) + ") hosts"
    elif len(str(i)) is 3 and str(i).endswith("0"): #to grab spelling for 100's where the number ends in 0
        return s[(i/100)]+"-hundred"+s[((i -((i/100)*100))/10)*10]+s[i-(((i/100)*100)+((i -((i/100)*100))/10)*10)] +" (" + str(i) + ") hosts"
    else:
        return "ERROR, was not able to return the number of host(s)"

def ip_sort(hosts):
    """Put the provided IP addresses into order"""

    ips = []
    for ip in hosts:
        ips.append(netaddr.IPAddress(ip))
    ips = sorted(ips)
    sorted_hosts = []
    for i in ips:
        sorted_hosts.append(str(i))
    return sorted_hosts

def generate_hosts_table(file, ass):
    """Build a list of assessment interesting hosts; hosts with atleast one TCP or UDP port open."""

    hosts = {}
    file.add_page_break()
    print "[-]Generating Interesting Hosts Table"
    #Build dictionary of host IDs and IPs from gauntlet's 'hosts' table
    engagement = db_query("""SELECT value FROM gauntlet_"""+ ass+""".engagement_details WHERE engagement_details.key = 'Engagement Task 1'""", ass)
    if engagement:
        if 'Internal' in engagement[0][0]:
            temp = db_query("""SELECT host_id, ip_address, machine_name from hosts""", ass)
        else:
            temp = db_query("""SELECT host_id, ip_address, fqdn from hosts""", ass)
    else:
        temp = db_query("""SELECT host_id, ip_address, machine_name from hosts""", ass)
    temp2 = db_query("""SELECT host_id, port, protocol from ports""", ass)
    for i in temp:
        tcp = []
        udp = []
        for j in temp2:
            if (j[0] == i[0]) and (j[1] != "0"):
                if j[2] == 'tcp':
                    tcp.append(j[1])
                elif j[2] == 'udp':
                    udp.append(j[1])
                else:
                    pass
            else:
                pass
        hosts[i[0]] = {'IP':i[1], 'Name':i[2], 'TCP':tcp, 'UDP':udp}
    x = 0
    for host in hosts:
        if (len(hosts[host]['TCP']) > 0) or (len(hosts[host]['UDP']) > 0):
            x = x + 1
        else:
            pass
    print "[i]"+str(x) + " Interesting Hosts"
    file.add_heading(str(x) + ' Interesting Host(s) List')
    table = file.add_table(rows=1, cols=4)
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'IP Address'
    hdr_cells[1].text = 'Hostname'
    hdr_cells[2].text = 'Open TCP Port(s)'
    hdr_cells[3].text = 'Open UDP Port(s)'
    table.style = 'MediumGrid1-Accent1'

    for k in hosts:
        if (len(hosts[k]['TCP']) > 0) or (len(hosts[k]['UDP']) > 0):
            x = x + 1
            row_cells = table.add_row().cells
            row_cells[0].text = hosts[k]['IP']
            if len(hosts[k]['Name']) > 0:
                row_cells[1].text = hosts[k]['Name']
            else:
                row_cells[1].text = "---"
            if len(hosts[k]['TCP']) > 0:
                row_cells[2].text = str(hosts[k]['TCP']).lstrip('[').rstrip(']').replace("'", "")
            else:
                row_cells[2].text = "---"
            if len(hosts[k]['UDP']) > 0:
                row_cells[3].text = str(hosts[k]['UDP']).lstrip('[').rstrip(']').replace("'", "")
            else:
                row_cells[3].text = "---"
        else:
            pass
    return file

def generate_vuln_list(report, assessment, rpt):
    """Build the bullet list of vulnerabilities used in the executive summary"""

    engagement = db_query("""SELECT value FROM gauntlet_"""+ assessment+""".engagement_details WHERE engagement_details.key = 'Engagement Task 1'""", assessment)

    if engagement:
        report.add_heading(str(engagement[0][0]) + ' NVA/PT')
    else:
        report.add_heading('NVA/PT')
    for i in rpt:
        item = rpt[i]['report_identification']
        for j in rpt[i]['vulns']:
            item = item.replace("The assessment team identified [n]", int_to_string(len(rpt[i]['vulns'][j]['vuln_hosts'])))
            item = item.rstrip('.')
            item = item[0:1].upper() + item[1:]
            report.add_paragraph(item, style='ListBullet')
    return report

def db_query(q, assessment):
    """General use function used for querying the assessment database"""

    db = MySQLdb.connect(host=args.db_host, user=args.db_user, passwd=args.db_pass, port=args.db_port, db='gauntlet_'+assessment)
    try:
        gauntlet=db.cursor()
        gauntlet.execute(q)
        recordset = gauntlet.fetchall()
        gauntlet.close()
        return recordset
    except:
        print "There was an error performing the following query: "
        print q

def save_report(file, ass):
    """Save the generated assessment report"""
    out_dir = get_path()
    guinevere_file = os.path.join(out_dir, "Guinevere_"+ass+".docx")
    file.save(guinevere_file)
    print "[!]Report saved to: " + guinevere_file

def retest():
    """Create a report for a retest of an assessment"""

    os.system('clear')
    banner()
    print "Retrieving available assessments..."

    #Collect data from the original assessment
    original_assessment = get_assessment("the original assessment")
    banner()
    original_crosstable = get_crosstable(original_assessment)
    print "[-]Gathering original assessment vulnerability IDs..."
    original_vID = assessment_vulns(original_assessment, original_crosstable)
    print "[-]Gathering original assessment vulnerability dataset..."
    original_vuln = get_vulns(original_vID, original_assessment, original_crosstable)

    #Collect data from the retest
    retest_assessment = get_assessment("the retest assessment")
    banner()
    retest_crosstable = get_crosstable(retest_assessment)
    print "[-]Gathering retest vulnerability IDs..."
    retest_vID = assessment_vulns(retest_assessment, retest_crosstable)
    print "[-]Gathering retest vulnerability dataset..."
    retest_vuln = get_vulns(retest_vID, retest_assessment, retest_crosstable)

    #Create the report stub
    retest_report = docx.Document()
    retest_report.add_heading(original_assessment+' Retest Results')

    retest = {} #Dictionary to hold retest data

    for i in original_vuln:
        if original_vuln[i]['vuln_rating'] is not None:
            retest[i] = {'vuln_id': i, 'vuln_title': original_vuln[i]['vuln_title'], 'vuln_rating': original_vuln[i]['vuln_rating'], 'total_orig': len(set(original_vuln[i]['vuln_hosts']))}
            if i in retest_vuln:
                o = set(original_vuln[i]['vuln_hosts']) #Original
                r = set(retest_vuln[i]['vuln_hosts'])   #Retest
                l = o - r                               #Leftover, fixed hosts
                nr = r - o                               #New Retest Hosts
                dr = r - nr                             #Delta Retest; only retest hosts that were in the original
                retest[i].update({'total_retest': len(set(dr))})
                if len(l) == 0:
                    retest[i].update({'status': 'Not Remediated'})
                else:
                    retest[i].update({'status': 'Partially Remediated'})
                    retest[i].update({'v_hosts': dr})#Hosts still vulnerable
                    retest[i].update({'f_hosts': l}) #Fixed hosts
            else:
                retest[i].update({'status': 'Remediated'})

    #Build Status Table
    retest_report.add_heading('Vulnerability Status')
    status_table = retest_report.add_table(rows=1, cols=3)
    status_table.style = 'MediumGrid1-Accent1'
    hdr_cells = status_table.rows[0].cells
    hdr_cells[0].text = 'Severity'
    hdr_cells[1].text = 'Vulnerability'
    hdr_cells[2].text = 'Status'

    #Add Critical first
    for i in retest:
        if retest[i]['vuln_rating'] is 'Critical':
            row_cells = status_table.add_row().cells
            row_cells[0].text = retest[i]['vuln_rating']
            row_cells[1].text = retest[i]['vuln_title']
            row_cells[2].text = retest[i]['status']

    #Add High second
    for i in retest:
        if retest[i]['vuln_rating'] is 'High':
            row_cells = status_table.add_row().cells
            row_cells[0].text = retest[i]['vuln_rating']
            row_cells[1].text = retest[i]['vuln_title']
            row_cells[2].text = retest[i]['status']

    #Add Medium third
    for i in retest:
        if retest[i]['vuln_rating'] is 'Medium':
            row_cells = status_table.add_row().cells
            row_cells[0].text = retest[i]['vuln_rating']
            row_cells[1].text = retest[i]['vuln_title']
            row_cells[2].text = retest[i]['status']

    #Add Low last
    for i in retest:
        if retest[i]['vuln_rating'] is 'Low':
            row_cells = status_table.add_row().cells
            row_cells[0].text = retest[i]['vuln_rating']
            row_cells[1].text = retest[i]['vuln_title']
            row_cells[2].text = retest[i]['status']

    #Build Still Vulnerable Hosts Table
    retest_report.add_heading('Hosts That Are Still Vulnerable')
    vulnerable_table = retest_report.add_table(rows=1, cols=2)
    vulnerable_table.style = 'MediumGrid1-Accent1'
    hdr_cells = vulnerable_table.rows[0].cells
    hdr_cells[0].text = 'Vulnerability'
    hdr_cells[1].text = 'Hosts'

    for i in retest:
        if 'v_hosts' in retest[i]:
            row_cells = vulnerable_table.add_row().cells
            row_cells[0].text = retest[i]['vuln_title']
            hosts = []
            for h in retest[i]['v_hosts']:
                hosts.append(h[0])
            row_cells[1].text = ((str(ip_sort(hosts)).replace("'", "")).lstrip("[")).rstrip("]")

    #Build stats table
    o_total_c = 0   #Original Total Critical
    r_total_c = 0   #Retest Total Critical
    o_total_h = 0
    r_total_h = 0
    o_total_m = 0
    r_total_m = 0
    o_total_l = 0
    r_total_l = 0
    for i in retest:
        #Critical Vulnerabilities
        if retest[i]['vuln_rating'] is 'Critical':
            o_total_c += retest[i]['total_orig']
            if 'total_retest' in retest[i]:
                r_total_c += retest[i]['total_retest']
        #High Vulnerabilities
        if retest[i]['vuln_rating'] is 'High':
            o_total_h += retest[i]['total_orig']
            if 'total_retest' in retest[i]:
                r_total_h += retest[i]['total_retest']
        #Medium Vulnerabilities
        if retest[i]['vuln_rating'] is 'Medium':
            o_total_m += retest[i]['total_orig']
            if 'total_retest' in retest[i]:
                r_total_m += retest[i]['total_retest']
        #Low Vulnerabilities
        if retest[i]['vuln_rating'] is 'Low':
            o_total_l += retest[i]['total_orig']
            if 'total_retest' in retest[i]:
                r_total_l += retest[i]['total_retest']

    s = "The original security assessment identified (" + str(o_total_c) + ") critical-severity, (" + str(o_total_h) + ") high-severity, (" + str(o_total_m) + ") medium-severity, and (" + str(o_total_l) + ") low-severity vulnerabilities."

    #Setup Table
    retest_report.add_heading('Retest Statistics')
    retest_report.add_paragraph(s)
    stats_table = retest_report.add_table(rows=1, cols=5)
    stats_table.style = 'MediumGrid1-Accent1'
    hdr_cells = stats_table.rows[0].cells
    hdr_cells[0].text = ''
    hdr_cells[1].text = 'Critical'
    hdr_cells[2].text = 'High'
    hdr_cells[3].text = 'Medium'
    hdr_cells[4].text = 'Low'
    #Original Assessment Numbers
    row_cells = stats_table.add_row().cells
    row_cells[0].text = 'Original'
    row_cells[1].text = str(o_total_c)
    row_cells[2].text = str(o_total_h)
    row_cells[3].text = str(o_total_m)
    row_cells[4].text = str(o_total_l)

    #Retest Assessment Numbers
    row_cells = stats_table.add_row().cells
    row_cells[0].text = 'Retest'
    row_cells[1].text = str(r_total_c)
    row_cells[2].text = str(r_total_h)
    row_cells[3].text = str(r_total_m)
    row_cells[4].text = str(r_total_l)

    save_report(retest_report, retest_assessment)

def main_menu():
    """Display the main menu"""

    i = None
    valid_options = {1: generate_assessment_report,
                     2: sql_dump,
                     3: retest,
                     4: patch_gauntlet,
    }
    os.system('clear')
    banner()
    while i is None:
        print "GUINEVERE MAIN MENU\n"
        print "[1]Generate Assessment Report"
        print "[2]Export Assessment"
        print "[3]Generate Retest Report"
        print "[4]Patch Gauntled Database"
        i = raw_input("\nWhat would you like to do: ")
        if int(i) in valid_options:
            valid_options[int(i)]()
        else:
            os.system('clear')
            banner()
            print "[!]" + str(i) + " is not a valid option, please try again: "
            i = None

def sql_dump():
    """Use mysqldump to export an assessment to a .sql file"""

    import subprocess, time, platform

    #Find the script location and set the mysqldump executable
    #Will implement functionality in the future
    script_path = os.path.dirname(os.path.realpath(__file__))
    bin_path = os.path.join(script_path, 'bin')
    #Determine the operating system
    operating_system = platform.platform()
    if 'Windows' in operating_system:
        ext = '.exe'
    elif 'Linux' in operating_system:
        ext = '.bin'
    else:
        ext = '.nothing'
    mysqldump = "mysqldump"
    if os.path.isdir(bin_path) and os.path.exists(bin_path+'mysqldump.'+ext):
        mysqldump = bin_path+'mysqldump.'+ext

    assessment = get_assessment("the assessment to backup")
    os.system('clear')
    banner()
    output_path = get_path()
    date_time = time.strftime('%m%d%Y-%H%M%S')
    try:
        sql_file = open(os.path.join(output_path, assessment+"_"+date_time+".sql"), "w")
        subprocess.call([mysqldump, "--host="+args.db_host, "-u", args.db_user, "-p"+args.db_pass, "gauntlet_"+assessment], stdout=sql_file)
        #os.system(mysqldump+" --host="+args.db_host+" -u "+args.db_user+" -p"+args.db_pass+" gauntlet_"+assessment+" > "+sql_file)
        print "[!]SQL file saved to: " + os.path.join(output_path, assessment+"_"+date_time+".sql")
    except OSError:
        print "[!]mysqldump is likely not in your path, please add it and try again"
        raise
    except:
        raise #Just use for debug

def get_path():
    """Prompt the user to enter a directory path"""

    output_path = None
    while output_path is None:
        print "[-]Please enter the directory where you would like the file saved?"
        output_path = raw_input()
        if os.path.isdir(output_path):
            pass
        else:
            os.system('clear')
            banner()
            print "[!]" + str(output_path) + " is not valid, please try again: "
            output_path = None
    return output_path

def write_single_vul(rpt, report):
    """Write the single vulnerability paragraph"""

    report.add_heading(rpt['report_title'] + " (" + rpt['report_rating']+")")

    for i in rpt['vulns']:
        hosts = []
        for j in set(rpt['vulns'][i]['vuln_hosts']):  # Build Single Dimensional List
            hosts.append(j[0])
        hosts = ip_sort(hosts)  # Create a unique & sorted list of hosts (avoids duplicate hosts)
        if len(hosts) == 1:         # If there is just one host
            p = rpt['report_identification'].replace("[n]", int_to_string(len(hosts))+ ' ('+hosts[0]+')')
        elif len(hosts) == 2:       # If there are two hosts
            p = rpt['report_identification'].replace("[n]", int_to_string(len(hosts))+ ' ('+hosts[0]+' and '+hosts[1]+')')
        elif len(hosts) >= 2 and len(hosts) <=5:  # If there are more than two but lest than five hosts
            host_list = ""
            for h in hosts:
                if h is hosts[len(hosts)-1]:  # Check to see if this is the last item in the list
                    host_list += "and " + h + ") "
                else:
                    host_list += h + ", "
            p = rpt['report_identification'].replace("[n]", int_to_string(len(hosts)) + ' ('+host_list)
        elif len(hosts) >= 6:  # If there are six or more hosts
            p = rpt['report_identification'].replace("[n]", int_to_string(len(hosts)) + ', see TABLE X,')

        if p.endswith(" ") or rpt['report_explanation'].startswith(" "):
            p += rpt['report_explanation']
        else:
            p += (" " + rpt['report_explanation'])
        if p.endswith(" ") or rpt['report_impact'].startswith(" "):
            p += rpt['report_impact']
        else:
            p += (" " + rpt['report_impact'])
        report.add_paragraph(p, style='Normal')
        report.add_paragraph(rpt['report_recommendation'], style='Normal')

        if len(hosts) >= 6:     # Draw the table
            c = 4  # number of desired columns
            r = int(math.ceil((len(hosts) / float(4))))  # Determine number of rows for table using a max of 4 columns
            hosts_table = report.add_table(rows=r, cols=c)
            hosts_table.style = 'MediumGrid1-Accent1'
            z = 0   # number of hosts
            x = 0   # row indices
            y = 0   # column indices
            while z < len(hosts):
                if (y / float(c)) == 1:  # Determine if we need to start putting data on a new row
                    y = 0   # reset column indices since max number of columns reached
                    x += 1
                hosts_table.cell(x, y).text = hosts[z]
                z += 1
                y += 1  # Add one to up the column data is put in
            if len(hosts)/float(c) != 1.000:  # Add "---" for empty spots in table
                d = c * (x+1)
                while d > len(hosts):
                    hosts_table.cell(x, y).text = "---"
                    d -= 1
                    y += 1

    return report

def write_multi_vul(rpt, report):

    total_hosts = 0
    for i in rpt['vulns']:
        total_hosts += len(rpt['vulns'][i]['vuln_hosts'])

    report.add_heading(rpt['report_title'] + " (" + rpt['report_rating']+")")
    p = rpt['report_identification'].replace("[n]", int_to_string(total_hosts))

    if p.endswith(" ") or rpt['report_explanation'].startswith(" "):
        p += rpt['report_explanation']
    else:
        p += (" " + rpt['report_explanation'])
    if p.endswith(" ") or rpt['report_impact'].startswith(" "):
        p += rpt['report_impact']
    else:
        p += (" " + rpt['report_impact'])

    report.add_paragraph(p, style='Normal')
    report.add_paragraph(rpt['report_recommendation'], style='Normal')

    table = report.add_table(rows=1, cols=2)
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'Vulnerability'
    hdr_cells[1].text = 'Affected Host(s)'
    table.style = 'MediumGrid1-Accent1'
    for i in rpt['vulns']:
        row_cells = table.add_row().cells
        row_cells[0].text = rpt['vulns'][i]['vuln_title']
        row_cells[1].text = str(len(rpt['vulns'][i]['vuln_hosts']))
    return report

def write_all_vuln(vuln, the_Report):

    print "[-]Writing list of all vulnerabilities to the report: "
    the_Report.add_page_break()
    the_Report.add_heading("List of Assessment Vulnerabilities", 1)
    for i in vuln:
        if vuln[i]['vuln_report_id'] is None and (((vuln[i]['vuln_rating'] is "Critical") and args.sC) or ((vuln[i]['vuln_rating'] is "High") and args.sH) or ((vuln[i]['vuln_rating'] is "Medium") and args.sM) or ((vuln[i]['vuln_rating'] is "Low") and args.sL) or ((vuln[i]['vuln_rating'] is "Informational") and args.sI)):
            print "\t[i]"+ vuln[i]['vuln_title'], "(" + vuln[i]['vuln_rating'] + ")"
            the_Report.add_heading(vuln[i]['vuln_title'] + " (" + vuln[i]['vuln_rating'] + ")", 2)
            if args.all_verb:
                the_Report.add_paragraph(vuln[i]['vuln_desc'], style='BodyText')
                the_Report.add_paragraph(vuln[i]['vuln_sol'], style='BodyText')
    return the_Report

def generate_assessment_report():
    """The main function for automatically generating an assessment report"""

    os.system('clear')
    banner()
    print "Retrieving available assessments..."
    assessment = get_assessment("the assessmnt to create a report for")
    banner()
    crosstable = get_crosstable(assessment)
    vID = assessment_vulns(assessment, crosstable)
    os.system('clear')
    banner()
    print "[-]Building list of found vulnerabilities for " + assessment + " Crosstable " + crosstable + "..."
    vuln = get_vulns(vID, assessment, crosstable)
    print "[-]Generating report for the following vulnerabilities:"
    rID = assessment_report(vuln)
    assessment_db = get_report(rID, vuln)
    the_Report = docx.Document()
    the_Report.add_heading(assessment, 1)
    the_Report = generate_vuln_list(the_Report, assessment, assessment_db)
    if ((len(assessment_db) is 0) and args.all_vulns is False):
        exit("[!]Nothing to report on, quitting...")

    for i in assessment_db: # Write the report in severity order
        if assessment_db[i]['report_rating'] == 'Critical' and args.sC:
            if len(assessment_db[i]['vulns']) > 1:                          # Grouped Vulnerabilty Write-up
                print '\t[i]Multi finding: ', assessment_db[i]['report_title']
                the_report = write_multi_vul(assessment_db[i], the_Report)
            elif assessment_db[i]['report_rating'] is not None:   # Single Vulnerability Write-up
                print "\t[i]" + assessment_db[i]['report_title'] + "(" + assessment_db[i]['report_rating'] + ")"
                the_Report = write_single_vul(assessment_db[i], the_Report)

    for i in assessment_db:
        if assessment_db[i]['report_rating'] == 'High' and args.sH:
            if len(assessment_db[i]['vulns']) > 1:
                print '\t[i]Multi finding: ', assessment_db[i]['report_title']
                the_report = write_multi_vul(assessment_db[i], the_Report)
            elif assessment_db[i]['report_rating'] is not None:
                print "\t[i]" + assessment_db[i]['report_title'] + "(" + assessment_db[i]['report_rating'] + ")"
                the_Report = write_single_vul(assessment_db[i], the_Report)

    for i in assessment_db:
        if assessment_db[i]['report_rating'] == 'Medium' and args.sM:
            if len(assessment_db[i]['vulns']) > 1:
                print '\t[i]Multi finding: ', assessment_db[i]['report_title']
                the_report = write_multi_vul(assessment_db[i], the_Report)
            elif assessment_db[i]['report_rating'] is not None:
                print "\t[i]" + assessment_db[i]['report_title'] + "(" + assessment_db[i]['report_rating'] + ")"
                the_Report = write_single_vul(assessment_db[i], the_Report)

    for i in assessment_db:
        if assessment_db[i]['report_rating'] == 'Low' and args.sL:
            if len(assessment_db[i]['vulns']) > 1:
                print '\t[i]Multi finding: ', assessment_db[i]['report_title']
                the_report = write_multi_vul(assessment_db[i], the_Report)
            elif assessment_db[i]['report_rating'] is not None:
                print "\t[i]" + assessment_db[i]['report_title'] + "(" + assessment_db[i]['report_rating'] + ")"
                the_Report = write_single_vul(assessment_db[i], the_Report)

    for i in assessment_db:
        if assessment_db[i]['report_rating'] == 'Informational' and args.sI:
            if len(assessment_db[i]['vulns']) > 1:
                print '\t[i]Multi finding: ', assessment_db[i]['report_title']
                the_report = write_multi_vul(assessment_db[i], the_Report)
            elif assessment_db[i]['report_rating'] is not None:
                print "\t[i]" + assessment_db[i]['report_title'] + "(" + assessment_db[i]['report_rating'] + ")"
                the_Report = write_single_vul(assessment_db[i], the_Report)

    if args.all_vulns:
        the_Report = write_all_vuln(vuln, the_Report)
    the_Report = generate_hosts_table(the_Report, assessment)
    save_report(the_Report, assessment)

def patch_gauntlet():
    print "Nothing to test right now"
    db = MySQLdb.connect(host=args.db_host, user=args.db_user, passwd=args.db_pass, port=args.db_port, db='gauntletdata')

    create_table = """
        CREATE TABLE report (
            report_id integer NOT NULL AUTO_INCREMENT,
            title character varying(255) NOT NULL DEFAULT '',
            identification blob,
            explanation blob,
            impact blob,
            recommendation blob,
            status ENUM('NEW','MODIFIED','ACCEPTED','MARKED','DELETED') NOT NULL,
            owner character varying(255) NOT NULL DEFAULT '',
            PRIMARY KEY (report_id)
        );"""
    mod_report = """ALTER TABLE report AUTO_INCREMENT = 50000;"""
    mod_vuln_1 = """ALTER TABLE vulns ADD report_id int;"""
    mod_vuln_2 = """ALTER TABLE vulns ADD FOREIGN KEY (report_id) REFERENCES report(report_id);"""

    os.system('clear')
    banner()
    print """[!]Please make sure you have previously selected "(Re-)Initialize Server" in Gauntlet."""
    raw_input("Press Enter to Continue")
    try:
        gauntlet = db.cursor()
        gauntlet.execute(create_table)
        gauntlet.execute(mod_report)
        gauntlet.execute(mod_vuln_1)
        gauntlet.execute(mod_vuln_2)
        gauntlet.close()
    except:
        print "\n[!]Please report this error to " + __maintainer__ + " by email at: " + __email__
        raise

    print "[-]You can now upload a new master dataset to Gauntlet"

if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        print "\n[!]User Interrupt! Quitting...."
    except:
        print "\n[!]Please report this error to " + __maintainer__ + "by email at: "+ __email__
        raise