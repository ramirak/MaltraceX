import requests
import json 

#session = requests.Session()
#session.headers = {'X-Apikey': '<api-key>'}

def get_report(hash, header_flag):
    url = "https://www.virustotal.com/api/v3/files/" + hash
    headers = {"accept": "application/json", "x-apikey": "4ac12be1e6eccf9a2dbd6d526531f489e322dd88b906ad2fccdc377a7481e18c"}
    response = requests.get(url, headers=headers)
    result = ""
    if response.status_code != 200:
        return "Could not find file's hash in Virus Total database"
    
    res = json.loads(response.text)
    report_attr = res["data"]["attributes"]
    if header_flag:
        result += "---------------------------------------------------------------------------------------------------\n"
        result += "----------------------------------------Virus Total report:----------------------------------------\n"
        result += "---------------------------------------------------------------------------------------------------\n"
    result += "Total Malicious: " + str(report_attr["last_analysis_stats"]["malicious"]) + "\n"
    result += "Total Undetected: " + str(report_attr["last_analysis_stats"]["undetected"]) + "\n"
    result += "File Reputation: " + str(report_attr["reputation"]) + "\n"
    if "popular_threat_classification" in report_attr:
        result += "Suggested label: " + report_attr["popular_threat_classification"]["suggested_threat_label"] + "\n"
    result += "---------------------------------------------\nEngines results:\n---------------------------------------------\n"
    engines_list = report_attr["last_analysis_results"]
    for i in engines_list:
        result += engines_list[i]["engine_name"] + " - " + engines_list[i]["category"] + "\n" 
    return result

# Wannacry hash for testing
# print(get_report("0a73291ab5607aef7db23863cf8e72f55bcb3c273bb47f00edf011515aeb5894"))
