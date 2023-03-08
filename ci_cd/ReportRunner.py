import xmltodict
import json
import argparse
import datetime
import requests
from requests.auth import HTTPBasicAuth
from ApiClient import ApiClient


CYCLONE_DX = 'cyclonedx.xml'
ANCHORE = 'anchore_report.json'
OWASP_DAST = 'report.xml'
API_OWASP_DAST = 'api_report.xml'
DEP_CHECK = 'dependency-check-report.json'
TERRA_SCAN = 'terrascan_out.json'
SECRET_SCAN = 'secret-scan.json'
PIPELINE = 'job_details.txt'
LOC = 'loc.json'



class ReportRunner(object):
    def __init__(self, repo_url, app_name, client_id, client_secret, vulnmanagerurl, repo_branch):
        self.api_client = ApiClient(client_id, client_secret, vulnmanagerurl)
        self.app_cmdb_id = self._get_app_cmdb_id(repo_url, app_name)
        self.repo_branch = repo_branch

    def _get_app_cmdb_id(self, repo_url, app_name):
        resp = self.api_client.send_search('search_businessapplications', 'RepoURL', repo_url)
        if not resp:
            now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            endpoint = 'add_businessapplications'
            output = [{
                "RepoURL": repo_url,
                "ApplicationName": app_name
            }]
            resp = self.api_client.send_post(endpoint, output)
            app_id = resp['ID'][0]
        else:
            app_id = resp[0]['ID']
        return app_id

    def _read_in_xml_file(self, file_path):
        with open(file_path, 'r') as f:
            xml_input = f.read()
        json_dict = xmltodict.parse(xml_input)
        return json_dict

    def _read_in_json_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            json_dict = json.load(f)
        return json_dict

    def read_in_cyclonedx_report(self):
        endpoint = 'sbom'
        input = self._read_in_xml_file(CYCLONE_DX)

        output = ''
        self.api_client.send_post(endpoint, output)

    def _get_docker_image_cmdb_id(self, image_name_and_tag):
        resp = self.api_client.send_search('search_dockerimages', 'ImageName:ImageTag', image_name_and_tag)
        if not resp:
            now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            endpoint = 'add_dockerimages'
            output = [{
                "ImageName": image_name_and_tag.split(':')[0],
                "ImageTag": image_name_and_tag.split(':')[1],
                "ImageId": ""
            }]
            resp = self.api_client.send_post(endpoint, output)
            img_id = resp['ID'][0]
        else:
            img_id = resp[0]['ID']
        return img_id

    def get_scan_id(self, scan_name):
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        scan_output = [{
            "ScanName": scan_name,
            "ScanType": "CI/CD",
            "ScanTargets": str(self.app_cmdb_id),
            "ScanStartDate": now,
            "ApplicationId": self.app_cmdb_id,
            "Branch": self.repo_branch
        }]
        resp = self.api_client.send_post('add_vulnerabilityscans', scan_output)
        if resp:
            scan_id = resp['ID'][0]
        else:
            scan_id = None
        return scan_id

    def read_in_anchore_report(self, image_name_and_tag):
        endpoint = 'add_vulnerabilities'
        self.docker_image_id = self._get_docker_image_cmdb_id(image_name_and_tag)
        input = self._read_in_json_file(ANCHORE)
        vulns = input['matches']
        output = []
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = self.get_scan_id('Anchore-CI_CD')
        for v in vulns:
            severity_native = v['vulnerability']['severity'].lower()
            if severity_native != 'negligible':
                if severity_native == 'unknown':
                    severity = 'Informational'
                elif severity_native == 'low':
                    severity = 'Low'
                elif severity_native == 'medium':
                    severity = 'Medium'
                elif severity_native == 'high':
                    severity = 'High'
                elif severity_native == 'critical':
                    severity = 'Critical'
                new = {
                    "VulnerabilityName": f"Docker Container Package Vulnerability - {v['vulnerability']['id']}",
                    "CVEID": v['vulnerability']['id'],
                    "CWEID": "",
                    "Description": v['vulnerability']['description'] if 'description' in v['vulnerability'] else f"Docker Container Package Vulnerability - {v['vulnerability']['id']} for package {v['artifact']['name']}-{v['artifact']['version']}",
                    "ReleaseDate": now,
                    "Severity": severity,
                    "Classification": "Container",
                    "Source": "Anchore-CI_CD",
                    "LastModifiedDate": now,
                    "ReferenceName": "Security Tracker",
                    "ReferenceUrl": v['vulnerability']['dataSource'],
                    "ReferenceTags": "None",
                    "AddDate": now,
                    "ApplicationId": self.app_cmdb_id,
                    "DockerImageId": self.docker_image_id,
                    "VulnerablePackage": f"{v['artifact']['name']}-{v['artifact']['version']}",
                    "VulnerableFilePath": v['artifact']['type'],
                    "ScanId": scan_id
                    }
                if new not in output:
                    output.append(new)

        if output:
            self.api_client.send_post(endpoint, output)

    def read_in_owasp_baseline_report(self, api=False):
        endpoint = 'add_vulnerabilities'
        if api:
            src_file = API_OWASP_DAST
        else:
            src_file = OWASP_DAST
        input = self._read_in_xml_file(src_file)
        r_vulns = input['OWASPZAPReport']['site']['alerts']['alertitem']
        output = []
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = self.get_scan_id('OWASP_ZAP-CI_CD')
        # pull out each instance and store as vuln
        vulns = []
        for v in r_vulns:
            instances = v['instances']['instance']
            if isinstance(instances, list):
                for i in instances:
                    for key in i:
                        v[key] = i[key]
                    vulns.append(v)
            else:
                for key in instances:
                    v[key] = instances[key]
                vulns.append(v)
        for v in vulns:
            severity_native = v['riskdesc'].lower().split(' (')[0]
            if severity_native == 'unknown':
                severity = 'Informational'
            elif severity_native == 'low':
                severity = 'Low'
            elif severity_native == 'medium':
                severity = 'Medium'
            elif severity_native == 'high':
                severity = 'High'
            elif severity_native == 'critical':
                severity = 'Critical'
            new = {
                "VulnerabilityName": v['name'],
                "CVEID": "",
                "CWEID": f"CWE-{v['cweid']}",
                "Description": (v["desc"] + "\n" + v["otherinfo"]) if 'otherinfo' in v and v['otherinfo'] else v['desc'],
                "ReleaseDate": now,
                "Severity": severity,
                "Classification": "DAST",
                "Source": "OWASP_ZAP-CI_CD",
                "LastModifiedDate": now,
                "ReferenceName": "Multiple",
                "ReferenceUrl": v['reference'] if v['reference'] else 'None',
                "ReferenceTags": "None",
                "AddDate": now,
                "ApplicationId": self.app_cmdb_id,
                "Uri": v['uri'],
                "HtmlMethod": v['method'],
                "Param": v['param'] if v['param'] else 'None',
                "Attack": v['attack'] if v['attack'] else 'None',
                "Evidence": v['evidence'] if v['evidence'] else 'None',
                "Solution": v['solution'] if v['solution'] else 'None',
                "ScanId": scan_id
            }
            output.append(new)
        if output:
            self.api_client.send_post(endpoint, output)

    def read_in_dependency_check_report(self):
        endpoint = 'add_vulnerabilities'
        input = self._read_in_json_file(DEP_CHECK)
        vulns = []
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = self.get_scan_id('OWASP_Dependency_Check-CI_CD')
        for i in input['dependencies']:
            if 'vulnerabilities' in i:
                if len(i['packages']) == 1:
                    for j in i['vulnerabilities']:
                        severity_native = j['severity'].lower()
                        if severity_native == 'info':
                            severity = 'Informational'
                        elif severity_native == 'low':
                            severity = 'Low'
                        elif severity_native == 'medium':
                            severity = 'Medium'
                        elif severity_native == 'high':
                            severity = 'High'
                        elif severity_native == 'critical':
                            severity = 'Critical'
                        new = {
                            "VulnerabilityName": f"Imported Library Vulnerability",
                            "CVEID": j['name'] if j['name'].startswith('CVE-') else "",
                            "CWEID": j["cwes"][0],
                            "Description": j["description"],
                            "ReleaseDate": now,
                            "Severity": severity,
                            "Classification": "SCA",
                            "Source": "OWASP_Dependency_Check-CI_CD",
                            "LastModifiedDate": now,
                            "ReferenceName": "Multiple",
                            "ReferenceUrl": j['references'][0]['url'],
                            "ReferenceTags": "None",
                            "AddDate": now,
                            "ApplicationId": self.app_cmdb_id,
                            "VulnerablePackage": i['packages'][0]['id'],
                            "VulnerableFileName": i['fileName'],
                            "VulnerableFilePath": i['filePath'],
                            "ScanId": scan_id
                        }
                        vulns.append(new)
                else:
                    print()
        if vulns:
            self.api_client.send_post(endpoint, vulns)

    def read_in_terrascan_report(self):
        endpoint = 'add_vulnerabilities'
        input = self._read_in_json_file(TERRA_SCAN)
        vulns = input['results']['violations']
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = self.get_scan_id('Terrascan-CI_CD')
        output = []
        for v in vulns:
            severity_native = v['severity'].lower()
            if severity_native == 'info':
                severity = 'Informational'
            elif severity_native == 'low':
                severity = 'Low'
            elif severity_native == 'medium':
                severity = 'Medium'
            elif severity_native == 'high':
                severity = 'High'
            elif severity_native == 'critical':
                severity = 'Critical'
            new = {
                "VulnerabilityName": f"Infrastructure as Code - {v['category']} - {v['rule_name']}",
                "CVEID": "",
                "CWEID": "",
                "Description": v["description"].replace("'", "").replace(":", ""),
                "ReleaseDate": now,
                "Severity": severity,
                "Classification": f"IaC-{v['category']}",
                "Source": "Terrascan-CI_CD",
                "LastModifiedDate": now,
                "AddDate": now,
                "ApplicationId": self.app_cmdb_id,
                "VulnerableFileName": v['file'],
                "SourceCodeFileStartLine": v['line'],
                "ScanId": scan_id
                }
            output.append(new)
        if output:
            self.api_client.send_post(endpoint, output)

    def read_in_secretscan_report(self):
        endpoint = 'add_vulnerabilities'
        vulns = []
        with open(SECRET_SCAN, 'r') as f:
            json_lines = f.readlines()
            for finding in json_lines:
                f = json.loads(finding)
                vulns.append(f)
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = self.get_scan_id('Trufflehog-CI_CD')
        output = []
        for v in vulns:

            new = {
                "VulnerabilityName": f"Hardcoded Secret - {v['DetectorName']}",
                "CVEID": "",
                "CWEID": "CWE-798",
                "Description": f"{v['DetectorName']} Secret/Credential Discovered in file: {v['SourceMetadata']['Data']['Filesystem']['file']}",
                "ReleaseDate": now,
                "Severity": "Critical",
                "Classification": f"SecretScan-{v['DetectorName']}",
                "Source": "Trufflehog-CI_CD",
                "LastModifiedDate": now,
                "AddDate": now,
                "ApplicationId": self.app_cmdb_id,
                "VulnerableFileName": v['SourceMetadata']['Data']['Filesystem']['file'],
                "ScanId": scan_id
                }
            output.append(new)
        if output:
            self.api_client.send_post(endpoint, output)

    def read_in_pipelinejob_report(self):
        endpoint = 'add_pipelinejobs'
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        details = {'ApplicationId': self.app_cmdb_id, 'Source': 'Jenkins CI/CD', 'Status': 'In-Progress', 'StartDate': now}
        with open(PIPELINE, 'r') as f:
            lines = f.readlines()
        for l in lines:
            line = l.replace('\n', '')
            if line.startswith('Branch Name: '):
                details['BranchName'] = line.split('Branch Name: ')[1]
            elif line.startswith('Build Number: '):
                details['BuildNum'] = line.split('Build Number: ')[1]
            elif line.startswith('Job Name: '):
                details['JobName'] = line.split('Job Name: ')[1]
            elif line.startswith('Project: '):
                details['Project'] = line.split('Project: ')[1]
            elif line.startswith('Node: '):
                details['Node'] = line.split('Node: ')[1]
            elif line.startswith('Git Commit: '):
                details['GitCommit'] = line.split('Git Commit: ')[1]
            elif line.startswith('Git Branch: '):
                details['GitBranch'] = line.split('Git Branch: ')[1]
            elif line.startswith('Git URL: '):
                details['GitUrl'] = line.split('Git URL: ')[1]
            elif line.startswith('Node IP: '):
                details['NodeIp'] = line.split('Node IP: ')[1]
        output = [details]
        if output:
            self.api_client.send_post(endpoint, output)

    def read_in_loc_report(self):
        endpoint = 'add_appcodecomposition'
        input = self._read_in_json_file(LOC)

        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        output = []
        new = {
            "AddDate": now,
            "ApplicationID": self.app_cmdb_id,
            "JavaFiles": int(input['JAVA_FILES']),
            "JavaLoc": int(input['JAVA_LOC']),
            "PythonFiles": int(input['PYTHON_FILES']),
            "PythonLoc": int(input['PYTHON_LOC']),
            "PerlFiles": int(input['PERL_FILES']),
            "PerlLoc": int(input['PERL_LOC']),
            "CFiles": int(input['C_FILES']),
            "CLoc": int(input['C_LOC']),
            "GoFiles": int(input['GO_FILES']),
            "GoLoc": int(input['GO_LOC']),
            "JavascriptFiles": int(input['JAVASCRIPT_FILES']),
            "JavascriptLoc": int(input['JAVASCRIPT_LOC']),
            }
        output.append(new)
        if output:
            self.api_client.send_post(endpoint, output)

    def get_sq_issues_for_project(self, project_key):
        endpoint = 'add_vulnerabilities'
        API_TOKEN = 'admin'
        PW = 'Nbal!ve1!'
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        url = f'http://192.168.0.35:9000/api/issues/search?projects={project_key}&facets=cwe,&types=VULNERABILITY&additionalFields=_all'
        resp = requests.get(url, headers, auth=HTTPBasicAuth(API_TOKEN, PW))
        json_resp = resp.json()
        vulns = json_resp['issues']
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = self.get_scan_id('SonarQube-CI_CD')
        output = []
        for v in vulns:
            severity_native = v['severity'].lower()
            if severity_native == 'info':
                severity = 'Informational'
            elif severity_native == 'minor':
                severity = 'Low'
            elif severity_native == 'major':
                severity = 'Medium'
            elif severity_native == 'critical':
                severity = 'High'
            elif severity_native == 'blocker':
                severity = 'Critical'
            new = {
                "VulnerabilityName": v['message'],
                "CVEID": "",
                "CWEID": "",
                "Description": v["message"],
                "ReleaseDate": now,
                "Severity": severity,
                "Classification": f"SAST",
                "Source": "SonarQube-CI_CD",
                "LastModifiedDate": now,
                "AddDate": now,
                "ApplicationId": self.app_cmdb_id,
                "VulnerableFileName": v['component'].rsplit('/', 1)[1],
                "VulnerableFilePath": v['component'].split(":")[1],
                "SourceCodeFileStartLine": v['textRange']['startLine'],
                "SourceCodeFileStartCol": v['textRange']['startOffset'],
                "SourceCodeFileEndLine": v['textRange']['endLine'],
                "SourceCodeFileEndCol": v['textRange']['endOffset'],
                "ScanId": scan_id
            }
            output.append(new)
        if output:
            self.api_client.send_post(endpoint, output)

    # JIRA Section #
    def read_in_jira_details(self, release_num, jira_user, jira_api_key):
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        self.jira_auth = HTTPBasicAuth(jira_user, jira_api_key)

        endpoint = 'add_releaseversions'
        release_notes, issues, release_date, source_id = self.get_release_notes(release_num)
        release_details = [{
            "ApplicationID": self.app_cmdb_id,
            "ReleaseName": release_num,
            "ReleaseDate": release_date,
            "Description": release_notes,
            "Source": "JIRA",
            "SourceID": source_id
        }]
        resp = self.api_client.send_post(endpoint, release_details)

        endpoint = 'add_servicetickets'
        output = []
        
        for i in issues:
            key = i['key']
            title = i['fields']['summary']
            description = ''
            if i['fields']['description']:
                for line in i['fields']['description']['content']:
                    description += '\n'.join([j['text'] for j in line['content']])
            new = {
                "ReleaseID": resp['ID'][0],
                "TicketName": f"{key} - {title}",
                "Description": description,
                "Source": "JIRA",
                "SourceID": i['id'],
                "Reporter": i['fields']['reporter']['displayName'],
                "Assignee": i['fields']['assignee']['emailAddress'],
                "Status": i['fields']['status']['name'],
            }
            output.append(new)
        self.api_client.send_post(endpoint, output)
    
    def get_issues(self):
        url = "https://securityuniversaltesting.atlassian.net/rest/api/3/search"
        headers = {
            "Accept": "application/json"
        }

        query = {
            'jql': 'project = VRS'
        }

        response = requests.request(
            "GET",
            url,
            headers=headers,
            params=query,
            auth=self.jira_auth
        )
        resp = json.loads(response.text)
        # print(json.dumps(json.loads(response.text), sort_keys=True, indent=4, separators=(",", ": ")))
        return resp['issues']

    def get_release_issues(self, release_num):
        all = self.get_issues()
        release_issues = []
        release_date = None
        source_id = None
        for i in all:
            for f in i['fields']['fixVersions']:
                name_check = f['name']
                if name_check == release_num:
                    release_issues.append(i)
                    if not release_date:
                        release_date = f['releaseDate']
                    if not source_id:
                        source_id = f['id']
                    break
        return release_issues, release_date, source_id

    def get_release_notes(self, release_num):
        issues, release_date, source_id = self.get_release_issues(release_num)
        notes = []
        for i in issues:
            key = i['key']
            title = i['fields']['summary']
            description = ''
            if i['fields']['description']:
                for line in i['fields']['description']['content']:
                    description += '\n'.join([j['text'] for j in line['content']])
            note = f"{key} - {title}: {description}\n\n"
            notes.append(note)
        release_notes = 'Fixes\n\n' + ''.join(notes)
        return release_notes, issues, release_date, source_id
    # END JIRA Section #
    
    # Github Section #
    def read_in_github_details(self):
        pass
    
    def get_pull_requests(self, repo_name, gh_api_token, gh_username):
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {gh_api_token}"
        }
        url = f'https://api.github.com/repos/SecurityUniversalOrg/{repo_name}/pulls'

        resp = requests.get(url, headers, auth=HTTPBasicAuth(gh_username, gh_api_token))
        json_resp = resp.json()
        return json_resp
    # END Github Section #

if __name__ == '__main__':
    arg_desc = 'Run in CI/CD Pipeline'
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=arg_desc)
    parser.add_argument("-t", "--testingtype", metavar="TESTINGTYPE", help="The type of report")
    parser.add_argument("-u", "--repourl", metavar="REPOURL", help="The GIT Repo URL")
    parser.add_argument("-a", "--appname", metavar="APPNAME", help="The Name of the Application")
    parser.add_argument("-i", "--clientid", metavar="CLIENTID", help="The oauth2 client_id for the Vuln Manager")
    parser.add_argument("-s", "--clientsecret", metavar="CLIENTSECRET", help="The oauth2 client_secret for the Vuln Manager")
    parser.add_argument("-v", "--vulnmanagerurl", metavar="VULNMANAGERURL", help="The URL for the Vuln Manager")
    parser.add_argument("-d", "--dockerimage", metavar="DOCKERIMAGE", help="The name and tag for the docker image", required=False)
    parser.add_argument("-p", "--projectkey", metavar="PROJECTKEY", help="The SonarQube project key",
                       required=False)
    parser.add_argument("-r", "--releasenum", metavar="RELEASENUM", help="The Application release number or name",
                        required=False)
    parser.add_argument("-j1", "--jirauser", metavar="JIRAUSER", help="The JIRA username",
                        required=False)
    parser.add_argument("-j2", "--jiraapikey", metavar="JIRAAPIKEY", help="The JIRA api key",
                        required=False)
    parser.add_argument("-b", "--branch", metavar="BRANCH", help="The Git Branch",
                        required=False)
    args = vars(parser.parse_args())
    repo_url = args["repourl"]
    app_name = args["appname"]
    client_id = args["clientid"]
    client_secret = args["clientsecret"]
    vulnmanagerurl = args["vulnmanagerurl"]
    report_type = args["testingtype"]
    branch = args["branch"]
    if report_type == 'anchore':
        docker_img = args['dockerimage']
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).read_in_anchore_report(docker_img)
    elif report_type == 'owasp_baseline':
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).read_in_owasp_baseline_report()
    elif report_type == 'owasp_baseline_api':
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).read_in_owasp_baseline_report(api=True)
    elif report_type == 'owasp_dependency_check':
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).read_in_dependency_check_report()
    elif report_type == 'terrascan':
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).read_in_terrascan_report()
    elif report_type == 'sonarqube':
        projectkey = args['projectkey']
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).get_sq_issues_for_project(projectkey)
    elif report_type == 'jira':
        release_num = args['releasenum']
        jira_user = args['jirauser']
        jira_api_key = args['jiraapikey']
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).read_in_jira_details(release_num, jira_user, jira_api_key)
    elif report_type == 'github':
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).read_in_github_details()
    elif report_type == 'secretscan':
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).read_in_secretscan_report()
    elif report_type == 'pipeline':
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).read_in_pipelinejob_report()
    elif report_type == 'loc':
        ReportRunner(repo_url, app_name, client_id, client_secret, vulnmanagerurl, branch).read_in_loc_report()
