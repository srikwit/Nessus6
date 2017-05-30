#!/usr/bin/python3
import requests
import json
import time
import sys
import urllib3
import datetime


from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings()

url = 'https://localhost:8834'
verify = False
token = ''
username = 'admin'
password = 'password'




def build_url(resource):
    return '{0}{1}'.format(url, resource)


def connect(method, resource, data=None, params=None):
    headers = {'X-Cookie': 'token={0}'.format(token),'content-type': 'application/json'}
    data = json.dumps(data)

    if method == 'POST':
        r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=params, headers=headers, verify=verify)

    if r.status_code != 200:
        e = r.json()
        print(e['error'])
        sys.exit()

    if 'download' in resource:
        return r.content

    try:
        return r.json()
    except ValueError:
        return r.content

def login(usr, pwd):
    login = {'username': usr, 'password': pwd}
    data = connect('POST', '/session', data=login)
    return data['token']

def logout():
    connect('DELETE', '/session')

def get_policies():
    data = connect('GET', '/editor/policy/templates')
    return dict((p['title'], p['uuid']) for p in data['templates'])

def get_history_ids(sid):
    data = connect('GET', '/scans/{0}'.format(sid))
    return dict((h['uuid'], h['history_id']) for h in data['history'])

def get_scan_history(sid, hid):
    params = {'history_id': hid}
    data = connect('GET', '/scans/{0}'.format(sid), params)

    return data['info']

def add(name, desc, targets, pid):
    scan = {'uuid': pid,
            'settings': {
                'name': name,
                'description': desc,
                'text_targets': targets}
            }
    data = connect('POST', '/scans', data=scan)
    return data['scan']

def launch(sid):
    data = connect('POST', '/scans/{0}/launch'.format(sid))
    return data['scan_uuid']

def status(sid, hid):
    d = get_scan_history(sid, hid)
    return d['status']

def export_status(sid, fid):
    data = connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))
    return data['status'] == 'ready'


def export(sid, hid):
    data = {'history_id': hid,
            'format': 'nessus',
            'chapters': 'vuln_hosts_summary'}
    data = connect('POST', '/scans/{0}/export'.format(sid), data=data)
    fid = data['file']
    while export_status(sid, fid) is False:
        time.sleep(5)
    return fid

def download(sid, fid):
    data = connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
    filename = 'nessus_{0}_{1}.nessus'.format(sid, fid)
    print('Saving scan results to {0}.'.format(filename))
    with open(filename, 'wb') as f:
        f.write(data)

def delete(sid):
    connect('DELETE', '/scans/{0}'.format(scan_id))

def history_delete(sid, hid):
    connect('DELETE', '/scans/{0}/history/{1}'.format(sid, hid))

if __name__ == '__main__':
    print('Login')
    token = login(username, password)
    target_checks=[]
    finalized_targets = ""
    with open("targets.txt","r") as targets:
        for target in targets.readlines():
            target_checks.append(target.rstrip("\r\n"))
    finalized_targets = ','.join(target_checks)
    print("Scanning these targets: "+finalized_targets)
    print('Adding new scan.')
    policies = get_policies()
    policy_id = policies['Basic Network Scan']
    scan_data = add('Network scan', 'CLI API scan using API', finalized_targets, policy_id)
    scan_id = scan_data['id']
    print('Launching new scan.')
    scan_uuid = launch(scan_id)
    history_ids = get_history_ids(scan_id)
    history_id = history_ids[scan_uuid]
    while status(scan_id, history_id) != 'completed':
        time.sleep(30)
    print('Exporting the completed scan.')
    file_id = export(scan_id, history_id)
    download(scan_id, file_id)
    print('Deleting the scan.')
    history_delete(scan_id, history_id)
    delete(scan_id)
    print('Logout')
    logout()
