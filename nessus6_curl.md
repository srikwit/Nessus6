Curl Examples
=============
All but a few requests require a content type of application/json. All requests with the exception of the POST request to /session require a token. In each of the requests below, the Nessus server is assumed to be 10.10.10.10. The example responses are formatted to make them easier to read.

Login
-----
curl -k -X POST -H 'Content-Type: application/json' -d '{"username":"username","password":"password"}' https://10.10.10.10:8834/session

{"token":"14632bb35282171c7b18472287c253668423eb16c1187803"}


Logout
------
curl -k -X DELETE -H 'X-Cookie: token=<token>' https://10.10.10.10:8834/session

null


File Upload
-----------
curl -k -X POST -H 'X-Cookie: token=<token>' -F 'Filename=test.nessus' -F 'Filedata=@test.nessus' https://10.10.10.10:8834/file/upload

{"fileuploaded":"test.nessus"}


Scan Import
-----------
The filename below should be the value of fileuploaded that is returned by the call to /file/upload.

curl -k -X POST -H 'X-Cookie: token=<token>' -H 'Content-Type: application/json' -d '{"file": "test.nessus"}' https://10.10.10.10:8834/scans/import

{
  "scan":{
    "timezone":null,
    "id":16,
    "last_modification_date":1418130215,
    "status":"imported",
    "user_permissions":128,
    "folder_id":2,
    "owner":"admin",
    "control":null,
    "starttime":null,
    "uuid":"462fd671-c13a-ea51-607b-3cfa027405500cc4a57660c16756",
    "rrules":null,
    "creation_date":1418130215,
    "read":false,
    "name":"Test Scan",
    "shared":false
  }
}


Policy Import
-------------
The filename below should be the value of fileuploaded that is returned by the call to /file/upload.

curl -k -X POST -H 'X-Cookie: token=<token>' -H 'Content-Type: application/json' -d '{"file": "test.nessus"}' https://10.10.10.10:8834/policies/import

{
  "no_target":"false",
  "template_uuid":"731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65",
  "description":"Create a new scan with API",
  "name":"Basic Network Scan",
  "owner":"admin",
  "shared":0,
  "user_permissions":128,
  "last_modification_date":1418130495,
  "creation_date":1418130495,
  "owner_id":2,"id":17
}


List Policies
-------------
This call will list all of the default templates built into Nessus. The uuid value for the policy will be needed to launch a scan using that policy.

curl -k -H 'X-Cookie: token=<token>' https://10.10.10.10:8834/editor/policy/templates

{
  "templates":[
    {
      "desc":"Approved for quarterly external scanning as required by PCI.",
      "title":"PCI Quarterly External Scan",
      "name":"asv",
      "subscription_only":false,
      "uuid":"cfc46c2d-30e7-bb2b-3b92-c75da136792d080c1fffcc429cfd",
      "cloud_only":false
    },
    {
      "desc":"A simple scan to discover live hosts and open ports.",
      "title":"Host Discovery",
      "name":"discovery",
      "subscription_only":false,
      "uuid":"bbd4f805-3966-d464-b2d1-0079eb89d69708c3a05ec2812bcf",
      "cloud_only":false},...
  ]
}


Add New Scan
------------
The uuid below can be obtained by making a GET request to /editor/policy/templates. Each template has a uuid value associated with it. To launch a scan using the newly created template you will need the id value from the response.

curl -k -X POST -H 'X-Cookie: token=<token>' -H 'Content-Type: application/json' -d '{"uuid": "cfc46c2d-30e7-bb2b-3b92-c75da136792d080c1fffcc429cfd", "settings": {"name": "Scan Name", "description": "Scan Description", "text_targets": "192.168.1.0/24"}' https://10.10.10.10:8834/scans

{
  "scan":{
    "uuid":"template-56530307-b864-6e73-7480-afc515e905ee2175bb49ae596312",
    "name":"Scan Name",
    "description":"Scan Description",
    "policy_id":19,
    "scanner_id":1,
    "emails":null,
    "custom_targets":"192.168.1.0\/24",
    "starttime":null,
    "rrules":null,
    "timezone":null,
    "notification_filters":null,
    "shared":0,
    "user_permissions":128,
    "default_permisssions":0,
    "owner":"admin",
    "owner_id":2,
    "last_modification_date":1418131472,
    "creation_date":1418131472,
    "type":"public",
    "id":20
  }
}


Launch a Scan
-------------
The scan id value can be obtained by reading the id field in the response when creating a new scan or by reading the id field from one of the scan objects returned by making a GET request to /scans.

curl -k -X POST -H 'X-Cookie: token=<token>' -d '' https://10.10.10.10:8834/scans/20/launch

{"scan_uuid":"26f7fde5-5906-91bd-5e85-d8b67676ce3157896aef4d6bf6a5"}


List Scans
----------
curl -k -H 'X-Cookie: token=<token>' https://10.10.10.10:8834/scans

{
  "folders":[
    {
      "unread_count":2,
      "custom":0,
      "default_tag":1,
      "type":"main",
      "name":"My Scans",
      "id":2
    },
    {
      "unread_count":null,
      "custom":0,
      "default_tag":0,
      "type":"trash",
      "name":"Trash",
      "id":3
    }
  ],
  "scans":[
    {
      "folder_id":2,
      "read":false,
      "last_modification_date":1418131921,
      "creation_date":1418131844,
      "status":"running",
      "uuid":"26f7fde5-5906-91bd-5e85-d8b67676ce3157896aef4d6bf6a5",
      "shared":false,
      "user_permissions":128,
      "owner":"admin",
      "timezone":null,
      "rrules":null,
      "starttime":null,
      "control":true,
      "name":"Scan Name",
      "id":20
    },
    {
      "folder_id":2,
      "read":false,
      "last_modification_date":1418130215,
      "creation_date":1418130215,
      "status":"imported",
      "uuid":"462fd671-c13a-ea51-607b-3cfa027405500cc4a57660c16756",
      "shared":false,
      "user_permissions":128,
      "owner":"admin",
      "timezone":null,
      "rrules":null,
      "starttime":null,
      "control":false,
      "name":"Test Scan",
      "id":16
    }
  ],
  "timestamp":1418131924
}
