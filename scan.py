import  glob
import  os
import  sys
import  traceback
from  dotenv import load_dotenv
load_dotenv()
API_KEY = os.getenv("GG_API_KEY") 

from pygitguardian import GGClient
from pygitguardian.config import MULTI_DOCUMENT_LIMIT

# Init GGClient for connecting to gitguardian
client = GGClient(api_key="API_KEY") 

# Creating a list of dictionaries for scanning files
to_scan = []
for name in glob.glob("**/*", recursive=True):
	with open(name) as fn:
		to_scan.append({"document": fn.read(), "filename": os.path.basename(name)})

to_process = []
for i in range(0, len(to_scan), MULTI_DOCUMENT_LIMIT):
   chunk = to_scan[i : i + MULTI_DOCUMENT_LIMIT]
   try:
       scan = client.multi_content_scan(chunk)
   except Exception as exc:
       # Handle exceptions such as schema validation
       traceback.print_exc(2, file=sys.stderr)
       print(str(exc))
   if not scan.success:
       print("Error scanning some files. Results may be incomplete.")
       print(scan)
   to_process.extend(scan.scan_results)

# Printing the results
for i, scan_result in enumerate(to_process):
   if scan_result.has_secrets:
       print(f"{chunk[i]['filename']}: {scan_result.policy_break_count} break/s found")
       # Printing policy break type
       for  policy_break in scan_result.policy_breaks:
           print(f"\t{policy_break.break_type}:")
           # Printing matches
           for match in policy_break.matches:
                print(f"\t\t{match.match_type}:{match.match}")

#JSON results   
for i, scan_result in enumerate(to_process):
   if scan_result.has_policy_breaks:
       print(scan_result.to_json())
