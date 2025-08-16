## Manual Testing

### Benign Example

Execute this test by running the command: python 2_analyze_domain.py --domain google.com

Expected output for a successful test is shown below:

```
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
  Java Version: openjdk version "17.0.16" 2025-07-15; OpenJDK Runtime Environment (build 17.0.16+8-Ubuntu-0ubuntu124.04.1); OpenJDK 64-Bit Server VM (build 17.0.16+8-Ubuntu-0ubuntu124.04.1, mixed mode, sharing)
  Starting server from /home/parallels/Documents/gwu-dc8-troop/SEAS-8414/week9/.venv/lib/python3.11/site-packages/h2o/backend/bin/h2o.jar
  Ice root: /tmp/tmpvo84nfm3
  JVM stdout: /tmp/tmpvo84nfm3/h2o_parallels_started_from_python.out
  JVM stderr: /tmp/tmpvo84nfm3/h2o_parallels_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 19 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  --------------------------------
H2O_cluster_uptime:         01 secs
H2O_cluster_timezone:       America/New_York
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 19 days
H2O_cluster_name:           H2O_from_python_parallels_3w7a0g
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    1 Gb
H2O_cluster_total_cores:    4
H2O_cluster_allowed_cores:  4
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.11.13 final
--------------------------  --------------------------------

Analyzing domain: google.com
Features -> length=10, entropy=2.6464
Prediction -> class=legit (dga=0.0000, legit=1.0000)

Prediction is 'legit', skipping GenAI playbook.

H2O session _sid_a674 closed.
```

### DGA Example

Execute this test by running the command: python 2_analyze_domain.py --domain 1qw0wj01buakpscg.com

Expected output for a successful test is shown below:

```
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
  Java Version: openjdk version "17.0.16" 2025-07-15; OpenJDK Runtime Environment (build 17.0.16+8-Ubuntu-0ubuntu124.04.1); OpenJDK 64-Bit Server VM (build 17.0.16+8-Ubuntu-0ubuntu124.04.1, mixed mode, sharing)
  Starting server from /home/parallels/Documents/gwu-dc8-troop/SEAS-8414/week9/.venv/lib/python3.11/site-packages/h2o/backend/bin/h2o.jar
  Ice root: /tmp/tmp_d2ysexi
  JVM stdout: /tmp/tmp_d2ysexi/h2o_parallels_started_from_python.out
  JVM stderr: /tmp/tmp_d2ysexi/h2o_parallels_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 19 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  --------------------------------
H2O_cluster_uptime:         00 secs
H2O_cluster_timezone:       America/New_York
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 19 days
H2O_cluster_name:           H2O_from_python_parallels_sve5nx
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    1 Gb
H2O_cluster_total_cores:    4
H2O_cluster_allowed_cores:  4
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.11.13 final
--------------------------  --------------------------------

Analyzing domain: 1qw0wj01buakpscg.com
Features -> length=20, entropy=3.9219
Prediction -> class=dga (dga=1.0000, legit=0.0000)

100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00,  1.42it/s]
- Alert: Potential DGA domain detected.
- Domain: '1qw0wj01buakpscg.com'
- AI Model Explanation (from SHAP): The model flagged this domain with 100.0% confidence. The classification was primarily driven by:
  - A 'length' value of 20 (strongly pushed the prediction towards 'dga').
  - A 'entropy' value of 3.9219 (slightly pushed the prediction towards 'dga'). 

XAI findings saved to: /home/parallels/Documents/gwu-dc8-troop/SEAS-8414/week9/xai_findings_1qw0wj01buakpscg_com.txt
SHAP force plot saved to: /home/parallels/Documents/gwu-dc8-troop/SEAS-8414/week9/explain_1qw0wj01buakpscg_com_shap_force.png

--- Requesting Prescriptive Incident Response Playbook (Gemini) ---
Here are the steps for the Tier 1 analyst:

1.  **Identify Source Host:** Determine which internal host attempted to communicate with the domain '1qw0wj01buakpscg.com'.
2.  **Isolate Host:** Immediately isolate the identified host from the network.
3.  **Escalate Incident:** Document all findings and escalate the incident to a Tier 2 analyst or SOC Lead. 

Playbook saved to: /home/parallels/Documents/gwu-dc8-troop/SEAS-8414/week9/playbook_1qw0wj01buakpscg_com.txt

H2O session _sid_aa2a closed.
```