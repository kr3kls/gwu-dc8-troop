## Testing

### Manual Testing

For manual testing, run the application and enter the following test cases manually:

| URL Type | Length | SSL Cert | Sub-domains | Anchor URL Risk | Links in Tags | Server Form Handler | Political Keywords | Prefix/Suffix | IP Address | Shortened URL | Contains @ symbol | Abnormal URL | Uses // for redirects |
|----------|--------|----------|-------------|-----------------|---------------|---------------------|--------------------|---------------|------------|---------------|--------------------|--------------|-----------------------|
| **Benign** | Normal | Trusted | One | Malicious | Many | Empty | No | No | No | No | No | No | No |
| **State-Sponsored Actor** | Normal | Trusted | Many | Safe | Few | Legitimate | No | Yes | No | No | No | No | No |
| **Organized Cybercrime** | Long | None | None | Safe | Few | Legitimate | No | Yes | Yes | Yes | Yes | Yes | Yes |
| **Hacktivist** | Long | None | Many | Suspicious | Some | Legitimate | Yes | No | No | No | Yes | Yes | Yes |


### Automated Testing

For automated testing, please ensure you are using python 3.11, and then run ```python test.py``` from the week8 folder in the repository. These tests also run whenever there is a commit to the repository as part of the GitHub Actions Workflow for this project. Successful output is shown below:
```
=== Test Results ===
           case expected_label pred_label  score   cluster               profile pass
         benign              0          0 1.0000                                    ✓
state_sponsored              1          1 1.0000 Cluster 1 State-Sponsored Actor    ✓
organized_crime              1          1 1.0000 Cluster 2  Organized Cybercrime    ✓
     hacktivist              1          1 1.0000 Cluster 0            Hacktivist    ✓

✅ All checks passed.
```