#!/bin/sh

set F = 1
	
set N_SERVERS = F * 3 + 1

for((i=10000; i < 10002; i++)); do
	osascript -e 'tell application "Terminal" to do script "java -cp ~/PasswordManager/pm-server/target/classes pm.ServerMain '$i'"'
	
done