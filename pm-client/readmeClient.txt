Instructions using Maven — Client:
——————————————————————————————————

To compile and copy the properties file to the output directory:
  mvn compile

To create a JAR with the compiled files:
  mvn package -Dmaven.test.skip=true

To generate launch scripts for Windows and Linux:
  mvn package appassembler:assemble -Dmaven.test.skip=true

To run:
  Using Maven appassembler plugin:
    On Windows:
      target\appassembler\bin\pm-client.bat
    On Linux:
     ./target/appassembler/bin/pm-client


To run test:
  mvn test