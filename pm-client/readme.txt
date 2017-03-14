Instructions using Maven:
------------------------

To compile and copy the properties file to the output directory:
  mvn compile

To create a JAR with the compiled files:
  mvn package

To generate launch scripts for Windows and Linux:
  mvn package appassembler:assemble

To run:
  Using Maven appassembler plugin:
    On Windows:
      target\appassembler\bin\pm-client.bat
    On Linux:
     ./target/appassembler/bin/pm-client


