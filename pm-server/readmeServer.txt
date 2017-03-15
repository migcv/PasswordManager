Instructions using Maven — Server:
——————————————————————————————————

To compile and copy the properties file to the output directory:
  mvn compile

To create a JAR with the compiled files:
  mvn package

To install the package into the local repository, for use as a dependency in other projects locally:
  mvn install
  
To generate launch scripts for Windows and Linux:
  mvn package appassembler:assemble


To run RMI server:
  Using Maven appassembler plugin:
    On Windows:
      target\appassembler\bin\pm-server.bat
    On Linux:
      ./target/appassembler/bin/pm-server