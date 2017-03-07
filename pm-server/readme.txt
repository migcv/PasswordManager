This is Java RMI implementation of the Tic Tac Toe game


Instructions using Maven:
------------------------

To compile and copy the properties file to the output directory:
  mvn compile

To create a JAR with the compiled files:
  mvn package

To install the package into the local repository, for use as a dependency in other projects locally:
  mvn install
  
To generate launch scripts for Windows and Linux:
  mvn package appassembler:assemble

To launch RMI Registry with required code base:
  (replace project directory as necessary)
  (if the path is wrong no warning is produced immediately)
  On Windows:
    start rmiregistry -J-Djava.rmi.server.codebase=file:/C:/temp/ttt-rmi-server/target/ttt-rmi-server-1.0-SNAPSHOT.jar
  On Linux
    rmiregistry -J-Djava.rmi.server.codebase=file:/tmp/ttt-rmi-server/target/ttt-rmi-server-1.0-SNAPSHOT.jar &

To run RMI server:
  Using Maven appassembler plugin:
    On Windows:
      target\appassembler\bin\ttt-rmi-server.bat
    On Linux:
      ./target/appassembler/bin/ttt-rmi-server


To configure Maven project in Eclipse:
-------------------------------------

If Maven pom.xml exist:
  'File', 'Import...', 'Maven'-'Existing Maven Projects'
  'Select root directory' and 'Browse' to the project base folder.
	Check that the desired POM is selected and 'Finish'.

If Maven pom.xml do not exist:
  'File', 'New...', 'Project...', 'Maven Projects'.
	Check 'Create a simple project (skip architype selection)'.
	Uncheck  'Use default Workspace location' and 'Browse' to the project base folder.
	Fill the fields in 'New Maven Project'.
	the Check if everything is OK and 'Finish'.

To run:
  Select the main class and click 'Run' (the green play button).
  Specify arguments using 'Run Configurations'

--
2015-03-02
Miguel.Pardal@tecnico.ulisboa.pt