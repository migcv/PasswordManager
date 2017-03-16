# PasswordManager

# Instructions using Maven — Client:

To compile and copy the properties file to the output directory:
```sh
$ mvn compile
```

To create a JAR with the compiled files:
```sh
mvn package -Dmaven.test.skip=true
```
To generate launch scripts for Windows and Linux:
```sh
mvn package appassembler:assemble -Dmaven.test.skip=true
```

To run using Maven appassembler plugin:
  - On Windows:

  ```sh
      target\appassembler\bin\pm-client.bat
  ```

  - On Linux:

  ```sh
     ./target/appassembler/bin/pm-client
  ```

To run test:
```sh
  mvn test
```
  
# Instructions using Maven — Server:

To compile and copy the properties file to the output directory:
```sh
  mvn compile
```

To create a JAR with the compiled files:
```sh
  mvn package
```

To install the package into the local repository, for use as a dependency in other projects locally:
```sh
  mvn install
```
  
To generate launch scripts for Windows and Linux:
```sh
  mvn package appassembler:assemble
```


To run RMI server using Maven appassembler plugin:
  - On Windows:

  ```sh
      target\appassembler\bin\pm-server.bat
  ```

  - On Linux:

  ```sh
     ./target/appassembler/bin/pm-server
  ```

