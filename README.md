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


```sh
  mvn compile package install 
```

To lauch the RMI servers :

  - On Windows:

```sh
    target\appassembler\bin\pm-server.bat 
```

  - On MAC:

  ```sh
     open run.scpt -- PasswordManager/pm-server
     click in the play button
  ```

To run the tests with Script Editor:
    All the scripts to inject byzantine behaviour are in the folder: PasswordManager/pm-server, with the following name:

```sh
    getWrongNonce
    getWrongWriteRank
    putWrongPass
    putWrongRID
    putWrongTimeStamp
```
