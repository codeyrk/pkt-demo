# PCAP Analysis Tool
## Introduction
PCAP analysis is tool for extracting useful intelligence from captured network traffic. Such PCAPs could be obtained from security agencies or business establishments where there is a need to monitor user’s network activity. 

This tools will keep on reading pcap files from a folder, analyze it and will upload final processed data to elasticsearch 

## Use Cases
- Profile User-IPs by for visited websites. 
- Classify Upload/download actions. 
- Classify IP address as service provider and users. 
- Timeline analysis: 
    - Identify the source of an event. 
    - Profile website traffic pattern and identify related websites. 
- Identify hacking/intrusion attempts.  
- Identify compromised users. 
- Profile services/website by service-type, country of origin etc. 
- Reconstruct un-encrypted emails, websites, VOIP calls etc.
- Analyze DNS traffic to reveal attempts of accessing blocked services. 
- Geolocation of IP-Address
- Device Profiling for NATed devices 
 

## Quick Start
#### Requirements
- [Golang](https://golang.org) version 1.14.2+
- [Java](https://www.java.com/en/download/help/download_options.xml) version 1.8
- TShark ([Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/index.html)) 2.6.9 

#### Setup
- set up GOPATH  `export GOPATH="~/go"`
- clone repo within GOPATH:
    - Please make sure to maintain the project path as specified below:
    - ```bash
      mkdir $GOPATH/src/github.com/codeyrk/pkt-demo
      cd $GOPATH/src/github.com/codeyrk/pkt-demo
      git clone https://github.com/codeyrk/pkt-demo.git
      export PCAP_TOOL_PATH="$GOPATH/src/github.com/codeyrk/pkt-demo" 
- Install dependencies:
    - ```bash
      cd "$PCAP_TOOL_PATH/test-live" 
      go mod tidy
      cd ../load-db
      go mod tidy
      ```

#### Start


- **From Docker**:
    - make sure to install docker before proceeding
    - ```bash
         cd "$PCAP_TOOL_PATH"
         
         //create docker image
         docker build -t local/docker-pcap_tools .
         
         //run docker
         docker run -v {pcap_data_folder_path}:/var/data -e JVM_OPTS='-Xms6g -Xmx6g' -e ELASTIC_HOST='{elastic_host}' -e CHUNK_FILE_SIZE_MB=400 docker-pcap_tools
         //Note: This will keep on reading pcap files from {pcap_data_folder_path}, analyze it and will upload final processed data to elasticsearch. It will create a new elastic index daily.

   
    
