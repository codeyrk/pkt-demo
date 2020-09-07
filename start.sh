#!/usr/bin/env bash

input_folder="/var/data/"
original_file_folder="01_original"
groomed_file_folder="02_groomed"
processed_file_folder="03_processed"
final_file_folder="04_final"
completed_file_folder="05_completed"
java_opts="-Xms8g -Xmx8g"
elastic_host="http://10.1.161.13:9200"
elastic_index="pcap_details"
bulk_size=1000
chunk_file_size_in_mb=500
current_dir=`pwd`

#This is update the params from env variable
init_params(){

    if ! [ -z "$ELASTIC_HOST" ]
    then
        elastic_host=$ELASTIC_HOST
    fi

    if ! [ -z "$JVM_OPTS" ]
    then
        java_opts=$JVM_OPTS
    fi

    if ! [ -z "$CHUNK_FILE_SIZE_MB" ]
    then
        chunk_file_size_in_mb=$CHUNK_FILE_SIZE_MB
    fi

    elastic_index=`date +%d-%m-%Y_pcap_data`

    echo "================================================================="
    echo "Params Used: "
    echo "java_opts: $java_opts"
    echo "elastic_host: $elastic_host"
    echo "elastic_index: $elastic_index"
    echo "bulk_size: $bulk_size"
    echo "chunk_file_size: $chunk_file_size_in_mb MB"
    echo "================================================================="

}

#This will calculate the number of chunk files
chunk_file_bucket_count(){
    file_size_mb=`du -m "$1" | cut -f1`
    if [ $file_size_mb -ge $chunk_file_size_in_mb ]
    then
        echo  `expr $file_size_mb / $chunk_file_size_in_mb`
    else
        echo 1
    fi
}

#It will break main Pcap files to 500Mb size of many files and will store it to $groomed_file_folder
break_pcap_file()
{
    pcap_file_path=`find $input_folder$original_file_folder -name "*.pcap" | head -n 1`
    if ! [ -z "$pcap_file_path" ]
    then
        echo "================================================================="
        echo "Breaking main pcap file: $pcap_file_path ......"
        echo "================================================================="
        relative_pcap_file_path=${pcap_file_path/$input_folder$original_file_folder/""}
        pcap_file_name=${relative_pcap_file_path##*/}
        relative_pcap_folder=${relative_pcap_file_path/$pcap_file_name/""}

        cd $current_dir/test-live
        groomed_folder_path=$input_folder$groomed_file_folder$relative_pcap_folder
        bucket_count=$( chunk_file_bucket_count $pcap_file_path )
        #Breaking pcap file
        ./test-live -r $pcap_file_path  -decode=false -dump=true -b $bucket_count -o $groomed_folder_path

        groom_files=(`ls $groomed_folder_path$pcap_file_name`)
        array_len=${#groom_files[@]}
        if [ $array_len -ge 1 ]
        then
            echo "Moving Pcap file: $pcap_file_path to completed folder "
            mkdir -p $input_folder$completed_file_folder$relative_pcap_folder
            mv $pcap_file_path ${pcap_file_path/$original_file_folder/$completed_file_folder}
        else
            echo "Error in breaking pcap file: $pcap_file_path"
        fi
    fi
}

#This is process groom file and extract the package details
process_groomed_file(){
    pcap_groomed_file_path=$1

    echo "================================================================="
    echo "processing sub file: $pcap_groomed_file_path ......"
    echo "================================================================="

    processed_folder_path=$input_folder$processed_file_folder$2
    # processing groomed file
    cd $current_dir/test-live
    ./test-live -r $1 -decode=true -dump=false -o $processed_folder_path 1>/dev/null

}

#this will call the Java jar to detect the devices
detect_devices(){
    processed_file_path=(`find $input_folder$processed_file_folder$1 -name "*pcap*.pcap.meta"`)
    array_len=${#processed_file_path[@]}
    if ! [ $array_len = 1 ]
    then
        echo "Error in generating meta file for $pcap_groomed_file_path. So skipping this file. Array len is $array_len"
        return 1
    else
        echo "================================================================="
        echo "Detecting Devices for $processed_file_path ......"
        echo "================================================================="

        cd $current_dir/java
        final_folder_path=$input_folder$final_file_folder$1
        java $java_opts -jar SessionProcessor-1.0-SNAPSHOT.jar $processed_file_path -o $final_folder_path
        return 0
    fi


}

#It will save session data to elastic search
load_to_db(){
    final_file_path=(`find $input_folder$final_file_folder$1 -name "*.ipa"`)
    array_len=${#final_file_path[@]}
    if ! [ $array_len = 1 ]
    then
        echo "Error in generating SessionLog file for $processed_file_path. So skipping this file. Array len is $array_len"
        return 1
    else
        echo "================================================================="
        echo "Loading to DB for file: $final_file_path ......"
        echo "================================================================="
        cd $current_dir/load-db
        output=$(./load-db -bulk $bulk_size -e $elastic_host -f $final_file_path -x $elastic_index 2>&1)
        echo $output
        if ! [[ $output =~ "indexed :" ]];
        then
            echo "Error in saving data to elastic"
            return 1
        fi
        return 0
    fi
}


### Main script starts here
have_more_files_to_process=false
init_params
while :
do
    if ! $have_more_files_to_process ; then
    #	Sleeping before starting new iteration
        sleep 2
    fi
    have_more_files_to_process=false
	echo "Starting new iteration"

    # This will break pcap files in smaller sizes
    break_pcap_file

    #Processing Sub File from groomed folder one by one
    mkdir -p $input_folder$groomed_file_folder
    for pcap_groomed_file_path in `find $input_folder$groomed_file_folder -name "*pcap*.pcap"`:
    do
       if [ -z "$pcap_file_path" ]; then
           continue
       fi
       have_more_files_to_process=true
       pcap_groomed_file_path=${pcap_groomed_file_path/".pcap:"/".pcap"}

       #Variable to be used
       relative_file_path=${pcap_groomed_file_path/$input_folder$groomed_file_folder/""}
       file_name=${relative_file_path##*/}
       relative_folder=${relative_file_path/$file_name/""}

       # process groom pcap file
       process_groomed_file $pcap_groomed_file_path $relative_folder

       # Detecting the devices
       if ! detect_devices $relative_file_path; then
            continue
       fi

       #Loading to DB
       if ! load_to_db $relative_file_path; then
            continue
       fi

       rm $pcap_groomed_file_path
    done
done