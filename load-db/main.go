package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/pcapgo"
	"github.com/olivere/elastic"
)

const ES_BULK_COUNT = 1000

var esClient *elastic.Client
var bulkRequest *elastic.BulkService
var bulkRequestCount int

var packetDetails = flag.String("f", "", "Filename to read packet details from")
var devMapFile = flag.String("d", "", "Filename to read device map from")
var elasticURL = flag.String("e", "", "Elastic search url")
var index = flag.String("x", "", "Elastic search index")

type result struct {
}

func ReadLine(r *bufio.Reader) ([]byte, error) {
	line, pre, err := r.ReadLine()
	var l []byte
	for {
		if pre == false {
			break
		}
		l, pre, err = r.ReadLine()
		line = append(line, l...)
	}
	return line, err
}

var deviceMap map[int64]string
var devToFileMap map[string]*deviceFile

type deviceFile struct {
	f   *os.File
	w   *pcapgo.Writer
	dev string
}

func initElastic() {
	if *elasticURL == "" {
		log.Println("Elastic URL not specified")
		return
	}
	var err error
	esClient, err = elastic.NewClient(elastic.SetURL(*elasticURL))
	if err != nil {
		log.Println("Failed to init Elastic")
		return
	}
	bulkRequest = esClient.Bulk()
	bulkRequestCount = 0
}

func flushBulkRequests() {
	if esClient == nil {
		return
	}

	numberOfActions := bulkRequest.NumberOfActions()

	// Do sends the bulk requests to Elasticsearch
	bulkResponse, err := bulkRequest.Do(context.Background())
	if err != nil {
		// ...
	}

	// Bulk request actions get cleared
	if bulkRequest.NumberOfActions() != 0 {
		// ...
	}

	// Indexed returns information abount indexed documents
	indexed := bulkResponse.Indexed()
	if len(indexed) != numberOfActions {
		log.Println("problem with bulk request")
	} else {
		log.Println("indexed : ", bulkRequestCount)
	}

	//bulkRequestCount = 0
}
func pushToElastic(id string, obj interface{}) {

	if esClient == nil {
		return
	}

	testIndexName := filepath.Base(*index + ".pcap_tshark")
	testIndexName = strings.ToLower(testIndexName)
	testDocType := "bdr"

	// Add a document
	indexRequest := elastic.NewBulkIndexRequest().
		Index(testIndexName).
		Type(testDocType).
		Id(id).
		Doc(obj)

	bulkRequest = bulkRequest.Add(indexRequest)
	bulkRequestCount += 1

	if bulkRequestCount%ES_BULK_COUNT == 0 {
		flushBulkRequests()
	}

}

func load_packet_device_map() bool {
	if *devMapFile == "" {
		log.Println("Empty Device Map File")
		return false
	}

	csvFile, err := os.Open(*devMapFile)
	if err != nil {
		fmt.Println("fail to load map file")
		log.Fatal(err)
	}

	reader := csv.NewReader(bufio.NewReader(csvFile))
	// var pktInfo []PktInfo
	for {
		line, error := reader.Read()
		if error == io.EOF {
			break
		} else if error != nil {
			log.Fatal(error)
		}
		v1, _ := strconv.ParseInt(line[0], 10, 64)
		v2 := line[8]

		deviceMap[v1] = v2
	}

	fmt.Println("Entries in deviceMap: ", len(deviceMap))

	return true
}

func main() {
	util.Run()

	deviceMap = make(map[int64]string)
	devToFileMap = make(map[string]*deviceFile)

	if !load_packet_device_map() {
		return
	}

	if *packetDetails == "" {
		log.Println("Packet details file not specified")
		return
	}

	initElastic()

	// Test read permissions
	FILE, err := os.OpenFile(*packetDetails, os.O_RDONLY, 0666)
	if err != nil {
		if os.IsPermission(err) {
			log.Println("Error: Read permission denied.")
		}
	}

	reader := bufio.NewReader(FILE)

	dec := json.NewDecoder(reader)
	// // read open bracket
	// t, err := dec.Token()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Printf("%T: %v\n", t, t)

	var i int

	// while the array contains values
	for dec.More() {
		i++
		var obj interface{}
		// decode an array value (Message)
		err := dec.Decode(&obj)
		if err != nil {
			log.Fatal(err)
		}

		if i%2 == 1 {
			continue
		}

		m := obj.(map[string]interface{})
		n := m["layers"].(map[string]interface{})
		tsv := n["frame_time_epoch"].([]interface{})
		ts := tsv[0].(string)
		ts = strings.Replace(ts, ".", "", -1)
		t, _ := strconv.ParseInt(ts, 10, 64)
		id := deviceMap[t]
		if id != "" {
			m["DeviceId"] = id
			// ret, _ := json.Marshal(obj)

			pushToElastic(ts, obj)
			// fmt.Println(string(ret))
		}

	}

	// read closing bracket
	// t, err = dec.Token()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// for {
	// 	line, err := ReadLine(reader)
	// 	line, err = ReadLine(reader)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		if err == io.EOF {
	// 			break
	// 		}
	// 	}

	// 	// fmt.Println(string(line))

	// 	var obj interface{}
	// 	err = json.Unmarshal(line, &obj)

	// 	if err != nil {
	// 		fmt.Println(err)
	// 	} else {
	// 		m := obj.(map[string]interface{})
	// 		n := m["layers"].(map[string]interface{})
	// 		p := n["frame"].(map[string]interface{})
	// 		ts := p["frame_frame_time_epoch"].(string)
	// 		ts = strings.Replace(ts, ".", "", -1)
	// 		t, _ := strconv.ParseInt(ts, 10, 64)
	// 		id := deviceMap[t]
	// 		if id != "" {
	// 			m["DeviceId"] = id
	// 			// ret, _ := json.Marshal(obj)

	// 			pushToElastic(ts, obj)
	// 			// fmt.Println(string(ret))
	// 		}
	// 	}
	// }

	flushBulkRequests()
	FILE.Close()

	// file := "../../../../PCAPData/dev2.pcap"
	// // file := "../packet_library/split_pcap_new/out/IP_192.168.15.4/DEV_2/nitroba.pcap_192.168.15.4_DEV_2.pcap"
	// // file := "../packet_library/PCAPData/dev2.pcap"
	// d := goshark.NewDecoder()
	// if err := d.DecodeStart(file); err != nil {
	// 	log.Println("Decode start fail:", err)
	// 	return
	// }

	// for {
	// 	f, err := d.NextPacket()
	// 	if err != nil {
	// 		log.Println("Get packet fail:", err)
	// 		if err == io.EOF {
	// 			break
	// 		}
	// 		continue
	// 	}

	// 	// fmt.Print(f.Attrs)

	// 	// fmt.Println(f)
	// 	var fld goshark.Field
	// 	var ok bool
	// 	var val string

	// 	key := "ssl.handshake.extensions_server_name"
	// 	val, ok = f.Iskey(key)
	// 	if ok {
	// 		fmt.Printf("key: %s\nvalue: %s\n", key, val)
	// 	}

	// 	fld, ok = f.Getfield("ssl.handshake.certificate")
	// 	if ok {
	// 		fld, ok = fld.Getfield("x509af.validity_element")
	// 		if ok {
	// 			fld, ok = fld.Getfield("x509af.notBefore")
	// 			if ok {
	// 				val, ok = fld.Iskey("x509af.utcTime")
	// 				if ok {
	// 					fmt.Println("Valid After: ", val)
	// 				}
	// 			}
	// 			fld = *fld.Parent
	// 			fld, ok = fld.Getfield("x509af.notAfter")
	// 			if ok {
	// 				val, ok = fld.Iskey("x509af.utcTime")
	// 				if ok {
	// 					fmt.Println("Valid Before: ", val)
	// 				}
	// 			}
	// 		}
	// 	}

	// }

	// d.DecodeEnd()

}
