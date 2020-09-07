package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var pcapfile = flag.String("r", "", "PCAP File to read from")
var device = flag.String("i", "", "interface to read from")
var outDir = flag.String("o", "/tmp", "Output directory")
var buckets = flag.Uint("b", 1, "No of buckets")
var by = flag.String("s", "ip", "Split by")
var bpf = flag.String("f", "not port 22", "BPF filter for pcap")
var dump = flag.Bool("dump", false, "Write PCAP ?")
var decode = flag.Bool("decode", false, "Decode PCAP ?")
var limitPackets = flag.Uint("c", 0, "Packets to process")

var fileToWrite string

var linkType layers.LinkType

func main() {
	defer util.Run()()

	// to change the flags on the default logger
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var files []os.FileInfo

	// Open device
	handle, err := pcap.OpenLive(*device, 65535, true, -1)
	if err != nil {
		log.Println("error opening interface: ", *device, err)

		files, err = ioutil.ReadDir(*pcapfile)
		if err != nil {
			if t, err := os.Stat(*pcapfile); os.IsNotExist(err) {
				//file does not exist
				log.Fatal(t, err)
			} else {
				fileToWrite = *pcapfile
				files = make([]os.FileInfo, 1)
				files[0] = t
			}
		} else {
			fileToWrite = files[0].Name()
		}
	} else {
		defer handle.Close()

		fileToWrite = *device
		if err := handle.SetBPFFilter(*bpf); err != nil {
			log.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(int(*buckets))

	var channels [512]chan gopacket.Packet
	for i := 0; i < int(*buckets); i++ {
		channels[i] = make(chan gopacket.Packet)
		go packetHandler(channels[i], &wg)
	}

	processFiles(*pcapfile, files, &channels)

	log.Println("Closing channels")
	for i := 0; i < int(*buckets); i++ {
		close(channels[i])
	}

	log.Println("Waiting for threads.")
	wg.Wait()

	log.Println("Finished.......")
}

var routine int
var packetsRead uint
var packetLimitReached = false

func processFiles(dir string, files []os.FileInfo, channels *[512]chan gopacket.Packet) {
	//for each file
	for _, file := range files {
		if packetLimitReached {
			return
		}
		filename := dir
		fi, _ := os.Stat(dir)
		if fi.Mode().IsDir() {
			filename = filename + "/" + file.Name()
		}
		//Open file
		handle, err := pcap.OpenOffline(filename)
		if err != nil {
			log.Println("error opening file: ", err)
			continue
		}

		log.Println("File opened: ", filename)
		if err := handle.SetBPFFilter(*bpf); err != nil {
			log.Println(err)
		}
		defer handle.Close()

		linkType = handle.LinkType()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.NoCopy = true
		for {
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				log.Println("EOF reached")
				break
			} else if err != nil {
				log.Println("Error:", err)
				continue
			}
			packetsRead++

			switch *by {
			case "ip":
				if net := packet.NetworkLayer(); net != nil {
					x := uint(net.NetworkFlow().FastHash())
					channels[x%(*buckets)] <- packet
				}
			case "port":
				if tx := packet.TransportLayer(); tx != nil {
					x := uint(tx.TransportFlow().FastHash())
					channels[x%(*buckets)] <- packet
				}
			}

			if *limitPackets != 0 && *limitPackets < packetsRead {
				packetLimitReached = true
				log.Println("Limit reached. Processed Packets::", *limitPackets)
				break
			}
		}
	}
}

func packetHandler(pkts chan gopacket.Packet, wg *sync.WaitGroup) {
	id := routine
	routine++
	i := 0

	f, w, wstd, flusher := func(wg *sync.WaitGroup) (*os.File, *pcapgo.Writer, *pcapgo.Writer, *bufio.Writer) {
		filename := filepath.Base(fileToWrite) + "_" + strconv.Itoa(id) + ".pcap"
		filename = strings.Replace(filename, "-", "_", -1)
		filename = strings.Replace(filename, ">", "", -1)

		dir := *outDir + "/" + filepath.Base(fileToWrite)

		var f *os.File
		var err error
		var w, wstd *pcapgo.Writer
		var reader *bufio.Reader
		var writer *bufio.Writer

		// Open output pcap file and write header
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			log.Println(err)
		}

		if *dump == true {
			log.Println("Dump is true: ", *dump)

			f, err = os.Create(dir + "/" + filename)
			if err != nil {
				log.Println(err)
			}
			w = pcapgo.NewWriter(f)

			err = w.WriteFileHeader(65535, linkType)
			if err != nil {
				log.Println(err)
			}
		}

		if *decode == true {

			log.Println("Decode is true:", *decode)

			reader, writer = scheduleReader(filename)

			go consume(filename, reader, writer, wg)

			wstd = pcapgo.NewWriter(writer)
			err = wstd.WriteFileHeader(65535, linkType)
			if err != nil {
				log.Println(err)
			}
		}
		return f, w, wstd, writer
	}(wg)

	for pkt := range pkts {
		i++
		if i%100000 == 0 {
			fmt.Println("Routine:", id, "Counter:", i, "Length:", len(pkt.Data()))
		}

		if *dump == true {
			err := w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
			if err != nil {
				log.Println(err)
			}
		}

		if *decode == true {
			err := wstd.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
			if err != nil {
				log.Println(err)
			}
		}
		// data := pkt.Data()
		// _, err = io.Copy(os.Stdout, bytes.NewReader(data))
		// if err != nil {
		// 	log.Println(err)
		// }
	}

	if *decode == true {
		flusher.Flush()
	}

	log.Println("Routine:", id, "Counter:", i, "Length:", 0)
	if f != nil {
		err := f.Close()
		if err != nil {
			log.Println(err)
		}
	}

	//routine done
	wg.Done()
}

//Config structure
type Config struct {
	Database struct {
		Host     string `json:"host"`
		Password string `json:"password"`
	} `json:"database"`
	Host    string `json:"host"`
	Port    string `json:"port"`
	Command string `json:"cmd"`
}

func loadConfiguration(file string) Config {
	var config Config
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		fmt.Println(err.Error())
	}
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&config)
	return config
}

func scheduleReader(fileName string) (*bufio.Reader, *bufio.Writer) {

	config := loadConfiguration("./conf.json")

	cmd := exec.Command("sh", "-c", config.Command)
	// cmd := exec.Command("sh", "-c", "tshark -N nd -T ek -i - -Y '!(tcp.port == 22)' -e frame.number -e frame.protocols "+
	// 	"-e frame.time_epoch -e ip.proto -e ipv6.nxt -e udp.stream -e tcp.stream -e ip.src -e ipv6.src -e ip.src_host -e ipv6.src_host -e udp.srcport -e tcp.srcport -e tcp.options.timestamp.tsval "+
	// 	"-e ip.dst -e ipv6.dst -e ip.dst_host -e ipv6.dst_host -e udp.dstport -e tcp.dstport -e tcp.options.timestamp.tsecr -e frame.cap_len -e tcp.flags.syn "+
	// 	"-e tcp.flags.ack -e tcp.flags.fin -e tcp.flags.res -e ssl.handshake.extensions_server_name "+
	// 	"-e http.host -e http.request.full_uri -e http.request.uri.query.parameter -e http.request.method "+
	// 	"-e http.content_type  -e http.content_length -e http.user_agent -e http.cookie "+
	// 	"-e radius.User_Name -e radius.Framed-IP-Address -e radius.Acct_Session_Id -e radius.Calling_Station_Id "+
	// 	"| grep -v '_index'")

	writer, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil
	}

	reader, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil
	}

	bufioReader := bufio.NewReaderSize(reader, 1024*1024)
	bufioWriter := bufio.NewWriterSize(writer, 1024*1024)

	err = cmd.Start()
	if err != nil {
		return nil, nil
	}
	return bufioReader, bufioWriter
}

func consume(file string, reader *bufio.Reader, writer *bufio.Writer, wg *sync.WaitGroup) {
	wg.Add(1)
	dir := *outDir + "/" + filepath.Base(fileToWrite)

	// Open output pcap file and write header
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		log.Println(err)
	}

	f, err := os.Create(dir + "/" + file + ".meta")
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	//	log.Println("Before read line for loop")
	var lines = 0
	for {
		line, pre, err := reader.ReadLine()
		for pre {
			var temp []byte
			temp, pre, err = reader.ReadLine()
			line = append(line, temp...)
		}

		if err == io.EOF {
			log.Println("Consumed Lines: ", lines)

			if strings.Contains(fileToWrite, ".pcap") {
				wg.Done()
				return
			}
			// break
			time.Sleep(1 * time.Second)
			continue
		}

		if err != nil {
			log.Println(err)
		}

		lines++

		_, err = f.Write(line)
		if err != nil {
			log.Println(err)
		}
		_, err = f.Write([]byte("\n"))
		if err != nil {
			log.Println(err)
		}

		fmt.Println(string(line))
	}
}
