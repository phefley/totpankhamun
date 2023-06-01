// reference https://www.developer.com/languages/intro-socket-programming-go/

// reference https://github.com/pquerna/otp/blob/master/totp/totp.go

package main

import (
	"flag"
	"io"
	"log"
	"os/exec"
	"strings"

	"github.com/mdp/qrterminal/v3"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"bytes"
	"fmt"
	"image/png"
	"net"
	"os"
	"strconv"
	"time"
)

func display(key *otp.Key, data []byte) {
	//fmt.Printf("Issuer:       %s\n", key.Issuer())
	//fmt.Printf("Account Name: %s\n", key.AccountName())
	//fmt.Printf("Secret:       %s\n", key.Secret())
	//fmt.Println("Writing PNG to qr-code.png....")
	//ioutil.WriteFile("qr-code.png", data, 0644)
	//fmt.Println("")
	qrterminal.Generate(key.URL(), qrterminal.H, os.Stdout)
	//fmt.Println("Please add your TOTP to your OTP Application now!")
	//fmt.Println("")
}

func keyhole(port int, waitTimeInSeconds int, incomingAddressChan chan string) {
	addr, err := net.ResolveTCPAddr("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		fmt.Println("[-] Could not parse the port number in to a local TCP address.")
		log.Fatal(err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		fmt.Println("[-] Could not start the TCP listener on port ", port, ".")
		log.Fatal(err)
	}
	l.SetDeadline(time.Now().Add(time.Duration(waitTimeInSeconds) * time.Second))
	defer l.Close()

	conn, err := l.Accept()
	if err != nil {
		//Can't die here!
		//log.Println(err)
	} else {
		io.Copy(conn, conn)
		incomingAddr := conn.RemoteAddr()
		incomingAddressChan <- strings.Split(incomingAddr.String(), ":")[0]
		conn.Close()
	}
}

func haskey(mapToTest map[string]int, str string) bool {
	for k := range mapToTest {
		if k == str {
			return true
		}
	}
	return false
}

func main() {

	var baseFlag int
	var roundsFlag int
	var actionCommand string
	winnerMap := make(map[string]int)

	flag.IntVar(&baseFlag, "base", 1000, "What base should be added to the port? Must be between 1000 and 64000.")
	flag.IntVar(&roundsFlag, "rounds", 1, "How many rounds are required for success?")
	flag.StringVar(&actionCommand, "action", "", "The command which will be executed when successful. The template {CALLER} can be used to obtain the IP address of the successful caller.")
	flag.Parse()
	if baseFlag < 1000 || baseFlag > 64000 {
		log.Fatal("[-] The base value must be between 1000 and 64000.")
	}

	haveAWinner := false

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "totpankhuman.tomb",
		AccountName: "archaeologist@tomb-raider.com",
	})
	if err != nil {
		panic(err)
	}
	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)

	// display the QR code to the user.
	display(key, buf.Bytes())

	for !haveAWinner {
		currentSecondHand := time.Now().Second()
		if currentSecondHand == 0 || currentSecondHand == 30 {
			// Need to start this process only on :00 and :30 second marks.
			codeString, err := totp.GenerateCode(key.Secret(), time.Now())
			if err != nil {
				fmt.Println(err)
			}

			firstPortBase, err := strconv.Atoi(string(codeString[:3]))
			if err != nil {
				fmt.Println(err)
			}

			secondPortBase, err := strconv.Atoi(string(codeString[3:]))
			if err != nil {
				fmt.Println(err)
			}

			firstPort := baseFlag + firstPortBase
			secondPort := baseFlag + secondPortBase
			//fmt.Println("First port:", firstPort)
			//fmt.Println("Second port:", secondPort)

			var firstCallerChannel chan string = make(chan string, 1)
			var secondCallerChannel chan string = make(chan string, 1)
			go keyhole(firstPort, 30, firstCallerChannel)
			go keyhole(secondPort, 30, secondCallerChannel)

			fmt.Println("[*] Started next port listeners. Waiting on connections...")
			time.Sleep(30 * time.Second)

			var firstCaller string
			var secondCaller string

			if len(firstCallerChannel) > 0 {
				firstCaller = <-firstCallerChannel
				fmt.Println("[+] Got a first caller in on channel")
			}
			if len(secondCallerChannel) > 0 {
				secondCaller = <-secondCallerChannel
				fmt.Println("[+] Got a second caller in on channel")
			}
			if (firstCaller != "") && (secondCaller != "") {
				fmt.Println("[+] Got two callers. Making sure they're the same...")
				if firstCaller == secondCaller {
					if haskey(winnerMap, secondCaller) {
						winnerMap[secondCaller] = winnerMap[secondCaller] + 1
					} else {
						winnerMap[secondCaller] = 1
					}
					fmt.Println("[++]", secondCaller, "is a winner and has won", winnerMap[secondCaller], "times.")
					// Check round count
					if winnerMap[secondCaller] >= roundsFlag {
						haveAWinner = true
						fmt.Println("[++]", secondCaller, "is the overall winner!")
					}
					if actionCommand != "" {
						actionCommand = strings.Replace(actionCommand, "{CALLER}", secondCaller, -1)
						fmt.Println("[+] Will execute:", actionCommand)
						cmd := exec.Command(actionCommand)
						if err := cmd.Start(); err != nil {
							log.Fatal(err)
						}
					}
				}
			}
		} else {
			time.Sleep(1 * time.Second)
		}
	}
}
