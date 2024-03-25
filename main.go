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
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
)

func display(key *otp.Key) {
	fmt.Printf("Issuer:       %s\n", key.Issuer())
	fmt.Printf("Account Name: %s\n", key.AccountName())
	fmt.Printf("Secret:       %s\n", key.Secret())
	fmt.Println()
	qrterminal.Generate(key.URL(), qrterminal.H, os.Stdout)
	fmt.Println("Please add this TOTP to your OTP Application now!")
	fmt.Println("")
}

func readKey(fileName string) *otp.Key {
	content, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Println("[-] Could not open the keyfile to read from.")
		fmt.Println(err)
	}
	urlStr := string(content)
	key, err := otp.NewKeyFromURL(urlStr)
	if err != nil {
		fmt.Println("[-] Could not parse the data from the key file.")
		fmt.Println(err)
	}
	return key
}

func writeKey(key *otp.Key, fileName string) {
	outfile, err := os.Create(fileName)
	if err != nil {
		fmt.Println("[-] Could not open the keyfile to write to.")
		fmt.Println(err)
	}
	_, err = outfile.WriteString(key.URL())
	if err != nil {
		fmt.Println("[-] Could not write the keyfile.")
		fmt.Println(err)
	}
	err = outfile.Close()
	if err != nil {
		fmt.Println("[-] Could not close the keyfile.")
		fmt.Println(err)
	}
}

func writeKeyQr(keyPtr *otp.Key, fileName string) {
	var buf bytes.Buffer
	img, err := keyPtr.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)
	os.WriteFile(fileName, buf.Bytes(), 0644)
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

	var baseFlag, roundsFlag, tripwiresFlag int
	var actionCommandFlag, actionCommandArgsFlag, keyFileFlag, qrPngFileFlag string
	var generateKeyFlag bool
	var keyPtr *otp.Key
	var keyUrl string

	winnerMap := make(map[string]int)

	flag.BoolVar(&generateKeyFlag, "generatekey", false, "Should we generate a TOTP for you? If so, we'll need a keyfile (-keyfile) to write it to if you want.")
	flag.StringVar(&keyFileFlag, "keyfile", "", "A filename to a keyfile to read in and use or to write to (when -generatekey is used as well).")
	flag.StringVar(&qrPngFileFlag, "qrfile", "", "A (.png) filename to write the key QR to when generated.")
	flag.IntVar(&baseFlag, "base", 1000, "What base should be added to the port? Must be between 1000 and 64000.")
	flag.IntVar(&roundsFlag, "rounds", 1, "How many rounds are required for success?")
	flag.IntVar(&tripwiresFlag, "tripwires", 0, "How many tripwires should be deployed?")
	flag.StringVar(&actionCommandFlag, "action", "", "The command which will be executed when successful. Not the args.")
	flag.StringVar(&actionCommandArgsFlag, "actionargs", "", "The command arguments. The template {CALLER} can be used to obtain the IP address of the successful caller.")
	flag.Parse()

	if baseFlag < 1000 || baseFlag > 64000 {
		log.Fatal("[-] The base value must be between 1000 and 64000.")
	}

	haveAWinner := false

	if generateKeyFlag {
		keyPtr, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "totpankhuman.tomb",
			AccountName: "archaeologist@tomb-raider.com",
		})
		if err != nil {
			panic(err)
		}

		if qrPngFileFlag != "" {
			// Convert TOTP key into a PNG
			writeKeyQr(keyPtr, qrPngFileFlag)
		}

		// display the QR code to the user.
		display(keyPtr)

		keyUrl = keyPtr.URL()
		fmt.Println("[*] Generated key:", keyUrl)
		// should we write that keyfile?
		if keyFileFlag != "" {
			fmt.Println("[*] writing the key file out to", keyFileFlag)
			writeKey(keyPtr, keyFileFlag)
		}
	} else {
		if keyFileFlag != "" {
			fmt.Println("[*] reading key data from", keyFileFlag)
			keyPtr = readKey(keyFileFlag)
			keyUrl = keyPtr.URL()
		} else {
			// I need a key!!!
			log.Fatal("[--] You need to either provide a key file or let me generate one.")
		}
	}

	// Why do I have to do this?? Garbage collection seems to wipe my key object
	keyPtr, err := otp.NewKeyFromURL(keyUrl)
	if err != nil {
		fmt.Println(err)
	}

	for !haveAWinner {
		currentSecondHand := time.Now().Second()
		if currentSecondHand == 0 || currentSecondHand == 30 {
			fmt.Println()
			// Need to start this process only on :00 and :30 second marks.
			codeString, err := totp.GenerateCode(keyPtr.Secret(), time.Now())
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
			fmt.Println("First port:", firstPort)
			fmt.Println("Second port:", secondPort)

			var firstCallerChannel chan string = make(chan string, 1)
			var secondCallerChannel chan string = make(chan string, 1)
			go keyhole(firstPort, 30, firstCallerChannel)
			go keyhole(secondPort, 30, secondCallerChannel)

			var twChannel chan string = make(chan string, tripwiresFlag)
			// Do we need to set up tripwires?
			if tripwiresFlag > 0 {
				for i := 1; i <= tripwiresFlag; i++ {
					var tripPort int
					for {
						// make a random integer less than 1000
						tripPort = rand.Intn(1000) + baseFlag
						// confirm is't not one of the portBases
						if (tripPort != firstPort) && (tripPort != secondPort) {
							break
						}
					}
					// start a tripwire on that
					go keyhole(tripPort, 30, twChannel)
					fmt.Println("Started tripwire on:", tripPort)
				}
			}

			fmt.Println("[*] Started next port listeners. Waiting on connections...")
			time.Sleep(25 * time.Second)

			// close channels
			close(twChannel)

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
			if len(twChannel) > 0 {
				//invalidate any votes and remove them from the map
				for perp := range twChannel {
					fmt.Println("[-] Tripped a wire: ", perp)
					if firstCaller == perp {
						firstCaller = ""
						fmt.Println("[-] Invalidating a vote for", perp, "as they tripped a wire.")
					}
					if secondCaller == perp {
						secondCaller = ""
						fmt.Println("[-] Invalidating a vote for", perp, "as they tripped a wire.")
					}
					if haskey(winnerMap, perp) {
						delete(winnerMap, perp)
						fmt.Println("[-] Removing previous wins for", perp, "as they tripped a wire.")
					}
				}
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
					if actionCommandFlag != "" {
						actionCommandArgsFlag = strings.Replace(actionCommandArgsFlag, "{CALLER}", secondCaller, -1)
						fmt.Println("[+] Will execute:", actionCommandFlag, actionCommandArgsFlag)
						cmd := exec.Command(actionCommandFlag, actionCommandArgsFlag)
						if err := cmd.Start(); err != nil {
							log.Fatal(err)
						}
					}
				}
			}
		} else {
			time.Sleep(1 * time.Second)
			fmt.Print(".")
		}
	}
}
