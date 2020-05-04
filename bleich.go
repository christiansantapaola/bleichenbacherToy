package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/qrowsxi/modulo"
)

type server struct {
	pubkey, privkey, e int64
}

func (s *server) leakyDecrypt(cryptedMessage int64) int {
	message := modulo.RSADecrypt(cryptedMessage, s.privkey, s.pubkey)
	return int(message & int64(1))
}

type client struct {
	pubkey, e int64
}

func (c *client) encrypt(message int64) int64 {
	return modulo.RSAEncrypt(message, c.e, c.pubkey)
}

// Filter will filter an []in64 array
func Filter(array []int64, f func(elem int64) bool) []int64 {
	var result []int64
	for _, elem := range array {
		if f(elem) {
			result = append(result, elem)
		}
	}
	return result
}

// GuessFromLeaks will guess the password given the leaked bits
func GuessFromLeaks(leaks []int64, pubkey int64) []int64 {
	var guess []int64
	for i := int64(0); i < pubkey; i++ {
		guess = append(guess, i)
	}
	for i, bit := range leaks {
		if bit%2 == 0 {
			guess = Filter(guess, func(elem int64) bool {
				pow2, _ := modulo.PowerMod(int64(2), int64(i), pubkey)
				if ((elem*pow2)%pubkey)%2 == 0 {
					return true
				}
				return false
			})
		} else {
			guess = Filter(guess, func(elem int64) bool {
				pow2, _ := modulo.PowerMod(int64(2), int64(i), pubkey)
				if ((elem*pow2)%pubkey)%2 != 0 {
					return true
				}
				return false
			})
		}
		fmt.Println(fmt.Sprintf("%d * message mod %d first bit is: %d", (2 << i), pubkey, bit))
		fmt.Println("guess is in\n", guess)
	}
	return guess
}

func UsageError(name string) {
	fmt.Println(fmt.Sprintf("usage: %s pubkey e privkey message", name))
	os.Exit(1)
}

func main() {
	var pubkey int64
	var e int64
	var privkey int64
	var message int64
	if len(os.Args) < 2 {
		UsageError("bleichenbacher-toy")
	}
	pubkey, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil {
		UsageError("bleichenbacher-toy")
	}
	e, err = strconv.ParseInt(os.Args[2], 10, 64)
	if err != nil {
		UsageError("bleichenbacher-toy")
	}
	privkey, err = strconv.ParseInt(os.Args[3], 10, 64)
	if err != nil {
		UsageError("bleichenbacher-toy")
	}
	message, err = strconv.ParseInt(os.Args[4], 10, 64)
	if err != nil {
		UsageError("bleichenbacher-toy")
	}
	if pubkey >= 256 || e >= 256 || privkey >= 256 || message >= 256 {
		fmt.Println("all value should be 1byte value (0,255)")
		os.Exit(1)
	}
	cl := client{pubkey, e}
	srv := server{pubkey, privkey, e}
	cryptedMessage := cl.encrypt(message)
	fmt.Println("crypted message known is: ", cryptedMessage)
	var leaks []int64
	for i := int64(0); i < 8; i++ {
		pow2, _ := modulo.PowerMod(2, i*cl.e, cl.pubkey)
		bit := srv.leakyDecrypt(cryptedMessage * pow2 % cl.pubkey)
		leaks = append(leaks, int64(bit))
	}
	fmt.Println("leaks: ", leaks)
	guess := GuessFromLeaks(leaks, cl.pubkey)
	fmt.Println("message is: ", message)
	fmt.Println("guess is: ", guess)
}
