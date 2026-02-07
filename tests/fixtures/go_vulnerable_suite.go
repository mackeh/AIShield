package main

import (
	"crypto/md5"
	"fmt"
	"math/rand"
	"os/exec"
)

func insecureDemo(userInput string, token string, incoming string) {
	_ = md5.Sum([]byte(token))

	cmd := exec.Command("sh", "-c", "cat "+userInput)
	_ = cmd.Run()

	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userInput)
	_ = query

	if token == incoming {
		fmt.Println("timing-unsafe compare")
	}

	code := rand.Intn(1000000)
	_ = code
}
