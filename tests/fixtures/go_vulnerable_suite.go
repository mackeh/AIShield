package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

func insecureDemo(userInput string, token string, incoming string, req *http.Request, w http.ResponseWriter) {
	_ = md5.Sum([]byte(token))
	_ = sha1.Sum([]byte(token))
	_, _ = des.NewCipher([]byte("12345678"))
	_, _ = rsa.GenerateKey(rand.Reader, 1024)

	cmd := exec.Command("sh", "-c", "cat "+userInput)
	_ = cmd.Run()

	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userInput)
	query2 := "SELECT * FROM users WHERE name = " + userInput
	_ = query
	_ = query2

	_, _ = os.ReadFile("/var/data/" + userInput)
	http.Redirect(w, req, req.URL.Query().Get("next"), http.StatusFound)

	apiKey := req.URL.Query().Get("apiKey")
	incomingApiKey := req.Header.Get("X-Api-Key")
	password := req.URL.Query().Get("password")
	expectedPassword := req.Header.Get("X-Expected-Password")

	if token == incoming {
		fmt.Println("timing-unsafe compare")
	}
	if apiKey == incomingApiKey {
		fmt.Println("insecure api key compare")
	}
	if password == expectedPassword {
		fmt.Println("insecure password compare")
	}
	if strings.ToLower(token) == strings.ToLower(incoming) {
		fmt.Println("case-normalized compare")
	}

	authorization := "Bearer " + token
	_ = authorization

	code := mrand.Intn(1000000)
	_ = code

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	_ = tlsConfig
	w.Header().Set("Access-Control-Allow-Origin", "*")
	log.Printf("debug: %v", req.Header)
	_ = http.ListenAndServe("0.0.0.0:8080", nil)
	debug := true
	_ = debug
}
