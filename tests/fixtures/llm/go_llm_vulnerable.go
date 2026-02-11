package main

import (
	"fmt"
	"os/exec"
)

// AISHIELD-GO-LLM-001: String formatting in LLM prompt
func createPrompt(userInput string) string {
	prompt := fmt.Sprintf("Answer the user question: %s", userInput)
	return sendToOpenAI(prompt)
}

// AISHIELD-GO-LLM-002: Exec on LLM response
func executeResponse(response string) {
	cmd := exec.Command("sh", "-c", response)
	cmd.Run()
}

// AISHIELD-GO-LLM-003: String concatenation in prompt
func buildPrompt(userInput string) string {
	prompt := "Process the following user input: " + userInput
	return prompt
}

func sendToOpenAI(prompt string) string {
	// openai completion call
	return ""
}
