package utils

import (
	"log"
	"os"
)

func GetEnv(varName string) (bool, string) {
	env := os.Getenv(varName)

	if env == "" {
		return false, ""
	}

	return true, env
}

func GetEnvOrExit(varName string) string {
	env := os.Getenv(varName)

	if env == "" {
		log.Fatalf("Missing required env var: %s", varName)
	}

	return env
}
