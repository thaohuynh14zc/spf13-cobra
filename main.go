package main

import (
	"fmt"
)

func main() {
	originalURL := cobra.GetOriginalURL()
	fmt.Printf("Hello, Bounty Hunter! Original URL: %s\n", originalURL)
}
