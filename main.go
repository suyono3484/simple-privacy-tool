package main

import (
	"fmt"
	"gitea.suyono.dev/suyono/simple-privacy-tool/cmd/spt"
)

func main() {
	err := spt.Execute()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		//panic(err)
	}
}
