package main

import (
	// "github.com/raisinbl/datn-sbom/genSbom"
	"github.com/raisinbl/datn-sbom/cmd"
	// "fmt"
	// "reflect"
	// "os"
	
)

func main(){
	// ssbom := genSbom.GenSBOM("test-fixture/python/requirements.txt")
	// fmt.Println(genSbom.PrintSBOM(ssbom))
	// genSbom.GetVuls2()
	cmd.Execute()

}