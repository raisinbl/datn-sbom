package main

import (
	"github.com/raisinbl/datn-sbom/genSbom"
	// "fmt"
	// "reflect"
	// "os"
)

func main(){
	// ssbom := genSbom.GenSBOM("test-fixture/python/requirements.txt")
	// fmt.Println(genSbom.PrintSBOM(ssbom))
	genSbom.GetVuls2()
}