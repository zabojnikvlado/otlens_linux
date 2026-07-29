package udpconversation

import "fmt"

type Key struct{EndpointAIP string; EndpointAPort uint16; EndpointBIP string; EndpointBPort uint16}
func NewKey(aip string, aport uint16,bip string,bport uint16) Key {if fmt.Sprintf("%s:%d",aip,aport)>fmt.Sprintf("%s:%d",bip,bport){return Key{bip,bport,aip,aport}};return Key{aip,aport,bip,bport}}
