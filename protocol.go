package main

import "github.com/subgraph/ozipc"

const SocketName = "@oz-control"

type OkMsg struct {
	_ string "Ok"
}

type ErrorMsg struct {
	Msg string "Error"
}

type AskForwarderMsg struct {
	Id   int "AskForwarder"
	Name string
	Addr string
	Port string
}

type ForwarderSuccessMsg struct {
	Proto string "ForwarderSuccess"
	Addr  string
	Port  string
}

type SandboxInfo struct {
	Id      int "SandboxInfo"
	Address string
	Profile string
	Mounts  []string
}

type ListSandboxesMsg struct {
	_ string "ListSandboxes"
}

type ListSandboxesResp struct {
	Sandboxes []SandboxInfo "ListSandboxesResp"
}

var messageFactory = ipc.NewMsgFactory(
	new(OkMsg),
	new(ErrorMsg),
	new(ForwarderSuccessMsg),
	new(AskForwarderMsg),
	new(ListSandboxesMsg),
	new(ListSandboxesResp),
	new(SandboxInfo),
)
