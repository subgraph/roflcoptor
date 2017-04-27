package ozclient

import (
	"errors"
	"fmt"
	"github.com/subgraph/ozipc"
)

func clientConnect() (*ipc.MsgConn, error) {
	return ipc.Connect(SocketName, messageFactory, nil)
}

func ListSandboxes() ([]SandboxInfo, error) {
	resp, err := clientSend(&ListSandboxesMsg{})
	if err != nil {
		return nil, err
	}
	body, ok := resp.Body.(*ListSandboxesResp)
	if !ok {
		return nil, errors.New("ListSandboxes response was not expected type")
	}
	return body.Sandboxes, nil
}

func clientSend(msg interface{}) (*ipc.Message, error) {
	c, err := clientConnect()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	rr, err := c.ExchangeMsg(msg)
	if err != nil {
		return nil, err
	}

	resp := <-rr.Chan()
	rr.Done()
	return resp, nil
}

func AskForwarder(id int, name, port string) (string, error) {
	askForwarderMsg := AskForwarderMsg{
		Id:   id,
		Name: name,
		Port: port,
	}
	resp, err := clientSend(&askForwarderMsg)
	if err != nil {
		return "", err
	}
	body, ok := resp.Body.(*ForwarderSuccessMsg)
	if !ok {
		body, ok := resp.Body.(*ErrorMsg)
		if ok {
			return "", fmt.Errorf("Unexpected message received for sandbox %d (%s) port %s: %+v", id, name, port, body.Msg)
		} else {
			return "", fmt.Errorf("Unknown message received: %+v", resp)
		}
	} else {
		return body.Addr, nil
	}
}
